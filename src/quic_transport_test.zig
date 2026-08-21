const std = @import("std");
const quic_zig = @import("quic");

const control = @import("control.zig");
const message = @import("message.zig");
const quic = @import("transport/quic.zig");
const quic_runtime = @import("transport/quic_runtime.zig");
const quic_streams = @import("transport/quic_streams.zig");

const test_cert_pem = @embedFile("testdata/test_cert.pem");
const test_key_pem = @embedFile("testdata/test_key.pem");

fn defaultParams() quic_zig.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
    };
}

fn testAddress(octet: u8, port: u16) quic_runtime.Address {
    return .{ .ipv4 = .{
        .addr = .{ 127, 0, 0, octet },
        .port = port,
    } };
}

fn pumpClientToServer(
    cli: *quic_zig.Client,
    srv: *quic_zig.Server,
    rx: []u8,
    addr: quic_zig.conn.path.Address,
    now_us: u64,
) !usize {
    var n: usize = 0;
    while (try cli.conn.poll(rx, now_us)) |len| {
        _ = try srv.feed(rx[0..len], addr, now_us);
        n += 1;
    }
    return n;
}

fn pumpServerToClient(
    srv: *quic_zig.Server,
    cli: *quic_zig.Client,
    rx: []u8,
    now_us: u64,
) !usize {
    var n: usize = 0;
    for (srv.iterator()) |slot| {
        while (try slot.conn.poll(rx, now_us)) |len| {
            try cli.conn.handle(rx[0..len], null, now_us);
            n += 1;
        }
    }
    return n;
}

fn pumpRuntimeClientToServer(
    client: *quic_runtime.ClientRuntime,
    listener: *quic_runtime.ListenerRuntime,
    rx: []u8,
    client_addr: quic_runtime.Address,
    now_us: u64,
) !usize {
    var n: usize = 0;
    while (try client.drainOutbound(rx, now_us)) |out| {
        _ = try listener.feedInbound(.{
            .bytes = rx[0..out.len],
            .from = client_addr,
        }, now_us);
        n += 1;
    }
    return n;
}

fn pumpRuntimeServerToClient(
    listener: *quic_runtime.ListenerRuntime,
    client: *quic_runtime.ClientRuntime,
    rx: []u8,
    now_us: u64,
) !usize {
    var n: usize = 0;
    while (try listener.drainOutbound(rx, now_us)) |out| {
        try client.feedInbound(.{
            .bytes = rx[0..out.len],
            .from = null,
        }, now_us);
        n += 1;
    }
    return n;
}

fn driveRuntime(
    client: *quic_runtime.ClientRuntime,
    listener: *quic_runtime.ListenerRuntime,
    rx: []u8,
    client_addr: quic_runtime.Address,
    now_us: u64,
) !void {
    _ = try pumpRuntimeClientToServer(client, listener, rx, client_addr, now_us);
    _ = try pumpRuntimeServerToClient(listener, client, rx, now_us);
    try listener.tick(now_us);
    try client.tick(now_us);
}

fn driveRuntimeReady(
    client: *quic_runtime.ClientRuntime,
    listener: *quic_runtime.ListenerRuntime,
) !void {
    var rx: [8192]u8 = undefined;
    const client_addr = testAddress(0x61, 4433);

    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = @as(u64, step + 1) * 1_000;
        try driveRuntime(client, listener, &rx, client_addr, now_us);
        if (client.connection().handshakeDone() and listener.connectionCount() > 0 and
            listener.connection(0).?.handshakeDone()) return;
    }

    return error.WouldBlock;
}

fn driveHermeticQuicReady(
    allocator: std.mem.Allocator,
    client_session: *quic.QuicSession,
    server_session: *quic.QuicSession,
) !void {
    const protos = [_][]const u8{quic.alpn};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test fixture
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr = testAddress(0x51, 4433);
    try cli.conn.advance();

    var rounds_to_handshake: u32 = 0;
    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = @as(u64, step) * 1_000;

        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);

        try srv.tick(now_us);
        try cli.conn.tick(now_us);

        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone())
        {
            rounds_to_handshake = step + 1;
            break;
        }
    }

    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());
    try std.testing.expect(rounds_to_handshake > 0);
    try std.testing.expect(rounds_to_handshake <= 12);
    try std.testing.expectEqualStrings(quic.alpn, cli.conn.inner.alpnSelected().?);
    try std.testing.expectEqualStrings(quic.alpn, srv.iterator()[0].conn.inner.alpnSelected().?);

    try client_session.onQuicReady();
    try server_session.onQuicReady();
}

const HermeticQuicPair = struct {
    srv: quic_zig.Server,
    cli: quic_zig.Client,
    peer_addr: quic_zig.conn.path.Address = testAddress(0x53, 4433),

    fn init(allocator: std.mem.Allocator) !HermeticQuicPair {
        const protos = [_][]const u8{quic.alpn};

        var srv = try quic_zig.Server.init(.{
            .allocator = allocator,
            .tls_cert_pem = test_cert_pem,
            .tls_key_pem = test_key_pem,
            .alpn_protocols = &protos,
            .transport_params = defaultParams(),
        });
        errdefer srv.deinit();

        var cli = try quic_zig.Client.connect(.{
            .insecure_skip_verify = true, // self-signed test fixture
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = defaultParams(),
        });
        errdefer cli.deinit();

        var pair: HermeticQuicPair = .{ .srv = srv, .cli = cli };
        try pair.handshake();
        return pair;
    }

    fn deinit(self: *HermeticQuicPair) void {
        self.cli.deinit();
        self.srv.deinit();
        self.* = undefined;
    }

    fn serverConn(self: *HermeticQuicPair) *quic_zig.Connection {
        return self.srv.iterator()[0].conn;
    }

    fn drive(self: *HermeticQuicPair, now_us: u64) !void {
        var rx: [8192]u8 = undefined;
        _ = try pumpClientToServer(&self.cli, &self.srv, &rx, self.peer_addr, now_us);
        while (self.srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&self.srv, &self.cli, &rx, now_us);
        try self.srv.tick(now_us);
        try self.cli.conn.tick(now_us);
    }

    fn handshake(self: *HermeticQuicPair) !void {
        try self.cli.conn.advance();

        var rounds_to_handshake: u32 = 0;
        var step: u32 = 0;
        while (step < 32) : (step += 1) {
            const now_us: u64 = @as(u64, step + 1) * 1_000;
            try self.drive(now_us);

            if (self.cli.conn.handshakeDone() and self.srv.iterator().len > 0 and
                self.srv.iterator()[0].conn.handshakeDone())
            {
                rounds_to_handshake = step + 1;
                break;
            }
        }

        try std.testing.expect(self.cli.conn.handshakeDone());
        try std.testing.expectEqual(@as(usize, 1), self.srv.connectionCount());
        try std.testing.expect(self.srv.iterator()[0].conn.handshakeDone());
        try std.testing.expect(rounds_to_handshake > 0);
        try std.testing.expect(rounds_to_handshake <= 12);
        try std.testing.expectEqualStrings(quic.alpn, self.cli.conn.inner.alpnSelected().?);
        try std.testing.expectEqualStrings(quic.alpn, self.srv.iterator()[0].conn.inner.alpnSelected().?);
    }
};

test {
    _ = quic;
}

test "hermetic quic-zig Client/Server handshake marks qmsg sessions QUIC-ready" {
    const allocator = std.testing.allocator;

    var client = try quic.QuicSession.init(allocator, 10, .client, .{
        .peer_id = "client-a",
    });
    defer client.deinit();

    var server = try quic.QuicSession.init(allocator, 11, .server, .{
        .peer_id = "server-a",
    });
    defer server.deinit();

    try std.testing.expectEqual(quic.State.waiting_for_quic, client.state());
    try std.testing.expectEqual(quic.State.waiting_for_quic, server.state());

    try driveHermeticQuicReady(allocator, &client, &server);

    try std.testing.expectEqual(quic.State.quic_ready, client.state());
    try std.testing.expectEqual(quic.State.quic_ready, server.state());
}

test "qmsg QUIC sessions exchange HELLO over real QUIC uni streams" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{quic.alpn};

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test fixture
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer cli.deinit();

    var rx: [8192]u8 = undefined;
    const peer_addr = testAddress(0x52, 4433);
    try cli.conn.advance();

    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = @as(u64, step + 1) * 1_000;
        _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        _ = try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);

        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());

    var client = try quic.QuicSession.init(allocator, 20, .client, .{
        .peer_id = "client-a",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req,
        .datagram_enabled = true,
    });
    defer client.deinit();

    var server = try quic.QuicSession.init(allocator, 21, .server, .{
        .peer_id = "server-a",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req,
        .datagram_enabled = true,
        .max_message_size = 4096,
    });
    defer server.deinit();

    try client.onQuicReady();
    try server.onQuicReady();

    const client_stream_id = try client.sendLocalHelloOnStream(cli.conn);
    try std.testing.expectEqual(quic.localControlStreamId(.client), client_stream_id);

    _ = try pumpClientToServer(&cli, &srv, &rx, peer_addr, 100_000);
    const slot = srv.iterator()[0];
    try server.acceptPeerControlFromStream(slot.conn, quic.peerControlStreamId(.server), 64 * 1024);

    const server_stream_id = try server.sendLocalHelloOnStream(slot.conn);
    try std.testing.expectEqual(quic.localControlStreamId(.server), server_stream_id);

    _ = try pumpServerToClient(&srv, &cli, &rx, 101_000);
    try client.acceptPeerControlFromStream(cli.conn, quic.peerControlStreamId(.client), 64 * 1024);

    try std.testing.expectEqual(quic.State.ready, client.state());
    try std.testing.expectEqual(quic.State.ready, server.state());
    try std.testing.expectEqualStrings("server-a", client.peerId());
    try std.testing.expectEqualStrings("client-a", server.peerId());
    try std.testing.expect(client.session.datagram_enabled);
    try std.testing.expect(server.session.datagram_enabled);
    try std.testing.expectEqual(@as(usize, 4096), client.session.max_message_size);
}

test "reliable message helper delivers pair-style echo over hermetic QUIC streams" {
    const allocator = std.testing.allocator;

    var pair = try HermeticQuicPair.init(allocator);
    defer pair.deinit();

    var client_ids = quic.StreamIdAllocator.init(.client);
    var server_ids = quic.StreamIdAllocator.init(.server);
    const request_stream = try client_ids.nextBidi();
    const echo_stream = try server_ids.nextBidi();

    var request_sender = try quic.ReliableMessageSender.init(allocator, request_stream, .{
        .subject = "pair.echo",
        .id = 100,
        .body = "ping",
    }, .{}, .{});
    defer request_sender.deinit();

    var server_receiver = quic.ReliableMessageReceiver.init(allocator, request_stream, .{});
    defer server_receiver.deinit();

    var got_request: ?message.Message = null;
    var step: u32 = 0;
    while (step < 20_000 and got_request == null) : (step += 1) {
        _ = try request_sender.pump(pair.cli.conn);
        try pair.drive(100_000 + @as(u64, step) * 1_000);

        const server_conn = pair.serverConn();
        if (server_conn.stream(request_stream) != null) {
            got_request = try server_receiver.read(server_conn);
        }
    }
    var request = got_request orelse return error.WouldBlock;
    defer request.deinit();

    try std.testing.expectEqual(@as(message.MessageId, 100), request.id);
    try std.testing.expectEqualStrings("pair.echo", request.subject);
    try std.testing.expectEqualStrings("ping", request.body);

    var echo_sender = try quic.ReliableMessageSender.init(allocator, echo_stream, .{
        .subject = request.subject,
        .id = request.id,
        .body = request.body,
    }, .{}, .{});
    defer echo_sender.deinit();

    var client_receiver = quic.ReliableMessageReceiver.init(allocator, echo_stream, .{});
    defer client_receiver.deinit();

    var got_echo: ?message.Message = null;
    step = 0;
    while (step < 20_000 and got_echo == null) : (step += 1) {
        _ = try echo_sender.pump(pair.serverConn());
        try pair.drive(200_000 + @as(u64, step) * 1_000);

        if (pair.cli.conn.stream(echo_stream) != null) {
            got_echo = try client_receiver.read(pair.cli.conn);
        }
    }
    var echo = got_echo orelse return error.WouldBlock;
    defer echo.deinit();

    try std.testing.expectEqual(@as(message.MessageId, 100), echo.id);
    try std.testing.expectEqualStrings("pair.echo", echo.subject);
    try std.testing.expectEqualStrings("ping", echo.body);
}

test "reliable message helper correlates req rep over one hermetic QUIC stream" {
    const allocator = std.testing.allocator;

    var pair = try HermeticQuicPair.init(allocator);
    defer pair.deinit();

    var client_ids = quic.StreamIdAllocator.init(.client);
    const stream_id = try client_ids.nextBidi();
    const request_out: message.OutgoingMessage = .{
        .subject = "user.get",
        .id = 777,
        .deadline_ms = 1_000,
        .body = "alice",
    };
    const correlation = try quic.requestCorrelation(stream_id, request_out);

    var request_sender = try quic.ReliableMessageSender.init(allocator, stream_id, request_out, .{}, .{});
    defer request_sender.deinit();

    var server_receiver = quic.ReliableMessageReceiver.init(allocator, stream_id, .{});
    defer server_receiver.deinit();

    var got_request: ?message.Message = null;
    var step: u32 = 0;
    while (step < 20_000 and got_request == null) : (step += 1) {
        _ = try request_sender.pump(pair.cli.conn);
        try pair.drive(300_000 + @as(u64, step) * 1_000);

        const server_conn = pair.serverConn();
        if (server_conn.stream(stream_id) != null) {
            got_request = try server_receiver.read(server_conn);
        }
    }
    var request = got_request orelse return error.WouldBlock;
    defer request.deinit();

    try std.testing.expectEqual(@as(message.MessageId, 777), request.id);
    try std.testing.expectEqualStrings("user.get", request.subject);
    try std.testing.expectEqualStrings("alice", request.body);

    var reply_sender = try quic.ReliableMessageSender.init(allocator, stream_id, .{
        .subject = request.subject,
        .id = request.id,
        .flags = .{ .final = true },
        .body = "Alice Example",
    }, .{}, .{ .open_bidi = false });
    defer reply_sender.deinit();

    var client_receiver = quic.ReliableMessageReceiver.init(allocator, stream_id, .{});
    defer client_receiver.deinit();

    var got_reply: ?message.Message = null;
    step = 0;
    while (step < 20_000 and got_reply == null) : (step += 1) {
        _ = try reply_sender.pump(pair.serverConn());
        try pair.drive(400_000 + @as(u64, step) * 1_000);

        if (pair.cli.conn.stream(stream_id) != null) {
            got_reply = try client_receiver.read(pair.cli.conn);
        }
    }
    var reply = got_reply orelse return error.WouldBlock;
    defer reply.deinit();

    try correlation.expectReply(stream_id, reply);
    try std.testing.expectEqualStrings("user.get", reply.subject);
    try std.testing.expectEqualStrings("Alice Example", reply.body);
}

test "runtime wrappers drive qmsg HELLO and reliable req rep with stream adapter" {
    const allocator = std.testing.allocator;

    var listener = try quic_runtime.ListenerRuntime.init(allocator, "127.0.0.1:4433", .{
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .transport = .{
            .peer_id = "server-runtime",
            .role_flags = control.RoleFlags.server,
            .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        },
    });
    defer listener.deinit();

    var client = try quic_runtime.ClientRuntime.init(allocator, "127.0.0.1:4433", .{
        .server_name = "localhost",
        .insecure_skip_verify = true, // self-signed demo/test fixture
        .transport = .{
            .peer_id = "client-runtime",
            .role_flags = control.RoleFlags.client,
            .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        },
    });
    defer client.deinit();

    try driveRuntimeReady(&client, &listener);
    try std.testing.expectEqual(@as(usize, 1), listener.connectionCount());

    var client_session = try quic.QuicSession.init(allocator, 30, .client, .{
        .peer_id = "client-runtime",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    });
    defer client_session.deinit();

    var server_session = try quic.QuicSession.init(allocator, 31, .server, .{
        .peer_id = "server-runtime",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    });
    defer server_session.deinit();

    try client_session.onQuicReady();
    try server_session.onQuicReady();

    var rx: [8192]u8 = undefined;
    const client_addr = testAddress(0x62, 4433);

    _ = try client_session.sendLocalHelloOnStream(client.connection());
    try driveRuntime(&client, &listener, &rx, client_addr, 100_000);
    try server_session.acceptPeerControlFromStream(listener.connection(0).?, quic.peerControlStreamId(.server), 64 * 1024);

    _ = try server_session.sendLocalHelloOnStream(listener.connection(0).?);
    try driveRuntime(&client, &listener, &rx, client_addr, 101_000);
    try client_session.acceptPeerControlFromStream(client.connection(), quic.peerControlStreamId(.client), 64 * 1024);

    try std.testing.expectEqual(quic.State.ready, client_session.state());
    try std.testing.expectEqual(quic.State.ready, server_session.state());

    var client_adapter = quic_streams.QuicConnectionAdapter.init(client.connection());
    var server_adapter = quic_streams.QuicConnectionAdapter.init(listener.connection(0).?);
    var client_ids = quic_streams.StreamIdAllocator.init(.client);
    const stream_id = try client_ids.nextBidi();
    const request_out: message.OutgoingMessage = .{
        .subject = "user.get",
        .id = 9001,
        .deadline_ms = 1_000,
        .body = "ada",
    };
    const correlation = try quic_streams.requestCorrelation(stream_id, request_out);

    var request_sender = try quic_streams.ReliableMessageSender.init(allocator, stream_id, request_out, .{}, .{});
    defer request_sender.deinit();

    var server_receiver = quic_streams.ReliableMessageReceiver.init(allocator, stream_id, .{});
    defer server_receiver.deinit();

    var got_request: ?message.Message = null;
    var step: u32 = 0;
    while (step < 20_000 and got_request == null) : (step += 1) {
        _ = try request_sender.pump(&client_adapter);
        try driveRuntime(&client, &listener, &rx, client_addr, 200_000 + @as(u64, step) * 1_000);

        if (listener.connection(0).?.stream(stream_id) != null) {
            got_request = try server_receiver.pump(&server_adapter);
        }
    }
    var request = got_request orelse return error.WouldBlock;
    defer request.deinit();

    try std.testing.expectEqual(@as(message.MessageId, 9001), request.id);
    try std.testing.expectEqualStrings("user.get", request.subject);
    try std.testing.expectEqualStrings("ada", request.body);

    var reply_sender = try quic_streams.ReliableMessageSender.init(allocator, stream_id, .{
        .subject = request.subject,
        .id = request.id,
        .flags = .{ .final = true },
        .body = "Ada Lovelace",
    }, .{}, .{ .open_bidi = false });
    defer reply_sender.deinit();

    var client_receiver = quic_streams.ReliableMessageReceiver.init(allocator, stream_id, .{});
    defer client_receiver.deinit();

    var got_reply: ?message.Message = null;
    step = 0;
    while (step < 20_000 and got_reply == null) : (step += 1) {
        _ = try reply_sender.pump(&server_adapter);
        try driveRuntime(&client, &listener, &rx, client_addr, 300_000 + @as(u64, step) * 1_000);

        if (client.connection().stream(stream_id) != null) {
            got_reply = try client_receiver.pump(&client_adapter);
        }
    }
    var reply = got_reply orelse return error.WouldBlock;
    defer reply.deinit();

    try correlation.expectReply(stream_id, reply);
    try std.testing.expectEqualStrings("user.get", reply.subject);
    try std.testing.expectEqualStrings("Ada Lovelace", reply.body);
}
