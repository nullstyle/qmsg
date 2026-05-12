const std = @import("std");
const qmsg = @import("qmsg");

const control = qmsg.control;
const message = qmsg.message;
const quic = qmsg.transport.quic;
const quic_runtime = qmsg.transport.quic_runtime;
const quic_streams = qmsg.transport.quic_streams;

const loopback_client_addr: quic_runtime.Address = .{
    .ipv4 = .{
        .addr = .{ 127, 0, 0, 1 },
        .port = 55_555,
    },
};

const test_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBnjCCAUOgAwIBAgIUFt1GU+R4bofYqJSYwkrpkAV20a8wCgYIKoZIzj0EAwIw
    \\FTETMBEGA1UEAwwKbnVsbHEtdGVzdDAgFw0yNjA1MDMyMTU2MzNaGA8yMTI2MDQw
    \\OTIxNTYzM1owFTETMBEGA1UEAwwKbnVsbHEtdGVzdDBZMBMGByqGSM49AgEGCCqG
    \\SM49AwEHA0IABFcmwnNrWU16PY0JrQwalnjDX/F1w0IOCv8yky4Ox8HJEV2XmDaJ
    \\ymam4Wid7icYSRYNb6fp9zXBB2B9UsfM9xqjbzBtMB0GA1UdDgQWBBSTs06H3woK
    \\Vt48NaHuysDahvgsbzAfBgNVHSMEGDAWgBSTs06H3woKVt48NaHuysDahvgsbzAP
    \\BgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggq
    \\hkjOPQQDAgNJADBGAiEAu3QuT9mHeOo94dC5y5dHrIRblt4kbwujsmGehuoxnCcC
    \\IQCOqAJ7lNk1F2TFQdXB0OefVpkgjrDEihMRYExg1JYjtQ==
    \\-----END CERTIFICATE-----
;

const test_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzUrI/FOBJi8pN/nj
    \\GEC8VX0qopctKjRupKbnSkxSmUehRANCAARXJsJza1lNej2NCa0MGpZ4w1/xdcNC
    \\Dgr/MpMuDsfByRFdl5g2icpmpuFone4nGEkWDW+n6fc1wQdgfVLHzPca
    \\-----END PRIVATE KEY-----
;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var listener = try quic_runtime.ListenerRuntime.init(allocator, "127.0.0.1:4433", .{
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .transport = .{
            .peer_id = "server",
            .role_flags = control.RoleFlags.server,
            .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        },
    });
    defer listener.deinit();

    var client = try quic_runtime.ClientRuntime.init(allocator, "127.0.0.1:4433", .{
        .server_name = "localhost",
        .transport = .{
            .peer_id = "client",
            .role_flags = control.RoleFlags.client,
            .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        },
    });
    defer client.deinit();

    try driveHandshake(&client, &listener);
    try exchangeHello(allocator, &client, &listener);
    try exchangeReqRep(allocator, &client, &listener);
}

fn driveHandshake(
    client: *quic_runtime.ClientRuntime,
    listener: *quic_runtime.ListenerRuntime,
) !void {
    var rx: [8192]u8 = undefined;

    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = @as(u64, step + 1) * 1_000;
        try drive(client, listener, &rx, loopback_client_addr, now_us);
        if (client.connection().handshakeDone() and listener.connectionCount() == 1 and
            listener.connection(0).?.handshakeDone()) return;
    }

    return error.ConnectionLost;
}

fn exchangeHello(
    allocator: std.mem.Allocator,
    client: *quic_runtime.ClientRuntime,
    listener: *quic_runtime.ListenerRuntime,
) !void {
    var client_session = try quic.QuicSession.init(allocator, 1, .client, .{
        .peer_id = "client",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    });
    defer client_session.deinit();

    var server_session = try quic.QuicSession.init(allocator, 2, .server, .{
        .peer_id = "server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    });
    defer server_session.deinit();

    try client_session.onQuicReady();
    try server_session.onQuicReady();

    var rx: [8192]u8 = undefined;

    _ = try client_session.sendLocalHelloOnStream(client.connection());
    try drive(client, listener, &rx, loopback_client_addr, 100_000);
    try server_session.acceptPeerControlFromStream(listener.connection(0).?, quic.peerControlStreamId(.server), 64 * 1024);

    _ = try server_session.sendLocalHelloOnStream(listener.connection(0).?);
    try drive(client, listener, &rx, loopback_client_addr, 101_000);
    try client_session.acceptPeerControlFromStream(client.connection(), quic.peerControlStreamId(.client), 64 * 1024);

    if (client_session.state() != .ready or server_session.state() != .ready) return error.InvalidState;
}

fn exchangeReqRep(
    allocator: std.mem.Allocator,
    client: *quic_runtime.ClientRuntime,
    listener: *quic_runtime.ListenerRuntime,
) !void {
    var client_adapter = quic_streams.QuicConnectionAdapter.init(client.connection());
    var server_adapter = quic_streams.QuicConnectionAdapter.init(listener.connection(0).?);
    var client_ids = quic_streams.StreamIdAllocator.init(.client);
    const stream_id = try client_ids.nextBidi();

    const request_out: message.OutgoingMessage = .{
        .subject = "user.get",
        .id = 42,
        .deadline_ms = 250,
        .body = "user-42",
    };
    const correlation = try quic_streams.requestCorrelation(stream_id, request_out);

    var request_sender = try quic_streams.ReliableMessageSender.init(allocator, stream_id, request_out, .{}, .{});
    defer request_sender.deinit();

    var request_receiver = quic_streams.ReliableMessageReceiver.init(allocator, stream_id, .{});
    defer request_receiver.deinit();

    var rx: [8192]u8 = undefined;

    var got_request: ?message.Message = null;
    var step: u32 = 0;
    while (step < 20_000 and got_request == null) : (step += 1) {
        _ = try request_sender.pump(&client_adapter);
        try drive(client, listener, &rx, loopback_client_addr, 200_000 + @as(u64, step) * 1_000);
        if (listener.connection(0).?.stream(stream_id) != null) {
            got_request = try request_receiver.pump(&server_adapter);
        }
    }

    var request = got_request orelse return error.WouldBlock;
    defer request.deinit();

    var reply_sender = try quic_streams.ReliableMessageSender.init(allocator, stream_id, .{
        .subject = request.subject,
        .id = request.id,
        .flags = .{ .final = true },
        .headers = &.{.{ .name = "content-type", .value = "application/json" }},
        .body = "{\"id\":\"user-42\",\"name\":\"Ada\"}",
    }, .{}, .{ .open_bidi = false });
    defer reply_sender.deinit();

    var reply_receiver = quic_streams.ReliableMessageReceiver.init(allocator, stream_id, .{});
    defer reply_receiver.deinit();

    var got_reply: ?message.Message = null;
    step = 0;
    while (step < 20_000 and got_reply == null) : (step += 1) {
        _ = try reply_sender.pump(&server_adapter);
        try drive(client, listener, &rx, loopback_client_addr, 300_000 + @as(u64, step) * 1_000);
        if (client.connection().stream(stream_id) != null) {
            got_reply = try reply_receiver.pump(&client_adapter);
        }
    }

    var reply = got_reply orelse return error.WouldBlock;
    defer reply.deinit();
    try correlation.expectReply(stream_id, reply);

    std.debug.print("quic req/rep received {s}: {s}\n", .{ reply.subject, reply.body });
}

fn drive(
    client: *quic_runtime.ClientRuntime,
    listener: *quic_runtime.ListenerRuntime,
    rx: []u8,
    client_addr: quic_runtime.Address,
    now_us: u64,
) !void {
    while (try client.drainOutbound(rx, now_us)) |out| {
        _ = try listener.feedInbound(.{
            .bytes = rx[0..out.len],
            .from = client_addr,
        }, now_us);
    }
    while (try listener.drainOutbound(rx, now_us)) |out| {
        try client.feedInbound(.{
            .bytes = rx[0..out.len],
            .from = null,
        }, now_us);
    }
    try listener.tick(now_us);
    try client.tick(now_us);
}
