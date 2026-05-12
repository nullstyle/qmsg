const std = @import("std");
const quic_zig = @import("quic_zig");

const control = @import("../control.zig");
const envelope = @import("../envelope.zig");
const message = @import("../message.zig");
const session_mod = @import("../session.zig");
const quic = @import("quic.zig");
const quic_streams = @import("quic_streams.zig");

pub const PumpResult = struct {
    control_frames_read: usize = 0,
    reliable_sent_complete: usize = 0,
    reliable_received: usize = 0,
};

pub const ReceivedReliable = struct {
    stream_id: u64,
    message: message.Message,

    pub fn takeMessage(self: *ReceivedReliable) message.Message {
        const msg = self.message;
        self.* = undefined;
        return msg;
    }

    pub fn deinit(self: *ReceivedReliable) void {
        self.message.deinit();
        self.* = undefined;
    }
};

pub const QuicSessionRuntime = struct {
    allocator: std.mem.Allocator,
    session: quic.QuicSession,
    stream_ids: quic_streams.StreamIdAllocator,
    control_sender: ?quic_streams.ControlStreamSender = null,
    control_receiver: ?quic_streams.ControlStreamReceiver = null,
    reliable_senders: std.AutoHashMap(u64, quic_streams.ReliableMessageSender),
    reliable_receivers: std.AutoHashMap(u64, quic_streams.ReliableMessageReceiver),
    inbox: std.ArrayList(ReceivedReliable) = .empty,
    envelope_codec: envelope.CodecOptions = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        session_id: session_mod.SessionId,
        role: quic.Role,
        options: quic.QuicOptions,
    ) !QuicSessionRuntime {
        return .{
            .allocator = allocator,
            .session = try quic.QuicSession.init(allocator, session_id, role, options),
            .stream_ids = quic_streams.StreamIdAllocator.init(streamRole(role)),
            .reliable_senders = std.AutoHashMap(u64, quic_streams.ReliableMessageSender).init(allocator),
            .reliable_receivers = std.AutoHashMap(u64, quic_streams.ReliableMessageReceiver).init(allocator),
            .envelope_codec = envelopeCodecFromOptions(options),
        };
    }

    pub fn deinit(self: *QuicSessionRuntime) void {
        if (self.control_sender) |*sender| sender.deinit();
        if (self.control_receiver) |*receiver| receiver.deinit();

        var senders = self.reliable_senders.valueIterator();
        while (senders.next()) |sender| sender.deinit();
        self.reliable_senders.deinit();

        var receivers = self.reliable_receivers.valueIterator();
        while (receivers.next()) |receiver| receiver.deinit();
        self.reliable_receivers.deinit();

        for (self.inbox.items) |*received| received.deinit();
        self.inbox.deinit(self.allocator);

        self.session.deinit();
        self.* = undefined;
    }

    pub fn id(self: QuicSessionRuntime) session_mod.SessionId {
        return self.session.session.id;
    }

    pub fn appSession(self: *QuicSessionRuntime) *session_mod.Session {
        return &self.session.session;
    }

    pub fn state(self: QuicSessionRuntime) quic.State {
        return self.session.state();
    }

    pub fn peerId(self: QuicSessionRuntime) []const u8 {
        return self.session.peerId();
    }

    pub fn onQuicReady(self: *QuicSessionRuntime) !void {
        try self.session.onQuicReady();
        try self.armPeerControlReceiver();
        try self.queueLocalHello();
    }

    pub fn queueReliable(self: *QuicSessionRuntime, outgoing: message.OutgoingMessage) !u64 {
        if (self.session.state() != .ready) return error.InvalidState;

        const stream_id = try self.stream_ids.nextBidi();
        try self.queueReliableOnStream(stream_id, outgoing, .{});
        return stream_id;
    }

    pub fn sendReliable(self: *QuicSessionRuntime, outgoing: message.OutgoingMessage) !u64 {
        return self.queueReliable(outgoing);
    }

    pub fn queueReliableOnStream(
        self: *QuicSessionRuntime,
        stream_id: u64,
        outgoing: message.OutgoingMessage,
        options: quic_streams.ReliableWriteOptions,
    ) !void {
        if (self.session.state() != .ready) return error.InvalidState;
        if (self.reliable_senders.contains(stream_id)) return error.StreamAlreadyOpen;

        var sender = try quic_streams.ReliableMessageSender.init(
            self.allocator,
            stream_id,
            outgoing,
            self.envelope_codec,
            options,
        );
        errdefer sender.deinit();

        try self.reliable_senders.put(stream_id, sender);
    }

    pub fn replyReliableOnStream(
        self: *QuicSessionRuntime,
        stream_id: u64,
        outgoing: message.OutgoingMessage,
    ) !void {
        try self.queueReliableOnStream(stream_id, outgoing, .{ .open_bidi = false });
    }

    pub fn acceptReliableStream(self: *QuicSessionRuntime, stream_id: u64) !void {
        if (self.session.state() != .ready) return error.InvalidState;
        if (self.reliable_receivers.contains(stream_id)) return error.StreamAlreadyOpen;

        const receiver = quic_streams.ReliableMessageReceiver.init(
            self.allocator,
            stream_id,
            self.envelope_codec,
        );
        try self.reliable_receivers.put(stream_id, receiver);
    }

    pub fn acceptPeerBidiStreamsConnection(self: *QuicSessionRuntime, conn: *quic_zig.Connection) !usize {
        if (self.session.state() != .ready) return 0;

        var accepted: usize = 0;
        var stream_ids: std.ArrayList(u64) = .empty;
        defer stream_ids.deinit(self.allocator);

        var it = conn.streamIterator();
        while (it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (!isPeerBidiStreamId(self.session.role, stream_id)) continue;
            if (self.reliable_receivers.contains(stream_id)) continue;
            try stream_ids.append(self.allocator, stream_id);
        }

        for (stream_ids.items) |stream_id| {
            self.acceptReliableStream(stream_id) catch |err| switch (err) {
                error.StreamAlreadyOpen => continue,
                else => return err,
            };
            accepted += 1;
        }

        return accepted;
    }

    pub fn pumpConnection(self: *QuicSessionRuntime, conn: *quic_zig.Connection) !PumpResult {
        var adapter = quic_streams.QuicConnectionAdapter.init(conn);
        return self.pump(&adapter);
    }

    pub fn pump(self: *QuicSessionRuntime, transport: anytype) !PumpResult {
        var result: PumpResult = .{};

        if (self.control_sender) |*sender| {
            if (try sender.pump(transport) == .complete) {
                sender.deinit();
                self.control_sender = null;
            }
        }

        if (self.control_receiver) |*receiver| {
            var frames: std.ArrayList(control.Frame) = .empty;
            defer {
                for (frames.items) |*frame| frame.deinit();
                frames.deinit(self.allocator);
            }

            const read = receiver.pump(transport, &frames) catch |err| switch (err) {
                error.StreamNotFound => return result,
                else => return err,
            };
            result.control_frames_read += read.frames_read;
            if (frames.items.len > 0) {
                try self.acceptPeerControlFrames(frames.items);
            }
            if (read.stream_complete) {
                receiver.deinit();
                self.control_receiver = null;
            }
        }

        result.reliable_sent_complete += try self.pumpReliableSenders(transport);
        result.reliable_received += try self.pumpReliableReceivers(transport);
        return result;
    }

    pub fn recvReliable(self: *QuicSessionRuntime) ?ReceivedReliable {
        if (self.inbox.items.len == 0) return null;
        return self.inbox.orderedRemove(0);
    }

    pub fn inboxLen(self: QuicSessionRuntime) usize {
        return self.inbox.items.len;
    }

    pub fn pendingReliableSenders(self: QuicSessionRuntime) usize {
        return self.reliable_senders.count();
    }

    pub fn pendingReliableReceivers(self: QuicSessionRuntime) usize {
        return self.reliable_receivers.count();
    }

    pub fn hasControlSender(self: QuicSessionRuntime) bool {
        return self.control_sender != null;
    }

    pub fn hasControlReceiver(self: QuicSessionRuntime) bool {
        return self.control_receiver != null;
    }

    fn armPeerControlReceiver(self: *QuicSessionRuntime) !void {
        if (self.control_receiver != null) return;
        self.control_receiver = quic_streams.ControlStreamReceiver.init(
            self.allocator,
            quic.peerControlStreamId(self.session.role),
            .{ .codec = self.session.options.control_codec },
        );
    }

    fn queueLocalHello(self: *QuicSessionRuntime) !void {
        if (self.session.local_hello_sent) return;
        if (self.control_sender != null) return error.InvalidState;

        const frames = [_]control.Frame{.{ .hello = helloFromOptions(self.session.options) }};
        var sender = try quic_streams.ControlStreamSender.init(
            self.allocator,
            quic.localControlStreamId(self.session.role),
            &frames,
            self.session.options.control_codec,
            .{},
        );
        errdefer sender.deinit();

        const marker = try self.session.encodeLocalHello();
        self.allocator.free(marker);

        self.control_sender = sender;
    }

    fn acceptPeerControlFrames(
        self: *QuicSessionRuntime,
        frames: []const control.Frame,
    ) !void {
        const encoded = try quic_streams.encodeControlStream(
            self.allocator,
            frames,
            self.session.options.control_codec,
        );
        defer self.allocator.free(encoded);
        try self.session.acceptPeerControl(encoded);
    }

    fn pumpReliableSenders(self: *QuicSessionRuntime, transport: anytype) !usize {
        var complete_ids: std.ArrayList(u64) = .empty;
        defer complete_ids.deinit(self.allocator);

        var senders = self.reliable_senders.iterator();
        while (senders.next()) |entry| {
            if (try entry.value_ptr.pump(transport) == .complete) {
                try complete_ids.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (complete_ids.items) |stream_id| {
            if (self.reliable_senders.fetchRemove(stream_id)) |entry| {
                var sender = entry.value;
                sender.deinit();
            }
        }
        return complete_ids.items.len;
    }

    fn pumpReliableReceivers(self: *QuicSessionRuntime, transport: anytype) !usize {
        var complete_ids: std.ArrayList(u64) = .empty;
        defer complete_ids.deinit(self.allocator);

        var received_count: usize = 0;
        var receivers = self.reliable_receivers.iterator();
        while (receivers.next()) |entry| {
            if (try entry.value_ptr.pump(transport)) |received| {
                errdefer {
                    var cleanup = received;
                    cleanup.deinit();
                }
                try self.inbox.append(self.allocator, .{
                    .stream_id = entry.key_ptr.*,
                    .message = received,
                });
                try complete_ids.append(self.allocator, entry.key_ptr.*);
                received_count += 1;
            }
        }

        for (complete_ids.items) |stream_id| {
            if (self.reliable_receivers.fetchRemove(stream_id)) |entry| {
                var receiver = entry.value;
                receiver.deinit();
            }
        }
        return received_count;
    }
};

fn streamRole(role: quic.Role) quic_streams.Role {
    return switch (role) {
        .client => .client,
        .server => .server,
    };
}

fn envelopeCodecFromOptions(options: quic.QuicOptions) envelope.CodecOptions {
    return .{
        .max_message_size = options.max_message_size,
        .max_header_bytes = options.max_header_bytes,
        .max_headers = options.max_header_count,
    };
}

fn helloFromOptions(options: quic.QuicOptions) control.Hello {
    return .{
        .wire_version = control.default_wire_version,
        .peer_id = options.peer_id,
        .role_flags = options.role_flags,
        .supported_patterns = options.supported_patterns,
        .max_message_size = options.max_message_size,
        .max_header_bytes = options.max_header_bytes,
        .max_header_count = options.max_header_count,
        .datagram_enabled = options.datagram_enabled,
        .heartbeat_interval_ms = options.heartbeat_interval_ms,
        .auth = options.auth,
    };
}

pub fn isPeerBidiStreamId(role: quic.Role, stream_id: u64) bool {
    if ((stream_id & 0x2) != 0) return false;
    const initiated_by_server = (stream_id & 0x1) != 0;
    return switch (role) {
        .client => initiated_by_server,
        .server => !initiated_by_server,
    };
}

const FakeStream = struct {
    incoming: std.ArrayList(u8) = .empty,
    read_offset: usize = 0,
    final_size: ?u64 = null,
    writes: std.ArrayList(u8) = .empty,
    write_limit: usize = std.math.maxInt(usize),
    opened_bidi: bool = false,
    opened_uni: bool = false,
    finished: bool = false,

    fn deinit(self: *FakeStream, allocator: std.mem.Allocator) void {
        self.incoming.deinit(allocator);
        self.writes.deinit(allocator);
        self.* = undefined;
    }
};

const FakeTransport = struct {
    allocator: std.mem.Allocator,
    streams: std.AutoHashMap(u64, FakeStream),

    fn init(allocator: std.mem.Allocator) FakeTransport {
        return .{
            .allocator = allocator,
            .streams = std.AutoHashMap(u64, FakeStream).init(allocator),
        };
    }

    fn deinit(self: *FakeTransport) void {
        var streams = self.streams.valueIterator();
        while (streams.next()) |stream| stream.deinit(self.allocator);
        self.streams.deinit();
        self.* = undefined;
    }

    pub fn openBidi(self: *FakeTransport, stream_id: u64) !void {
        const entry = try self.getOrPutStream(stream_id);
        entry.value_ptr.opened_bidi = true;
    }

    pub fn openUni(self: *FakeTransport, stream_id: u64) !void {
        const entry = try self.getOrPutStream(stream_id);
        entry.value_ptr.opened_uni = true;
    }

    pub fn streamWrite(self: *FakeTransport, stream_id: u64, bytes: []const u8) !usize {
        const stream = (try self.getOrPutStream(stream_id)).value_ptr;
        const writable = @min(bytes.len, stream.write_limit);
        if (writable == 0) return 0;
        try stream.writes.appendSlice(self.allocator, bytes[0..writable]);
        return writable;
    }

    pub fn streamFinish(self: *FakeTransport, stream_id: u64) !void {
        const stream = (try self.getOrPutStream(stream_id)).value_ptr;
        stream.finished = true;
    }

    pub fn streamRead(self: *FakeTransport, stream_id: u64, out: []u8) !usize {
        const stream = self.streams.getPtr(stream_id) orelse return error.StreamNotFound;
        const available = stream.incoming.items.len - stream.read_offset;
        if (available == 0) return 0;
        const n = @min(available, out.len);
        std.mem.copyForwards(u8, out[0..n], stream.incoming.items[stream.read_offset..][0..n]);
        stream.read_offset += n;
        return n;
    }

    pub fn streamReceiveStatus(self: *FakeTransport, stream_id: u64) ?quic_streams.ReceiveStatus {
        const stream = self.streams.getPtr(stream_id) orelse return null;
        return .{
            .final_size = stream.final_size,
            .read_offset = @intCast(stream.read_offset),
        };
    }

    fn setWriteLimit(self: *FakeTransport, stream_id: u64, limit: usize) !void {
        const stream = (try self.getOrPutStream(stream_id)).value_ptr;
        stream.write_limit = limit;
    }

    fn takeWrites(
        self: *FakeTransport,
        stream_id: u64,
        dst: *FakeTransport,
    ) !void {
        const source = self.streams.getPtr(stream_id) orelse return error.StreamNotFound;
        const target = (try dst.getOrPutStream(stream_id)).value_ptr;
        try target.incoming.appendSlice(dst.allocator, source.writes.items);
        target.final_size = target.incoming.items.len;
    }

    fn getOrPutStream(self: *FakeTransport, stream_id: u64) !std.AutoHashMap(u64, FakeStream).GetOrPutResult {
        const entry = try self.streams.getOrPut(stream_id);
        if (!entry.found_existing) entry.value_ptr.* = .{};
        return entry;
    }
};

fn pumpBoth(
    client: *QuicSessionRuntime,
    client_io: *FakeTransport,
    server: *QuicSessionRuntime,
    server_io: *FakeTransport,
) !void {
    _ = try client.pump(client_io);
    _ = try server.pump(server_io);
    try client_io.takeWrites(quic.localControlStreamId(.client), server_io);
    try server_io.takeWrites(quic.localControlStreamId(.server), client_io);
    _ = try client.pump(client_io);
    _ = try server.pump(server_io);
}

test "session runtime exchanges HELLO and reaches ready" {
    const allocator = std.testing.allocator;

    var client = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer client.deinit();
    var server = try QuicSessionRuntime.init(allocator, 2, .server, .{ .peer_id = "server-a" });
    defer server.deinit();

    var client_io = FakeTransport.init(allocator);
    defer client_io.deinit();
    var server_io = FakeTransport.init(allocator);
    defer server_io.deinit();

    try client.onQuicReady();
    try server.onQuicReady();
    try std.testing.expect(client.hasControlSender());
    try std.testing.expect(client.hasControlReceiver());

    try pumpBoth(&client, &client_io, &server, &server_io);

    try std.testing.expectEqual(quic.State.ready, client.state());
    try std.testing.expectEqual(quic.State.ready, server.state());
    try std.testing.expectEqualStrings("server-a", client.peerId());
    try std.testing.expectEqualStrings("client-a", server.peerId());
    try std.testing.expect(!client.hasControlSender());
    try std.testing.expect(!client.hasControlReceiver());
}

test "session runtime cleans up completed reliable sender" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .server, .{ .peer_id = "server-a" });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try runtime.onQuicReady();
    try peer.onQuicReady();
    try pumpBoth(&runtime, &io, &peer, &peer_io);

    const stream_id = try runtime.queueReliable(.{
        .subject = "pair.echo",
        .id = 42,
        .body = "ping",
    });
    try io.setWriteLimit(stream_id, 3);

    while (runtime.pendingReliableSenders() != 0) {
        _ = try runtime.pump(&io);
    }

    try std.testing.expectEqual(@as(usize, 0), runtime.pendingReliableSenders());
    const stream = io.streams.get(stream_id) orelse return error.StreamNotFound;
    try std.testing.expect(stream.opened_bidi);
    try std.testing.expect(stream.finished);
}

test "session runtime transfers receiver ownership to inbox" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .server, .{ .peer_id = "server-a" });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .client, .{ .peer_id = "client-a" });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try runtime.onQuicReady();
    try peer.onQuicReady();
    try pumpBoth(&peer, &peer_io, &runtime, &io);

    const stream_id: u64 = 0;
    const encoded = try quic_streams.encodeReliableMessage(allocator, .{
        .subject = "jobs.run",
        .id = 7,
        .body = "now",
    }, .{});
    defer allocator.free(encoded);

    const entry = try io.getOrPutStream(stream_id);
    try entry.value_ptr.incoming.appendSlice(allocator, encoded);
    entry.value_ptr.final_size = encoded.len;

    try runtime.acceptReliableStream(stream_id);
    _ = try runtime.pump(&io);

    try std.testing.expectEqual(@as(usize, 0), runtime.pendingReliableReceivers());
    try std.testing.expectEqual(@as(usize, 1), runtime.inboxLen());

    var received = runtime.recvReliable().?;
    defer received.deinit();
    try std.testing.expectEqual(stream_id, received.stream_id);
    try std.testing.expectEqualStrings("jobs.run", received.message.subject);
    try std.testing.expectEqualStrings("now", received.message.body);
    try std.testing.expectEqual(@as(usize, 0), runtime.inboxLen());
}

test "session runtime replies on an accepted peer stream" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .server, .{ .peer_id = "server-a" });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .client, .{ .peer_id = "client-a" });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try runtime.onQuicReady();
    try peer.onQuicReady();
    try pumpBoth(&peer, &peer_io, &runtime, &io);

    const stream_id: u64 = 0;
    try runtime.replyReliableOnStream(stream_id, .{
        .subject = "user.get",
        .id = 7,
        .body = "Ada",
    });

    while (runtime.pendingReliableSenders() != 0) {
        _ = try runtime.pump(&io);
    }

    const stream = io.streams.get(stream_id) orelse return error.StreamNotFound;
    try std.testing.expect(!stream.opened_bidi);
    try std.testing.expect(stream.finished);

    const encoded = try quic_streams.encodeReliableMessage(allocator, .{
        .subject = "jobs.run",
        .id = 9,
        .body = "now",
    }, .{});
    defer allocator.free(encoded);

    const entry = try io.getOrPutStream(stream_id);
    try entry.value_ptr.incoming.appendSlice(allocator, encoded);
    entry.value_ptr.final_size = encoded.len;

    try runtime.acceptReliableStream(stream_id);
    _ = try runtime.pump(&io);

    var received = runtime.recvReliable().?;
    var owned = received.takeMessage();
    defer owned.deinit();
    try std.testing.expectEqualStrings("jobs.run", owned.subject);
}

test "session runtime gates reliable streams until ready" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer runtime.deinit();

    try std.testing.expectError(error.InvalidState, runtime.queueReliable(.{
        .subject = "pair.echo",
        .body = "ping",
    }));
    try std.testing.expectError(error.InvalidState, runtime.acceptReliableStream(0));
}

test "peer bidi stream id helper follows QUIC low bits" {
    try std.testing.expect(isPeerBidiStreamId(.server, 0));
    try std.testing.expect(!isPeerBidiStreamId(.server, 1));
    try std.testing.expect(!isPeerBidiStreamId(.server, 2));
    try std.testing.expect(isPeerBidiStreamId(.client, 1));
    try std.testing.expect(!isPeerBidiStreamId(.client, 0));
    try std.testing.expect(!isPeerBidiStreamId(.client, 3));
}
