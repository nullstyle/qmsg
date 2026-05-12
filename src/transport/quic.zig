const std = @import("std");
const quic_zig = @import("quic_zig");

const control = @import("../control.zig");
const session_mod = @import("../session.zig");

pub const alpn = "qmsg/1";
pub const control_stream_type: u64 = 0x51;

const default_alpn_protocols = [_][]const u8{alpn};

pub const Role = enum {
    client,
    server,
};

pub const State = enum {
    idle,
    listening,
    dialing,
    waiting_for_quic,
    quic_ready,
    local_hello_sent,
    ready,
    closing,
    closed,
};

pub const QuicOptions = struct {
    alpn_protocols: []const []const u8 = &default_alpn_protocols,
    peer_id: []const u8 = "qmsg",
    role_flags: u64 = 0,
    supported_patterns: u64 = control.PatternBits.all,
    max_message_size: usize = 1024 * 1024,
    max_header_bytes: usize = 16 * 1024,
    max_header_count: usize = 32,
    datagram_enabled: bool = false,
    max_datagram_frame_size: u64 = 0,
    heartbeat_interval_ms: u64 = 0,
    auth: control.AuthProperties = .{},
    control_codec: control.CodecOptions = .{},

    max_idle_timeout_ms: u64 = 30_000,
    initial_max_data: u64 = 16 * 1024 * 1024,
    initial_max_stream_data_bidi_local: u64 = 1024 * 1024,
    initial_max_stream_data_bidi_remote: u64 = 1024 * 1024,
    initial_max_stream_data_uni: u64 = 64 * 1024,
    initial_max_streams_bidi: u64 = 256,
    initial_max_streams_uni: u64 = 16,
    active_connection_id_limit: u64 = 4,
};

pub const QuicListener = struct {
    allocator: std.mem.Allocator,
    endpoint: []u8,
    options: QuicOptions,
    state_value: State = .idle,

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: []const u8,
        options: QuicOptions,
    ) !QuicListener {
        if (endpoint.len == 0) return error.InvalidEndpoint;
        try validateAlpn(options.alpn_protocols);
        _ = toTransportParams(options);

        return .{
            .allocator = allocator,
            .endpoint = try allocator.dupe(u8, endpoint),
            .options = options,
            .state_value = .listening,
        };
    }

    pub fn deinit(self: *QuicListener) void {
        self.allocator.free(self.endpoint);
        self.* = undefined;
    }

    pub fn state(self: QuicListener) State {
        return self.state_value;
    }

    pub fn close(self: *QuicListener) void {
        self.state_value = .closed;
    }
};

pub const QuicDialer = struct {
    allocator: std.mem.Allocator,
    endpoint: []u8,
    server_name: []u8,
    options: QuicOptions,
    state_value: State = .idle,

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: []const u8,
        server_name: []const u8,
        options: QuicOptions,
    ) !QuicDialer {
        if (endpoint.len == 0 or server_name.len == 0) return error.InvalidEndpoint;
        try validateAlpn(options.alpn_protocols);
        _ = toTransportParams(options);

        const owned_endpoint = try allocator.dupe(u8, endpoint);
        errdefer allocator.free(owned_endpoint);
        const owned_server_name = try allocator.dupe(u8, server_name);
        errdefer allocator.free(owned_server_name);

        return .{
            .allocator = allocator,
            .endpoint = owned_endpoint,
            .server_name = owned_server_name,
            .options = options,
            .state_value = .dialing,
        };
    }

    pub fn deinit(self: *QuicDialer) void {
        self.allocator.free(self.server_name);
        self.allocator.free(self.endpoint);
        self.* = undefined;
    }

    pub fn state(self: QuicDialer) State {
        return self.state_value;
    }

    pub fn close(self: *QuicDialer) void {
        self.state_value = .closed;
    }
};

pub const QuicSession = struct {
    allocator: std.mem.Allocator,
    role: Role,
    options: QuicOptions,
    state_value: State = .waiting_for_quic,
    local_hello_sent: bool = false,
    peer_hello_received: bool = false,
    peer_id: ?[]u8 = null,
    session: session_mod.Session,

    pub fn init(
        allocator: std.mem.Allocator,
        id: session_mod.SessionId,
        role: Role,
        options: QuicOptions,
    ) !QuicSession {
        try validateAlpn(options.alpn_protocols);
        _ = toTransportParams(options);

        return .{
            .allocator = allocator,
            .role = role,
            .options = options,
            .session = .{
                .id = id,
                .transport = .quic,
                .datagram_enabled = options.datagram_enabled,
                .max_message_size = options.max_message_size,
            },
        };
    }

    pub fn deinit(self: *QuicSession) void {
        if (self.peer_id) |peer_id| self.allocator.free(peer_id);
        self.* = undefined;
    }

    pub fn state(self: QuicSession) State {
        return self.state_value;
    }

    pub fn peerId(self: QuicSession) []const u8 {
        return self.peer_id orelse "";
    }

    pub fn onQuicReady(self: *QuicSession) !void {
        switch (self.state_value) {
            .waiting_for_quic, .quic_ready => {
                self.state_value = .quic_ready;
                self.refreshState();
            },
            .closing, .closed => return error.InvalidState,
            else => return error.InvalidState,
        }
    }

    pub fn encodeLocalHello(self: *QuicSession) ![]u8 {
        if (self.state_value != .quic_ready and self.state_value != .ready) return error.InvalidState;
        if (self.local_hello_sent) return error.InvalidState;

        const bytes = try encodeHelloControlStream(self.allocator, self.options);
        self.local_hello_sent = true;
        self.refreshState();
        return bytes;
    }

    pub fn acceptPeerControl(self: *QuicSession, bytes: []const u8) !void {
        if (self.state_value == .waiting_for_quic or self.state_value == .closing or self.state_value == .closed) {
            return error.InvalidState;
        }

        const frames = try decodeControlStream(self.allocator, bytes, self.options.control_codec);
        defer {
            for (frames) |*frame| frame.deinit();
            self.allocator.free(frames);
        }

        for (frames) |*frame| {
            switch (frame.*) {
                .hello => |hello| try self.acceptHello(hello),
                else => return error.UnexpectedFrame,
            }
        }
        self.refreshState();
    }

    pub fn close(self: *QuicSession) void {
        self.state_value = .closed;
    }

    fn acceptHello(self: *QuicSession, hello: control.Hello) !void {
        if (self.peer_hello_received) return error.InvalidState;
        if (hello.wire_version != control.default_wire_version) return error.VersionMismatch;
        if (hello.peer_id.len == 0) return error.PeerIdTooLarge;

        const owned_peer_id = try self.allocator.dupe(u8, hello.peer_id);
        errdefer self.allocator.free(owned_peer_id);
        if (self.peer_id) |previous| self.allocator.free(previous);
        self.peer_id = owned_peer_id;
        self.peer_hello_received = true;

        self.session.peer_id = self.peer_id.?;
        self.session.datagram_enabled = self.options.datagram_enabled and hello.datagram_enabled;
        self.session.max_message_size = @min(self.options.max_message_size, hello.max_message_size);
    }

    fn refreshState(self: *QuicSession) void {
        if (self.state_value == .closing or self.state_value == .closed) return;
        if (self.local_hello_sent and self.peer_hello_received) {
            self.state_value = .ready;
        } else if (self.local_hello_sent) {
            self.state_value = .local_hello_sent;
        } else {
            self.state_value = .quic_ready;
        }
    }
};

pub fn validateAlpn(protocols: []const []const u8) !void {
    if (protocols.len == 0) return error.InvalidEndpoint;
    for (protocols) |protocol| {
        if (std.mem.eql(u8, protocol, alpn)) return;
    }
    return error.UnsupportedTransport;
}

pub fn encodeHelloControlStream(allocator: std.mem.Allocator, options: QuicOptions) ![]u8 {
    return encodeControlStream(allocator, .{ .hello = helloFromOptions(options) }, options.control_codec);
}

pub fn encodeControlStream(
    allocator: std.mem.Allocator,
    first_frame: control.Frame,
    options: control.CodecOptions,
) ![]u8 {
    const frame_bytes = try encodeControlFrame(allocator, first_frame, options);
    defer allocator.free(frame_bytes);

    var bytes = try std.ArrayList(u8).initCapacity(
        allocator,
        (try varIntLen(control_stream_type)) + frame_bytes.len,
    );
    errdefer bytes.deinit(allocator);

    try appendVarInt(allocator, &bytes, control_stream_type);
    try bytes.appendSlice(allocator, frame_bytes);
    return try bytes.toOwnedSlice(allocator);
}

pub fn encodeControlFrame(
    allocator: std.mem.Allocator,
    frame: control.Frame,
    options: control.CodecOptions,
) ![]u8 {
    const payload = try control.encode(allocator, frame, options);
    defer allocator.free(payload);

    var bytes = try std.ArrayList(u8).initCapacity(
        allocator,
        (try varIntLen(payload.len)) + payload.len,
    );
    errdefer bytes.deinit(allocator);

    try appendVarInt(allocator, &bytes, payload.len);
    try bytes.appendSlice(allocator, payload);
    return try bytes.toOwnedSlice(allocator);
}

pub fn decodeControlStream(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: control.CodecOptions,
) ![]control.Frame {
    var reader: Reader = .{ .bytes = bytes };
    const stream_type = try reader.readVarInt();
    if (stream_type != control_stream_type) return error.InvalidControlFrame;

    var frames: std.ArrayList(control.Frame) = .empty;
    errdefer {
        for (frames.items) |*frame| frame.deinit();
        frames.deinit(allocator);
    }

    while (reader.remaining() > 0) {
        const payload_len_u64 = try reader.readVarInt();
        const payload_len = std.math.cast(usize, payload_len_u64) orelse return error.FrameTooLarge;
        if (payload_len > reader.remaining()) return error.MalformedFrame;

        const payload = reader.bytes[reader.index..][0..payload_len];
        reader.index += payload_len;
        try frames.append(allocator, try control.decode(allocator, payload, options));
    }

    if (frames.items.len == 0) return error.MalformedFrame;
    return try frames.toOwnedSlice(allocator);
}

fn helloFromOptions(options: QuicOptions) control.Hello {
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

fn toTransportParams(options: QuicOptions) quic_zig.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = options.max_idle_timeout_ms,
        .initial_max_data = options.initial_max_data,
        .initial_max_stream_data_bidi_local = options.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote = options.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = options.initial_max_stream_data_uni,
        .initial_max_streams_bidi = options.initial_max_streams_bidi,
        .initial_max_streams_uni = options.initial_max_streams_uni,
        .active_connection_id_limit = options.active_connection_id_limit,
        .max_datagram_frame_size = if (options.datagram_enabled)
            @max(options.max_datagram_frame_size, 1200)
        else
            0,
    };
}

fn appendVarInt(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), value: u64) !void {
    switch (try varIntLen(value)) {
        1 => try bytes.append(allocator, @intCast(value)),
        2 => {
            const encoded: u16 = 0x4000 | @as(u16, @intCast(value));
            try bytes.append(allocator, @intCast(encoded >> 8));
            try bytes.append(allocator, @intCast(encoded & 0xff));
        },
        4 => {
            const encoded: u32 = 0x8000_0000 | @as(u32, @intCast(value));
            try bytes.append(allocator, @intCast(encoded >> 24));
            try bytes.append(allocator, @intCast((encoded >> 16) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 8) & 0xff));
            try bytes.append(allocator, @intCast(encoded & 0xff));
        },
        8 => {
            const encoded: u64 = 0xc000_0000_0000_0000 | value;
            try bytes.append(allocator, @intCast(encoded >> 56));
            try bytes.append(allocator, @intCast((encoded >> 48) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 40) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 32) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 24) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 16) & 0xff));
            try bytes.append(allocator, @intCast((encoded >> 8) & 0xff));
            try bytes.append(allocator, @intCast(encoded & 0xff));
        },
        else => unreachable,
    }
}

fn varIntLen(value: u64) !usize {
    if (value < (1 << 6)) return 1;
    if (value < (1 << 14)) return 2;
    if (value < (1 << 30)) return 4;
    if (value < (1 << 62)) return 8;
    return error.InvalidControlFrame;
}

const Reader = struct {
    bytes: []const u8,
    index: usize = 0,

    fn remaining(self: Reader) usize {
        return self.bytes.len - self.index;
    }

    fn readVarInt(self: *Reader) !u64 {
        if (self.remaining() == 0) return error.MalformedFrame;

        const first = self.bytes[self.index];
        const length: usize = switch (first >> 6) {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            else => unreachable,
        };
        if (self.remaining() < length) return error.MalformedFrame;

        var value: u64 = first & 0x3f;
        var offset: usize = 1;
        while (offset < length) : (offset += 1) {
            value = (value << 8) | self.bytes[self.index + offset];
        }
        self.index += length;

        if ((try varIntLen(value)) != length) return error.MalformedFrame;
        return value;
    }
};

test "QUIC options map to private quic-zig transport parameters" {
    const params = toTransportParams(.{
        .datagram_enabled = true,
        .max_datagram_frame_size = 900,
        .initial_max_streams_uni = 4,
    });

    try std.testing.expectEqual(@as(u64, 30_000), params.max_idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 4), params.initial_max_streams_uni);
    try std.testing.expectEqual(@as(u64, 1200), params.max_datagram_frame_size);

    try validateAlpn(&.{"qmsg/1"});
    try std.testing.expectError(error.UnsupportedTransport, validateAlpn(&.{"h3"}));
}

test "control stream HELLO glue round trips through marker and length prefix" {
    const allocator = std.testing.allocator;

    const bytes = try encodeHelloControlStream(allocator, .{
        .peer_id = "node-a",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req,
        .datagram_enabled = true,
    });
    defer allocator.free(bytes);

    const frames = try decodeControlStream(allocator, bytes, .{});
    defer {
        for (frames) |*frame| frame.deinit();
        allocator.free(frames);
    }

    try std.testing.expectEqual(@as(usize, 1), frames.len);
    try std.testing.expectEqual(control.Tag.hello, std.meta.activeTag(frames[0]));
    try std.testing.expectEqualStrings("node-a", frames[0].hello.peer_id);
    try std.testing.expect(frames[0].hello.datagram_enabled);
}

test "QUIC session reaches ready after QUIC and HELLO exchange" {
    const allocator = std.testing.allocator;

    var client = try QuicSession.init(allocator, 1, .client, .{
        .peer_id = "client-a",
        .role_flags = control.RoleFlags.client,
        .datagram_enabled = true,
    });
    defer client.deinit();

    var server = try QuicSession.init(allocator, 2, .server, .{
        .peer_id = "server-a",
        .role_flags = control.RoleFlags.server,
        .datagram_enabled = true,
        .max_message_size = 4096,
    });
    defer server.deinit();

    try client.onQuicReady();
    try server.onQuicReady();

    const client_hello = try client.encodeLocalHello();
    defer allocator.free(client_hello);
    const server_hello = try server.encodeLocalHello();
    defer allocator.free(server_hello);

    try server.acceptPeerControl(client_hello);
    try client.acceptPeerControl(server_hello);

    try std.testing.expectEqual(State.ready, client.state());
    try std.testing.expectEqual(State.ready, server.state());
    try std.testing.expectEqualStrings("server-a", client.peerId());
    try std.testing.expectEqualStrings("client-a", server.peerId());
    try std.testing.expect(client.session.datagram_enabled);
    try std.testing.expectEqual(@as(usize, 4096), client.session.max_message_size);
}

test "QUIC session rejects control bytes before QUIC readiness" {
    const allocator = std.testing.allocator;

    var sess = try QuicSession.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer sess.deinit();

    const bytes = try encodeHelloControlStream(allocator, .{ .peer_id = "server-a" });
    defer allocator.free(bytes);

    try std.testing.expectError(error.InvalidState, sess.encodeLocalHello());
    try std.testing.expectError(error.InvalidState, sess.acceptPeerControl(bytes));
}
