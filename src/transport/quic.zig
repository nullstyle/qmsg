const std = @import("std");
const quic_zig = @import("quic");

const auth = @import("../auth.zig");
const control = @import("../control.zig");
const envelope = @import("../envelope.zig");
const message = @import("../message.zig");
const session_mod = @import("../session.zig");
const quic_session_runtime = @import("quic_session_runtime.zig");

pub const alpn = "qmsg/1";
pub const control_stream_type: u64 = 0x51;

/// Application CONNECTION_CLOSE code for a session-level protocol
/// violation (malformed control/reliable framing). Same 0x51_xx
/// family as `quic_cancel.CloseReason`'s stream codes.
pub const protocol_error_code: u64 = 0x51_05;

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

pub const StreamIdAllocator = struct {
    next_bidi: u64,
    next_uni: u64,

    pub fn init(role: Role) StreamIdAllocator {
        return switch (role) {
            .client => .{ .next_bidi = 0, .next_uni = 2 },
            .server => .{ .next_bidi = 1, .next_uni = 3 },
        };
    }

    pub fn nextBidi(self: *StreamIdAllocator) !u64 {
        return self.next(&self.next_bidi);
    }

    pub fn nextUni(self: *StreamIdAllocator) !u64 {
        return self.next(&self.next_uni);
    }

    fn next(_: *StreamIdAllocator, cursor: *u64) !u64 {
        const id = cursor.*;
        cursor.* = std.math.add(u64, cursor.*, 4) catch return error.InvalidState;
        return id;
    }
};

pub const ReliableWriteOptions = struct {
    open_bidi: bool = true,
    finish: bool = true,
};

pub const ReliableWriteProgress = enum {
    pending,
    complete,
};

pub const ReliableMessageSender = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    bytes: []u8,
    offset: usize = 0,
    options: ReliableWriteOptions = .{},
    opened: bool = false,
    finished: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        stream_id: u64,
        outgoing: message.OutgoingMessage,
        codec_options: envelope.CodecOptions,
        options: ReliableWriteOptions,
    ) !ReliableMessageSender {
        const bytes = try encodeReliableMessage(allocator, outgoing, codec_options);
        errdefer allocator.free(bytes);

        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .bytes = bytes,
            .options = options,
        };
    }

    pub fn deinit(self: *ReliableMessageSender) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn pump(self: *ReliableMessageSender, conn: *quic_zig.Connection) !ReliableWriteProgress {
        if (!self.opened) {
            if (self.options.open_bidi) _ = try conn.openBidi(self.stream_id);
            self.opened = true;
        }

        while (self.offset < self.bytes.len) {
            const written = try conn.streamWrite(self.stream_id, self.bytes[self.offset..]);
            if (written == 0) return .pending;
            self.offset += written;
        }

        if (self.options.finish and !self.finished) {
            try conn.streamFinish(self.stream_id);
            self.finished = true;
        }

        return .complete;
    }
};

pub const ReliableMessageReceiver = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    codec_options: envelope.CodecOptions,
    bytes: std.ArrayList(u8) = .empty,
    decoded: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        stream_id: u64,
        codec_options: envelope.CodecOptions,
    ) ReliableMessageReceiver {
        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .codec_options = codec_options,
        };
    }

    pub fn deinit(self: *ReliableMessageReceiver) void {
        self.bytes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn read(self: *ReliableMessageReceiver, conn: *quic_zig.Connection) !?message.Message {
        if (self.decoded) return error.InvalidState;

        try self.checkStreamResetAndSize(conn);
        var scratch: [4096]u8 = undefined;
        while (true) {
            const n = try conn.streamRead(self.stream_id, &scratch);
            if (n == 0) break;
            if (n > self.codec_options.max_message_size or
                self.bytes.items.len > self.codec_options.max_message_size - n)
            {
                return error.MessageTooLarge;
            }
            try self.bytes.appendSlice(self.allocator, scratch[0..n]);
        }

        if (!try self.streamComplete(conn)) return null;

        self.decoded = true;
        return try decodeReliableMessage(self.allocator, self.bytes.items, self.codec_options);
    }

    fn checkStreamResetAndSize(self: *ReliableMessageReceiver, conn: *quic_zig.Connection) !void {
        const stream = conn.stream(self.stream_id) orelse return error.StreamNotFound;
        if (stream.recv.reset != null) return error.StreamReset;
        if (stream.recv.final_size) |final_size| {
            if (final_size > self.codec_options.max_message_size) return error.MessageTooLarge;
        }
    }

    fn streamComplete(self: *ReliableMessageReceiver, conn: *quic_zig.Connection) !bool {
        const stream = conn.stream(self.stream_id) orelse return error.StreamNotFound;
        if (stream.recv.reset != null) return error.StreamReset;
        const final_size = stream.recv.final_size orelse return false;
        return stream.recv.read_offset == final_size;
    }
};

pub const RequestCorrelation = struct {
    stream_id: u64,
    message_id: message.MessageId,

    pub fn expectReply(self: RequestCorrelation, stream_id: u64, reply: message.Message) !void {
        if (stream_id != self.stream_id) return error.UnexpectedFrame;
        if (reply.id != self.message_id) return error.UnexpectedFrame;
    }
};

pub fn encodeReliableMessage(
    allocator: std.mem.Allocator,
    outgoing: message.OutgoingMessage,
    options: envelope.CodecOptions,
) ![]u8 {
    if (outgoing.flags.unreliable) return error.InvalidMessage;
    return envelope.encode(allocator, outgoing, options);
}

pub fn decodeReliableMessage(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: envelope.CodecOptions,
) !message.Message {
    return envelope.decode(allocator, bytes, options);
}

pub fn requestCorrelation(stream_id: u64, outgoing: message.OutgoingMessage) !RequestCorrelation {
    if (outgoing.id == 0) return error.InvalidMessage;
    return .{
        .stream_id = stream_id,
        .message_id = outgoing.id,
    };
}

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
    auth_config: auth.AuthConfig = .{},
    /// Listener template for channel binding: when set, each accepted
    /// session mints a fresh HELLO challenge from this config,
    /// advertises it in the outgoing HELLO, and verifies inbound
    /// credentials against the challenge-bound implicit assertion.
    /// Wired where the adapter creates server sessions (Node's
    /// driverServerSessionCreate); the session owns the minted
    /// binding for its lifetime.
    hello_challenge: ?auth.HelloChallengeConfig = null,
    /// Dial-side channel binding: when set, the local HELLO is
    /// deferred until the peer's HELLO arrives and its credential is
    /// minted by this provider, bound to the peer's advertised
    /// challenge. The static `auth` credential fields are then
    /// ignored. Both ends deferring (provider on both sides) is not
    /// supported -- one side must send its HELLO eagerly.
    credential_provider: ?auth.CredentialProvider = null,
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
    /// Server side: the per-connection challenge binding minted from
    /// `options.hello_challenge` at session creation. Owns the
    /// challenge bytes that `options.auth.challenge` and
    /// `options.auth_config.hello_binding.context.challenge` borrow.
    hello_challenge_binding: ?auth.HelloChallengeBinding = null,
    /// The peer's advertised HELLO challenge (empty when it sent
    /// none) -- the input a dial-side CredentialProvider binds its
    /// token to.
    peer_hello_challenge: []u8 = &.{},
    /// Copies of the provider-minted auth properties (owned for the
    /// session's lifetime; the provider's originals die with its
    /// call). Null when the credential came in statically.
    owned_auth_credential: ?[]u8 = null,
    owned_auth_key_id_hint: ?[]u8 = null,
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
        if (self.hello_challenge_binding) |*binding| binding.deinit(self.allocator);
        if (self.peer_hello_challenge.len > 0) self.allocator.free(self.peer_hello_challenge);
        if (self.owned_auth_credential) |credential| self.allocator.free(credential);
        if (self.owned_auth_key_id_hint) |hint| self.allocator.free(hint);
        self.session.clearAuthorization(self.allocator);
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

    pub fn sendLocalHelloOnStream(self: *QuicSession, conn: *quic_zig.Connection) !u64 {
        if (self.state_value != .quic_ready and self.state_value != .ready) return error.InvalidState;
        if (self.local_hello_sent) return error.InvalidState;

        const stream_id = localControlStreamId(self.role);
        if (conn.stream(stream_id) == null) {
            _ = try conn.openUni(stream_id);
        }

        const bytes = try encodeHelloControlStream(self.allocator, self.options);
        defer self.allocator.free(bytes);

        const written = try conn.streamWrite(stream_id, bytes);
        if (written != bytes.len) return error.FlowControlled;
        try conn.streamFinish(stream_id);

        self.local_hello_sent = true;
        self.refreshState();
        return stream_id;
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

    pub fn acceptPeerControlFromStream(
        self: *QuicSession,
        conn: *quic_zig.Connection,
        stream_id: u64,
        max_bytes: usize,
    ) !void {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(self.allocator);

        var scratch: [1024]u8 = undefined;
        while (true) {
            const n = try conn.streamRead(stream_id, &scratch);
            if (n == 0) break;
            if (bytes.items.len + n > max_bytes) return error.FrameTooLarge;
            try bytes.appendSlice(self.allocator, scratch[0..n]);
        }
        if (bytes.items.len == 0) return error.MalformedFrame;

        try self.acceptPeerControl(bytes.items);
    }

    pub fn close(self: *QuicSession) void {
        self.state_value = .closed;
    }

    fn acceptHello(self: *QuicSession, hello: control.Hello) !void {
        if (self.peer_hello_received) return error.InvalidState;
        try self.validateHelloPolicy(hello);

        const owned_peer_id = try self.allocator.dupe(u8, hello.peer_id);
        errdefer self.allocator.free(owned_peer_id);

        const owned_challenge: []u8 = if (hello.auth.challenge.len > 0)
            try self.allocator.dupe(u8, hello.auth.challenge)
        else
            &.{};
        errdefer if (owned_challenge.len > 0) self.allocator.free(owned_challenge);

        var auth_committed = false;
        errdefer if (!auth_committed) self.session.clearAuthorization(self.allocator);
        try self.authenticateHello(hello);

        if (self.peer_id) |previous| self.allocator.free(previous);
        self.peer_id = owned_peer_id;
        self.peer_hello_challenge = owned_challenge;
        self.peer_hello_received = true;

        self.session.peer_id = self.peer_id.?;
        self.session.peer_heartbeat_interval_ms = hello.heartbeat_interval_ms;
        self.session.datagram_enabled = self.options.datagram_enabled and hello.datagram_enabled;
        self.session.max_message_size = @min(self.options.max_message_size, hello.max_message_size);
        auth_committed = true;
    }

    fn validateHelloPolicy(self: *QuicSession, hello: control.Hello) !void {
        if (hello.wire_version != control.default_wire_version) return error.VersionMismatch;
        if (hello.peer_id.len == 0) return error.PeerIdTooLarge;
        if (hello.supported_patterns == 0) return error.InvalidPattern;
        if ((hello.supported_patterns & ~control.PatternBits.all) != 0) return error.InvalidPattern;
        if ((hello.supported_patterns & self.options.supported_patterns) == 0) return error.InvalidPattern;
    }

    fn authenticateHello(self: *QuicSession, hello: control.Hello) !void {
        try self.session.authenticateHello(self.allocator, self.options.auth_config, .{
            .peer_id = hello.peer_id,
            .scheme = hello.auth.scheme,
            .credential = hello.auth.credential,
            .key_id_hint = hello.auth.key_id_hint,
            .challenge = hello.auth.challenge,
        });

        if (self.session.authorizationCache()) |authorization| {
            try checkHelloAuthorization(authorization, hello);
        }
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

pub fn localControlStreamId(role: Role) u64 {
    return switch (role) {
        .client => 2,
        .server => 3,
    };
}

pub fn peerControlStreamId(role: Role) u64 {
    return switch (role) {
        .client => localControlStreamId(.server),
        .server => localControlStreamId(.client),
    };
}

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

fn checkHelloAuthorization(authorization: auth.Authorization, hello: control.Hello) auth.Error!void {
    try checkHelloPattern(authorization, hello.supported_patterns, control.PatternBits.pair, .pair);
    try checkHelloPattern(authorization, hello.supported_patterns, control.PatternBits.req, .req);
    try checkHelloPattern(authorization, hello.supported_patterns, control.PatternBits.rep, .rep);
    try checkHelloPattern(authorization, hello.supported_patterns, control.PatternBits.pub_, .@"pub");
    try checkHelloPattern(authorization, hello.supported_patterns, control.PatternBits.sub, .sub);
    try checkHelloPattern(authorization, hello.supported_patterns, control.PatternBits.push, .push);
    try checkHelloPattern(authorization, hello.supported_patterns, control.PatternBits.pull, .pull);
    if (hello.datagram_enabled) try authorization.check(.{ .datagram = true });
}

fn checkHelloPattern(
    authorization: auth.Authorization,
    bits: u64,
    bit: u64,
    pattern: auth.Pattern,
) auth.Error!void {
    if ((bits & bit) != 0) try authorization.check(.{ .pattern = pattern });
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

test "HELLO exchange captures the peer heartbeat interval for negotiation" {
    const allocator = std.testing.allocator;

    var client = try QuicSession.init(allocator, 1, .client, .{
        .peer_id = "client-hb",
        .role_flags = control.RoleFlags.client,
        .heartbeat_interval_ms = 30_000,
    });
    defer client.deinit();
    var server = try QuicSession.init(allocator, 2, .server, .{
        .peer_id = "server-hb",
        .role_flags = control.RoleFlags.server,
        .heartbeat_interval_ms = 10_000,
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

    // Each side captured the PEER's advertised interval verbatim...
    try std.testing.expectEqual(@as(u64, 10_000), client.session.peer_heartbeat_interval_ms);
    try std.testing.expectEqual(@as(u64, 30_000), server.session.peer_heartbeat_interval_ms);

    // ...and the effective session heartbeat (QuicSessionRuntime's
    // computation over its own session) is the min when both offer one.
    var rt_client = try quic_session_runtime.QuicSessionRuntime.init(allocator, 901, .client, .{
        .peer_id = "rt-client",
        .role_flags = control.RoleFlags.client,
        .heartbeat_interval_ms = 30_000,
    });
    defer rt_client.deinit();
    rt_client.session.session.peer_heartbeat_interval_ms = client.session.peer_heartbeat_interval_ms;
    try std.testing.expectEqual(@as(u64, 10_000), rt_client.heartbeatInterval());

    // Opt-out is symmetric: either side advertising 0 means no heartbeat.
    var quiet = try QuicSession.init(allocator, 3, .client, .{
        .peer_id = "quiet",
        .role_flags = control.RoleFlags.client,
        .heartbeat_interval_ms = 5_000,
    });
    defer quiet.deinit();
    var silent_server = try QuicSession.init(allocator, 4, .server, .{
        .peer_id = "silent",
        .role_flags = control.RoleFlags.server,
        // heartbeat_interval_ms defaults to 0: no liveness offered.
    });
    defer silent_server.deinit();

    try quiet.onQuicReady();
    try silent_server.onQuicReady();
    const quiet_hello = try quiet.encodeLocalHello();
    defer allocator.free(quiet_hello);
    const silent_hello = try silent_server.encodeLocalHello();
    defer allocator.free(silent_hello);
    try silent_server.acceptPeerControl(quiet_hello);
    try quiet.acceptPeerControl(silent_hello);

    try std.testing.expectEqual(@as(u64, 5_000), silent_server.session.peer_heartbeat_interval_ms);
    var rt_quiet = try quic_session_runtime.QuicSessionRuntime.init(allocator, 902, .client, .{
        .peer_id = "rt-quiet",
        .role_flags = control.RoleFlags.client,
        .heartbeat_interval_ms = 5_000,
    });
    defer rt_quiet.deinit();
    rt_quiet.session.session.peer_heartbeat_interval_ms = 0; // peer opted out
    try std.testing.expectEqual(@as(u64, 0), rt_quiet.heartbeatInterval());
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

test "QUIC session rejects HELLO with incompatible wire version" {
    const allocator = std.testing.allocator;

    var sess = try QuicSession.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer sess.deinit();
    try sess.onQuicReady();

    const bytes = try encodeControlStream(allocator, .{ .hello = .{
        .wire_version = control.default_wire_version + 1,
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.pair,
    } }, .{});
    defer allocator.free(bytes);

    try std.testing.expectError(error.VersionMismatch, sess.acceptPeerControl(bytes));
    try std.testing.expectEqual(State.quic_ready, sess.state());
    try std.testing.expectEqualStrings("", sess.peerId());
}

test "QUIC session rejects HELLO with no compatible pattern" {
    const allocator = std.testing.allocator;

    var sess = try QuicSession.init(allocator, 1, .client, .{
        .peer_id = "client-a",
        .supported_patterns = control.PatternBits.req,
    });
    defer sess.deinit();
    try sess.onQuicReady();

    const bytes = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.pub_,
    });
    defer allocator.free(bytes);

    try std.testing.expectError(error.InvalidPattern, sess.acceptPeerControl(bytes));
    try std.testing.expectEqual(State.quic_ready, sess.state());
}

test "QUIC session rejects HELLO when auth is required but absent" {
    const allocator = std.testing.allocator;

    var sess = try QuicSession.init(allocator, 1, .client, .{
        .peer_id = "client-a",
        .auth_config = .{ .required = true },
    });
    defer sess.deinit();
    try sess.onQuicReady();

    const bytes = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.pair,
    });
    defer allocator.free(bytes);

    try std.testing.expectError(auth.Error.AuthenticationRequired, sess.acceptPeerControl(bytes));
    try std.testing.expect(!sess.session.isAuthenticated());
}

test "QUIC session permits anonymous HELLO when auth is optional" {
    const allocator = std.testing.allocator;

    var sess = try QuicSession.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer sess.deinit();
    try sess.onQuicReady();

    const bytes = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.pair,
    });
    defer allocator.free(bytes);

    try sess.acceptPeerControl(bytes);
    try std.testing.expectEqualStrings("server-a", sess.peerId());
    try std.testing.expect(sess.session.isAnonymous());
}

test "QUIC session retains the peer's advertised HELLO challenge" {
    const allocator = std.testing.allocator;

    var sess = try QuicSession.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer sess.deinit();
    try sess.onQuicReady();

    const bytes = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.pair,
        .auth = .{ .challenge = "nonce-1" },
    });
    defer allocator.free(bytes);

    try sess.acceptPeerControl(bytes);
    try std.testing.expectEqualStrings("nonce-1", sess.peer_hello_challenge);
    try std.testing.expect(sess.session.isAnonymous());
}

test "QUIC session forwards the peer challenge into binding validation" {
    const allocator = std.testing.allocator;

    // A binding policy tighter than the codec's 128-byte wire bound
    // must reject an over-long advertised challenge: the challenge is
    // policy input now, not decoration.
    var sess = try QuicSession.init(allocator, 1, .client, .{
        .peer_id = "client-a",
        .auth_config = .{ .hello_binding = .{ .max_challenge_bytes = 8 } },
    });
    defer sess.deinit();
    try sess.onQuicReady();

    const bytes = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.pair,
        .auth = .{ .challenge = "nine-bytes" },
    });
    defer allocator.free(bytes);

    try std.testing.expectError(auth.Error.ChallengeTooLarge, sess.acceptPeerControl(bytes));
    try std.testing.expectEqual(@as(usize, 0), sess.peer_hello_challenge.len);
}

test "QUIC session rejects unsupported scheme and authenticator unknown key" {
    const allocator = std.testing.allocator;

    const UnknownKeyAuthenticator = struct {
        fn authenticate(_: ?*anyopaque, _: std.mem.Allocator, _: auth.Credential) !auth.Authorization {
            return auth.Error.UnknownKey;
        }
    };

    var sess = try QuicSession.init(allocator, 1, .client, .{
        .peer_id = "client-a",
        .auth_config = .{
            .required = true,
            .authenticator = .{ .authenticate_fn = UnknownKeyAuthenticator.authenticate },
        },
    });
    defer sess.deinit();
    try sess.onQuicReady();

    const unsupported = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.pair,
        .auth = .{ .scheme = "bearer", .credential = "token" },
    });
    defer allocator.free(unsupported);

    try std.testing.expectError(auth.Error.UnsupportedCredential, sess.acceptPeerControl(unsupported));
    try std.testing.expectEqualStrings("", sess.peerId());
    try std.testing.expect(!sess.session.isAuthenticated());

    const unknown_key = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.pair,
        .auth = .{ .scheme = auth.hello_auth_scheme_paseto, .credential = "token" },
    });
    defer allocator.free(unknown_key);

    try std.testing.expectError(auth.Error.UnknownKey, sess.acceptPeerControl(unknown_key));
    try std.testing.expectEqualStrings("", sess.peerId());
    try std.testing.expect(!sess.session.isAuthenticated());
}

test "QUIC session caches successful HELLO authorization" {
    const allocator = std.testing.allocator;

    const SuccessAuthenticator = struct {
        calls: usize = 0,

        fn authenticate(ptr: ?*anyopaque, alloc: std.mem.Allocator, credential: auth.Credential) !auth.Authorization {
            const self: *@This() = @ptrCast(@alignCast(ptr.?));
            self.calls += 1;
            try std.testing.expectEqualStrings("token", credential.token);
            return try (auth.Authorization{
                .subject = "service:server",
                .issuer = "issuer",
                .allowed_patterns = auth.PatternSet.init(&.{.pair}),
                .allowed_subjects = .allow_all,
            }).clone(alloc);
        }
    };

    var success = SuccessAuthenticator{};
    var sess = try QuicSession.init(allocator, 1, .client, .{
        .peer_id = "client-a",
        .auth_config = .{
            .required = true,
            .authenticator = .{
                .ptr = &success,
                .authenticate_fn = SuccessAuthenticator.authenticate,
            },
        },
    });
    defer sess.deinit();
    try sess.onQuicReady();

    const bytes = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.pair,
        .auth = .{ .scheme = auth.hello_auth_scheme_paseto, .credential = "token" },
    });
    defer allocator.free(bytes);

    try sess.acceptPeerControl(bytes);
    try std.testing.expectEqual(@as(usize, 1), success.calls);
    try std.testing.expectEqualStrings("server-a", sess.peerId());
    try std.testing.expect(sess.session.isAuthenticated());
    try std.testing.expectEqualStrings("service:server", sess.session.authorizationCache().?.subject);
    try sess.session.requirePattern(.pair);
}

test "QUIC session applies auth policy to HELLO patterns and datagrams" {
    const allocator = std.testing.allocator;

    const AuthHarness = struct {
        fn authenticate(_: ?*anyopaque, alloc: std.mem.Allocator, _: auth.Credential) !auth.Authorization {
            const subject = try alloc.dupe(u8, "peer");
            errdefer alloc.free(subject);
            const issuer = try alloc.dupe(u8, "issuer");
            errdefer alloc.free(issuer);

            return .{
                .subject = subject,
                .issuer = issuer,
                .allowed_patterns = auth.PatternSet.init(&.{.req}),
                .datagram_allowed = false,
            };
        }
    };

    var pattern_sess = try QuicSession.init(allocator, 1, .client, .{
        .peer_id = "client-a",
        .auth_config = .{
            .required = true,
            .authenticator = .{ .authenticate_fn = AuthHarness.authenticate },
        },
    });
    defer pattern_sess.deinit();
    try pattern_sess.onQuicReady();

    const pattern_bytes = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-a",
        .supported_patterns = control.PatternBits.rep,
        .auth = .{ .scheme = auth.hello_auth_scheme_paseto, .credential = "token" },
    });
    defer allocator.free(pattern_bytes);

    try std.testing.expectError(auth.Error.Unauthorized, pattern_sess.acceptPeerControl(pattern_bytes));

    var datagram_sess = try QuicSession.init(allocator, 2, .client, .{
        .peer_id = "client-b",
        .datagram_enabled = true,
        .auth_config = .{
            .required = true,
            .authenticator = .{ .authenticate_fn = AuthHarness.authenticate },
        },
    });
    defer datagram_sess.deinit();
    try datagram_sess.onQuicReady();

    const datagram_bytes = try encodeHelloControlStream(allocator, .{
        .peer_id = "server-b",
        .supported_patterns = control.PatternBits.req,
        .datagram_enabled = true,
        .auth = .{ .scheme = auth.hello_auth_scheme_paseto, .credential = "token" },
    });
    defer allocator.free(datagram_bytes);

    try std.testing.expectError(auth.Error.Unauthorized, datagram_sess.acceptPeerControl(datagram_bytes));
    try std.testing.expect(!datagram_sess.session.isAuthenticated());
}

test "QUIC stream id allocator owns role-specific stream ids" {
    var client_ids = StreamIdAllocator.init(.client);
    try std.testing.expectEqual(@as(u64, 0), try client_ids.nextBidi());
    try std.testing.expectEqual(@as(u64, 4), try client_ids.nextBidi());
    try std.testing.expectEqual(@as(u64, 2), try client_ids.nextUni());
    try std.testing.expectEqual(@as(u64, 6), try client_ids.nextUni());

    var server_ids = StreamIdAllocator.init(.server);
    try std.testing.expectEqual(@as(u64, 1), try server_ids.nextBidi());
    try std.testing.expectEqual(@as(u64, 5), try server_ids.nextBidi());
    try std.testing.expectEqual(@as(u64, 3), try server_ids.nextUni());
    try std.testing.expectEqual(@as(u64, 7), try server_ids.nextUni());
}

test "reliable message helpers encode decode and reject unreliable flag" {
    const allocator = std.testing.allocator;

    const bytes = try encodeReliableMessage(allocator, .{
        .subject = "pair.echo",
        .id = 42,
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "hello",
    }, .{});
    defer allocator.free(bytes);

    var decoded = try decodeReliableMessage(allocator, bytes, .{});
    defer decoded.deinit();

    try std.testing.expectEqual(@as(message.MessageId, 42), decoded.id);
    try std.testing.expectEqualStrings("pair.echo", decoded.subject);
    try std.testing.expectEqualStrings("hello", decoded.body);
    try std.testing.expectEqualStrings("content-type", decoded.headers[0].name);

    try std.testing.expectError(error.InvalidMessage, encodeReliableMessage(allocator, .{
        .subject = "pair.echo",
        .flags = .{ .unreliable = true },
    }, .{}));
}

test "request correlation requires same stream and message id" {
    const allocator = std.testing.allocator;

    const correlation = try requestCorrelation(0, .{
        .subject = "user.get",
        .id = 700,
        .body = "request",
    });

    var reply = try message.Message.init(allocator, .{
        .subject = "user.get",
        .id = 700,
        .body = "reply",
    });
    defer reply.deinit();

    try correlation.expectReply(0, reply);
    try std.testing.expectError(error.UnexpectedFrame, correlation.expectReply(1, reply));

    reply.id = 701;
    try std.testing.expectError(error.UnexpectedFrame, correlation.expectReply(0, reply));
    try std.testing.expectError(error.InvalidMessage, requestCorrelation(0, .{
        .subject = "user.get",
        .id = 0,
    }));
}
