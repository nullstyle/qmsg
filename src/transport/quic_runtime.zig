const std = @import("std");
const quic_zig = @import("quic_zig");

const quic = @import("quic.zig");

const Net = std.Io.net;

pub const Address = quic_zig.conn.path.Address;
pub const Connection = quic_zig.Connection;
pub const ConnectionEvent = quic_zig.ConnectionEvent;
pub const FeedOutcome = quic_zig.Server.FeedOutcome;
pub const IncomingDatagram = quic_zig.IncomingDatagram;
pub const OutgoingDatagram = quic_zig.OutgoingDatagram;
pub const TimerDeadline = quic_zig.conn.TimerDeadline;

pub const default_rx_buffer_bytes: usize = 64 * 1024;
pub const default_tx_buffer_bytes: usize = 1500;

pub const Error = error{
    InvalidEndpoint,
    InvalidState,
    EndpointClosed,
    EndpointInUse,
    EndpointNotFound,
    QueueFull,
    FlowControlled,
    WouldBlock,
    MessageTooLarge,
    UnsupportedTransport,
    OutOfMemory,
};

pub const ParsedEndpoint = struct {
    literal: []const u8,
    ip: Net.IpAddress,
    path_address: Address,

    pub fn port(self: ParsedEndpoint) u16 {
        return switch (self.ip) {
            .ip4 => |ip4| ip4.port,
            .ip6 => |ip6| ip6.port,
        };
    }
};

pub const ListenerOptions = struct {
    tls_cert_pem: []const u8,
    tls_key_pem: []const u8,
    transport: quic.QuicOptions = .{},
};

pub const ClientOptions = struct {
    server_name: []const u8,
    transport: quic.QuicOptions = .{},
    ca_pem: ?[]const u8 = null,
};

pub const Inbound = struct {
    bytes: []u8,
    from: ?Address = null,
};

pub const DrainedDatagram = struct {
    len: usize,
    to: ?Address = null,
    path_id: u32 = 0,
    connection_index: ?usize = null,
    stateless: bool = false,
};

pub const Timer = struct {
    deadline: TimerDeadline,
    connection_index: ?usize = null,
};

pub const RuntimeEvent = struct {
    event: ConnectionEvent,
    connection_index: ?usize = null,
};

pub fn parseEndpoint(endpoint: []const u8) Error!ParsedEndpoint {
    const literal = stripScheme(endpoint) orelse return error.InvalidEndpoint;
    if (literal.len == 0) return error.InvalidEndpoint;
    if (!hasExplicitPort(literal)) return error.InvalidEndpoint;

    const ip = Net.IpAddress.parseLiteral(literal) catch return error.InvalidEndpoint;
    return .{
        .literal = literal,
        .ip = ip,
        .path_address = ipAddressToPathAddress(ip),
    };
}

pub fn mapQuicError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidConfig => error.InvalidEndpoint,
        error.DatagramTooLarge => error.MessageTooLarge,
        error.DatagramQueueFull => error.QueueFull,
        error.DatagramUnavailable => error.FlowControlled,
        error.StreamLimitExceeded,
        error.ConnectionIdLimitExceeded,
        error.ConnectionIdRequired,
        error.PathLimitExceeded,
        error.KeyUpdateBlocked,
        => error.FlowControlled,
        error.StreamNotFound,
        error.PathNotFound,
        => error.EndpointNotFound,
        error.HandshakeFailed,
        error.PeerAlerted,
        error.UnsupportedCipherSuite,
        error.PeerDcidNotSet,
        error.EmptyEarlyDataContext,
        error.KeyUpdateUnavailable,
        error.DatagramIdExhausted,
        error.InvalidStreamId,
        error.StreamAlreadyOpen,
        error.ConnectionIdAlreadyInUse,
        => error.InvalidState,
        else => error.InvalidState,
    };
}

pub fn ipAddressToPathAddress(addr: Net.IpAddress) Address {
    return switch (addr) {
        .ip4 => |ip4| .{ .ipv4 = .{
            .addr = ip4.bytes,
            .port = ip4.port,
        } },
        .ip6 => |ip6| .{ .ipv6 = .{
            .addr = ip6.bytes,
            .port = ip6.port,
            .flow = ip6.flow,
        } },
    };
}

pub fn pathAddressToIpAddress(addr: Address) ?Net.IpAddress {
    return switch (addr) {
        .unspecified => null,
        .ipv4 => |ip4| .{ .ip4 = .{
            .bytes = ip4.addr,
            .port = ip4.port,
        } },
        .ipv6 => |ip6| .{ .ip6 = .{
            .bytes = ip6.addr,
            .port = ip6.port,
            .flow = ip6.flow,
        } },
    };
}

pub const ListenerRuntime = struct {
    allocator: std.mem.Allocator,
    endpoint_text: []u8,
    endpoint_value: ParsedEndpoint,
    server: quic_zig.Server,
    pending_stateless: ?quic_zig.Server.StatelessResponse = null,

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint_literal: []const u8,
        options: ListenerOptions,
    ) Error!ListenerRuntime {
        if (options.tls_cert_pem.len == 0 or options.tls_key_pem.len == 0) {
            return error.InvalidEndpoint;
        }
        try validateRuntimeAlpn(options.transport.alpn_protocols);

        const endpoint_text = allocator.dupe(u8, endpoint_literal) catch return error.OutOfMemory;
        errdefer allocator.free(endpoint_text);

        const endpoint_value = try parseEndpoint(endpoint_text);
        const server = quic_zig.Server.init(.{
            .allocator = allocator,
            .tls_cert_pem = options.tls_cert_pem,
            .tls_key_pem = options.tls_key_pem,
            .alpn_protocols = options.transport.alpn_protocols,
            .transport_params = transportParamsFromOptions(options.transport),
        }) catch |err| return mapQuicError(err);

        return .{
            .allocator = allocator,
            .endpoint_text = endpoint_text,
            .endpoint_value = endpoint_value,
            .server = server,
        };
    }

    pub fn deinit(self: *ListenerRuntime) void {
        self.server.deinit();
        self.allocator.free(self.endpoint_text);
        self.* = undefined;
    }

    pub fn endpoint(self: ListenerRuntime) ParsedEndpoint {
        return self.endpoint_value;
    }

    pub fn connectionCount(self: *const ListenerRuntime) usize {
        return self.server.connectionCount();
    }

    pub fn connection(self: *ListenerRuntime, index: usize) ?*Connection {
        const slots = self.server.iterator();
        if (index >= slots.len) return null;
        return slots[index].conn;
    }

    pub fn feedInbound(
        self: *ListenerRuntime,
        inbound: Inbound,
        now_us: u64,
    ) Error!FeedOutcome {
        return self.server.feed(inbound.bytes, inbound.from, now_us) catch |err| mapQuicError(err);
    }

    pub fn drainOutbound(
        self: *ListenerRuntime,
        dst: []u8,
        now_us: u64,
    ) Error!?DrainedDatagram {
        if (self.pending_stateless) |entry| {
            if (dst.len < entry.len) return error.MessageTooLarge;
            @memcpy(dst[0..entry.len], entry.slice());
            self.pending_stateless = null;
            return .{
                .len = entry.len,
                .to = entry.dst,
                .stateless = true,
            };
        }

        if (self.server.drainStatelessResponse()) |entry| {
            if (dst.len < entry.len) {
                self.pending_stateless = entry;
                return error.MessageTooLarge;
            }
            @memcpy(dst[0..entry.len], entry.slice());
            return .{
                .len = entry.len,
                .to = entry.dst,
                .stateless = true,
            };
        }

        for (self.server.iterator(), 0..) |slot, index| {
            const out = slot.conn.pollDatagram(dst, now_us) catch |err| return mapQuicError(err);
            if (out) |datagram| {
                return .{
                    .len = datagram.len,
                    .to = datagram.to orelse slot.peer_addr,
                    .path_id = datagram.path_id,
                    .connection_index = index,
                };
            }
        }
        return null;
    }

    pub fn tick(self: *ListenerRuntime, now_us: u64) Error!void {
        return self.server.tick(now_us) catch |err| mapQuicError(err);
    }

    pub fn reap(self: *ListenerRuntime) usize {
        return self.server.reap();
    }

    pub fn nextTimer(self: *ListenerRuntime, now_us: u64) ?Timer {
        var best: ?Timer = null;
        for (self.server.iterator(), 0..) |slot, index| {
            if (slot.conn.nextTimerDeadline(now_us)) |deadline| {
                considerTimer(&best, .{
                    .deadline = deadline,
                    .connection_index = index,
                });
            }
        }
        return best;
    }

    pub fn pollEvent(self: *ListenerRuntime) ?RuntimeEvent {
        for (self.server.iterator(), 0..) |slot, index| {
            if (slot.conn.pollEvent()) |event| {
                return .{
                    .event = event,
                    .connection_index = index,
                };
            }
        }
        return null;
    }

    pub fn queueDatagram(
        self: *ListenerRuntime,
        connection_index: usize,
        payload: []const u8,
    ) Error!u64 {
        const conn = self.connection(connection_index) orelse return error.EndpointNotFound;
        return conn.sendDatagramTracked(payload) catch |err| mapQuicError(err);
    }

    pub fn receiveDatagram(
        self: *ListenerRuntime,
        connection_index: usize,
        dst: []u8,
    ) ?IncomingDatagram {
        const conn = self.connection(connection_index) orelse return null;
        return conn.receiveDatagramInfo(dst);
    }
};

pub const ClientRuntime = struct {
    allocator: std.mem.Allocator,
    endpoint_text: []u8,
    endpoint_value: ParsedEndpoint,
    client: quic_zig.Client,

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint_literal: []const u8,
        options: ClientOptions,
    ) Error!ClientRuntime {
        if (options.server_name.len == 0) return error.InvalidEndpoint;
        try validateRuntimeAlpn(options.transport.alpn_protocols);

        const endpoint_text = allocator.dupe(u8, endpoint_literal) catch return error.OutOfMemory;
        errdefer allocator.free(endpoint_text);

        const endpoint_value = try parseEndpoint(endpoint_text);
        var client = quic_zig.Client.connect(.{
            .allocator = allocator,
            .server_name = options.server_name,
            .alpn_protocols = options.transport.alpn_protocols,
            .transport_params = transportParamsFromOptions(options.transport),
            .ca_pem = options.ca_pem,
        }) catch |err| return mapQuicError(err);
        errdefer client.deinit();

        client.conn.advance() catch |err| return mapQuicError(err);

        return .{
            .allocator = allocator,
            .endpoint_text = endpoint_text,
            .endpoint_value = endpoint_value,
            .client = client,
        };
    }

    pub fn deinit(self: *ClientRuntime) void {
        self.client.deinit();
        self.allocator.free(self.endpoint_text);
        self.* = undefined;
    }

    pub fn endpoint(self: ClientRuntime) ParsedEndpoint {
        return self.endpoint_value;
    }

    pub fn connection(self: *ClientRuntime) *Connection {
        return self.client.conn;
    }

    pub fn feedInbound(
        self: *ClientRuntime,
        inbound: Inbound,
        now_us: u64,
    ) Error!void {
        return self.client.conn.handle(inbound.bytes, inbound.from, now_us) catch |err| mapQuicError(err);
    }

    pub fn drainOutbound(
        self: *ClientRuntime,
        dst: []u8,
        now_us: u64,
    ) Error!?DrainedDatagram {
        const out = self.client.conn.pollDatagram(dst, now_us) catch |err| return mapQuicError(err);
        if (out) |datagram| {
            return .{
                .len = datagram.len,
                .to = datagram.to orelse self.endpoint_value.path_address,
                .path_id = datagram.path_id,
                .connection_index = 0,
            };
        }
        return null;
    }

    pub fn tick(self: *ClientRuntime, now_us: u64) Error!void {
        return self.client.conn.tick(now_us) catch |err| mapQuicError(err);
    }

    pub fn nextTimer(self: *ClientRuntime, now_us: u64) ?Timer {
        const deadline = self.client.conn.nextTimerDeadline(now_us) orelse return null;
        return .{
            .deadline = deadline,
            .connection_index = 0,
        };
    }

    pub fn pollEvent(self: *ClientRuntime) ?RuntimeEvent {
        const event = self.client.conn.pollEvent() orelse return null;
        return .{
            .event = event,
            .connection_index = 0,
        };
    }

    pub fn queueDatagram(self: *ClientRuntime, payload: []const u8) Error!u64 {
        return self.client.conn.sendDatagramTracked(payload) catch |err| mapQuicError(err);
    }

    pub fn receiveDatagram(self: *ClientRuntime, dst: []u8) ?IncomingDatagram {
        return self.client.conn.receiveDatagramInfo(dst);
    }
};

fn stripScheme(endpoint: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, endpoint, "quic://")) return endpoint["quic://".len..];
    if (std.mem.startsWith(u8, endpoint, "udp://")) return endpoint["udp://".len..];
    if (std.mem.indexOf(u8, endpoint, "://") != null) return null;
    return endpoint;
}

fn hasExplicitPort(literal: []const u8) bool {
    if (literal.len == 0) return false;
    if (literal[0] == '[') {
        const close = std.mem.indexOfScalar(u8, literal, ']') orelse return false;
        return close + 2 < literal.len and literal[close + 1] == ':';
    }

    const colon = std.mem.lastIndexOfScalar(u8, literal, ':') orelse return false;
    return colon + 1 < literal.len;
}

fn validateRuntimeAlpn(protocols: []const []const u8) Error!void {
    if (protocols.len == 0) return error.InvalidEndpoint;
    for (protocols) |protocol| {
        if (std.mem.eql(u8, protocol, quic.alpn)) return;
    }
    return error.UnsupportedTransport;
}

fn transportParamsFromOptions(options: quic.QuicOptions) quic_zig.tls.TransportParams {
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

fn considerTimer(best: *?Timer, candidate: Timer) void {
    if (best.* == null or candidate.deadline.at_us < best.*.?.deadline.at_us) {
        best.* = candidate;
    }
}

const test_cert_pem = @embedFile("../testdata/test_cert.pem");
const test_key_pem = @embedFile("../testdata/test_key.pem");

test "QUIC runtime parses endpoint literals and schemes" {
    const v4 = try parseEndpoint("127.0.0.1:4433");
    try std.testing.expectEqual(@as(u16, 4433), v4.port());
    try std.testing.expectEqual(std.meta.Tag(Address).ipv4, std.meta.activeTag(v4.path_address));

    const v6 = try parseEndpoint("quic://[::1]:8443");
    try std.testing.expectEqual(@as(u16, 8443), v6.port());
    try std.testing.expectEqual(std.meta.Tag(Address).ipv6, std.meta.activeTag(v6.path_address));

    const udp = try parseEndpoint("udp://0.0.0.0:0");
    try std.testing.expectEqual(@as(u16, 0), udp.port());

    try std.testing.expectError(error.InvalidEndpoint, parseEndpoint(""));
    try std.testing.expectError(error.InvalidEndpoint, parseEndpoint("localhost:4433"));
    try std.testing.expectError(error.InvalidEndpoint, parseEndpoint("127.0.0.1"));
    try std.testing.expectError(error.InvalidEndpoint, parseEndpoint("http://127.0.0.1:4433"));
}

test "QUIC runtime listener lifecycle is socket-free" {
    const allocator = std.testing.allocator;

    var listener = try ListenerRuntime.init(allocator, "127.0.0.1:4433", .{
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .transport = .{ .peer_id = "server-a" },
    });
    defer listener.deinit();

    try std.testing.expectEqual(@as(usize, 0), listener.connectionCount());
    try std.testing.expect(listener.nextTimer(0) == null);

    var out: [default_tx_buffer_bytes]u8 = undefined;
    try std.testing.expect((try listener.drainOutbound(&out, 0)) == null);
}

test "QUIC runtime client lifecycle emits initial datagram and timer without network" {
    const allocator = std.testing.allocator;

    var client = try ClientRuntime.init(allocator, "127.0.0.1:4433", .{
        .server_name = "localhost",
        .transport = .{ .peer_id = "client-a" },
    });
    defer client.deinit();

    var out: [default_rx_buffer_bytes]u8 = undefined;
    const first = (try client.drainOutbound(&out, 1_000)) orelse return error.WouldBlock;
    try std.testing.expect(first.len > 0);
    try std.testing.expect(first.to != null);
    try std.testing.expectEqual(std.meta.Tag(Address).ipv4, std.meta.activeTag(first.to.?));
    try std.testing.expect(client.nextTimer(1_000) != null);
}

test "QUIC runtime maps quic-zig errors to qmsg-ish transport errors" {
    try std.testing.expectEqual(error.OutOfMemory, mapQuicError(error.OutOfMemory));
    try std.testing.expectEqual(error.InvalidEndpoint, mapQuicError(error.InvalidConfig));
    try std.testing.expectEqual(error.MessageTooLarge, mapQuicError(error.DatagramTooLarge));
    try std.testing.expectEqual(error.QueueFull, mapQuicError(error.DatagramQueueFull));
    try std.testing.expectEqual(error.FlowControlled, mapQuicError(error.DatagramUnavailable));
    try std.testing.expectEqual(error.EndpointNotFound, mapQuicError(error.StreamNotFound));
    try std.testing.expectEqual(error.InvalidState, mapQuicError(error.HandshakeFailed));

    const params = transportParamsFromOptions(.{
        .datagram_enabled = true,
        .max_datagram_frame_size = 10,
    });
    try std.testing.expectEqual(@as(u64, 1200), params.max_datagram_frame_size);
}
