const std = @import("std");

const quic_runtime = @import("quic_runtime.zig");

const Io = std.Io;
const Net = Io.net;

pub const Address = quic_runtime.Address;
pub const ClientRuntime = quic_runtime.ClientRuntime;
pub const ListenerRuntime = quic_runtime.ListenerRuntime;
pub const Timer = quic_runtime.Timer;

pub const default_bind_literal = "0.0.0.0:0";
pub const default_receive_timeout: Io.Timeout = .{
    .duration = .{ .raw = .zero, .clock = .awake },
};

pub const Error = quic_runtime.Error ||
    std.mem.Allocator.Error ||
    Net.IpAddress.BindError ||
    Net.Socket.SendError ||
    Net.Socket.ReceiveTimeoutError;

pub const Datagram = struct {
    bytes: []u8,
    from: Net.IpAddress,
    path_address: Address,
};

pub const SentDatagram = struct {
    drained: quic_runtime.DrainedDatagram,
    to: Net.IpAddress,
};

pub const ListenerOptions = struct {
    bind_literal: []const u8,
    runtime: quic_runtime.ListenerOptions,
    rx_buffer_bytes: usize = quic_runtime.default_rx_buffer_bytes,
    tx_buffer_bytes: usize = quic_runtime.default_tx_buffer_bytes,
    receive_timeout: Io.Timeout = default_receive_timeout,
};

pub const ClientOptions = struct {
    target_literal: []const u8,
    runtime: quic_runtime.ClientOptions,
    bind_literal: []const u8 = default_bind_literal,
    rx_buffer_bytes: usize = quic_runtime.default_rx_buffer_bytes,
    tx_buffer_bytes: usize = quic_runtime.default_tx_buffer_bytes,
    receive_timeout: Io.Timeout = default_receive_timeout,
};

pub const ListenerRecvResult = struct {
    datagram: Datagram,
    outcome: quic_runtime.FeedOutcome,
};

pub const Listener = struct {
    allocator: std.mem.Allocator,
    io: Io,
    socket: Net.Socket,
    runtime: ListenerRuntime,
    rx_buffer: []u8,
    tx_buffer: []u8,
    receive_timeout: Io.Timeout,

    pub fn start(allocator: std.mem.Allocator, io: Io, options: ListenerOptions) Error!Listener {
        try validateListenerOptions(options);

        const bind_endpoint = try quic_runtime.parseEndpoint(options.bind_literal);
        var socket = try bindUdpSocket(io, bind_endpoint.ip);
        errdefer socket.close(io);

        var runtime = try ListenerRuntime.init(allocator, options.bind_literal, options.runtime);
        errdefer runtime.deinit();

        const rx_buffer = try allocator.alloc(u8, options.rx_buffer_bytes);
        errdefer allocator.free(rx_buffer);

        const tx_buffer = try allocator.alloc(u8, options.tx_buffer_bytes);
        errdefer allocator.free(tx_buffer);

        return .{
            .allocator = allocator,
            .io = io,
            .socket = socket,
            .runtime = runtime,
            .rx_buffer = rx_buffer,
            .tx_buffer = tx_buffer,
            .receive_timeout = options.receive_timeout,
        };
    }

    pub fn deinit(self: *Listener) void {
        self.socket.close(self.io);
        self.runtime.deinit();
        self.allocator.free(self.rx_buffer);
        self.allocator.free(self.tx_buffer);
        self.* = undefined;
    }

    pub fn localAddress(self: Listener) Net.IpAddress {
        return self.socket.address;
    }

    pub fn recvOne(self: *Listener) Error!?Datagram {
        return recvUdpOne(&self.socket, self.io, self.rx_buffer, self.receive_timeout);
    }

    pub fn recvAndFeedOne(self: *Listener, now_us: u64) Error!?ListenerRecvResult {
        const datagram = (try self.recvOne()) orelse return null;
        const outcome = try self.runtime.feedInbound(.{
            .bytes = datagram.bytes,
            .from = datagram.path_address,
        }, now_us);
        return .{
            .datagram = datagram,
            .outcome = outcome,
        };
    }

    pub fn drainOne(self: *Listener, now_us: u64) Error!?quic_runtime.DrainedDatagram {
        return self.runtime.drainOutbound(self.tx_buffer, now_us);
    }

    pub fn drainAndSendOne(self: *Listener, now_us: u64) Error!?SentDatagram {
        const drained = (try self.drainOne(now_us)) orelse return null;
        const to = try drainedTarget(drained);
        try self.socket.send(self.io, &to, self.tx_buffer[0..drained.len]);
        return .{
            .drained = drained,
            .to = to,
        };
    }

    pub fn tick(self: *Listener, now_us: u64) Error!void {
        try self.runtime.tick(now_us);
    }

    pub fn nextTimer(self: *Listener, now_us: u64) ?Timer {
        return self.runtime.nextTimer(now_us);
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: Io,
    socket: Net.Socket,
    runtime: ClientRuntime,
    rx_buffer: []u8,
    tx_buffer: []u8,
    receive_timeout: Io.Timeout,

    pub fn start(allocator: std.mem.Allocator, io: Io, options: ClientOptions) Error!Client {
        try validateClientOptions(options);

        const bind_endpoint = try quic_runtime.parseEndpoint(options.bind_literal);
        var socket = try bindUdpSocket(io, bind_endpoint.ip);
        errdefer socket.close(io);

        var runtime = try ClientRuntime.init(allocator, options.target_literal, options.runtime);
        errdefer runtime.deinit();

        const rx_buffer = try allocator.alloc(u8, options.rx_buffer_bytes);
        errdefer allocator.free(rx_buffer);

        const tx_buffer = try allocator.alloc(u8, options.tx_buffer_bytes);
        errdefer allocator.free(tx_buffer);

        return .{
            .allocator = allocator,
            .io = io,
            .socket = socket,
            .runtime = runtime,
            .rx_buffer = rx_buffer,
            .tx_buffer = tx_buffer,
            .receive_timeout = options.receive_timeout,
        };
    }

    pub fn deinit(self: *Client) void {
        self.socket.close(self.io);
        self.runtime.deinit();
        self.allocator.free(self.rx_buffer);
        self.allocator.free(self.tx_buffer);
        self.* = undefined;
    }

    pub fn localAddress(self: Client) Net.IpAddress {
        return self.socket.address;
    }

    pub fn target(self: Client) quic_runtime.ParsedEndpoint {
        return self.runtime.endpoint();
    }

    pub fn recvOne(self: *Client) Error!?Datagram {
        return recvUdpOne(&self.socket, self.io, self.rx_buffer, self.receive_timeout);
    }

    pub fn recvAndFeedOne(self: *Client, now_us: u64) Error!?Datagram {
        const datagram = (try self.recvOne()) orelse return null;
        try self.runtime.feedInbound(.{
            .bytes = datagram.bytes,
            .from = datagram.path_address,
        }, now_us);
        return datagram;
    }

    pub fn drainOne(self: *Client, now_us: u64) Error!?quic_runtime.DrainedDatagram {
        return self.runtime.drainOutbound(self.tx_buffer, now_us);
    }

    pub fn drainAndSendOne(self: *Client, now_us: u64) Error!?SentDatagram {
        const drained = (try self.drainOne(now_us)) orelse return null;
        const to = try drainedTarget(drained);
        try self.socket.send(self.io, &to, self.tx_buffer[0..drained.len]);
        return .{
            .drained = drained,
            .to = to,
        };
    }

    pub fn tick(self: *Client, now_us: u64) Error!void {
        try self.runtime.tick(now_us);
    }

    pub fn nextTimer(self: *Client, now_us: u64) ?Timer {
        return self.runtime.nextTimer(now_us);
    }
};

pub fn validateListenerOptions(options: ListenerOptions) quic_runtime.Error!void {
    _ = try quic_runtime.parseEndpoint(options.bind_literal);
    try validateBuffers(options.rx_buffer_bytes, options.tx_buffer_bytes);
}

pub fn validateClientOptions(options: ClientOptions) quic_runtime.Error!void {
    _ = try quic_runtime.parseEndpoint(options.bind_literal);
    _ = try quic_runtime.parseEndpoint(options.target_literal);
    try validateBuffers(options.rx_buffer_bytes, options.tx_buffer_bytes);
}

fn validateBuffers(rx_buffer_bytes: usize, tx_buffer_bytes: usize) quic_runtime.Error!void {
    if (rx_buffer_bytes < 1200 or tx_buffer_bytes < 1200) return error.MessageTooLarge;
}

fn bindUdpSocket(io: Io, address: Net.IpAddress) Net.IpAddress.BindError!Net.Socket {
    return Net.IpAddress.bind(&address, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
}

fn recvUdpOne(
    socket: *const Net.Socket,
    io: Io,
    buffer: []u8,
    timeout: Io.Timeout,
) Error!?Datagram {
    const message = socket.receiveTimeout(io, buffer, timeout) catch |err| switch (err) {
        error.Timeout => return null,
        else => |e| return e,
    };
    if (message.flags.trunc) return error.MessageTooLarge;
    const path_address = quic_runtime.ipAddressToPathAddress(message.from);
    return .{
        .bytes = message.data,
        .from = message.from,
        .path_address = path_address,
    };
}

fn drainedTarget(drained: quic_runtime.DrainedDatagram) quic_runtime.Error!Net.IpAddress {
    const to = drained.to orelse return error.InvalidState;
    return quic_runtime.pathAddressToIpAddress(to) orelse error.InvalidEndpoint;
}

test "QUIC UDP validates listener endpoints and buffers without sockets" {
    const test_cert_pem = @embedFile("../testdata/test_cert.pem");
    const test_key_pem = @embedFile("../testdata/test_key.pem");

    try validateListenerOptions(.{
        .bind_literal = "udp://127.0.0.1:0",
        .runtime = .{
            .tls_cert_pem = test_cert_pem,
            .tls_key_pem = test_key_pem,
            .transport = .{ .peer_id = "server-a" },
        },
    });

    try std.testing.expectError(error.InvalidEndpoint, validateListenerOptions(.{
        .bind_literal = "localhost:4433",
        .runtime = .{
            .tls_cert_pem = test_cert_pem,
            .tls_key_pem = test_key_pem,
            .transport = .{ .peer_id = "server-a" },
        },
    }));

    try std.testing.expectError(error.MessageTooLarge, validateListenerOptions(.{
        .bind_literal = "127.0.0.1:0",
        .runtime = .{
            .tls_cert_pem = test_cert_pem,
            .tls_key_pem = test_key_pem,
            .transport = .{ .peer_id = "server-a" },
        },
        .rx_buffer_bytes = 1199,
    }));
}

test "QUIC UDP validates client bind and target literals without sockets" {
    try validateClientOptions(.{
        .bind_literal = "127.0.0.1:0",
        .target_literal = "quic://127.0.0.1:4433",
        .runtime = .{
            .server_name = "localhost",
            .transport = .{ .peer_id = "client-a" },
        },
    });

    try std.testing.expectError(error.InvalidEndpoint, validateClientOptions(.{
        .bind_literal = "127.0.0.1:0",
        .target_literal = "",
        .runtime = .{
            .server_name = "localhost",
            .transport = .{ .peer_id = "client-a" },
        },
    }));

    try std.testing.expectError(error.MessageTooLarge, validateClientOptions(.{
        .bind_literal = "127.0.0.1:0",
        .target_literal = "127.0.0.1:4433",
        .runtime = .{
            .server_name = "localhost",
            .transport = .{ .peer_id = "client-a" },
        },
        .tx_buffer_bytes = 1024,
    }));
}

test "QUIC UDP resolves drained runtime targets to std Io addresses" {
    const endpoint = try quic_runtime.parseEndpoint("127.0.0.1:4433");
    const target = try drainedTarget(.{
        .len = 12,
        .to = endpoint.path_address,
    });

    try std.testing.expect(target.eql(&endpoint.ip));
    try std.testing.expectError(error.InvalidState, drainedTarget(.{ .len = 1 }));
}
