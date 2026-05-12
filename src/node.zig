const std = @import("std");
const socket = @import("socket.zig");
const session = @import("session.zig");
const transport = @import("transport/root.zig");

pub const NodeOptions = struct {
    max_sessions: usize = 1024,
};

pub const Event = union(enum) {
    connected: session.SessionId,
    closed: session.SessionId,
    message_dropped: struct {
        session_id: ?session.SessionId = null,
        bytes: usize,
    },
};

pub const InprocRepId = usize;
pub const QuicListenerId = usize;
pub const QuicSessionId = session.SessionId;

pub const InprocRepOptions = struct {
    socket: socket.SocketOptions(.rep) = .{},
    session: ?session.Session = null,
};

pub const RunOnceResult = struct {
    messages: usize = 0,
    events_pending: usize = 0,

    pub fn didWork(self: RunOnceResult) bool {
        return self.messages != 0;
    }
};

pub const InprocRepEndpoint = struct {
    id: InprocRepId,
    network: *transport.inproc.Network,
    address: []u8,
    socket: socket.Socket(.rep),
    session: session.Session,

    fn deinit(self: *InprocRepEndpoint, allocator: std.mem.Allocator) void {
        self.network.unbindPattern(self.address) catch {};
        self.socket.deinit();
        allocator.free(self.address);
        self.* = undefined;
    }
};

pub const QuicListenOptions = struct {
    transport: transport.quic.QuicOptions = .{},
};

pub const QuicSessionOptions = struct {
    role: transport.quic.Role,
    transport: transport.quic.QuicOptions = .{},
    user_data: ?*anyopaque = null,
};

pub const QuicListenerRuntime = struct {
    id: QuicListenerId,
    listener: transport.quic.QuicListener,

    fn deinit(self: *QuicListenerRuntime) void {
        self.listener.deinit();
        self.* = undefined;
    }
};

pub const QuicSessionRuntime = struct {
    session: transport.quic.QuicSession,

    pub fn id(self: QuicSessionRuntime) QuicSessionId {
        return self.session.session.id;
    }

    pub fn appSession(self: *QuicSessionRuntime) *session.Session {
        return &self.session.session;
    }

    fn deinit(self: *QuicSessionRuntime) void {
        self.session.deinit();
        self.* = undefined;
    }
};

pub const Node = struct {
    allocator: std.mem.Allocator,
    options: NodeOptions,
    events: std.ArrayList(Event) = .empty,
    inproc_rep_endpoints: std.ArrayList(*InprocRepEndpoint) = .empty,
    quic_listeners: std.ArrayList(*QuicListenerRuntime) = .empty,
    quic_sessions: std.ArrayList(*QuicSessionRuntime) = .empty,
    now_us: u64 = 0,
    next_session_id: session.SessionId = 1,

    pub fn init(allocator: std.mem.Allocator, options: NodeOptions) !Node {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    pub fn deinit(self: *Node) void {
        for (self.quic_sessions.items) |runtime| {
            runtime.deinit();
            self.allocator.destroy(runtime);
        }
        self.quic_sessions.deinit(self.allocator);
        for (self.quic_listeners.items) |runtime| {
            runtime.deinit();
            self.allocator.destroy(runtime);
        }
        self.quic_listeners.deinit(self.allocator);
        for (self.inproc_rep_endpoints.items) |endpoint| {
            endpoint.deinit(self.allocator);
            self.allocator.destroy(endpoint);
        }
        self.inproc_rep_endpoints.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn listen(self: *Node, kind: transport.Kind, endpoint: transport.Endpoint) !void {
        return switch (kind) {
            .inproc => error.UnsupportedTransport,
            .quic => {
                if (std.meta.activeTag(endpoint) != .quic) return error.InvalidEndpoint;
                _ = try self.listenQuic(endpoint.quic, .{});
            },
        };
    }

    pub fn dial(self: *Node, kind: transport.Kind, endpoint: transport.Endpoint) !session.SessionId {
        _ = self;
        _ = endpoint;
        return switch (kind) {
            .inproc => error.UnsupportedTransport,
            .quic => error.UnsupportedTransport,
        };
    }

    pub fn tick(self: *Node, now_us: u64) !void {
        self.now_us = now_us;
    }

    pub fn listenQuic(self: *Node, endpoint: []const u8, options: QuicListenOptions) !QuicListenerId {
        if (self.quic_listeners.items.len >= self.options.max_sessions) return error.TooManySessions;

        const id = self.quic_listeners.items.len;
        const runtime = try self.allocator.create(QuicListenerRuntime);
        var owns_runtime = true;
        errdefer if (owns_runtime) self.allocator.destroy(runtime);

        runtime.* = .{
            .id = id,
            .listener = try transport.quic.QuicListener.init(self.allocator, endpoint, options.transport),
        };
        errdefer if (owns_runtime) runtime.deinit();

        try self.quic_listeners.append(self.allocator, runtime);
        owns_runtime = false;
        return id;
    }

    pub fn openQuicSession(self: *Node, options: QuicSessionOptions) !*QuicSessionRuntime {
        if (self.quic_sessions.items.len >= self.options.max_sessions) return error.TooManySessions;

        const runtime = try self.allocator.create(QuicSessionRuntime);
        var owns_runtime = true;
        errdefer if (owns_runtime) self.allocator.destroy(runtime);

        runtime.* = .{
            .session = try transport.quic.QuicSession.init(
                self.allocator,
                self.nextSessionId(),
                options.role,
                options.transport,
            ),
        };
        errdefer if (owns_runtime) runtime.deinit();
        runtime.session.session.user_data = options.user_data;

        try self.quic_sessions.append(self.allocator, runtime);
        owns_runtime = false;
        try self.emit(.{ .connected = runtime.id() });
        return runtime;
    }

    pub fn quicSession(self: *Node, id: QuicSessionId) ?*QuicSessionRuntime {
        for (self.quic_sessions.items) |runtime| {
            if (runtime.id() == id) return runtime;
        }
        return null;
    }

    pub fn closeQuicSession(self: *Node, id: QuicSessionId) !void {
        for (self.quic_sessions.items, 0..) |runtime, index| {
            if (runtime.id() != id) continue;

            runtime.session.close();
            try self.emit(.{ .closed = id });
            _ = self.quic_sessions.orderedRemove(index);
            runtime.deinit();
            self.allocator.destroy(runtime);
            return;
        }
        return error.EndpointNotFound;
    }

    pub fn listenInprocRep(
        self: *Node,
        network: *transport.inproc.Network,
        address: []const u8,
        options: InprocRepOptions,
    ) !InprocRepId {
        if (self.inproc_rep_endpoints.items.len >= self.options.max_sessions) return error.TooManySessions;

        const owned_address = try self.allocator.dupe(u8, address);
        var owns_address = true;
        errdefer if (owns_address) self.allocator.free(owned_address);

        const id = self.inproc_rep_endpoints.items.len;
        const sess = options.session orelse self.nextInprocSession();
        const endpoint = try self.allocator.create(InprocRepEndpoint);
        var owns_endpoint = true;
        errdefer if (owns_endpoint) self.allocator.destroy(endpoint);

        endpoint.* = .{
            .id = id,
            .network = network,
            .address = owned_address,
            .socket = try socket.Socket(.rep).init(self.allocator, options.socket),
            .session = sess,
        };
        owns_address = false;
        errdefer if (owns_endpoint) endpoint.deinit(self.allocator);

        try endpoint.socket.listenInproc(network, address);
        try self.inproc_rep_endpoints.append(self.allocator, endpoint);
        owns_endpoint = false;

        var appended = true;
        errdefer if (appended) {
            const removed = self.inproc_rep_endpoints.orderedRemove(id);
            removed.deinit(self.allocator);
            self.allocator.destroy(removed);
        };

        try self.emit(.{ .connected = sess.id });
        appended = false;
        return id;
    }

    pub fn runOnce(self: *Node, dispatcher: anytype) !RunOnceResult {
        for (self.inproc_rep_endpoints.items) |endpoint| {
            if (try dispatcher.dispatchInprocRep(endpoint)) {
                return .{
                    .messages = 1,
                    .events_pending = self.eventCount(),
                };
            }
        }

        return .{ .events_pending = self.eventCount() };
    }

    pub fn poll(self: *Node, out: []Event) !usize {
        const count = @min(out.len, self.events.items.len);
        for (out[0..count], 0..) |*slot, index| {
            slot.* = self.events.items[index];
        }
        for (0..count) |_| {
            _ = self.events.orderedRemove(0);
        }
        return count;
    }

    pub fn nextTimer(self: *const Node) ?u64 {
        _ = self;
        return null;
    }

    pub fn emit(self: *Node, event: Event) !void {
        try self.events.append(self.allocator, event);
    }

    pub fn eventCount(self: *const Node) usize {
        return self.events.items.len;
    }

    fn nextInprocSession(self: *Node) session.Session {
        return .{
            .id = self.nextSessionId(),
            .transport = .inproc,
        };
    }

    fn nextSessionId(self: *Node) session.SessionId {
        const id = self.next_session_id;
        self.next_session_id +%= 1;
        if (self.next_session_id == 0) self.next_session_id = 1;
        return id;
    }
};

test {
    std.testing.refAllDecls(@This());
}

test "Node queues and polls events in FIFO order" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    try n.emit(.{ .connected = 1 });
    try n.emit(.{ .message_dropped = .{ .session_id = 1, .bytes = 32 } });
    try n.emit(.{ .closed = 1 });

    try std.testing.expectEqual(@as(usize, 3), n.eventCount());

    var first: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&first));
    try std.testing.expectEqual(@as(session.SessionId, 1), first[0].connected);
    try std.testing.expectEqual(@as(usize, 2), n.eventCount());

    var rest: [4]Event = undefined;
    try std.testing.expectEqual(@as(usize, 2), try n.poll(&rest));
    try std.testing.expectEqual(@as(?session.SessionId, 1), rest[0].message_dropped.session_id);
    try std.testing.expectEqual(@as(usize, 32), rest[0].message_dropped.bytes);
    try std.testing.expectEqual(@as(session.SessionId, 1), rest[1].closed);
    try std.testing.expectEqual(@as(usize, 0), n.eventCount());
}

test "Node tick records current time and keeps transport placeholders explicit" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    try n.tick(99);
    try std.testing.expectEqual(@as(u64, 99), n.now_us);
    try std.testing.expect(n.nextTimer() == null);
    _ = try n.listenQuic("127.0.0.1:4433", .{});
    try std.testing.expectEqual(@as(usize, 1), n.quic_listeners.items.len);
    try std.testing.expectError(error.UnsupportedTransport, n.dial(.quic, .{ .quic = "127.0.0.1:4433" }));
}

test "Node prepares QUIC listener and session lifecycle without sockets" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const listener_id = try n.listenQuic("127.0.0.1:4433", .{});
    try std.testing.expectEqual(@as(QuicListenerId, 0), listener_id);
    try std.testing.expectEqual(transport.quic.State.listening, n.quic_listeners.items[listener_id].listener.state());

    const runtime = try n.openQuicSession(.{
        .role = .server,
        .transport = .{
            .peer_id = "server-a",
            .datagram_enabled = true,
            .max_message_size = 4096,
        },
    });
    const id = runtime.id();
    try std.testing.expectEqual(@as(session.SessionId, 1), id);
    try std.testing.expectEqual(session.TransportKind.quic, runtime.appSession().transport);
    try std.testing.expect(runtime.appSession().datagram_enabled);
    try std.testing.expectEqual(@as(usize, 4096), runtime.appSession().max_message_size);

    var first: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&first));
    try std.testing.expectEqual(id, first[0].connected);

    try n.closeQuicSession(id);
    try std.testing.expect(n.quicSession(id) == null);

    var rest: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&rest));
    try std.testing.expectEqual(id, rest[0].closed);
}

test "Node runOnce dispatches one inproc rep request through dispatcher" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    _ = try n.listenInprocRep(&network, "users", .{});

    var req = try socket.Socket(.req).init(allocator, .{});
    defer req.deinit();
    try req.dialInproc(&network, "users");

    _ = try req.sendRequest(.{ .subject = "user.get", .body = "42" });

    const Dispatcher = struct {
        fn dispatchInprocRep(_: *@This(), endpoint: *InprocRepEndpoint) !bool {
            var request = (try endpoint.socket.tryRecv()) orelse return false;
            defer request.deinit();

            try endpoint.socket.reply(request, .{
                .subject = "",
                .body = request.message.body,
            });
            return true;
        }
    };

    var dispatcher = Dispatcher{};
    const result = try n.runOnce(&dispatcher);
    try std.testing.expect(result.didWork());

    var reply = try req.recv();
    defer reply.deinit();
    try std.testing.expectEqualStrings("user.get", reply.subject);
    try std.testing.expectEqualStrings("42", reply.body);
}
