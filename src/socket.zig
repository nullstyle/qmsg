const std = @import("std");

const message = @import("message.zig");
const protocol = @import("protocol/root.zig");
const queue = @import("queue.zig");
const subject_mod = @import("subject.zig");
const transport = @import("transport/root.zig");

pub const Pattern = protocol.Pattern;
pub const OnFull = queue.OnFull;
pub const QueueOptions = queue.QueueOptions;
pub const InprocEndpoint = transport.inproc.PatternEndpoint;

pub const Request = struct {
    message: message.Message,

    pub fn id(self: Request) message.MessageId {
        return self.message.id;
    }

    pub fn subject(self: Request) []const u8 {
        return self.message.subject;
    }

    pub fn deadlineMs(self: Request) ?u64 {
        return self.message.deadline_ms;
    }

    pub fn deinit(self: *Request) void {
        self.message.deinit();
        self.* = undefined;
    }
};

pub const SocketError = error{
    InvalidEndpoint,
    InvalidPattern,
    InvalidState,
    InvalidSubject,
    InvalidSubjectFilter,
    MessageTooLarge,
    QueueFull,
    WouldBlock,
    FlowControlled,
    PeerClosed,
    UnexpectedFrame,
    UnsupportedTransport,
};

pub fn SocketOptions(comptime pattern: Pattern) type {
    return struct {
        recv_queue: QueueOptions = defaultRecvQueue(pattern),
        send_queue: QueueOptions = defaultSendQueue(pattern),
        max_message_size: usize = 1024 * 1024,
        max_subscriptions: usize = if (pattern == .sub) 64 else 0,
        max_inflight_requests: usize = if (pattern == .req) 1024 else 0,
    };
}

pub fn Socket(comptime pattern: Pattern) type {
    return switch (pattern) {
        .pair => PairSocket,
        .req => ReqSocket,
        .rep => RepSocket,
        .@"pub" => PubSocket,
        .sub => SubSocket,
        .push => PushSocket,
        .pull => PullSocket,
    };
}

pub const PairSocket = struct {
    core: Core(.pair),

    pub fn init(allocator: std.mem.Allocator, options: SocketOptions(.pair)) !PairSocket {
        return .{ .core = try Core(.pair).init(allocator, options) };
    }

    pub fn deinit(self: *PairSocket) void {
        self.core.deinit();
    }

    pub fn inprocEndpoint(self: *PairSocket) InprocEndpoint {
        return self.core.inprocEndpoint();
    }

    pub fn connectInproc(self: *PairSocket, peer: InprocEndpoint) !void {
        try self.core.connectInproc(peer);
    }

    pub fn listen(self: *PairSocket, endpoint: transport.Endpoint) !void {
        try self.core.listen(endpoint);
    }

    pub fn dial(self: *PairSocket, endpoint: transport.Endpoint) !void {
        try self.core.dial(endpoint);
    }

    pub fn listenInproc(self: *PairSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.listen(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn dialInproc(self: *PairSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.dial(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn send(self: *PairSocket, outgoing: message.OutgoingMessage) !void {
        try self.core.sendToFirst(.pair, outgoing, .{});
    }

    pub fn recv(self: *PairSocket) !message.Message {
        return self.core.recv();
    }
};

pub const ReqSocket = struct {
    core: Core(.req),

    pub fn init(allocator: std.mem.Allocator, options: SocketOptions(.req)) !ReqSocket {
        return .{ .core = try Core(.req).init(allocator, options) };
    }

    pub fn deinit(self: *ReqSocket) void {
        self.core.deinit();
    }

    pub fn inprocEndpoint(self: *ReqSocket) InprocEndpoint {
        return self.core.inprocEndpoint();
    }

    pub fn connectInproc(self: *ReqSocket, peer: InprocEndpoint) !void {
        try self.core.connectInproc(peer);
    }

    pub fn listen(self: *ReqSocket, endpoint: transport.Endpoint) !void {
        try self.core.listen(endpoint);
    }

    pub fn dial(self: *ReqSocket, endpoint: transport.Endpoint) !void {
        try self.core.dial(endpoint);
    }

    pub fn listenInproc(self: *ReqSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.listen(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn dialInproc(self: *ReqSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.dial(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn sendRequest(self: *ReqSocket, outgoing: message.OutgoingMessage) !message.MessageId {
        const id = if (outgoing.id == 0) self.core.nextMessageId() else outgoing.id;
        try self.core.addInflight(id);
        errdefer _ = self.core.removeInflight(id);

        try self.core.sendToFirst(.rep, outgoing, .{ .id = id });
        return id;
    }

    pub fn request(self: *ReqSocket, outgoing: message.OutgoingMessage) !message.Message {
        _ = try self.sendRequest(outgoing);
        return self.recv();
    }

    pub fn recv(self: *ReqSocket) !message.Message {
        var reply = try self.core.recv();
        if (!self.core.removeInflight(reply.id)) {
            reply.deinit();
            return error.UnexpectedFrame;
        }
        return reply;
    }
};

pub const RepSocket = struct {
    core: Core(.rep),

    pub fn init(allocator: std.mem.Allocator, options: SocketOptions(.rep)) !RepSocket {
        return .{ .core = try Core(.rep).init(allocator, options) };
    }

    pub fn deinit(self: *RepSocket) void {
        self.core.deinit();
    }

    pub fn inprocEndpoint(self: *RepSocket) InprocEndpoint {
        return self.core.inprocEndpoint();
    }

    pub fn connectInproc(self: *RepSocket, peer: InprocEndpoint) !void {
        try self.core.connectInproc(peer);
    }

    pub fn listen(self: *RepSocket, endpoint: transport.Endpoint) !void {
        try self.core.listen(endpoint);
    }

    pub fn dial(self: *RepSocket, endpoint: transport.Endpoint) !void {
        try self.core.dial(endpoint);
    }

    pub fn listenInproc(self: *RepSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.listen(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn dialInproc(self: *RepSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.dial(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn recv(self: *RepSocket) !Request {
        return .{ .message = try self.core.recv() };
    }

    pub fn reply(self: *RepSocket, request_to_answer: Request, outgoing: message.OutgoingMessage) !void {
        try self.core.sendToFirst(.req, outgoing, .{
            .id = request_to_answer.message.id,
            .deadline_ms = request_to_answer.message.deadline_ms,
            .subject = if (outgoing.subject.len == 0) request_to_answer.message.subject else null,
        });
    }
};

pub const PubSocket = struct {
    core: Core(.@"pub"),

    pub fn init(allocator: std.mem.Allocator, options: SocketOptions(.@"pub")) !PubSocket {
        return .{ .core = try Core(.@"pub").init(allocator, options) };
    }

    pub fn deinit(self: *PubSocket) void {
        self.core.deinit();
    }

    pub fn inprocEndpoint(self: *PubSocket) InprocEndpoint {
        return self.core.inprocEndpoint();
    }

    pub fn connectInproc(self: *PubSocket, peer: InprocEndpoint) !void {
        try self.core.connectInproc(peer);
    }

    pub fn listen(self: *PubSocket, endpoint: transport.Endpoint) !void {
        try self.core.listen(endpoint);
    }

    pub fn dial(self: *PubSocket, endpoint: transport.Endpoint) !void {
        try self.core.dial(endpoint);
    }

    pub fn listenInproc(self: *PubSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.listen(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn dialInproc(self: *PubSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.dial(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn publish(self: *PubSocket, outgoing: message.OutgoingMessage) !void {
        try self.core.sendToAll(.sub, outgoing, .{});
    }
};

pub const SubSocket = struct {
    core: Core(.sub),

    pub fn init(allocator: std.mem.Allocator, options: SocketOptions(.sub)) !SubSocket {
        return .{ .core = try Core(.sub).init(allocator, options) };
    }

    pub fn deinit(self: *SubSocket) void {
        self.core.deinit();
    }

    pub fn inprocEndpoint(self: *SubSocket) InprocEndpoint {
        return self.core.inprocEndpoint();
    }

    pub fn connectInproc(self: *SubSocket, peer: InprocEndpoint) !void {
        try self.core.connectInproc(peer);
    }

    pub fn listen(self: *SubSocket, endpoint: transport.Endpoint) !void {
        try self.core.listen(endpoint);
    }

    pub fn dial(self: *SubSocket, endpoint: transport.Endpoint) !void {
        try self.core.dial(endpoint);
    }

    pub fn listenInproc(self: *SubSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.listen(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn dialInproc(self: *SubSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.dial(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn subscribe(self: *SubSocket, filter: []const u8) !void {
        try self.core.subscribe(filter);
    }

    pub fn unsubscribe(self: *SubSocket, filter: []const u8) void {
        self.core.unsubscribe(filter);
    }

    pub fn recv(self: *SubSocket) !message.Message {
        return self.core.recv();
    }
};

pub const PushSocket = struct {
    core: Core(.push),

    pub fn init(allocator: std.mem.Allocator, options: SocketOptions(.push)) !PushSocket {
        return .{ .core = try Core(.push).init(allocator, options) };
    }

    pub fn deinit(self: *PushSocket) void {
        self.core.deinit();
    }

    pub fn inprocEndpoint(self: *PushSocket) InprocEndpoint {
        return self.core.inprocEndpoint();
    }

    pub fn connectInproc(self: *PushSocket, peer: InprocEndpoint) !void {
        try self.core.connectInproc(peer);
    }

    pub fn listen(self: *PushSocket, endpoint: transport.Endpoint) !void {
        try self.core.listen(endpoint);
    }

    pub fn dial(self: *PushSocket, endpoint: transport.Endpoint) !void {
        try self.core.dial(endpoint);
    }

    pub fn listenInproc(self: *PushSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.listen(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn dialInproc(self: *PushSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.dial(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn push(self: *PushSocket, outgoing: message.OutgoingMessage) !void {
        try self.core.sendToNext(.pull, outgoing, .{});
    }
};

pub const PullSocket = struct {
    core: Core(.pull),

    pub fn init(allocator: std.mem.Allocator, options: SocketOptions(.pull)) !PullSocket {
        return .{ .core = try Core(.pull).init(allocator, options) };
    }

    pub fn deinit(self: *PullSocket) void {
        self.core.deinit();
    }

    pub fn inprocEndpoint(self: *PullSocket) InprocEndpoint {
        return self.core.inprocEndpoint();
    }

    pub fn connectInproc(self: *PullSocket, peer: InprocEndpoint) !void {
        try self.core.connectInproc(peer);
    }

    pub fn listen(self: *PullSocket, endpoint: transport.Endpoint) !void {
        try self.core.listen(endpoint);
    }

    pub fn dial(self: *PullSocket, endpoint: transport.Endpoint) !void {
        try self.core.dial(endpoint);
    }

    pub fn listenInproc(self: *PullSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.listen(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn dialInproc(self: *PullSocket, network: *transport.inproc.Network, address: []const u8) !void {
        try self.dial(.{ .inproc = .{ .network = network, .address = address } });
    }

    pub fn recv(self: *PullSocket) !message.Message {
        return self.core.recv();
    }
};

const MessageOverrides = struct {
    id: ?message.MessageId = null,
    deadline_ms: ?u64 = null,
    subject: ?[]const u8 = null,
};

const Subscription = struct {
    filter: subject_mod.Filter,
    order: usize,
};

fn Core(comptime pattern: Pattern) type {
    return struct {
        const Self = @This();
        const Options = SocketOptions(pattern);

        allocator: std.mem.Allocator,
        options: Options,
        inbox: queue.Queue,
        peers: std.ArrayList(InprocEndpoint) = .empty,
        subscriptions: std.ArrayList(Subscription) = .empty,
        inflight: std.ArrayList(message.MessageId) = .empty,
        next_id: message.MessageId = 1,
        next_peer: usize = 0,

        fn init(allocator: std.mem.Allocator, options: Options) !Self {
            if (options.recv_queue.max_messages == 0) return error.InvalidState;
            return .{
                .allocator = allocator,
                .options = options,
                .inbox = try queue.Queue.init(allocator, options.recv_queue),
            };
        }

        fn deinit(self: *Self) void {
            self.inbox.deinit();
            for (self.subscriptions.items) |*subscription| {
                subscription.filter.deinit();
            }
            self.subscriptions.deinit(self.allocator);
            self.inflight.deinit(self.allocator);
            self.peers.deinit(self.allocator);
            self.* = undefined;
        }

        fn inprocEndpoint(self: *Self) InprocEndpoint {
            return .{
                .pattern = pattern,
                .context = @ptrCast(self),
                .enqueue = enqueue,
                .accepts = accepts,
                .connect_peer = connectPeer,
            };
        }

        fn connectInproc(self: *Self, peer: InprocEndpoint) !void {
            if (!pattern.canSendTo(peer.pattern)) return error.InvalidPattern;
            try self.peers.append(self.allocator, peer);
        }

        fn listen(self: *Self, endpoint: transport.Endpoint) !void {
            switch (endpoint) {
                .inproc => |inproc| try inproc.network.bindPattern(inproc.address, self.inprocEndpoint()),
                .quic => return error.UnsupportedTransport,
            }
        }

        fn dial(self: *Self, endpoint: transport.Endpoint) !void {
            switch (endpoint) {
                .inproc => |inproc| try inproc.network.dialPattern(inproc.address, self.inprocEndpoint()),
                .quic => return error.UnsupportedTransport,
            }
        }

        fn recv(self: *Self) !message.Message {
            return self.inbox.pop();
        }

        fn sendToFirst(self: *Self, expected_peer: Pattern, outgoing: message.OutgoingMessage, overrides: MessageOverrides) !void {
            try validateOutgoing(outgoing, self.options.max_message_size, overrides.subject);

            for (self.peers.items) |peer| {
                if (peer.pattern != expected_peer) continue;
                const effective_subject = overrides.subject orelse outgoing.subject;
                if (!peer.accepts(peer.context, effective_subject)) continue;

                const msg = try cloneOutgoing(self.allocator, outgoing, overrides);
                try deliver(peer, msg);
                return;
            }

            return error.PeerClosed;
        }

        fn sendToAll(self: *Self, expected_peer: Pattern, outgoing: message.OutgoingMessage, overrides: MessageOverrides) !void {
            try validateOutgoing(outgoing, self.options.max_message_size, overrides.subject);

            for (self.peers.items) |peer| {
                if (peer.pattern != expected_peer) continue;
                const effective_subject = overrides.subject orelse outgoing.subject;
                if (!peer.accepts(peer.context, effective_subject)) continue;

                const msg = try cloneOutgoing(self.allocator, outgoing, overrides);
                try deliver(peer, msg);
            }
        }

        fn sendToNext(self: *Self, expected_peer: Pattern, outgoing: message.OutgoingMessage, overrides: MessageOverrides) !void {
            try validateOutgoing(outgoing, self.options.max_message_size, overrides.subject);
            if (self.peers.items.len == 0) return error.PeerClosed;

            var attempts: usize = 0;
            var last_error: anyerror = error.PeerClosed;
            while (attempts < self.peers.items.len) : (attempts += 1) {
                const index = (self.next_peer + attempts) % self.peers.items.len;
                const peer = self.peers.items[index];
                if (peer.pattern != expected_peer) continue;

                const effective_subject = overrides.subject orelse outgoing.subject;
                if (!peer.accepts(peer.context, effective_subject)) continue;

                const msg = try cloneOutgoing(self.allocator, outgoing, overrides);
                deliver(peer, msg) catch |err| {
                    last_error = err;
                    continue;
                };

                self.next_peer = (index + 1) % self.peers.items.len;
                return;
            }

            return last_error;
        }

        fn subscribe(self: *Self, filter: []const u8) !void {
            if (pattern != .sub) return error.InvalidPattern;
            if (self.subscriptions.items.len >= self.options.max_subscriptions) return error.QueueFull;

            for (self.subscriptions.items) |subscription| {
                if (std.mem.eql(u8, subscription.filter.text, filter)) return;
            }

            var owned = try subject_mod.Filter.init(self.allocator, filter);
            errdefer owned.deinit();

            try self.subscriptions.append(self.allocator, .{
                .filter = owned,
                .order = self.subscriptions.items.len,
            });
        }

        fn unsubscribe(self: *Self, filter: []const u8) void {
            if (pattern != .sub) return;

            var index: usize = 0;
            while (index < self.subscriptions.items.len) : (index += 1) {
                if (!std.mem.eql(u8, self.subscriptions.items[index].filter.text, filter)) continue;
                var subscription = self.subscriptions.orderedRemove(index);
                subscription.filter.deinit();
                return;
            }
        }

        fn addInflight(self: *Self, id: message.MessageId) !void {
            if (pattern != .req) return error.InvalidPattern;
            if (id == 0) return error.InvalidState;
            if (self.inflight.items.len >= self.options.max_inflight_requests) return error.FlowControlled;
            for (self.inflight.items) |existing| {
                if (existing == id) return error.InvalidState;
            }
            try self.inflight.append(self.allocator, id);
        }

        fn removeInflight(self: *Self, id: message.MessageId) bool {
            if (pattern != .req) return false;
            for (self.inflight.items, 0..) |existing, index| {
                if (existing == id) {
                    _ = self.inflight.orderedRemove(index);
                    return true;
                }
            }
            return false;
        }

        fn nextMessageId(self: *Self) message.MessageId {
            const id = self.next_id;
            self.next_id +%= 1;
            if (self.next_id == 0) self.next_id = 1;
            return id;
        }

        fn enqueue(context: *anyopaque, msg: message.Message) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (pattern == .sub and !self.acceptsSubject(msg.subject)) {
                var dropped = msg;
                dropped.deinit();
                return;
            }
            _ = try self.inbox.push(msg);
        }

        fn accepts(context: *anyopaque, subject: []const u8) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            return self.acceptsSubject(subject);
        }

        fn connectPeer(context: *anyopaque, peer: InprocEndpoint) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            try self.connectInproc(peer);
        }

        fn acceptsSubject(self: *Self, subject: []const u8) bool {
            if (pattern != .sub) return true;
            for (self.subscriptions.items) |subscription| {
                if (subscription.filter.matches(subject) catch false) return true;
            }
            return false;
        }
    };
}

fn defaultRecvQueue(comptime pattern: Pattern) QueueOptions {
    return switch (pattern) {
        .@"pub", .push => .{ .max_messages = 1, .max_bytes = 1, .on_full = .drop_newest },
        else => .{},
    };
}

fn defaultSendQueue(comptime pattern: Pattern) QueueOptions {
    return switch (pattern) {
        .@"pub" => .{ .max_messages = 1024, .max_bytes = 16 * 1024 * 1024, .on_full = .drop_oldest },
        else => .{},
    };
}

fn deliver(peer: InprocEndpoint, msg: message.Message) !void {
    var owned = msg;
    peer.enqueue(peer.context, owned) catch |err| {
        owned.deinit();
        return err;
    };
}

fn validateOutgoing(outgoing: message.OutgoingMessage, max_message_size: usize, subject_override: ?[]const u8) !void {
    const effective_subject = subject_override orelse outgoing.subject;
    try subject_mod.validate(effective_subject);

    const size = outgoingBytes(outgoing, effective_subject);
    if (size > max_message_size) return error.MessageTooLarge;
}

fn cloneOutgoing(
    allocator: std.mem.Allocator,
    outgoing: message.OutgoingMessage,
    overrides: MessageOverrides,
) !message.Message {
    const effective_subject = overrides.subject orelse outgoing.subject;
    const deadline_ms = outgoing.deadline_ms orelse overrides.deadline_ms;
    const id = overrides.id orelse outgoing.id;

    return message.Message.init(allocator, .{
        .subject = effective_subject,
        .id = id,
        .flags = outgoing.flags,
        .deadline_ms = deadline_ms,
        .headers = outgoing.headers,
        .body = outgoing.body,
    });
}

pub fn deinitMessage(msg: *message.Message) void {
    msg.deinit();
}

fn outgoingBytes(outgoing: message.OutgoingMessage, effective_subject: []const u8) usize {
    var total = effective_subject.len + outgoing.body.len;
    for (outgoing.headers) |header| {
        total += header.name.len + header.value.len;
    }
    return total;
}

test "pair sends and receives owned messages over explicit inproc endpoints" {
    const allocator = std.testing.allocator;

    var left = try Socket(.pair).init(allocator, .{});
    defer left.deinit();
    var right = try Socket(.pair).init(allocator, .{});
    defer right.deinit();

    try left.connectInproc(right.inprocEndpoint());
    try right.connectInproc(left.inprocEndpoint());

    try left.send(.{ .subject = "control.ping", .body = "hello" });

    var received = try right.recv();
    defer received.deinit();

    try std.testing.expectEqualStrings("control.ping", received.subject);
    try std.testing.expectEqualStrings("hello", received.body);
}

test "sockets can bind and dial through explicit inproc network" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var rep = try Socket(.rep).init(allocator, .{});
    defer rep.deinit();
    var req = try Socket(.req).init(allocator, .{});
    defer req.deinit();

    try rep.listenInproc(&network, "svc.users");
    try req.dialInproc(&network, "svc.users");

    const id = try req.sendRequest(.{ .subject = "user.get", .body = "42" });

    var request = try rep.recv();
    defer request.deinit();
    try rep.reply(request, .{ .subject = "user.ok", .body = "Ada" });

    var reply = try req.recv();
    defer reply.deinit();
    try std.testing.expectEqual(id, reply.id);
    try std.testing.expectEqualStrings("Ada", reply.body);
}

test "bounded receive queue reports backpressure" {
    const allocator = std.testing.allocator;

    var left = try Socket(.pair).init(allocator, .{});
    defer left.deinit();
    var right = try Socket(.pair).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .fail },
    });
    defer right.deinit();

    try left.connectInproc(right.inprocEndpoint());

    try left.send(.{ .subject = "one", .body = "first" });
    try std.testing.expectError(error.QueueFull, left.send(.{ .subject = "two", .body = "second" }));

    var received = try right.recv();
    defer received.deinit();
    try std.testing.expectEqualStrings("one", received.subject);
}

test "req rep preserves correlation id and deadline" {
    const allocator = std.testing.allocator;

    var req = try Socket(.req).init(allocator, .{});
    defer req.deinit();
    var rep = try Socket(.rep).init(allocator, .{});
    defer rep.deinit();

    try req.connectInproc(rep.inprocEndpoint());
    try rep.connectInproc(req.inprocEndpoint());

    const id = try req.sendRequest(.{
        .subject = "user.get",
        .deadline_ms = 500,
        .body = "42",
    });
    try std.testing.expect(id != 0);

    var request = try rep.recv();
    defer request.deinit();

    try std.testing.expectEqual(id, request.id());
    try std.testing.expectEqual(@as(?u64, 500), request.deadlineMs());
    try std.testing.expectEqualStrings("user.get", request.subject());
    try std.testing.expectEqualStrings("42", request.message.body);

    try rep.reply(request, .{ .subject = "user.result", .body = "Ada" });

    var reply = try req.recv();
    defer reply.deinit();

    try std.testing.expectEqual(id, reply.id);
    try std.testing.expectEqual(@as(?u64, 500), reply.deadline_ms);
    try std.testing.expectEqualStrings("user.result", reply.subject);
    try std.testing.expectEqualStrings("Ada", reply.body);
}

test "pub sub delivers only matching subscribed subjects" {
    const allocator = std.testing.allocator;

    var pub_socket = try Socket(.@"pub").init(allocator, .{});
    defer pub_socket.deinit();
    var sub_socket = try Socket(.sub).init(allocator, .{});
    defer sub_socket.deinit();

    try sub_socket.subscribe("metrics.*");
    try sub_socket.subscribe("presence.>");
    try pub_socket.connectInproc(sub_socket.inprocEndpoint());

    try pub_socket.publish(.{ .subject = "metrics.cpu", .body = "90" });
    try pub_socket.publish(.{ .subject = "jobs.image.resize", .body = "ignored" });
    try pub_socket.publish(.{ .subject = "presence.user.123", .body = "online" });

    var first = try sub_socket.recv();
    defer first.deinit();
    try std.testing.expectEqualStrings("metrics.cpu", first.subject);

    var second = try sub_socket.recv();
    defer second.deinit();
    try std.testing.expectEqualStrings("presence.user.123", second.subject);

    try std.testing.expectError(error.WouldBlock, sub_socket.recv());
}

test "push distributes work across pull sockets" {
    const allocator = std.testing.allocator;

    var push_socket = try Socket(.push).init(allocator, .{});
    defer push_socket.deinit();
    var pull_a = try Socket(.pull).init(allocator, .{});
    defer pull_a.deinit();
    var pull_b = try Socket(.pull).init(allocator, .{});
    defer pull_b.deinit();

    try push_socket.connectInproc(pull_a.inprocEndpoint());
    try push_socket.connectInproc(pull_b.inprocEndpoint());

    try push_socket.push(.{ .subject = "jobs.resize", .body = "a" });
    try push_socket.push(.{ .subject = "jobs.resize", .body = "b" });

    var first = try pull_a.recv();
    defer first.deinit();
    var second = try pull_b.recv();
    defer second.deinit();

    try std.testing.expectEqualStrings("a", first.body);
    try std.testing.expectEqualStrings("b", second.body);
}

test "subscription filters validate wildcard placement" {
    const allocator = std.testing.allocator;

    var sub_socket = try Socket(.sub).init(allocator, .{});
    defer sub_socket.deinit();

    try sub_socket.subscribe("metrics.*");
    try sub_socket.subscribe("presence.>");
    try sub_socket.subscribe(">");

    try std.testing.expectError(error.InvalidSubjectFilter, sub_socket.subscribe("metrics*"));
    try std.testing.expectError(error.InvalidSubjectFilter, sub_socket.subscribe("presence.>.extra"));
}
