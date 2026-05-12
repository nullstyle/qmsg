const std = @import("std");

const message = @import("message.zig");
const protocol = @import("protocol/root.zig");
const pushpull = protocol.pushpull;
const pubsub = protocol.pubsub;
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

pub const ErrorReply = struct {
    pub const code_header = "qmsg-error-code";
    pub const message_header = "qmsg-error-message";

    subject: []const u8 = "",
    code: []const u8,
    message: []const u8 = "",
};

pub const SocketError = error{
    InvalidEndpoint,
    InvalidPattern,
    InvalidState,
    InvalidSubject,
    InvalidSubjectFilter,
    MessageTooLarge,
    NoPeer,
    QueueFull,
    WouldBlock,
    FlowControlled,
    DuplicateInflightRequest,
    TooManyInflightRequests,
    DeadlineExceeded,
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

    pub fn tryRecv(self: *PairSocket) !?message.Message {
        return self.core.recvOrNull();
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
        return self.sendRequestAt(outgoing, nowMs());
    }

    pub fn sendRequestAt(self: *ReqSocket, outgoing: message.OutgoingMessage, sent_at_ms: u64) !message.MessageId {
        _ = self.core.expireInflight(sent_at_ms);
        const id = if (outgoing.id == 0) self.core.nextAvailableMessageId() else outgoing.id;
        try self.core.addInflight(id, outgoing.deadline_ms, sent_at_ms);
        errdefer _ = self.core.removeInflight(id);

        try self.core.sendToFirst(.rep, outgoing, .{ .id = id });
        return id;
    }

    pub fn cancelRequest(self: *ReqSocket, id: message.MessageId) bool {
        return self.core.removeInflight(id);
    }

    pub fn expireRequests(self: *ReqSocket, now_ms: u64) usize {
        return self.core.expireInflight(now_ms);
    }

    pub fn inflightCount(self: *ReqSocket) usize {
        return self.core.inflightCount();
    }

    /// Sends a request and immediately attempts to receive its reply.
    ///
    /// This is only appropriate when the selected transport/responder can
    /// produce a reply synchronously. For normal polling or event-loop usage,
    /// call `sendRequest` and then `recv`/`tryRecv` separately.
    pub fn request(self: *ReqSocket, outgoing: message.OutgoingMessage) !message.Message {
        const id = try self.sendRequest(outgoing);
        var completed = false;
        errdefer if (!completed) {
            _ = self.core.removeInflight(id);
        };

        const reply = try self.recv();
        completed = true;
        return reply;
    }

    /// Test/helper convenience for synchronous inproc-style responders.
    ///
    /// `responder` must provide `respond() !void`; it is invoked after the
    /// request is sent and before the reply is polled.
    pub fn requestComplete(self: *ReqSocket, outgoing: message.OutgoingMessage, responder: anytype) !message.Message {
        const id = try self.sendRequest(outgoing);
        var completed = false;
        errdefer if (!completed) {
            _ = self.core.removeInflight(id);
        };

        try responder.respond();

        const reply = try self.recv();
        completed = true;
        return reply;
    }

    pub fn recv(self: *ReqSocket) !message.Message {
        return self.recvAt(nowMs());
    }

    pub fn recvAt(self: *ReqSocket, now_ms: u64) !message.Message {
        var reply = try self.core.recv();
        self.core.completeInflight(reply.id, now_ms) catch |err| {
            reply.deinit();
            return err;
        };
        return reply;
    }

    pub fn tryRecv(self: *ReqSocket) !?message.Message {
        return self.tryRecvAt(nowMs());
    }

    pub fn tryRecvAt(self: *ReqSocket, now_ms: u64) !?message.Message {
        var reply = (try self.core.recvOrNull()) orelse {
            _ = self.core.expireInflight(now_ms);
            return null;
        };
        self.core.completeInflight(reply.id, now_ms) catch |err| {
            reply.deinit();
            return err;
        };
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

    pub fn tryRecv(self: *RepSocket) !?Request {
        const received = (try self.core.recvOrNull()) orelse return null;
        return .{ .message = received };
    }

    pub fn reply(self: *RepSocket, request_to_answer: Request, outgoing: message.OutgoingMessage) !void {
        try self.core.sendToFirst(.req, outgoing, .{
            .id = request_to_answer.message.id,
            .deadline_ms = request_to_answer.message.deadline_ms,
            .subject = if (outgoing.subject.len == 0) request_to_answer.message.subject else null,
        });
    }

    pub fn replyError(self: *RepSocket, request_to_answer: Request, app_error: ErrorReply) !void {
        const headers = [_]message.Header{
            .{ .name = ErrorReply.code_header, .value = app_error.code },
            .{ .name = ErrorReply.message_header, .value = app_error.message },
        };

        try self.reply(request_to_answer, .{
            .subject = app_error.subject,
            .flags = .{ .err = true },
            .headers = &headers,
            .body = app_error.message,
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

    pub fn tryRecv(self: *SubSocket) !?message.Message {
        return self.core.recvOrNull();
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

    /// Sends one work item to a credited puller.
    ///
    /// Push/pull is at-most-once: after a transport accepts a message, qmsg
    /// does not retry it on another puller if that transport later fails.
    pub fn push(self: *PushSocket, outgoing: message.OutgoingMessage) !void {
        try self.core.sendPush(outgoing);
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

    pub fn tryRecv(self: *PullSocket) !?message.Message {
        return self.core.recvOrNull();
    }
};

const MessageOverrides = struct {
    id: ?message.MessageId = null,
    deadline_ms: ?u64 = null,
    subject: ?[]const u8 = null,
};

const InflightRequest = struct {
    id: message.MessageId,
    deadline_ms: ?u64,
    sent_at_ms: u64,

    fn expiresAt(self: InflightRequest) ?u64 {
        const deadline_ms = self.deadline_ms orelse return null;
        return self.sent_at_ms +| deadline_ms;
    }

    fn isExpired(self: InflightRequest, now_ms: u64) bool {
        const expires_at = self.expiresAt() orelse return false;
        return now_ms >= expires_at;
    }
};

fn Core(comptime pattern: Pattern) type {
    return struct {
        const Self = @This();
        const Options = SocketOptions(pattern);

        allocator: std.mem.Allocator,
        options: Options,
        inbox: queue.Queue,
        peers: std.ArrayList(InprocEndpoint) = .empty,
        local_subscriptions: pubsub.SubscriptionSet,
        subscriber_registry: pubsub.Registry,
        inflight: std.ArrayList(InflightRequest) = .empty,
        next_id: message.MessageId = 1,
        next_peer: usize = 0,

        fn init(allocator: std.mem.Allocator, options: Options) !Self {
            if (options.recv_queue.max_messages == 0) return error.InvalidState;
            var inbox = try queue.Queue.init(allocator, options.recv_queue);
            errdefer inbox.deinit();

            return .{
                .allocator = allocator,
                .options = options,
                .inbox = inbox,
                .local_subscriptions = pubsub.SubscriptionSet.init(allocator, options.max_subscriptions),
                .subscriber_registry = pubsub.Registry.init(allocator),
            };
        }

        fn deinit(self: *Self) void {
            self.inbox.deinit();
            self.local_subscriptions.deinit();
            self.subscriber_registry.deinit();
            self.inflight.deinit(self.allocator);
            self.peers.deinit(self.allocator);
            self.* = undefined;
        }

        fn inprocEndpoint(self: *Self) InprocEndpoint {
            return .{
                .pattern = pattern,
                .pubsub_id = Self.pubsubId(self),
                .recv_queue_options = self.options.recv_queue,
                .context = @ptrCast(self),
                .enqueue = Self.enqueue,
                .accepts = Self.accepts,
                .puller_flow = Self.pullerFlow,
                .connect_peer = Self.connectPeer,
                .subscribe_peer = Self.subscribePeer,
                .unsubscribe_peer = Self.unsubscribePeer,
                .sync_subscriptions = Self.syncSubscriptions,
            };
        }

        fn connectInproc(self: *Self, peer: InprocEndpoint) !void {
            if (!pattern.canSendTo(peer.pattern)) return error.InvalidPattern;
            if (self.hasPeer(peer)) return;
            try self.peers.append(self.allocator, peer);
            errdefer _ = self.peers.pop();
            try Self.connectPubSub(self, peer);
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

        fn recvOrNull(self: *Self) !?message.Message {
            return self.inbox.popOrNull();
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

            return error.NoPeer;
        }

        fn sendToAll(self: *Self, expected_peer: Pattern, outgoing: message.OutgoingMessage, overrides: MessageOverrides) !void {
            if (pattern == .@"pub" and expected_peer == .sub) {
                return self.publishToSubscribers(outgoing, overrides);
            }

            try validateOutgoing(outgoing, self.options.max_message_size, overrides.subject);

            for (self.peers.items) |peer| {
                if (peer.pattern != expected_peer) continue;
                const effective_subject = overrides.subject orelse outgoing.subject;
                if (!peer.accepts(peer.context, effective_subject)) continue;

                const msg = try cloneOutgoing(self.allocator, outgoing, overrides);
                try deliver(peer, msg);
            }
        }

        fn publishToSubscribers(self: *Self, outgoing: message.OutgoingMessage, overrides: MessageOverrides) !void {
            try validateOutgoing(outgoing, self.options.max_message_size, overrides.subject);

            const effective_subject = overrides.subject orelse outgoing.subject;
            var first_error: ?anyerror = null;

            for (self.peers.items) |peer| {
                if (peer.pattern != .sub) continue;
                if (!self.subscriber_registry.matches(peer.pubsub_id, effective_subject)) continue;

                const msg = try cloneOutgoing(self.allocator, outgoing, overrides);
                deliver(peer, msg) catch |err| {
                    if (first_error == null) first_error = err;
                    continue;
                };
            }

            if (first_error) |err| return err;
        }

        fn sendToNext(self: *Self, expected_peer: Pattern, outgoing: message.OutgoingMessage, overrides: MessageOverrides) !void {
            try validateOutgoing(outgoing, self.options.max_message_size, overrides.subject);
            if (self.peers.items.len == 0) return error.NoPeer;

            var attempts: usize = 0;
            var last_error: anyerror = error.NoPeer;
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

        fn sendPush(self: *Self, outgoing: message.OutgoingMessage) !void {
            if (pattern != .push) return error.InvalidPattern;

            try validateOutgoing(outgoing, self.options.max_message_size, null);
            if (self.peers.items.len == 0) return error.NoPeer;

            const msg_bytes = outgoingBytes(outgoing, outgoing.subject);
            var scan = pushpull.Scan{};

            var attempts: usize = 0;
            while (attempts < self.peers.items.len) : (attempts += 1) {
                const index = (self.next_peer + attempts) % self.peers.items.len;
                const peer = self.peers.items[index];
                if (peer.pattern != .pull) continue;
                if (!peer.accepts(peer.context, outgoing.subject)) continue;

                const flow = peer.puller_flow(peer.context);
                if (scan.record(flow, msg_bytes) != .ready) continue;

                const msg = try cloneOutgoing(self.allocator, outgoing, .{});
                try deliver(peer, msg);
                self.next_peer = pushpull.nextFairIndex(index, self.peers.items.len);
                return;
            }

            return scan.err();
        }

        fn connectPubSub(self: *Self, peer: InprocEndpoint) !void {
            if (pattern == .@"pub" and peer.pattern == .sub) {
                try self.subscriber_registry.addPeer(peer.pubsub_id, peer.recv_queue_options);
                errdefer _ = self.subscriber_registry.removePeer(peer.pubsub_id);
                try peer.sync_subscriptions(peer.context, self.inprocEndpoint());
                try peer.connect_peer(peer.context, self.inprocEndpoint());
                return;
            }

            if (pattern == .sub and peer.pattern == .@"pub") {
                try self.replaySubscriptions(peer);
            }
        }

        fn replaySubscriptions(self: *Self, publisher: InprocEndpoint) !void {
            if (pattern != .sub) return error.InvalidPattern;

            for (self.local_subscriptions.entries.items) |entry| {
                try publisher.subscribe_peer(
                    publisher.context,
                    Self.pubsubId(self),
                    entry.filter.text,
                    self.options.recv_queue,
                );
            }
        }

        fn subscribe(self: *Self, filter: []const u8) !void {
            if (pattern != .sub) return error.InvalidPattern;

            const added = try self.local_subscriptions.add(filter);
            if (!added) return;

            for (self.peers.items) |peer| {
                if (peer.pattern != .@"pub") continue;
                try peer.subscribe_peer(peer.context, Self.pubsubId(self), filter, self.options.recv_queue);
            }
        }

        fn unsubscribe(self: *Self, filter: []const u8) void {
            if (pattern != .sub) return;
            if (!self.local_subscriptions.remove(filter)) return;

            for (self.peers.items) |peer| {
                if (peer.pattern != .@"pub") continue;
                peer.unsubscribe_peer(peer.context, Self.pubsubId(self), filter);
            }
        }

        fn addInflight(self: *Self, id: message.MessageId, deadline_ms: ?u64, sent_at_ms: u64) !void {
            if (pattern != .req) return error.InvalidPattern;
            if (id == 0) return error.InvalidState;
            _ = self.expireInflight(sent_at_ms);
            if (self.inflight.items.len >= self.options.max_inflight_requests) return error.TooManyInflightRequests;
            for (self.inflight.items) |existing| {
                if (existing.id == id) return error.DuplicateInflightRequest;
            }
            try self.inflight.append(self.allocator, .{
                .id = id,
                .deadline_ms = deadline_ms,
                .sent_at_ms = sent_at_ms,
            });
        }

        fn removeInflight(self: *Self, id: message.MessageId) bool {
            if (pattern != .req) return false;
            for (self.inflight.items, 0..) |existing, index| {
                if (existing.id == id) {
                    _ = self.inflight.orderedRemove(index);
                    return true;
                }
            }
            return false;
        }

        fn completeInflight(self: *Self, id: message.MessageId, now_ms: u64) !void {
            if (pattern != .req) return error.InvalidPattern;
            for (self.inflight.items, 0..) |existing, index| {
                if (existing.id == id) {
                    _ = self.inflight.orderedRemove(index);
                    if (existing.isExpired(now_ms)) return error.DeadlineExceeded;
                    return;
                }
            }
            return error.UnexpectedFrame;
        }

        fn expireInflight(self: *Self, now_ms: u64) usize {
            if (pattern != .req) return 0;

            var expired: usize = 0;
            var index: usize = 0;
            while (index < self.inflight.items.len) {
                if (self.inflight.items[index].isExpired(now_ms)) {
                    _ = self.inflight.orderedRemove(index);
                    expired += 1;
                    continue;
                }
                index += 1;
            }
            return expired;
        }

        fn inflightCount(self: *Self) usize {
            if (pattern != .req) return 0;
            return self.inflight.items.len;
        }

        fn pubsubId(self: *Self) pubsub.PeerId {
            return @intFromPtr(self);
        }

        fn nextMessageId(self: *Self) message.MessageId {
            const id = self.next_id;
            self.next_id +%= 1;
            if (self.next_id == 0) self.next_id = 1;
            return id;
        }

        fn nextAvailableMessageId(self: *Self) message.MessageId {
            var id = self.nextMessageId();
            while (self.hasInflight(id)) {
                id = self.nextMessageId();
            }
            return id;
        }

        fn hasInflight(self: *Self, id: message.MessageId) bool {
            if (pattern != .req) return false;
            for (self.inflight.items) |existing| {
                if (existing.id == id) return true;
            }
            return false;
        }

        fn hasPeer(self: *Self, peer: InprocEndpoint) bool {
            for (self.peers.items) |existing| {
                if (existing.pattern == peer.pattern and existing.context == peer.context) return true;
            }
            return false;
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

        fn pullerFlow(context: *anyopaque) pushpull.PullerFlow {
            const self: *Self = @ptrCast(@alignCast(context));
            return pushpull.PullerFlow.fromQueue(
                self.options.recv_queue,
                self.inbox.len(),
                self.inbox.bytes(),
            );
        }

        fn connectPeer(context: *anyopaque, peer: InprocEndpoint) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            try self.connectInproc(peer);
        }

        fn subscribePeer(context: *anyopaque, peer_id: pubsub.PeerId, filter: []const u8, options: QueueOptions) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (pattern != .@"pub") return error.InvalidPattern;
            _ = try self.subscriber_registry.subscribe(peer_id, filter, options);
        }

        fn unsubscribePeer(context: *anyopaque, peer_id: pubsub.PeerId, filter: []const u8) void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (pattern != .@"pub") return;
            _ = self.subscriber_registry.unsubscribe(peer_id, filter);
        }

        fn syncSubscriptions(context: *anyopaque, publisher: InprocEndpoint) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (pattern != .sub) return;
            try self.replaySubscriptions(publisher);
        }

        fn acceptsSubject(self: *Self, subject: []const u8) bool {
            if (pattern != .sub) return true;
            return self.local_subscriptions.matches(subject);
        }
    };
}

fn nowMs() u64 {
    var timespec: std.posix.timespec = undefined;
    switch (std.posix.errno(std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &timespec))) {
        .SUCCESS => {},
        else => return 0,
    }

    const seconds: u64 = @intCast(@max(timespec.sec, 0));
    const nanos: u64 = @intCast(@max(timespec.nsec, 0));
    return seconds *| std.time.ms_per_s +| nanos / std.time.ns_per_ms;
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

test "tryRecv returns null instead of WouldBlock for receive-capable sockets" {
    const allocator = std.testing.allocator;

    var pair_socket = try Socket(.pair).init(allocator, .{});
    defer pair_socket.deinit();
    try expectNoMessage(try pair_socket.tryRecv());

    var req_socket = try Socket(.req).init(allocator, .{});
    defer req_socket.deinit();
    try expectNoMessage(try req_socket.tryRecv());

    var rep_socket = try Socket(.rep).init(allocator, .{});
    defer rep_socket.deinit();
    try expectNoRequest(try rep_socket.tryRecv());

    var sub_socket = try Socket(.sub).init(allocator, .{});
    defer sub_socket.deinit();
    try expectNoMessage(try sub_socket.tryRecv());

    var pull_socket = try Socket(.pull).init(allocator, .{});
    defer pull_socket.deinit();
    try expectNoMessage(try pull_socket.tryRecv());
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

test "invalid peer patterns and missing peers report socket-level errors" {
    const allocator = std.testing.allocator;

    var pair_socket = try Socket(.pair).init(allocator, .{});
    defer pair_socket.deinit();
    var req_socket = try Socket(.req).init(allocator, .{});
    defer req_socket.deinit();
    var rep_socket = try Socket(.rep).init(allocator, .{});
    defer rep_socket.deinit();

    try std.testing.expectError(error.InvalidPattern, pair_socket.connectInproc(req_socket.inprocEndpoint()));
    try std.testing.expectError(error.InvalidPattern, req_socket.connectInproc(pair_socket.inprocEndpoint()));

    try std.testing.expectError(error.NoPeer, pair_socket.send(.{ .subject = "control.ping" }));
    try std.testing.expectError(error.NoPeer, req_socket.sendRequest(.{ .subject = "user.get", .id = 42 }));

    try req_socket.connectInproc(rep_socket.inprocEndpoint());
    _ = try req_socket.sendRequest(.{ .subject = "user.get", .id = 42 });

    var received = try rep_socket.recv();
    defer received.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 42), received.id());
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

test "req rejects duplicate explicit ids and max inflight overflows" {
    const allocator = std.testing.allocator;

    var req = try Socket(.req).init(allocator, .{});
    defer req.deinit();
    var rep = try Socket(.rep).init(allocator, .{});
    defer rep.deinit();
    try req.connectInproc(rep.inprocEndpoint());

    _ = try req.sendRequest(.{ .subject = "user.get", .id = 7 });
    try std.testing.expectError(error.DuplicateInflightRequest, req.sendRequest(.{ .subject = "user.get", .id = 7 }));

    var duplicate_source = try rep.recv();
    defer duplicate_source.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 7), duplicate_source.id());

    var limited_req = try Socket(.req).init(allocator, .{ .max_inflight_requests = 1 });
    defer limited_req.deinit();
    var limited_rep = try Socket(.rep).init(allocator, .{});
    defer limited_rep.deinit();
    try limited_req.connectInproc(limited_rep.inprocEndpoint());

    _ = try limited_req.sendRequest(.{ .subject = "user.get", .id = 10 });
    try std.testing.expectError(error.TooManyInflightRequests, limited_req.sendRequest(.{ .subject = "user.get", .id = 11 }));

    var limited_source = try limited_rep.recv();
    defer limited_source.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 10), limited_source.id());
}

test "req cleans inflight entries on no peer and duplicate ids do not enqueue" {
    const allocator = std.testing.allocator;

    var req = try Socket(.req).init(allocator, .{});
    defer req.deinit();

    try std.testing.expectError(error.NoPeer, req.sendRequestAt(.{
        .subject = "user.get",
        .id = 7,
        .deadline_ms = 250,
    }, 1_000));
    try std.testing.expectEqual(@as(usize, 0), req.inflightCount());

    var rep = try Socket(.rep).init(allocator, .{});
    defer rep.deinit();
    try req.connectInproc(rep.inprocEndpoint());

    _ = try req.sendRequestAt(.{
        .subject = "user.get",
        .id = 7,
        .deadline_ms = 250,
    }, 1_000);
    try std.testing.expectEqual(@as(usize, 1), req.inflightCount());

    try std.testing.expectError(error.DuplicateInflightRequest, req.sendRequestAt(.{
        .subject = "user.get",
        .id = 7,
        .deadline_ms = 250,
    }, 1_001));
    try std.testing.expectEqual(@as(usize, 1), req.inflightCount());

    var received = try rep.recv();
    defer received.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 7), received.id());
    try expectNoRequest(try rep.tryRecv());
}

test "req deadlines expire inflight state and reject late replies" {
    const allocator = std.testing.allocator;

    var req = try Socket(.req).init(allocator, .{});
    defer req.deinit();
    var rep = try Socket(.rep).init(allocator, .{});
    defer rep.deinit();

    try req.connectInproc(rep.inprocEndpoint());
    try rep.connectInproc(req.inprocEndpoint());

    _ = try req.sendRequestAt(.{
        .subject = "user.get",
        .id = 9,
        .deadline_ms = 50,
    }, 1_000);
    try std.testing.expectEqual(@as(usize, 1), req.inflightCount());
    try std.testing.expectEqual(@as(usize, 0), req.expireRequests(1_049));
    try std.testing.expectEqual(@as(usize, 1), req.inflightCount());

    var expired_request = try rep.recv();
    defer expired_request.deinit();

    try std.testing.expectEqual(@as(usize, 1), req.expireRequests(1_050));
    try std.testing.expectEqual(@as(usize, 0), req.inflightCount());

    try rep.reply(expired_request, .{ .subject = "user.get.ok", .body = "late" });
    try std.testing.expectError(error.UnexpectedFrame, req.recvAt(1_051));

    _ = try req.sendRequestAt(.{
        .subject = "user.get",
        .id = 9,
        .deadline_ms = 50,
    }, 1_060);
    try std.testing.expectEqual(@as(usize, 1), req.inflightCount());
    try std.testing.expect(req.cancelRequest(9));
    try std.testing.expectEqual(@as(usize, 0), req.inflightCount());
    try std.testing.expect(!req.cancelRequest(9));
}

test "req recv reports deadline exceeded when reply arrives too late" {
    const allocator = std.testing.allocator;

    var req = try Socket(.req).init(allocator, .{});
    defer req.deinit();
    var rep = try Socket(.rep).init(allocator, .{});
    defer rep.deinit();

    try req.connectInproc(rep.inprocEndpoint());
    try rep.connectInproc(req.inprocEndpoint());

    _ = try req.sendRequestAt(.{
        .subject = "user.get",
        .id = 11,
        .deadline_ms = 10,
    }, 2_000);

    var request = try rep.recv();
    defer request.deinit();
    try rep.reply(request, .{ .subject = "user.get.ok", .body = "late" });

    try std.testing.expectError(error.DeadlineExceeded, req.recvAt(2_010));
    try std.testing.expectEqual(@as(usize, 0), req.inflightCount());
}

test "req queue pressure rolls back only the rejected inflight request" {
    const allocator = std.testing.allocator;

    var req = try Socket(.req).init(allocator, .{});
    defer req.deinit();
    var rep = try Socket(.rep).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .fail },
    });
    defer rep.deinit();

    try req.connectInproc(rep.inprocEndpoint());
    try rep.connectInproc(req.inprocEndpoint());

    _ = try req.sendRequestAt(.{
        .subject = "user.get",
        .id = 1,
        .deadline_ms = 100,
    }, 3_000);
    try std.testing.expectEqual(@as(usize, 1), req.inflightCount());

    try std.testing.expectError(error.QueueFull, req.sendRequestAt(.{
        .subject = "user.get",
        .id = 2,
        .deadline_ms = 100,
    }, 3_001));
    try std.testing.expectEqual(@as(usize, 1), req.inflightCount());
    try std.testing.expect(!req.cancelRequest(2));

    var first = try rep.recv();
    defer first.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 1), first.id());
    try rep.reply(first, .{ .subject = "user.get.ok", .body = "Ada" });

    var reply = try req.recvAt(3_050);
    defer reply.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 1), reply.id);
    try std.testing.expectEqual(@as(usize, 0), req.inflightCount());

    _ = try req.sendRequestAt(.{
        .subject = "user.get",
        .id = 2,
        .deadline_ms = 100,
    }, 3_051);
    try std.testing.expectEqual(@as(usize, 1), req.inflightCount());
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

    var reply = (try req.tryRecv()) orelse return error.TestExpectedEqual;
    defer reply.deinit();

    try std.testing.expectEqual(id, reply.id);
    try std.testing.expectEqual(@as(?u64, 500), reply.deadline_ms);
    try std.testing.expectEqualStrings("user.result", reply.subject);
    try std.testing.expectEqualStrings("Ada", reply.body);
}

test "rep error replies preserve correlation and use stable error shape" {
    const allocator = std.testing.allocator;

    var req = try Socket(.req).init(allocator, .{});
    defer req.deinit();
    var rep = try Socket(.rep).init(allocator, .{});
    defer rep.deinit();

    try req.connectInproc(rep.inprocEndpoint());
    try rep.connectInproc(req.inprocEndpoint());

    const id = try req.sendRequestAt(.{
        .subject = "user.get",
        .deadline_ms = 250,
        .body = "missing",
    }, 4_000);

    var request = try rep.recv();
    defer request.deinit();
    try rep.replyError(request, .{
        .code = "not_found",
        .message = "user not found",
    });

    var reply = try req.recvAt(4_100);
    defer reply.deinit();

    try std.testing.expectEqual(id, reply.id);
    try std.testing.expect(reply.flags.err);
    try std.testing.expectEqual(@as(?u64, 250), reply.deadline_ms);
    try std.testing.expectEqualStrings("user.get", reply.subject);
    try std.testing.expectEqualStrings("user not found", reply.body);
    try std.testing.expectEqual(@as(usize, 2), reply.headers.len);
    try std.testing.expectEqualStrings(ErrorReply.code_header, reply.headers[0].name);
    try std.testing.expectEqualStrings("not_found", reply.headers[0].value);
    try std.testing.expectEqualStrings(ErrorReply.message_header, reply.headers[1].name);
    try std.testing.expectEqualStrings("user not found", reply.headers[1].value);
}

test "request is immediate-only while requestComplete runs a synchronous responder" {
    const allocator = std.testing.allocator;

    var req = try Socket(.req).init(allocator, .{});
    defer req.deinit();
    var rep = try Socket(.rep).init(allocator, .{});
    defer rep.deinit();
    try req.connectInproc(rep.inprocEndpoint());
    try rep.connectInproc(req.inprocEndpoint());

    try std.testing.expectError(error.WouldBlock, req.request(.{
        .subject = "sync.first",
        .id = 100,
        .deadline_ms = 250,
    }));

    var orphaned_request = try rep.recv();
    defer orphaned_request.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 100), orphaned_request.id());
    try rep.reply(orphaned_request, .{ .subject = "sync.first.ok", .body = "late" });
    try std.testing.expectError(error.UnexpectedFrame, req.recv());

    const Responder = struct {
        rep: *Socket(.rep),

        fn respond(self: *@This()) !void {
            var received = try self.rep.recv();
            defer received.deinit();
            try self.rep.reply(received, .{ .subject = "sync.second.ok", .body = "done" });
        }
    };

    var responder = Responder{ .rep = &rep };
    var reply = try req.requestComplete(.{
        .subject = "sync.second",
        .deadline_ms = 500,
        .body = "go",
    }, &responder);
    defer reply.deinit();

    try std.testing.expect(reply.id != 0);
    try std.testing.expectEqual(@as(?u64, 500), reply.deadline_ms);
    try std.testing.expectEqualStrings("sync.second.ok", reply.subject);
    try std.testing.expectEqualStrings("done", reply.body);
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

    try expectNoMessage(try sub_socket.tryRecv());
    try std.testing.expectError(error.WouldBlock, sub_socket.recv());
}

test "pub sub replays and updates subscriptions at the publisher" {
    const allocator = std.testing.allocator;

    var pub_socket = try Socket(.@"pub").init(allocator, .{});
    defer pub_socket.deinit();
    var sub_socket = try Socket(.sub).init(allocator, .{});
    defer sub_socket.deinit();

    try pub_socket.connectInproc(sub_socket.inprocEndpoint());
    try sub_socket.connectInproc(pub_socket.inprocEndpoint());
    try pub_socket.publish(.{ .subject = "metrics.cpu", .body = "ignored" });
    try expectNoMessage(try sub_socket.tryRecv());

    try sub_socket.subscribe("metrics.*");
    try pub_socket.publish(.{ .subject = "metrics.cpu", .body = "91" });

    var first = try sub_socket.recv();
    defer first.deinit();
    try std.testing.expectEqualStrings("metrics.cpu", first.subject);
    try std.testing.expectEqualStrings("91", first.body);

    sub_socket.unsubscribe("metrics.*");
    try pub_socket.publish(.{ .subject = "metrics.mem", .body = "ignored" });
    try expectNoMessage(try sub_socket.tryRecv());
}

test "pub sub fanout continues past slow consumers in peer order" {
    const allocator = std.testing.allocator;

    var pub_socket = try Socket(.@"pub").init(allocator, .{});
    defer pub_socket.deinit();
    var slow = try Socket(.sub).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .fail },
    });
    defer slow.deinit();
    var fast = try Socket(.sub).init(allocator, .{
        .recv_queue = .{ .max_messages = 4, .max_bytes = 1024, .on_full = .fail },
    });
    defer fast.deinit();
    var other = try Socket(.sub).init(allocator, .{});
    defer other.deinit();

    try slow.subscribe("metrics.*");
    try fast.subscribe("metrics.*");
    try other.subscribe("jobs.*");

    try pub_socket.connectInproc(slow.inprocEndpoint());
    try pub_socket.connectInproc(fast.inprocEndpoint());
    try pub_socket.connectInproc(other.inprocEndpoint());

    try pub_socket.publish(.{ .subject = "metrics.cpu", .body = "first" });
    try std.testing.expectError(error.QueueFull, pub_socket.publish(.{ .subject = "metrics.cpu", .body = "second" }));

    var slow_first = try slow.recv();
    defer slow_first.deinit();
    try std.testing.expectEqualStrings("first", slow_first.body);
    try expectNoMessage(try slow.tryRecv());

    var fast_first = try fast.recv();
    defer fast_first.deinit();
    try std.testing.expectEqualStrings("first", fast_first.body);
    var fast_second = try fast.recv();
    defer fast_second.deinit();
    try std.testing.expectEqualStrings("second", fast_second.body);

    try expectNoMessage(try other.tryRecv());
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

test "push puller credit limits inflight work and replenishes after receive" {
    const allocator = std.testing.allocator;

    var push_socket = try Socket(.push).init(allocator, .{});
    defer push_socket.deinit();
    var pull_socket = try Socket(.pull).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .block },
    });
    defer pull_socket.deinit();

    try push_socket.connectInproc(pull_socket.inprocEndpoint());

    try push_socket.push(.{ .subject = "jobs.resize", .body = "first" });
    try std.testing.expectError(error.FlowControlled, push_socket.push(.{ .subject = "jobs.resize", .body = "second" }));

    var first = try pull_socket.recv();
    defer first.deinit();
    try std.testing.expectEqualStrings("first", first.body);

    try push_socket.push(.{ .subject = "jobs.resize", .body = "second" });
    var second = try pull_socket.recv();
    defer second.deinit();
    try std.testing.expectEqualStrings("second", second.body);
}

test "push skips saturated pullers and resumes fair order" {
    const allocator = std.testing.allocator;

    var push_socket = try Socket(.push).init(allocator, .{});
    defer push_socket.deinit();
    var pull_a = try Socket(.pull).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .block },
    });
    defer pull_a.deinit();
    var pull_b = try Socket(.pull).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .block },
    });
    defer pull_b.deinit();

    try push_socket.connectInproc(pull_a.inprocEndpoint());
    try push_socket.connectInproc(pull_b.inprocEndpoint());

    try push_socket.push(.{ .subject = "jobs.resize", .body = "a1" });
    try push_socket.push(.{ .subject = "jobs.resize", .body = "b1" });
    try std.testing.expectError(error.FlowControlled, push_socket.push(.{ .subject = "jobs.resize", .body = "blocked" }));

    var a1 = try pull_a.recv();
    defer a1.deinit();
    try std.testing.expectEqualStrings("a1", a1.body);

    try push_socket.push(.{ .subject = "jobs.resize", .body = "a2" });

    var b1 = try pull_b.recv();
    defer b1.deinit();
    try std.testing.expectEqualStrings("b1", b1.body);

    var a2 = try pull_a.recv();
    defer a2.deinit();
    try std.testing.expectEqualStrings("a2", a2.body);
}

test "push reports deterministic flow control before fail-full pressure" {
    const allocator = std.testing.allocator;

    var first_push = try Socket(.push).init(allocator, .{});
    defer first_push.deinit();
    var first_fail = try Socket(.pull).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .fail },
    });
    defer first_fail.deinit();
    var first_block = try Socket(.pull).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .block },
    });
    defer first_block.deinit();

    try first_push.connectInproc(first_fail.inprocEndpoint());
    try first_push.connectInproc(first_block.inprocEndpoint());
    try first_push.push(.{ .subject = "jobs.resize", .body = "fail-full" });
    try first_push.push(.{ .subject = "jobs.resize", .body = "block-full" });
    try std.testing.expectError(error.FlowControlled, first_push.push(.{ .subject = "jobs.resize", .body = "pressure" }));

    var second_push = try Socket(.push).init(allocator, .{});
    defer second_push.deinit();
    var second_block = try Socket(.pull).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .block },
    });
    defer second_block.deinit();
    var second_fail = try Socket(.pull).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .fail },
    });
    defer second_fail.deinit();

    try second_push.connectInproc(second_block.inprocEndpoint());
    try second_push.connectInproc(second_fail.inprocEndpoint());
    try second_push.push(.{ .subject = "jobs.resize", .body = "block-full" });
    try second_push.push(.{ .subject = "jobs.resize", .body = "fail-full" });
    try std.testing.expectError(error.FlowControlled, second_push.push(.{ .subject = "jobs.resize", .body = "pressure" }));
}

test "push pull fail-full and drop-newest policies are honored" {
    const allocator = std.testing.allocator;

    var fail_push = try Socket(.push).init(allocator, .{});
    defer fail_push.deinit();
    var fail_pull = try Socket(.pull).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .fail },
    });
    defer fail_pull.deinit();

    try fail_push.connectInproc(fail_pull.inprocEndpoint());
    try fail_push.push(.{ .subject = "jobs.resize", .body = "kept" });
    try std.testing.expectError(error.QueueFull, fail_push.push(.{ .subject = "jobs.resize", .body = "rejected" }));

    var kept = try fail_pull.recv();
    defer kept.deinit();
    try std.testing.expectEqualStrings("kept", kept.body);

    var drop_push = try Socket(.push).init(allocator, .{});
    defer drop_push.deinit();
    var drop_pull = try Socket(.pull).init(allocator, .{
        .recv_queue = .{ .max_messages = 1, .max_bytes = 1024, .on_full = .drop_newest },
    });
    defer drop_pull.deinit();

    try drop_push.connectInproc(drop_pull.inprocEndpoint());
    try drop_push.push(.{ .subject = "jobs.resize", .body = "kept" });
    try drop_push.push(.{ .subject = "jobs.resize", .body = "dropped" });

    var received = try drop_pull.recv();
    defer received.deinit();
    try std.testing.expectEqualStrings("kept", received.body);
    try expectNoMessage(try drop_pull.tryRecv());
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

    var full_sub = try Socket(.sub).init(allocator, .{ .max_subscriptions = 0 });
    defer full_sub.deinit();

    try std.testing.expectError(error.InvalidSubjectFilter, full_sub.subscribe("bad*"));
    try std.testing.expectError(error.QueueFull, full_sub.subscribe("still.valid"));
}

fn expectNoMessage(maybe: ?message.Message) !void {
    var unexpected = maybe orelse return;
    defer unexpected.deinit();
    return error.TestUnexpectedResult;
}

fn expectNoRequest(maybe: ?Request) !void {
    var unexpected = maybe orelse return;
    defer unexpected.deinit();
    return error.TestUnexpectedResult;
}
