//! Owned pair/req/rep QUIC sockets with an explicit owner-clock pump.
//! A movable outer handle owns one heap-stable Node. Its canonical event
//! engine is the only receive consumer and request tracker; no Socket inbox
//! or second correlation table is attached to it.
const std = @import("std");
const node = @import("node.zig");
const message = @import("message.zig");
const protocol = @import("protocol/root.zig");
const control = @import("control.zig");
const quic = @import("transport/quic.zig");

pub const Options = struct {
    /// Queue/request/session limits and the caller's I/O implementation.
    /// The facade always selects canonical event delivery and its own inbound
    /// pattern profile, regardless of those fields in this options value.
    node: node.NodeOptions = .{},
    max_listeners: usize = 1,
};

const State = opaque {};
const Owned = struct {
    allocator: std.mem.Allocator,
    node: node.Node,
    max_listeners: usize,
    listeners: usize = 0,
};

pub fn Socket(comptime pattern: protocol.Pattern) type {
    if (pattern != .pair and pattern != .req and pattern != .rep)
        @compileError("owned QUIC sockets support pair, req, and rep");
    return struct {
        const Self = @This();
        state: *State,

        pub fn init(allocator: std.mem.Allocator, options: Options) !Self {
            const owned = try allocator.create(Owned);
            errdefer allocator.destroy(owned);
            var node_options = options.node;
            node_options.delivery = .events;
            node_options.event_format = .canonical;
            node_options.quic_inbound = switch (pattern) {
                .pair => .pair,
                .req => .refuse,
                .rep => .requests,
                else => unreachable,
            };
            owned.* = .{ .allocator = allocator, .node = try node.Node.init(allocator, node_options), .max_listeners = options.max_listeners };
            return .{ .state = @ptrCast(owned) };
        }

        /// Destroy once. Moving this handle is safe; copying it does not
        /// create another owner. Retained reply handles fail after teardown.
        pub fn deinit(self: *Self) void {
            const owned = self.owner();
            const allocator = owned.allocator;
            owned.node.deinit();
            allocator.destroy(owned);
            self.* = undefined;
        }

        pub fn listen(self: Self, address: []const u8, options: node.QuicListenOptions) !node.QuicListenerId {
            const owned = self.owner();
            if (owned.listeners >= owned.max_listeners) return error.TooManyListeners;
            var configured = options;
            configured.transport = try transportOptions(options.transport);
            configured.receive_timeout = @import("transport/quic_udp.zig").default_receive_timeout;
            const id = try owned.node.listenQuic(address, configured);
            owned.listeners += 1;
            return id;
        }

        /// Returns an allocated session before TLS/HELLO readiness. Inspect
        /// sessionStatus while driving pump; connected is not a ready signal.
        pub fn dial(self: Self, address: []const u8, options: node.QuicDialOptions) !node.QuicSessionId {
            var configured = options;
            configured.transport = try transportOptions(options.transport);
            configured.receive_timeout = @import("transport/quic_udp.zig").default_receive_timeout;
            return self.owner().node.dialQuic(address, configured);
        }

        pub fn localAddress(self: Self, listener: node.QuicListenerId) !std.Io.net.IpAddress {
            return self.owner().node.quicListenerAddress(listener);
        }

        /// Nonblocking with default listen/dial options. No clock reads,
        /// sleeps, threads, or hidden drive loop. Poll consumes queued events.
        pub fn pump(self: Self, now_us: u64) !void {
            const owned = self.owner();
            if (now_us < owned.node.now_us) return error.ClockMovedBackwards;
            try owned.node.tick(now_us);
        }

        /// Absolute monotonic microseconds, including request and lifecycle
        /// deadlines. Combine with borrowed UDP readiness in the owner's wait.
        pub fn nextTimer(self: Self) ?u64 {
            return self.owner().node.nextTimer();
        }

        pub fn readableSockets(self: Self, out: []std.Io.net.Socket.Handle) !usize {
            return self.owner().node.readableSockets(out);
        }

        pub fn sessionStatus(self: Self, id: node.QuicSessionId) ?node.SessionStatus {
            return self.owner().node.sessionStatus(id);
        }

        /// The caller owns every returned event and deinits the whole batch.
        /// This is the sole receive surface; raw session inboxes are private.
        pub fn poll(self: Self, out: []node.Event) !usize {
            return self.owner().node.poll(out);
        }

        pub fn request(self: Self, id: node.QuicSessionId, outgoing: message.OutgoingMessage) !node.RequestId {
            if (comptime pattern != .req) @compileError("request requires a req QUIC socket");
            return self.owner().node.request(.{ .quic = id }, outgoing);
        }

        pub fn cancelRequest(self: Self, id: node.RequestId) !bool {
            if (comptime pattern != .req) @compileError("cancelRequest requires a req QUIC socket");
            return self.owner().node.cancelRequest(id);
        }

        pub fn takeOutcome(self: Self, id: node.RequestId) ?node.Event {
            if (comptime pattern != .req) @compileError("takeOutcome requires a req QUIC socket");
            return self.owner().node.takeOutcome(id);
        }

        pub fn reply(self: Self, handle: message.ReplyHandle, outgoing: message.OutgoingMessage) !void {
            if (comptime pattern != .rep) @compileError("reply requires a rep QUIC socket");
            try self.owner().node.reply(handle, outgoing);
        }

        pub fn send(self: Self, id: node.QuicSessionId, outgoing: message.OutgoingMessage) !void {
            if (comptime pattern != .pair) @compileError("send requires a pair QUIC socket");
            try self.owner().node.sendQuic(id, outgoing);
        }

        pub fn closeSession(self: Self, id: node.QuicSessionId) !void {
            try self.owner().node.closeQuicSession(id);
        }

        pub fn goaway(self: Self, id: node.QuicSessionId, code: u64, reason: []const u8, now_us: u64, timeout_us: u64) !void {
            const owned = self.owner();
            if (now_us < owned.node.now_us) return error.ClockMovedBackwards;
            try owned.node.goawayQuicSession(id, code, reason, now_us, timeout_us);
            owned.node.now_us = now_us;
        }

        pub fn stats(self: Self) node.Stats {
            return self.owner().node.stats();
        }

        fn owner(self: Self) *Owned {
            return @ptrCast(@alignCast(self.state));
        }

        fn transportOptions(options: quic.QuicOptions) !quic.QuicOptions {
            var configured = options;
            const selected = switch (pattern) {
                .pair => control.PatternBits.pair,
                .req => control.PatternBits.req,
                .rep => control.PatternBits.rep,
                else => unreachable,
            };
            const counterpart = switch (pattern) {
                .pair => control.PatternBits.pair,
                .req => control.PatternBits.rep,
                .rep => control.PatternBits.req,
                else => unreachable,
            };
            if (options.required_peer_patterns & ~counterpart != 0) return error.InvalidPattern;
            if (options.datagram_enabled) return error.UnsupportedTransport;
            configured.supported_patterns = selected;
            configured.required_peer_patterns |= counterpart;
            return configured;
        }
    };
}

test "owned QUIC socket initialization selects one canonical owner without I/O" {
    var req = try Socket(.req).init(std.testing.allocator, .{ .node = .{ .delivery = .legacy, .event_format = .legacy_transport } });
    // Moving a handle does not move the Node or change interior pointers.
    var moved = req;
    req = undefined;
    defer moved.deinit();
    try std.testing.expectEqual(.events, moved.owner().node.options.delivery);
    try std.testing.expectEqual(.canonical, moved.owner().node.options.event_format);
    try std.testing.expectEqual(.refuse, moved.owner().node.options.quic_inbound);
    try moved.pump(10_000);
    try std.testing.expectError(error.ClockMovedBackwards, moved.pump(9_000));
    try std.testing.expect(moved.nextTimer() == null);
    var no_sockets: [0]std.Io.net.Socket.Handle = .{};
    try std.testing.expectEqual(@as(usize, 0), try moved.readableSockets(&no_sockets));
}

test {
    _ = @import("quic_socket_test.zig");
}
