const std = @import("std");
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

pub const Node = struct {
    allocator: std.mem.Allocator,
    options: NodeOptions,
    events: std.ArrayList(Event) = .empty,
    now_us: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, options: NodeOptions) !Node {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    pub fn deinit(self: *Node) void {
        self.events.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn listen(self: *Node, kind: transport.Kind, endpoint: transport.Endpoint) !void {
        _ = self;
        _ = endpoint;
        return switch (kind) {
            .inproc => error.UnsupportedTransport,
            .quic => error.UnsupportedTransport,
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
    try std.testing.expectError(error.UnsupportedTransport, n.listen(.quic, .{ .quic = "127.0.0.1:4433" }));
    try std.testing.expectError(error.UnsupportedTransport, n.dial(.quic, .{ .quic = "127.0.0.1:4433" }));
}
