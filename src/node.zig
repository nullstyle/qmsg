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

    pub fn init(allocator: std.mem.Allocator, options: NodeOptions) !Node {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    pub fn deinit(self: *Node) void {
        _ = self;
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
        _ = self;
        _ = now_us;
    }

    pub fn poll(self: *Node, out: []Event) !usize {
        _ = self;
        _ = out;
        return 0;
    }

    pub fn nextTimer(self: *const Node) ?u64 {
        _ = self;
        return null;
    }
};

test {
    std.testing.refAllDecls(@This());
}
