const std = @import("std");
const subject_mod = @import("subject.zig");

pub const MessageId = u64;

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Flags = packed struct(u8) {
    final: bool = true,
    no_reply: bool = false,
    err: bool = false,
    unreliable: bool = false,
    _reserved: u4 = 0,

    pub fn bits(self: Flags) u8 {
        return @as(u8, @bitCast(self));
    }

    pub fn fromBits(bits_value: u64) !Flags {
        if (bits_value > std.math.maxInt(u8)) return error.InvalidMessage;

        const bits_u8: u8 = @intCast(bits_value);
        if ((bits_u8 & 0xf0) != 0) return error.InvalidMessage;

        return @as(Flags, @bitCast(bits_u8));
    }
};

pub const OutgoingMessage = struct {
    subject: []const u8,
    id: MessageId = 0,
    flags: Flags = .{},
    deadline_ms: ?u64 = null,
    headers: []const Header = &.{},
    body: []const u8 = &.{},
};

/// Local return capability. Never serialized. Retain a copy for a deferred reply;
/// invalidation makes replies to closed/replaced endpoints fail safely.
pub const ReplyHandle = struct {
    state: *State,

    pub const Target = struct {
        allocator: std.mem.Allocator,
        refs: usize = 1,
        context: ?*anyopaque,
        send: *const fn (*anyopaque, u64, OutgoingMessage) anyerror!void,

        pub fn create(allocator: std.mem.Allocator, context: *anyopaque, send: *const fn (*anyopaque, u64, OutgoingMessage) anyerror!void) !*Target {
            const target = try allocator.create(Target);
            target.* = .{ .allocator = allocator, .context = context, .send = send };
            return target;
        }
        pub fn invalidate(self: *Target) void {
            self.context = null;
        }
        pub fn release(self: *Target) void {
            self.refs -= 1;
            if (self.refs == 0) self.allocator.destroy(self);
        }
    };
    const State = struct {
        target: *Target,
        refs: usize = 1,
        route: u64,
        id: MessageId,
        deadline_ms: ?u64,
        subject: []u8,
        completed: bool = false,
    };

    pub fn init(target: *Target, route: u64, request: OutgoingMessage) !ReplyHandle {
        const state = try target.allocator.create(State);
        errdefer target.allocator.destroy(state);
        const subject = try target.allocator.dupe(u8, request.subject);
        target.refs += 1;
        state.* = .{ .target = target, .route = route, .id = request.id, .deadline_ms = request.deadline_ms, .subject = subject };
        return .{ .state = state };
    }
    pub fn retain(self: ReplyHandle) ReplyHandle {
        self.state.refs += 1;
        return self;
    }
    pub fn deinit(self: *ReplyHandle) void {
        const state = self.state;
        state.refs -= 1;
        if (state.refs == 0) {
            const target = state.target;
            target.allocator.free(state.subject);
            target.allocator.destroy(state);
            target.release();
        }
        self.* = undefined;
    }
    pub fn reply(self: ReplyHandle, outgoing: OutgoingMessage) !void {
        const state = self.state;
        const context = state.target.context orelse return error.EndpointClosed;
        if (state.completed) return error.InvalidState;
        var effective = outgoing;
        effective.id = state.id;
        if (effective.subject.len == 0) effective.subject = state.subject;
        if (effective.deadline_ms == null) effective.deadline_ms = state.deadline_ms;
        try state.target.send(context, state.route, effective);
        if (effective.flags.final) state.completed = true;
    }
};

pub const Message = struct {
    allocator: std.mem.Allocator,
    reply_handle: ?ReplyHandle = null,
    /// Local inproc request generation; never serialized or copied to an outgoing frame.
    local_correlation: u64 = 0,
    subject: []u8,
    id: MessageId = 0,
    flags: Flags = .{},
    deadline_ms: ?u64 = null,
    headers: []Header = &.{},
    body: []u8 = &.{},

    pub fn init(allocator: std.mem.Allocator, out: OutgoingMessage) !Message {
        try subject_mod.validate(out.subject);

        const subject_copy = try allocator.dupe(u8, out.subject);
        errdefer allocator.free(subject_copy);

        const body_copy = try allocator.dupe(u8, out.body);
        errdefer allocator.free(body_copy);

        const headers_copy = try allocator.alloc(Header, out.headers.len);
        errdefer allocator.free(headers_copy);

        var headers_initialized: usize = 0;
        errdefer {
            for (headers_copy[0..headers_initialized]) |header| {
                freeConst(allocator, header.name);
                freeConst(allocator, header.value);
            }
        }

        for (out.headers, 0..) |header, index| {
            const name_copy = try allocator.dupe(u8, header.name);
            const value_copy = allocator.dupe(u8, header.value) catch |err| {
                allocator.free(name_copy);
                return err;
            };

            headers_copy[index] = .{
                .name = name_copy,
                .value = value_copy,
            };
            headers_initialized += 1;
        }

        return .{
            .allocator = allocator,
            .subject = subject_copy,
            .id = out.id,
            .flags = out.flags,
            .deadline_ms = out.deadline_ms,
            .headers = headers_copy,
            .body = body_copy,
        };
    }

    pub fn clone(self: Message, allocator: std.mem.Allocator) !Message {
        var copy = try init(allocator, .{
            .subject = self.subject,
            .id = self.id,
            .flags = self.flags,
            .deadline_ms = self.deadline_ms,
            .headers = self.headers,
            .body = self.body,
        });
        copy.local_correlation = self.local_correlation;
        if (self.reply_handle) |handle| copy.reply_handle = handle.retain();
        return copy;
    }

    pub fn outgoing(self: Message) OutgoingMessage {
        return .{
            .subject = self.subject,
            .id = self.id,
            .flags = self.flags,
            .deadline_ms = self.deadline_ms,
            .headers = self.headers,
            .body = self.body,
        };
    }

    pub fn deinit(self: *Message) void {
        if (self.reply_handle) |*handle| handle.deinit();
        for (self.headers) |header| {
            freeConst(self.allocator, header.name);
            freeConst(self.allocator, header.value);
        }
        self.allocator.free(self.headers);
        self.allocator.free(self.body);
        self.allocator.free(self.subject);
        self.* = undefined;
    }
};

fn freeConst(allocator: std.mem.Allocator, bytes: []const u8) void {
    allocator.free(@constCast(bytes));
}

test "Message.init owns subject body and headers" {
    const allocator = std.testing.allocator;

    var subject_buf = try allocator.dupe(u8, "user.get");
    defer allocator.free(subject_buf);
    var body_buf = try allocator.dupe(u8, "before");
    defer allocator.free(body_buf);
    var header_name = try allocator.dupe(u8, "content-type");
    defer allocator.free(header_name);
    var header_value = try allocator.dupe(u8, "text/plain");
    defer allocator.free(header_value);

    var msg = try Message.init(allocator, .{
        .subject = subject_buf,
        .id = 42,
        .headers = &.{.{ .name = header_name, .value = header_value }},
        .body = body_buf,
    });
    defer msg.deinit();

    subject_buf[0] = 'X';
    body_buf[0] = 'X';
    header_name[0] = 'X';
    header_value[0] = 'X';

    try std.testing.expectEqualStrings("user.get", msg.subject);
    try std.testing.expectEqual(@as(MessageId, 42), msg.id);
    try std.testing.expectEqualStrings("before", msg.body);
    try std.testing.expectEqualStrings("content-type", msg.headers[0].name);
    try std.testing.expectEqualStrings("text/plain", msg.headers[0].value);
}

test "Message.clone creates independent storage" {
    const allocator = std.testing.allocator;

    var original = try Message.init(allocator, .{
        .subject = "jobs.image.resize",
        .headers = &.{.{ .name = "attempt", .value = "1" }},
        .body = "payload",
    });
    defer original.deinit();

    var cloned = try original.clone(allocator);
    defer cloned.deinit();

    original.subject[0] = 'X';
    original.body[0] = 'X';

    try std.testing.expectEqualStrings("jobs.image.resize", cloned.subject);
    try std.testing.expectEqualStrings("payload", cloned.body);
    try std.testing.expectEqualStrings("attempt", cloned.headers[0].name);
}

test "Message.init validates subject" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidSubject, Message.init(allocator, .{
        .subject = "metrics..cpu",
    }));
}

test "Flags bits reject reserved values" {
    const flags = try Flags.fromBits(0b0000_1011);
    try std.testing.expect(flags.final);
    try std.testing.expect(flags.no_reply);
    try std.testing.expect(!flags.err);
    try std.testing.expect(flags.unreliable);
    try std.testing.expectError(error.InvalidMessage, Flags.fromBits(0b0001_0000));
}
