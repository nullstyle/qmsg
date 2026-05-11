const std = @import("std");

const message = @import("message.zig");

pub const Message = message.Message;
pub const Header = message.Header;

pub const OnFull = enum {
    block,
    fail,
    drop_oldest,
    drop_newest,
};

pub const QueueOptions = struct {
    max_messages: usize = 1024,
    max_bytes: usize = 16 * 1024 * 1024,
    on_full: OnFull = .block,
};

pub const QueueStats = struct {
    enqueued: usize = 0,
    dropped_newest: usize = 0,
    dropped_oldest: usize = 0,
    queue_full: usize = 0,
    flow_controlled: usize = 0,
    message_too_large: usize = 0,
    high_water_messages: usize = 0,
    high_water_bytes: usize = 0,
};

pub const Error = error{
    QueueFull,
    FlowControlled,
    WouldBlock,
    MessageTooLarge,
};

pub const PushResult = union(enum) {
    enqueued,
    dropped_oldest: usize,
    dropped_newest,

    pub fn didEnqueue(self: PushResult) bool {
        return switch (self) {
            .enqueued, .dropped_oldest => true,
            .dropped_newest => false,
        };
    }

    pub fn droppedCount(self: PushResult) usize {
        return switch (self) {
            .enqueued => 0,
            .dropped_oldest => |count| count,
            .dropped_newest => 1,
        };
    }
};

pub const Queue = struct {
    allocator: std.mem.Allocator,
    options: QueueOptions,
    entries: []Message,
    head: usize = 0,
    count: usize = 0,
    byte_count: usize = 0,
    stats_data: QueueStats = .{},

    pub fn init(allocator: std.mem.Allocator, options: QueueOptions) std.mem.Allocator.Error!Queue {
        return .{
            .allocator = allocator,
            .options = options,
            .entries = try allocator.alloc(Message, options.max_messages),
        };
    }

    pub fn deinit(self: *Queue) void {
        self.clear();
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn clear(self: *Queue) void {
        while (self.popOrNull()) |msg_value| {
            var msg = msg_value;
            deinitOwnedMessage(&msg);
        }
    }

    /// Enqueue an owned message.
    ///
    /// On `.enqueued`, `.dropped_oldest`, and `.dropped_newest`, the queue has
    /// consumed `msg`. On error, the caller still owns `msg`.
    pub fn push(self: *Queue, msg: Message) Error!PushResult {
        const msg_bytes = messageByteSize(msg);

        if (msg_bytes > self.options.max_bytes) {
            self.stats_data.message_too_large += 1;
            return error.MessageTooLarge;
        }

        if (self.canFit(msg_bytes)) {
            self.pushBackAssumeCapacity(msg, msg_bytes);
            self.recordEnqueued();
            return .enqueued;
        }

        switch (self.options.on_full) {
            .block => {
                self.stats_data.flow_controlled += 1;
                return error.FlowControlled;
            },
            .fail => {
                self.stats_data.queue_full += 1;
                return error.QueueFull;
            },
            .drop_newest => {
                var dropped = msg;
                deinitOwnedMessage(&dropped);
                self.stats_data.dropped_newest += 1;
                return .dropped_newest;
            },
            .drop_oldest => {
                var dropped: usize = 0;
                while (self.count > 0 and !self.canFit(msg_bytes)) {
                    var old = self.popFrontAssumeNotEmpty();
                    deinitOwnedMessage(&old);
                    dropped += 1;
                }

                if (!self.canFit(msg_bytes)) {
                    self.stats_data.queue_full += 1;
                    return error.QueueFull;
                }

                self.pushBackAssumeCapacity(msg, msg_bytes);
                self.stats_data.dropped_oldest += dropped;
                self.recordEnqueued();
                return .{ .dropped_oldest = dropped };
            },
        }
    }

    pub fn pop(self: *Queue) Error!Message {
        return self.popOrNull() orelse error.WouldBlock;
    }

    pub fn popOrNull(self: *Queue) ?Message {
        if (self.count == 0) return null;
        return self.popFrontAssumeNotEmpty();
    }

    pub fn len(self: Queue) usize {
        return self.count;
    }

    pub fn bytes(self: Queue) usize {
        return self.byte_count;
    }

    pub fn capacityMessages(self: Queue) usize {
        return self.entries.len;
    }

    pub fn stats(self: Queue) QueueStats {
        return self.stats_data;
    }

    pub fn isEmpty(self: Queue) bool {
        return self.count == 0;
    }

    fn canFit(self: Queue, incoming_bytes: usize) bool {
        if (self.count >= self.entries.len) return false;
        if (incoming_bytes > self.options.max_bytes) return false;
        return self.byte_count <= self.options.max_bytes - incoming_bytes;
    }

    fn pushBackAssumeCapacity(self: *Queue, msg: Message, msg_bytes: usize) void {
        std.debug.assert(self.count < self.entries.len);
        std.debug.assert(msg_bytes <= self.options.max_bytes);
        std.debug.assert(self.byte_count <= self.options.max_bytes - msg_bytes);

        const index = (self.head + self.count) % self.entries.len;
        self.entries[index] = msg;
        self.count += 1;
        self.byte_count += msg_bytes;
    }

    fn popFrontAssumeNotEmpty(self: *Queue) Message {
        std.debug.assert(self.count > 0);

        const msg = self.entries[self.head];
        self.byte_count -= messageByteSize(msg);
        self.head = (self.head + 1) % self.entries.len;
        self.count -= 1;
        if (self.count == 0) self.head = 0;
        return msg;
    }

    fn recordEnqueued(self: *Queue) void {
        self.stats_data.enqueued += 1;
        self.stats_data.high_water_messages = @max(self.stats_data.high_water_messages, self.count);
        self.stats_data.high_water_bytes = @max(self.stats_data.high_water_bytes, self.byte_count);
    }
};

pub fn messageByteSize(msg: Message) usize {
    var total: usize = 0;
    total +|= msg.subject.len;
    total +|= msg.body.len;
    for (msg.headers) |header| {
        total +|= header.name.len;
        total +|= header.value.len;
    }
    return total;
}

pub fn cloneOwnedMessage(allocator: std.mem.Allocator, source: Message) std.mem.Allocator.Error!Message {
    var cloned = Message{
        .allocator = allocator,
        .subject = try allocator.dupe(u8, source.subject),
        .id = source.id,
        .flags = source.flags,
        .deadline_ms = source.deadline_ms,
        .headers = &.{},
        .body = &.{},
    };
    errdefer allocator.free(cloned.subject);

    cloned.body = try allocator.dupe(u8, source.body);
    errdefer allocator.free(cloned.body);

    cloned.headers = try allocator.alloc(Header, source.headers.len);
    errdefer allocator.free(cloned.headers);

    var initialized_headers: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized_headers) : (i += 1) {
            allocator.free(cloned.headers[i].name);
            allocator.free(cloned.headers[i].value);
        }
    }

    for (source.headers, 0..) |header, i| {
        const name = try allocator.dupe(u8, header.name);
        const value = allocator.dupe(u8, header.value) catch |err| {
            allocator.free(name);
            return err;
        };

        cloned.headers[i] = .{
            .name = name,
            .value = value,
        };
        initialized_headers += 1;
    }

    return cloned;
}

pub fn deinitOwnedMessage(msg: *Message) void {
    msg.deinit();
}

test {
    std.testing.refAllDecls(@This());
}

test "messageByteSize counts subject headers and body" {
    const allocator = std.testing.allocator;
    var msg = try testMessage(
        allocator,
        "metrics.cpu",
        "load=0.42",
        &.{
            .{ .name = "content-type", .value = "text/plain" },
            .{ .name = "host", .value = "node-a" },
        },
    );
    defer deinitOwnedMessage(&msg);

    try std.testing.expectEqual(@as(usize, 52), messageByteSize(msg));
}

test "fail policy reports QueueFull and preserves caller ownership" {
    const allocator = std.testing.allocator;
    var q = try Queue.init(allocator, .{
        .max_messages = 1,
        .max_bytes = 1024,
        .on_full = .fail,
    });
    defer q.deinit();

    const first = try testMessage(allocator, "a", "1", &.{});
    try expectPushResult(.enqueued, try q.push(first));

    var second = try testMessage(allocator, "b", "2", &.{});
    try std.testing.expectError(error.QueueFull, q.push(second));
    deinitOwnedMessage(&second);

    try std.testing.expectEqual(@as(usize, 1), q.len());
    try std.testing.expectEqual(@as(usize, 1), q.stats().enqueued);
    try std.testing.expectEqual(@as(usize, 1), q.stats().queue_full);
    try std.testing.expectEqual(@as(usize, 1), q.stats().high_water_messages);
    try std.testing.expectEqual(@as(usize, 2), q.stats().high_water_bytes);
}

test "block policy reports FlowControlled without blocking" {
    const allocator = std.testing.allocator;
    var q = try Queue.init(allocator, .{
        .max_messages = 1,
        .max_bytes = 1024,
        .on_full = .block,
    });
    defer q.deinit();

    const first = try testMessage(allocator, "a", "1", &.{});
    try expectPushResult(.enqueued, try q.push(first));

    var second = try testMessage(allocator, "b", "2", &.{});
    try std.testing.expectError(error.FlowControlled, q.push(second));
    deinitOwnedMessage(&second);

    try std.testing.expectEqual(@as(usize, 1), q.stats().enqueued);
    try std.testing.expectEqual(@as(usize, 1), q.stats().flow_controlled);
}

test "drop_oldest frees old messages and keeps byte accounting exact" {
    const allocator = std.testing.allocator;
    var q = try Queue.init(allocator, .{
        .max_messages = 4,
        .max_bytes = 10,
        .on_full = .drop_oldest,
    });
    defer q.deinit();

    const first = try testMessage(allocator, "a", "1111", &.{});
    try expectPushResult(.enqueued, try q.push(first));
    const second = try testMessage(allocator, "b", "2222", &.{});
    try expectPushResult(.enqueued, try q.push(second));
    try std.testing.expectEqual(@as(usize, 10), q.bytes());

    const third = try testMessage(allocator, "c", "3333", &.{});
    const result = try q.push(third);
    try expectPushResult(.{ .dropped_oldest = 1 }, result);
    try std.testing.expectEqual(@as(usize, 2), q.len());
    try std.testing.expectEqual(@as(usize, 10), q.bytes());
    try std.testing.expectEqual(@as(usize, 3), q.stats().enqueued);
    try std.testing.expectEqual(@as(usize, 1), q.stats().dropped_oldest);
    try std.testing.expectEqual(@as(usize, 2), q.stats().high_water_messages);
    try std.testing.expectEqual(@as(usize, 10), q.stats().high_water_bytes);

    var popped = try q.pop();
    defer deinitOwnedMessage(&popped);
    try std.testing.expectEqualStrings("b", popped.subject);
}

test "drop_newest consumes incoming message and leaves queue unchanged" {
    const allocator = std.testing.allocator;
    var q = try Queue.init(allocator, .{
        .max_messages = 1,
        .max_bytes = 1024,
        .on_full = .drop_newest,
    });
    defer q.deinit();

    const first = try testMessage(allocator, "a", "1", &.{});
    try expectPushResult(.enqueued, try q.push(first));

    const second = try testMessage(allocator, "b", "2", &.{});
    try expectPushResult(.dropped_newest, try q.push(second));
    try std.testing.expectEqual(@as(usize, 1), q.len());
    try std.testing.expectEqual(@as(usize, 1), q.stats().enqueued);
    try std.testing.expectEqual(@as(usize, 1), q.stats().dropped_newest);

    var popped = try q.pop();
    defer deinitOwnedMessage(&popped);
    try std.testing.expectEqualStrings("a", popped.subject);
}

test "oversized messages are rejected without taking ownership" {
    const allocator = std.testing.allocator;
    var q = try Queue.init(allocator, .{
        .max_messages = 8,
        .max_bytes = 3,
        .on_full = .drop_oldest,
    });
    defer q.deinit();

    var msg = try testMessage(allocator, "s", "body", &.{});
    try std.testing.expectError(error.MessageTooLarge, q.push(msg));
    deinitOwnedMessage(&msg);
    try std.testing.expectEqual(@as(usize, 1), q.stats().message_too_large);
}

test "pop on empty queue reports WouldBlock" {
    const allocator = std.testing.allocator;
    var q = try Queue.init(allocator, .{
        .max_messages = 1,
        .max_bytes = 1024,
    });
    defer q.deinit();

    try std.testing.expectError(error.WouldBlock, q.pop());
}

test "zero capacity queue deterministically rejects or drops without byte drift" {
    const allocator = std.testing.allocator;

    var fail_queue = try Queue.init(allocator, .{
        .max_messages = 0,
        .max_bytes = 1024,
        .on_full = .fail,
    });
    defer fail_queue.deinit();

    var first = try testMessage(allocator, "a", "1", &.{});
    try std.testing.expectError(error.QueueFull, fail_queue.push(first));
    deinitOwnedMessage(&first);
    try std.testing.expectEqual(@as(usize, 0), fail_queue.len());
    try std.testing.expectEqual(@as(usize, 0), fail_queue.bytes());
    try std.testing.expectEqual(@as(usize, 1), fail_queue.stats().queue_full);

    var drop_queue = try Queue.init(allocator, .{
        .max_messages = 0,
        .max_bytes = 1024,
        .on_full = .drop_newest,
    });
    defer drop_queue.deinit();

    const second = try testMessage(allocator, "b", "2", &.{});
    try expectPushResult(.dropped_newest, try drop_queue.push(second));
    try std.testing.expectEqual(@as(usize, 0), drop_queue.len());
    try std.testing.expectEqual(@as(usize, 0), drop_queue.bytes());
    try std.testing.expectEqual(@as(usize, 1), drop_queue.stats().dropped_newest);
}

test "low byte capacity can accept empty messages and reject non-empty messages" {
    const allocator = std.testing.allocator;
    var q = try Queue.init(allocator, .{
        .max_messages = 2,
        .max_bytes = 0,
        .on_full = .fail,
    });
    defer q.deinit();

    const empty = try testMessage(allocator, "", "", &.{});
    try expectPushResult(.enqueued, try q.push(empty));
    try std.testing.expectEqual(@as(usize, 1), q.len());
    try std.testing.expectEqual(@as(usize, 0), q.bytes());
    try std.testing.expectEqual(@as(usize, 1), q.stats().high_water_messages);
    try std.testing.expectEqual(@as(usize, 0), q.stats().high_water_bytes);

    var non_empty = try testMessage(allocator, "a", "", &.{});
    try std.testing.expectError(error.MessageTooLarge, q.push(non_empty));
    deinitOwnedMessage(&non_empty);
    try std.testing.expectEqual(@as(usize, 1), q.stats().message_too_large);

    var popped = try q.pop();
    defer deinitOwnedMessage(&popped);
    try std.testing.expectEqualStrings("", popped.subject);
}

fn expectPushResult(expected: PushResult, actual: PushResult) !void {
    switch (expected) {
        .enqueued => try std.testing.expect(actual == .enqueued),
        .dropped_newest => try std.testing.expect(actual == .dropped_newest),
        .dropped_oldest => |expected_count| switch (actual) {
            .dropped_oldest => |actual_count| try std.testing.expectEqual(expected_count, actual_count),
            else => return error.TestExpectedEqual,
        },
    }
}

fn testMessage(
    allocator: std.mem.Allocator,
    subject: []const u8,
    body: []const u8,
    headers: []const Header,
) !Message {
    var msg = Message{
        .allocator = allocator,
        .subject = try allocator.dupe(u8, subject),
        .headers = &.{},
        .body = &.{},
    };
    errdefer allocator.free(msg.subject);

    msg.body = try allocator.dupe(u8, body);
    errdefer allocator.free(msg.body);

    msg.headers = try allocator.alloc(Header, headers.len);
    errdefer allocator.free(msg.headers);

    var initialized_headers: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized_headers) : (i += 1) {
            allocator.free(msg.headers[i].name);
            allocator.free(msg.headers[i].value);
        }
    }

    for (headers, 0..) |header, i| {
        const name = try allocator.dupe(u8, header.name);
        const value = allocator.dupe(u8, header.value) catch |err| {
            allocator.free(name);
            return err;
        };

        msg.headers[i] = .{
            .name = name,
            .value = value,
        };
        initialized_headers += 1;
    }

    return msg;
}
