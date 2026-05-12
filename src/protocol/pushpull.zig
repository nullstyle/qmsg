const std = @import("std");

const control = @import("../control.zig");
const queue = @import("../queue.zig");
const subject_mod = @import("../subject.zig");

pub const Error = error{
    FlowControlled,
    MessageTooLarge,
    NoPeer,
    QueueFull,
};

pub const PeerId = usize;

pub const Credit = struct {
    messages: usize = 0,
    bytes: usize = 0,

    pub fn canSpend(self: Credit, msg_bytes: usize) bool {
        return self.messages > 0 and msg_bytes <= self.bytes;
    }

    pub fn spend(self: *Credit, msg_bytes: usize) Error!void {
        if (!self.canSpend(msg_bytes)) return error.FlowControlled;
        self.messages -= 1;
        self.bytes -= msg_bytes;
    }
};

pub const CreditApplyResult = enum {
    updated,
    removed,
};

pub fn emitCredit(sink: control.Sink, subject_filter: []const u8, credit: Credit) !void {
    const frame: control.Frame = .{ .credit = .{
        .subject_filter = subject_filter,
        .messages = try toU64(credit.messages),
        .bytes = try toU64(credit.bytes),
    } };
    try validateEmitFrame(frame);
    try sink.emitFrame(frame);
}

pub const CreditLedger = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    next_order: usize = 0,

    const Entry = struct {
        peer_id: PeerId,
        filter: subject_mod.Filter,
        credit: Credit,
        order: usize,

        fn deinit(self: *Entry) void {
            self.filter.deinit();
            self.* = undefined;
        }
    };

    pub fn init(allocator: std.mem.Allocator) CreditLedger {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *CreditLedger) void {
        for (self.entries.items) |*entry| {
            entry.deinit();
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn applyControlFrame(self: *CreditLedger, peer_id: PeerId, frame: control.Frame) !CreditApplyResult {
        return switch (frame) {
            .credit => |credit_frame| try self.applyCredit(peer_id, credit_frame),
            else => error.UnexpectedFrame,
        };
    }

    pub fn applyCredit(self: *CreditLedger, peer_id: PeerId, credit_frame: control.Credit) !CreditApplyResult {
        const credit = Credit{
            .messages = try toUsize(credit_frame.messages),
            .bytes = try toUsize(credit_frame.bytes),
        };

        for (self.entries.items, 0..) |*entry, index| {
            if (entry.peer_id != peer_id) continue;
            if (!std.mem.eql(u8, entry.filter.text, credit_frame.subject_filter)) continue;

            if (credit.messages == 0 and credit.bytes == 0) {
                var removed = self.entries.orderedRemove(index);
                removed.deinit();
                return .removed;
            }

            entry.credit = credit;
            return .updated;
        }

        var filter = try subject_mod.Filter.init(self.allocator, credit_frame.subject_filter);
        errdefer filter.deinit();

        if (credit.messages == 0 and credit.bytes == 0) return .removed;

        try self.entries.append(self.allocator, .{
            .peer_id = peer_id,
            .filter = filter,
            .credit = credit,
            .order = self.next_order,
        });
        self.next_order += 1;
        return .updated;
    }

    pub fn spend(self: *CreditLedger, peer_id: PeerId, subject: []const u8, msg_bytes: usize) Error!void {
        const index = try self.bestMatch(peer_id, subject);
        const entry = &self.entries.items[index];
        try entry.credit.spend(msg_bytes);
    }

    pub fn creditFor(self: CreditLedger, peer_id: PeerId, subject_filter: []const u8) Credit {
        for (self.entries.items) |entry| {
            if (entry.peer_id == peer_id and std.mem.eql(u8, entry.filter.text, subject_filter)) {
                return entry.credit;
            }
        }
        return .{};
    }

    pub fn removePeer(self: *CreditLedger, peer_id: PeerId) usize {
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (self.entries.items[index].peer_id != peer_id) {
                index += 1;
                continue;
            }

            var entry = self.entries.orderedRemove(index);
            entry.deinit();
            removed += 1;
        }
        return removed;
    }

    pub fn len(self: CreditLedger) usize {
        return self.entries.items.len;
    }

    fn bestMatch(self: CreditLedger, peer_id: PeerId, subject: []const u8) Error!usize {
        subject_mod.validate(subject) catch return error.NoPeer;

        var best_index: ?usize = null;
        var saw_peer = false;
        for (self.entries.items, 0..) |entry, index| {
            if (entry.peer_id != peer_id) continue;
            saw_peer = true;
            if (!(entry.filter.matches(subject) catch false)) continue;

            if (best_index) |best| {
                if (isHigherPriority(entry, self.entries.items[best])) {
                    best_index = index;
                }
            } else {
                best_index = index;
            }
        }

        return best_index orelse if (saw_peer) error.FlowControlled else error.NoPeer;
    }

    fn isHigherPriority(candidate: Entry, incumbent: Entry) bool {
        if (candidate.filter.exact != incumbent.filter.exact) {
            return candidate.filter.exact;
        }
        if (candidate.filter.segment_count != incumbent.filter.segment_count) {
            return candidate.filter.segment_count > incumbent.filter.segment_count;
        }
        if (candidate.filter.literal_segments != incumbent.filter.literal_segments) {
            return candidate.filter.literal_segments > incumbent.filter.literal_segments;
        }
        if (candidate.filter.has_glob != incumbent.filter.has_glob) {
            return !candidate.filter.has_glob;
        }
        return candidate.order < incumbent.order;
    }
};

pub const PullerFlow = struct {
    credit: Credit,
    queue: queue.QueueOptions,

    pub fn fromQueue(options: queue.QueueOptions, queued_messages: usize, queued_bytes: usize) PullerFlow {
        const available_messages = options.max_messages -| queued_messages;
        const available_bytes = options.max_bytes -| queued_bytes;
        return .{
            .credit = .{
                .messages = available_messages,
                .bytes = available_bytes,
            },
            .queue = options,
        };
    }

    pub fn candidateState(self: PullerFlow, msg_bytes: usize) CandidateState {
        if (msg_bytes > self.queue.max_bytes) return .message_too_large;
        if (self.credit.canSpend(msg_bytes)) return .ready;

        return switch (self.queue.on_full) {
            .block => .flow_controlled,
            .fail => .queue_full,
            .drop_newest => .ready,
            .drop_oldest => if (self.queue.max_messages == 0) .queue_full else .ready,
        };
    }
};

pub const CandidateState = enum {
    ready,
    flow_controlled,
    queue_full,
    message_too_large,
};

pub const Scan = struct {
    candidates: usize = 0,
    flow_controlled: usize = 0,
    queue_full: usize = 0,
    message_too_large: usize = 0,

    pub fn record(self: *Scan, flow: PullerFlow, msg_bytes: usize) CandidateState {
        const state = flow.candidateState(msg_bytes);
        self.candidates += 1;
        switch (state) {
            .ready => {},
            .flow_controlled => self.flow_controlled += 1,
            .queue_full => self.queue_full += 1,
            .message_too_large => self.message_too_large += 1,
        }
        return state;
    }

    pub fn err(self: Scan) Error {
        if (self.candidates == 0) return error.NoPeer;
        if (self.message_too_large == self.candidates) return error.MessageTooLarge;
        if (self.flow_controlled > 0) return error.FlowControlled;
        if (self.queue_full > 0) return error.QueueFull;
        if (self.message_too_large > 0) return error.MessageTooLarge;
        return error.NoPeer;
    }
};

pub fn nextFairIndex(selected: usize, peer_count: usize) usize {
    if (peer_count == 0) return 0;
    return (selected + 1) % peer_count;
}

fn toU64(value: usize) !u64 {
    return std.math.cast(u64, value) orelse error.InvalidControlFrame;
}

fn toUsize(value: u64) !usize {
    return std.math.cast(usize, value) orelse error.InvalidControlFrame;
}

fn validateEmitFrame(frame: control.Frame) !void {
    _ = try control.encodedSize(frame, .{
        .max_frame_size = std.math.maxInt(usize),
        .max_filter_len = std.math.maxInt(usize),
    });
}

const RecordingSink = struct {
    allocator: std.mem.Allocator,
    frames: std.ArrayList(control.Frame) = .empty,

    fn init(allocator: std.mem.Allocator) RecordingSink {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *RecordingSink) void {
        for (self.frames.items) |*frame| {
            frame.deinit();
        }
        self.frames.deinit(self.allocator);
        self.* = undefined;
    }

    fn sink(self: *RecordingSink) control.Sink {
        return .{
            .context = @ptrCast(self),
            .emit = emit,
        };
    }

    fn emit(context: *anyopaque, frame: control.Frame) anyerror!void {
        const self: *RecordingSink = @ptrCast(@alignCast(context));
        try self.frames.append(self.allocator, try cloneFrame(self.allocator, frame));
    }

    fn cloneFrame(allocator: std.mem.Allocator, frame: control.Frame) !control.Frame {
        return switch (frame) {
            .credit => |credit| .{ .credit = .{
                .allocator = allocator,
                .subject_filter = try allocator.dupe(u8, credit.subject_filter),
                .messages = credit.messages,
                .bytes = credit.bytes,
            } },
            else => error.UnexpectedFrame,
        };
    }
};

test "puller flow exposes remaining message and byte credit" {
    const flow = PullerFlow.fromQueue(.{
        .max_messages = 4,
        .max_bytes = 16,
        .on_full = .block,
    }, 2, 10);

    try std.testing.expectEqual(@as(usize, 2), flow.credit.messages);
    try std.testing.expectEqual(@as(usize, 6), flow.credit.bytes);
    try std.testing.expect(flow.credit.canSpend(6));
    try std.testing.expect(!flow.credit.canSpend(7));
}

test "credit emission writes a borrowed CREDIT control frame" {
    const allocator = std.testing.allocator;

    var sink = RecordingSink.init(allocator);
    defer sink.deinit();

    try emitCredit(sink.sink(), "jobs.*", .{ .messages = 4, .bytes = 1024 });

    try std.testing.expectEqual(@as(usize, 1), sink.frames.items.len);
    try std.testing.expectEqual(control.Tag.credit, std.meta.activeTag(sink.frames.items[0]));
    try std.testing.expectEqualStrings("jobs.*", sink.frames.items[0].credit.subject_filter);
    try std.testing.expectEqual(@as(u64, 4), sink.frames.items[0].credit.messages);
    try std.testing.expectEqual(@as(u64, 1024), sink.frames.items[0].credit.bytes);
}

test "credit spending is deterministic and saturating" {
    var credit = Credit{ .messages = 2, .bytes = 8 };

    try credit.spend(3);
    try std.testing.expectEqual(@as(usize, 1), credit.messages);
    try std.testing.expectEqual(@as(usize, 5), credit.bytes);

    try std.testing.expectError(error.FlowControlled, credit.spend(6));
    try std.testing.expectError(error.FlowControlled, credit.spend(5 + 1));
}

test "credit ledger applies credit updates without double counting duplicates" {
    const allocator = std.testing.allocator;
    var ledger = CreditLedger.init(allocator);
    defer ledger.deinit();

    try std.testing.expectEqual(CreditApplyResult.updated, try ledger.applyControlFrame(10, .{ .credit = .{
        .subject_filter = "jobs.*",
        .messages = 2,
        .bytes = 10,
    } }));
    try std.testing.expectEqual(CreditApplyResult.updated, try ledger.applyControlFrame(10, .{ .credit = .{
        .subject_filter = "jobs.*",
        .messages = 2,
        .bytes = 10,
    } }));
    try std.testing.expectEqual(@as(usize, 1), ledger.len());

    try ledger.spend(10, "jobs.resize", 4);
    try std.testing.expectEqual(@as(usize, 1), ledger.creditFor(10, "jobs.*").messages);
    try std.testing.expectEqual(@as(usize, 6), ledger.creditFor(10, "jobs.*").bytes);

    try ledger.spend(10, "jobs.resize", 6);
    try std.testing.expectEqual(@as(usize, 0), ledger.creditFor(10, "jobs.*").messages);
    try std.testing.expectEqual(@as(usize, 0), ledger.creditFor(10, "jobs.*").bytes);
    try std.testing.expectError(error.FlowControlled, ledger.spend(10, "jobs.resize", 1));
}

test "credit ledger chooses deterministic most-specific matching credit" {
    const allocator = std.testing.allocator;
    var ledger = CreditLedger.init(allocator);
    defer ledger.deinit();

    try std.testing.expectEqual(CreditApplyResult.updated, try ledger.applyControlFrame(1, .{ .credit = .{
        .subject_filter = "jobs.>",
        .messages = 5,
        .bytes = 50,
    } }));
    try std.testing.expectEqual(CreditApplyResult.updated, try ledger.applyControlFrame(1, .{ .credit = .{
        .subject_filter = "jobs.resize",
        .messages = 1,
        .bytes = 7,
    } }));
    try std.testing.expectEqual(CreditApplyResult.updated, try ledger.applyControlFrame(1, .{ .credit = .{
        .subject_filter = "jobs.*",
        .messages = 3,
        .bytes = 30,
    } }));

    try ledger.spend(1, "jobs.resize", 7);
    try std.testing.expectEqual(@as(usize, 0), ledger.creditFor(1, "jobs.resize").messages);
    try std.testing.expectEqual(@as(usize, 5), ledger.creditFor(1, "jobs.>").messages);
    try std.testing.expectEqual(@as(usize, 3), ledger.creditFor(1, "jobs.*").messages);

    try ledger.spend(1, "jobs.encode", 10);
    try std.testing.expectEqual(@as(usize, 2), ledger.creditFor(1, "jobs.*").messages);
    try std.testing.expectEqual(@as(usize, 5), ledger.creditFor(1, "jobs.>").messages);
}

test "credit ledger rejects invalid control and removes zero credit" {
    const allocator = std.testing.allocator;
    var ledger = CreditLedger.init(allocator);
    defer ledger.deinit();

    try std.testing.expectError(error.InvalidSubjectFilter, ledger.applyControlFrame(1, .{ .credit = .{
        .subject_filter = "jobs.>.extra",
        .messages = 1,
        .bytes = 1,
    } }));
    try std.testing.expectEqual(@as(usize, 0), ledger.len());

    try std.testing.expectError(error.UnexpectedFrame, ledger.applyControlFrame(1, .{ .subscribe = .{
        .filter = "jobs.*",
    } }));

    try std.testing.expectEqual(CreditApplyResult.updated, try ledger.applyControlFrame(1, .{ .credit = .{
        .subject_filter = "jobs.*",
        .messages = 1,
        .bytes = 4,
    } }));
    try std.testing.expectEqual(CreditApplyResult.removed, try ledger.applyControlFrame(1, .{ .credit = .{
        .subject_filter = "jobs.*",
        .messages = 0,
        .bytes = 0,
    } }));
    try std.testing.expectEqual(@as(usize, 0), ledger.len());
}

test "candidate state follows queue policy when credit is exhausted" {
    const block_flow = PullerFlow.fromQueue(.{ .max_messages = 1, .max_bytes = 8, .on_full = .block }, 1, 1);
    try std.testing.expectEqual(CandidateState.flow_controlled, block_flow.candidateState(1));

    const fail_flow = PullerFlow.fromQueue(.{ .max_messages = 1, .max_bytes = 8, .on_full = .fail }, 1, 1);
    try std.testing.expectEqual(CandidateState.queue_full, fail_flow.candidateState(1));

    const drop_newest_flow = PullerFlow.fromQueue(.{ .max_messages = 1, .max_bytes = 8, .on_full = .drop_newest }, 1, 1);
    try std.testing.expectEqual(CandidateState.ready, drop_newest_flow.candidateState(1));

    const drop_oldest_flow = PullerFlow.fromQueue(.{ .max_messages = 1, .max_bytes = 8, .on_full = .drop_oldest }, 1, 1);
    try std.testing.expectEqual(CandidateState.ready, drop_oldest_flow.candidateState(1));
}

test "scan reports deterministic pressure errors independent of candidate order" {
    const fail_flow = PullerFlow.fromQueue(.{ .max_messages = 1, .max_bytes = 8, .on_full = .fail }, 1, 1);
    const block_flow = PullerFlow.fromQueue(.{ .max_messages = 1, .max_bytes = 8, .on_full = .block }, 1, 1);

    var first = Scan{};
    try std.testing.expectEqual(CandidateState.queue_full, first.record(fail_flow, 1));
    try std.testing.expectEqual(CandidateState.flow_controlled, first.record(block_flow, 1));
    try std.testing.expectEqual(error.FlowControlled, first.err());

    var second = Scan{};
    try std.testing.expectEqual(CandidateState.flow_controlled, second.record(block_flow, 1));
    try std.testing.expectEqual(CandidateState.queue_full, second.record(fail_flow, 1));
    try std.testing.expectEqual(error.FlowControlled, second.err());
}
