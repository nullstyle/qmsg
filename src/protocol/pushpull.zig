const std = @import("std");

const queue = @import("../queue.zig");

pub const Error = error{
    FlowControlled,
    MessageTooLarge,
    NoPeer,
    QueueFull,
};

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

test "credit spending is deterministic and saturating" {
    var credit = Credit{ .messages = 2, .bytes = 8 };

    try credit.spend(3);
    try std.testing.expectEqual(@as(usize, 1), credit.messages);
    try std.testing.expectEqual(@as(usize, 5), credit.bytes);

    try std.testing.expectError(error.FlowControlled, credit.spend(6));
    try std.testing.expectError(error.FlowControlled, credit.spend(5 + 1));
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
