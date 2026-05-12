const std = @import("std");

const control = @import("../control.zig");
const protocol = @import("../protocol/root.zig");
const queue = @import("../queue.zig");
const quic_streams = @import("quic_streams.zig");

const pubsub = protocol.pubsub;
const pushpull = protocol.pushpull;

pub const ApplyResult = enum {
    subscribed,
    duplicate,
    unsubscribed,
    not_subscribed,
    credit_updated,
    credit_removed,
};

pub const ApplySummary = struct {
    subscribed: usize = 0,
    duplicate: usize = 0,
    unsubscribed: usize = 0,
    not_subscribed: usize = 0,
    credit_updated: usize = 0,
    credit_removed: usize = 0,

    pub fn record(self: *ApplySummary, result: ApplyResult) void {
        switch (result) {
            .subscribed => self.subscribed += 1,
            .duplicate => self.duplicate += 1,
            .unsubscribed => self.unsubscribed += 1,
            .not_subscribed => self.not_subscribed += 1,
            .credit_updated => self.credit_updated += 1,
            .credit_removed => self.credit_removed += 1,
        }
    }
};

pub const State = struct {
    allocator: std.mem.Allocator,
    registry: *pubsub.Registry,
    credit_ledger: *pushpull.CreditLedger,
    default_queue: queue.QueueOptions = .{},
    outgoing: std.ArrayList(control.Frame) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        registry: *pubsub.Registry,
        credit_ledger: *pushpull.CreditLedger,
        default_queue: queue.QueueOptions,
    ) State {
        return .{
            .allocator = allocator,
            .registry = registry,
            .credit_ledger = credit_ledger,
            .default_queue = default_queue,
        };
    }

    pub fn deinit(self: *State) void {
        self.clearQueuedFrames();
        self.outgoing.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn sink(self: *State) control.Sink {
        return .{
            .context = @ptrCast(self),
            .emit = emit,
        };
    }

    pub fn queueSubscribe(self: *State, filter: []const u8, options: queue.QueueOptions) !void {
        try pubsub.emitSubscribe(self.sink(), filter, options);
    }

    pub fn queueUnsubscribe(self: *State, filter: []const u8) !void {
        try pubsub.emitUnsubscribe(self.sink(), filter);
    }

    pub fn queueCredit(self: *State, subject_filter: []const u8, credit_value: pushpull.Credit) !void {
        try pushpull.emitCredit(self.sink(), subject_filter, credit_value);
    }

    pub fn queuedFrames(self: State) []const control.Frame {
        return self.outgoing.items;
    }

    pub fn clearQueuedFrames(self: *State) void {
        for (self.outgoing.items) |*frame| {
            frame.deinit();
        }
        self.outgoing.clearRetainingCapacity();
    }

    /// Builds the existing QUIC control-stream sender from currently queued
    /// frames. The sender encodes immediately, so queued frames remain owned by
    /// this State and can be cleared after the session driver observes send
    /// completion.
    pub fn initSender(
        self: State,
        stream_id: u64,
        codec_options: control.CodecOptions,
        write_options: quic_streams.ControlWriteOptions,
    ) !quic_streams.ControlStreamSender {
        return quic_streams.ControlStreamSender.init(
            self.allocator,
            stream_id,
            self.queuedFrames(),
            codec_options,
            write_options,
        );
    }

    pub fn applyReceived(self: *State, peer_id: pubsub.PeerId, frame: control.Frame) !ApplyResult {
        return switch (frame) {
            .subscribe, .unsubscribe => mapPubSubResult(
                try self.registry.applyControlFrame(peer_id, frame, self.default_queue),
            ),
            .credit => mapCreditResult(
                try self.credit_ledger.applyControlFrame(peer_id, frame),
            ),
            else => error.UnexpectedFrame,
        };
    }

    pub fn applyReceivedFrames(
        self: *State,
        peer_id: pubsub.PeerId,
        frames: []const control.Frame,
    ) !ApplySummary {
        var summary: ApplySummary = .{};
        for (frames) |frame| {
            summary.record(try self.applyReceived(peer_id, frame));
        }
        return summary;
    }

    fn emit(context: *anyopaque, frame: control.Frame) anyerror!void {
        const self: *State = @ptrCast(@alignCast(context));
        var owned = try cloneQueuedFrame(self.allocator, frame);
        errdefer owned.deinit();
        try self.outgoing.append(self.allocator, owned);
    }
};

fn mapPubSubResult(result: pubsub.ApplyResult) ApplyResult {
    return switch (result) {
        .subscribed => .subscribed,
        .duplicate => .duplicate,
        .unsubscribed => .unsubscribed,
        .not_subscribed => .not_subscribed,
    };
}

fn mapCreditResult(result: pushpull.CreditApplyResult) ApplyResult {
    return switch (result) {
        .updated => .credit_updated,
        .removed => .credit_removed,
    };
}

fn cloneQueuedFrame(allocator: std.mem.Allocator, frame: control.Frame) !control.Frame {
    return switch (frame) {
        .subscribe => |subscribe| .{ .subscribe = .{
            .allocator = allocator,
            .filter = try allocator.dupe(u8, subscribe.filter),
            .options = subscribe.options,
        } },
        .unsubscribe => |unsubscribe| .{ .unsubscribe = .{
            .allocator = allocator,
            .filter = try allocator.dupe(u8, unsubscribe.filter),
        } },
        .credit => |credit| .{ .credit = .{
            .allocator = allocator,
            .subject_filter = try allocator.dupe(u8, credit.subject_filter),
            .messages = credit.messages,
            .bytes = credit.bytes,
        } },
        else => error.UnexpectedFrame,
    };
}

test "queued control frames own emitted borrowed slices" {
    const allocator = std.testing.allocator;

    var registry = pubsub.Registry.init(allocator);
    defer registry.deinit();
    var ledger = pushpull.CreditLedger.init(allocator);
    defer ledger.deinit();

    var state = State.init(allocator, &registry, &ledger, .{});
    defer state.deinit();

    const subscribe_filter = try allocator.dupe(u8, "jobs.resize");
    defer allocator.free(subscribe_filter);
    const credit_filter = try allocator.dupe(u8, "pull.*");
    defer allocator.free(credit_filter);

    try state.queueSubscribe(subscribe_filter, .{ .on_full = .drop_oldest });
    try state.queueUnsubscribe(subscribe_filter);
    try state.queueCredit(credit_filter, .{ .messages = 3, .bytes = 99 });

    @memset(subscribe_filter, 'x');
    @memset(credit_filter, 'y');

    const frames = state.queuedFrames();
    try std.testing.expectEqual(@as(usize, 3), frames.len);
    try std.testing.expectEqual(control.Tag.subscribe, std.meta.activeTag(frames[0]));
    try std.testing.expectEqualStrings("jobs.resize", frames[0].subscribe.filter);
    try std.testing.expectEqual(@as(u64, pubsub.optionsFromQueue(.{ .on_full = .drop_oldest })), frames[0].subscribe.options);
    try std.testing.expectEqual(control.Tag.unsubscribe, std.meta.activeTag(frames[1]));
    try std.testing.expectEqualStrings("jobs.resize", frames[1].unsubscribe.filter);
    try std.testing.expectEqual(control.Tag.credit, std.meta.activeTag(frames[2]));
    try std.testing.expectEqualStrings("pull.*", frames[2].credit.subject_filter);
    try std.testing.expectEqual(@as(u64, 3), frames[2].credit.messages);
    try std.testing.expectEqual(@as(u64, 99), frames[2].credit.bytes);

    var sender = try state.initSender(quic_streams.localControlStreamId(.client), .{}, .{ .open_uni = false, .finish = false });
    defer sender.deinit();
    try std.testing.expect(sender.bytes.len > 0);

    state.clearQueuedFrames();
    try std.testing.expectEqual(@as(usize, 0), state.queuedFrames().len);
}

test "apply received subscribe unsubscribe and credit frames" {
    const allocator = std.testing.allocator;

    var registry = pubsub.Registry.init(allocator);
    defer registry.deinit();
    var ledger = pushpull.CreditLedger.init(allocator);
    defer ledger.deinit();

    var state = State.init(allocator, &registry, &ledger, .{ .on_full = .fail });
    defer state.deinit();

    try std.testing.expectEqual(ApplyResult.subscribed, try state.applyReceived(7, .{ .subscribe = .{
        .filter = "metrics.*",
        .options = pubsub.optionsFromQueue(.{ .on_full = .drop_newest }),
    } }));
    try std.testing.expect(registry.matches(7, "metrics.cpu"));
    try std.testing.expectEqual(@as(usize, 1), registry.subscriptionCount(7));

    try std.testing.expectEqual(ApplyResult.credit_updated, try state.applyReceived(7, .{ .credit = .{
        .subject_filter = "jobs.*",
        .messages = 4,
        .bytes = 4096,
    } }));
    try std.testing.expectEqual(pushpull.Credit{ .messages = 4, .bytes = 4096 }, ledger.creditFor(7, "jobs.*"));

    try std.testing.expectEqual(ApplyResult.unsubscribed, try state.applyReceived(7, .{ .unsubscribe = .{
        .filter = "metrics.*",
    } }));
    try std.testing.expect(!registry.matches(7, "metrics.cpu"));
}

test "apply received frames reports duplicate and removal results deterministically" {
    const allocator = std.testing.allocator;

    var registry = pubsub.Registry.init(allocator);
    defer registry.deinit();
    var ledger = pushpull.CreditLedger.init(allocator);
    defer ledger.deinit();

    var state = State.init(allocator, &registry, &ledger, .{});
    defer state.deinit();

    const frames = [_]control.Frame{
        .{ .subscribe = .{ .filter = "events.*", .options = 0 } },
        .{ .subscribe = .{ .filter = "events.*", .options = 0 } },
        .{ .unsubscribe = .{ .filter = "missing.*" } },
        .{ .credit = .{ .subject_filter = "jobs.*", .messages = 1, .bytes = 64 } },
        .{ .credit = .{ .subject_filter = "jobs.*", .messages = 0, .bytes = 0 } },
    };

    const summary = try state.applyReceivedFrames(9, &frames);
    try std.testing.expectEqual(@as(usize, 1), summary.subscribed);
    try std.testing.expectEqual(@as(usize, 1), summary.duplicate);
    try std.testing.expectEqual(@as(usize, 0), summary.unsubscribed);
    try std.testing.expectEqual(@as(usize, 1), summary.not_subscribed);
    try std.testing.expectEqual(@as(usize, 1), summary.credit_updated);
    try std.testing.expectEqual(@as(usize, 1), summary.credit_removed);
    try std.testing.expectEqual(@as(usize, 0), ledger.len());
}

test "unexpected control frames are rejected for queue and apply paths" {
    const allocator = std.testing.allocator;

    var registry = pubsub.Registry.init(allocator);
    defer registry.deinit();
    var ledger = pushpull.CreditLedger.init(allocator);
    defer ledger.deinit();

    var state = State.init(allocator, &registry, &ledger, .{});
    defer state.deinit();

    try std.testing.expectError(error.UnexpectedFrame, state.sink().emitFrame(.{ .goaway = .{
        .code = 1,
        .reason = "bye",
    } }));
    try std.testing.expectEqual(@as(usize, 0), state.queuedFrames().len);

    try std.testing.expectError(error.UnexpectedFrame, state.applyReceived(1, .{ .hello = .{
        .peer_id = "peer-a",
    } }));
}
