const std = @import("std");

const control = @import("../control.zig");
const queue = @import("../queue.zig");
const subject_mod = @import("../subject.zig");

pub const PeerId = usize;

pub const Match = struct {
    peer_id: PeerId,
    queue_options: queue.QueueOptions,
};

pub const ApplyResult = enum {
    subscribed,
    duplicate,
    unsubscribed,
    not_subscribed,
};

pub fn emitSubscribe(sink: control.Sink, filter: []const u8, options: queue.QueueOptions) !void {
    const frame: control.Frame = .{ .subscribe = .{
        .filter = filter,
        .options = optionsFromQueue(options),
    } };
    try validateEmitFrame(frame);
    try sink.emitFrame(frame);
}

pub fn emitUnsubscribe(sink: control.Sink, filter: []const u8) !void {
    const frame: control.Frame = .{ .unsubscribe = .{
        .filter = filter,
    } };
    try validateEmitFrame(frame);
    try sink.emitFrame(frame);
}

pub fn optionsFromQueue(options: queue.QueueOptions) u64 {
    return switch (options.on_full) {
        .block => 0,
        .fail => 1,
        .drop_oldest => 2,
        .drop_newest => 3,
    };
}

pub fn queueFromOptions(control_options: u64, defaults: queue.QueueOptions) !queue.QueueOptions {
    if ((control_options & ~@as(u64, 0x3)) != 0) return error.InvalidControlFrame;

    var options = defaults;
    options.on_full = switch (control_options & 0x3) {
        0 => .block,
        1 => .fail,
        2 => .drop_oldest,
        3 => .drop_newest,
        else => unreachable,
    };
    return options;
}

pub const SubscriptionSet = struct {
    allocator: std.mem.Allocator,
    max_subscriptions: usize,
    entries: std.ArrayList(Entry) = .empty,

    pub const Entry = struct {
        filter: subject_mod.Filter,
        order: usize,
    };

    pub fn init(allocator: std.mem.Allocator, max_subscriptions: usize) SubscriptionSet {
        return .{
            .allocator = allocator,
            .max_subscriptions = max_subscriptions,
        };
    }

    pub fn deinit(self: *SubscriptionSet) void {
        for (self.entries.items) |*entry| {
            entry.filter.deinit();
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(self: *SubscriptionSet, filter: []const u8) !bool {
        if (self.contains(filter)) return false;

        var owned = try subject_mod.Filter.init(self.allocator, filter);
        errdefer owned.deinit();

        if (self.entries.items.len >= self.max_subscriptions) return error.QueueFull;

        try self.entries.append(self.allocator, .{
            .filter = owned,
            .order = self.entries.items.len,
        });
        return true;
    }

    pub fn addAndEmit(self: *SubscriptionSet, sink: control.Sink, filter: []const u8, options: queue.QueueOptions) !bool {
        const added = try self.add(filter);
        if (!added) return false;
        errdefer _ = self.remove(filter);

        try emitSubscribe(sink, filter, options);
        return true;
    }

    pub fn remove(self: *SubscriptionSet, filter: []const u8) bool {
        for (self.entries.items, 0..) |entry, index| {
            if (!std.mem.eql(u8, entry.filter.text, filter)) continue;

            var removed = self.entries.orderedRemove(index);
            removed.filter.deinit();
            return true;
        }
        return false;
    }

    pub fn removeAndEmit(self: *SubscriptionSet, sink: control.Sink, filter: []const u8) !bool {
        if (!self.contains(filter)) return false;

        try emitUnsubscribe(sink, filter);
        return self.remove(filter);
    }

    pub fn contains(self: SubscriptionSet, filter: []const u8) bool {
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.filter.text, filter)) return true;
        }
        return false;
    }

    pub fn matches(self: SubscriptionSet, subject: []const u8) bool {
        for (self.entries.items) |entry| {
            if (entry.filter.matches(subject) catch false) return true;
        }
        return false;
    }

    /// The filter that claims `subject`: first match in subscription
    /// order, matching `matches` above. Borrowed text — valid until
    /// that filter is removed or the set deinits.
    pub fn matchedFilter(self: SubscriptionSet, subject: []const u8) ?[]const u8 {
        for (self.entries.items) |entry| {
            if (entry.filter.matches(subject) catch false) return entry.filter.text;
        }
        return null;
    }

    pub fn len(self: SubscriptionSet) usize {
        return self.entries.items.len;
    }
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    peers: std.ArrayList(Peer) = .empty,
    next_order: usize = 0,

    const Peer = struct {
        id: PeerId,
        order: usize,
        queue_options: queue.QueueOptions,
        subscriptions: SubscriptionSet,

        fn deinit(self: *Peer) void {
            self.subscriptions.deinit();
            self.* = undefined;
        }
    };

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Registry) void {
        for (self.peers.items) |*peer| {
            peer.deinit();
        }
        self.peers.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn addPeer(self: *Registry, peer_id: PeerId, options: queue.QueueOptions) !void {
        if (self.findPeer(peer_id)) |peer| {
            peer.queue_options = options;
            return;
        }

        try self.peers.append(self.allocator, .{
            .id = peer_id,
            .order = self.next_order,
            .queue_options = options,
            .subscriptions = SubscriptionSet.init(self.allocator, std.math.maxInt(usize)),
        });
        self.next_order += 1;
    }

    pub fn removePeer(self: *Registry, peer_id: PeerId) bool {
        for (self.peers.items, 0..) |peer, index| {
            if (peer.id != peer_id) continue;

            var removed = self.peers.orderedRemove(index);
            removed.deinit();
            return true;
        }
        return false;
    }

    pub fn subscribe(self: *Registry, peer_id: PeerId, filter: []const u8, options: queue.QueueOptions) !bool {
        try validateFilter(self.allocator, filter);

        if (self.findPeer(peer_id)) |peer| {
            if (peer.subscriptions.contains(filter)) return false;
            peer.queue_options = options;
            return try peer.subscriptions.add(filter);
        }

        try self.addPeer(peer_id, options);
        errdefer _ = self.removePeer(peer_id);
        return try self.findPeer(peer_id).?.subscriptions.add(filter);
    }

    pub fn unsubscribe(self: *Registry, peer_id: PeerId, filter: []const u8) bool {
        const peer = self.findPeer(peer_id) orelse return false;
        return peer.subscriptions.remove(filter);
    }

    pub fn applyControlFrame(self: *Registry, peer_id: PeerId, frame: control.Frame, defaults: queue.QueueOptions) !ApplyResult {
        return switch (frame) {
            .subscribe => |subscribe_frame| {
                const options = try queueFromOptions(subscribe_frame.options, defaults);
                if (try self.subscribe(peer_id, subscribe_frame.filter, options)) {
                    return .subscribed;
                }
                return .duplicate;
            },
            .unsubscribe => |unsubscribe_frame| {
                try validateFilter(self.allocator, unsubscribe_frame.filter);
                if (self.unsubscribe(peer_id, unsubscribe_frame.filter)) {
                    return .unsubscribed;
                }
                return .not_subscribed;
            },
            else => error.UnexpectedFrame,
        };
    }

    pub fn matches(self: Registry, peer_id: PeerId, subject: []const u8) bool {
        const peer = self.findPeerConst(peer_id) orelse return false;
        return peer.subscriptions.matches(subject);
    }

    pub fn collectMatches(self: Registry, subject: []const u8, out: *std.ArrayList(Match)) !void {
        try subject_mod.validate(subject);
        for (self.peers.items) |peer| {
            if (!peer.subscriptions.matches(subject)) continue;
            try out.append(self.allocator, .{
                .peer_id = peer.id,
                .queue_options = peer.queue_options,
            });
        }
    }

    pub fn peerCount(self: Registry) usize {
        return self.peers.items.len;
    }

    pub fn subscriptionCount(self: Registry, peer_id: PeerId) usize {
        const peer = self.findPeerConst(peer_id) orelse return 0;
        return peer.subscriptions.len();
    }

    fn findPeer(self: *Registry, peer_id: PeerId) ?*Peer {
        for (self.peers.items) |*peer| {
            if (peer.id == peer_id) return peer;
        }
        return null;
    }

    fn findPeerConst(self: Registry, peer_id: PeerId) ?*const Peer {
        for (self.peers.items) |*peer| {
            if (peer.id == peer_id) return peer;
        }
        return null;
    }
};

fn validateFilter(allocator: std.mem.Allocator, filter: []const u8) !void {
    var parsed = try subject_mod.Filter.init(allocator, filter);
    parsed.deinit();
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
            .subscribe => |subscribe| .{ .subscribe = .{
                .allocator = allocator,
                .filter = try allocator.dupe(u8, subscribe.filter),
                .options = subscribe.options,
            } },
            .unsubscribe => |unsubscribe| .{ .unsubscribe = .{
                .allocator = allocator,
                .filter = try allocator.dupe(u8, unsubscribe.filter),
            } },
            else => error.UnexpectedFrame,
        };
    }
};

test "subscription set validates filters before enforcing capacity" {
    const allocator = std.testing.allocator;
    var set = SubscriptionSet.init(allocator, 0);
    defer set.deinit();

    try std.testing.expectError(error.InvalidSubjectFilter, set.add("metrics*"));
    try std.testing.expectError(error.QueueFull, set.add("metrics.*"));
}

test "subscription set emits only effective local changes" {
    const allocator = std.testing.allocator;

    var sink = RecordingSink.init(allocator);
    defer sink.deinit();

    var set = SubscriptionSet.init(allocator, 8);
    defer set.deinit();

    try std.testing.expect(try set.addAndEmit(sink.sink(), "metrics.*", .{ .on_full = .drop_oldest }));
    try std.testing.expect(!try set.addAndEmit(sink.sink(), "metrics.*", .{ .on_full = .fail }));
    try std.testing.expect(try set.addAndEmit(sink.sink(), "presence.>", .{ .on_full = .drop_newest }));
    try std.testing.expect(try set.removeAndEmit(sink.sink(), "metrics.*"));
    try std.testing.expect(!try set.removeAndEmit(sink.sink(), "missing.*"));

    try std.testing.expectEqual(@as(usize, 3), sink.frames.items.len);
    try std.testing.expectEqual(control.Tag.subscribe, std.meta.activeTag(sink.frames.items[0]));
    try std.testing.expectEqualStrings("metrics.*", sink.frames.items[0].subscribe.filter);
    try std.testing.expectEqual(optionsFromQueue(.{ .on_full = .drop_oldest }), sink.frames.items[0].subscribe.options);
    try std.testing.expectEqual(control.Tag.subscribe, std.meta.activeTag(sink.frames.items[1]));
    try std.testing.expectEqualStrings("presence.>", sink.frames.items[1].subscribe.filter);
    try std.testing.expectEqual(optionsFromQueue(.{ .on_full = .drop_newest }), sink.frames.items[1].subscribe.options);
    try std.testing.expectEqual(control.Tag.unsubscribe, std.meta.activeTag(sink.frames.items[2]));
    try std.testing.expectEqualStrings("metrics.*", sink.frames.items[2].unsubscribe.filter);
}

test "registry stores subscriptions per peer and matches at source" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try std.testing.expect(try registry.subscribe(10, "metrics.*", .{ .on_full = .fail }));
    try std.testing.expect(try registry.subscribe(20, "metrics.cpu", .{ .on_full = .drop_oldest }));
    try std.testing.expect(try registry.subscribe(30, "presence.>", .{}));
    try std.testing.expect(!try registry.subscribe(20, "metrics.cpu", .{ .on_full = .drop_oldest }));

    var matches: std.ArrayList(Match) = .empty;
    defer matches.deinit(allocator);
    try registry.collectMatches("metrics.cpu", &matches);

    try std.testing.expectEqual(@as(usize, 2), matches.items.len);
    try std.testing.expectEqual(@as(PeerId, 10), matches.items[0].peer_id);
    try std.testing.expectEqual(queue.OnFull.fail, matches.items[0].queue_options.on_full);
    try std.testing.expectEqual(@as(PeerId, 20), matches.items[1].peer_id);
    try std.testing.expectEqual(queue.OnFull.drop_oldest, matches.items[1].queue_options.on_full);

    try std.testing.expect(registry.matches(10, "metrics.mem"));
    try std.testing.expect(!registry.matches(20, "metrics.mem"));
    try std.testing.expect(registry.matches(30, "presence.user.1"));

    try std.testing.expect(registry.unsubscribe(20, "metrics.cpu"));
    try std.testing.expect(!registry.matches(20, "metrics.cpu"));
    try std.testing.expectEqual(@as(usize, 0), registry.subscriptionCount(20));
}

test "registry applies subscription control frames idempotently" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try std.testing.expectEqual(ApplyResult.subscribed, try registry.applyControlFrame(42, .{ .subscribe = .{
        .filter = "metrics.*",
        .options = optionsFromQueue(.{ .on_full = .drop_newest }),
    } }, .{}));
    try std.testing.expectEqual(ApplyResult.duplicate, try registry.applyControlFrame(42, .{ .subscribe = .{
        .filter = "metrics.*",
        .options = optionsFromQueue(.{ .on_full = .fail }),
    } }, .{}));
    try std.testing.expectEqual(@as(usize, 1), registry.subscriptionCount(42));

    var matches: std.ArrayList(Match) = .empty;
    defer matches.deinit(allocator);
    try registry.collectMatches("metrics.cpu", &matches);
    try std.testing.expectEqual(@as(usize, 1), matches.items.len);
    try std.testing.expectEqual(queue.OnFull.drop_newest, matches.items[0].queue_options.on_full);

    try std.testing.expectEqual(ApplyResult.unsubscribed, try registry.applyControlFrame(42, .{ .unsubscribe = .{
        .filter = "metrics.*",
    } }, .{}));
    try std.testing.expectEqual(ApplyResult.not_subscribed, try registry.applyControlFrame(42, .{ .unsubscribe = .{
        .filter = "metrics.*",
    } }, .{}));
}

test "registry rejects invalid subscription control without mutating state" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try std.testing.expectError(error.InvalidControlFrame, registry.applyControlFrame(7, .{ .subscribe = .{
        .filter = "metrics.*",
        .options = 4,
    } }, .{}));
    try std.testing.expectEqual(@as(usize, 0), registry.peerCount());

    try std.testing.expectError(error.InvalidSubjectFilter, registry.applyControlFrame(7, .{ .subscribe = .{
        .filter = "metrics*",
        .options = 0,
    } }, .{}));
    try std.testing.expectEqual(@as(usize, 0), registry.peerCount());

    try std.testing.expectError(error.UnexpectedFrame, registry.applyControlFrame(7, .{ .credit = .{
        .subject_filter = "metrics.*",
        .messages = 1,
        .bytes = 1,
    } }, .{}));
}

test "registry keeps peer order stable for deterministic fanout" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator);
    defer registry.deinit();

    try registry.addPeer(3, .{});
    try registry.addPeer(1, .{});
    try registry.addPeer(2, .{});
    try std.testing.expect(try registry.subscribe(1, "events.>", .{}));
    try std.testing.expect(try registry.subscribe(2, "events.>", .{}));
    try std.testing.expect(try registry.subscribe(3, "events.>", .{}));

    var matches: std.ArrayList(Match) = .empty;
    defer matches.deinit(allocator);
    try registry.collectMatches("events.created", &matches);

    try std.testing.expectEqual(@as(PeerId, 3), matches.items[0].peer_id);
    try std.testing.expectEqual(@as(PeerId, 1), matches.items[1].peer_id);
    try std.testing.expectEqual(@as(PeerId, 2), matches.items[2].peer_id);

    try std.testing.expect(registry.removePeer(1));
    matches.clearRetainingCapacity();
    try registry.collectMatches("events.updated", &matches);
    try std.testing.expectEqual(@as(usize, 2), matches.items.len);
    try std.testing.expectEqual(@as(PeerId, 3), matches.items[0].peer_id);
    try std.testing.expectEqual(@as(PeerId, 2), matches.items[1].peer_id);
}

test {
    std.testing.refAllDecls(@This());
}
