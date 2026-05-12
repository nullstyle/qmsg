const std = @import("std");

const queue = @import("../queue.zig");
const subject_mod = @import("../subject.zig");

pub const PeerId = usize;

pub const Match = struct {
    peer_id: PeerId,
    queue_options: queue.QueueOptions,
};

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
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.filter.text, filter)) return false;
        }

        var owned = try subject_mod.Filter.init(self.allocator, filter);
        errdefer owned.deinit();

        if (self.entries.items.len >= self.max_subscriptions) return error.QueueFull;

        try self.entries.append(self.allocator, .{
            .filter = owned,
            .order = self.entries.items.len,
        });
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

    pub fn matches(self: SubscriptionSet, subject: []const u8) bool {
        for (self.entries.items) |entry| {
            if (entry.filter.matches(subject) catch false) return true;
        }
        return false;
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
        try self.addPeer(peer_id, options);
        return try self.findPeer(peer_id).?.subscriptions.add(filter);
    }

    pub fn unsubscribe(self: *Registry, peer_id: PeerId, filter: []const u8) bool {
        const peer = self.findPeer(peer_id) orelse return false;
        return peer.subscriptions.remove(filter);
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

test "subscription set validates filters before enforcing capacity" {
    const allocator = std.testing.allocator;
    var set = SubscriptionSet.init(allocator, 0);
    defer set.deinit();

    try std.testing.expectError(error.InvalidSubjectFilter, set.add("metrics*"));
    try std.testing.expectError(error.QueueFull, set.add("metrics.*"));
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
