const std = @import("std");

const queue = @import("../queue.zig");
const protocol = @import("../protocol/root.zig");

pub const EndpointId = usize;
pub const Message = queue.Message;
pub const QueueOptions = queue.QueueOptions;
pub const PushResult = queue.PushResult;
pub const Pattern = protocol.Pattern;

pub const Error = error{
    InvalidEndpoint,
    EndpointInUse,
    EndpointNotFound,
    QueueFull,
    FlowControlled,
    WouldBlock,
    MessageTooLarge,
};

pub const EndpointOptions = struct {
    queue: QueueOptions = .{},
};

pub const PatternEndpoint = struct {
    pattern: Pattern,
    context: *anyopaque,
    enqueue: *const fn (context: *anyopaque, msg: Message) anyerror!void,
    accepts: *const fn (context: *anyopaque, subject: []const u8) bool,
    connect_peer: *const fn (context: *anyopaque, peer: PatternEndpoint) anyerror!void,
};

pub const Delivery = struct {
    from: EndpointId,
    to: EndpointId,
    message: Message,

    pub fn deinit(self: *Delivery) void {
        queue.deinitOwnedMessage(&self.message);
        self.* = undefined;
    }
};

pub const BoundEndpoint = struct {
    network: *Network,
    id: EndpointId,

    pub fn endpointId(self: BoundEndpoint) EndpointId {
        return self.id;
    }

    pub fn recv(self: BoundEndpoint) (Error || std.mem.Allocator.Error)!Delivery {
        return self.network.recv(self.id);
    }

    pub fn sendTo(self: BoundEndpoint, to: EndpointId, msg: Message) (Error || std.mem.Allocator.Error)!PushResult {
        return self.network.send(self.id, to, msg);
    }

    pub fn reply(self: BoundEndpoint, delivery: Delivery, msg: Message) (Error || std.mem.Allocator.Error)!PushResult {
        return self.sendTo(delivery.from, msg);
    }
};

pub const Connection = struct {
    network: *Network,
    local_id: EndpointId,
    remote_id: EndpointId,

    pub fn localId(self: Connection) EndpointId {
        return self.local_id;
    }

    pub fn remoteId(self: Connection) EndpointId {
        return self.remote_id;
    }

    pub fn send(self: Connection, msg: Message) (Error || std.mem.Allocator.Error)!PushResult {
        return self.network.send(self.local_id, self.remote_id, msg);
    }

    pub fn recv(self: Connection) (Error || std.mem.Allocator.Error)!Delivery {
        return self.network.recv(self.local_id);
    }
};

pub const Network = struct {
    allocator: std.mem.Allocator,
    endpoints: std.ArrayList(EndpointState),
    bound: std.StringHashMap(EndpointId),
    pattern_bindings: std.StringHashMap(PatternEndpoint),
    pattern_binding_keys: std.ArrayList([]u8),

    pub fn init(allocator: std.mem.Allocator) Network {
        return .{
            .allocator = allocator,
            .endpoints = .empty,
            .bound = std.StringHashMap(EndpointId).init(allocator),
            .pattern_bindings = std.StringHashMap(PatternEndpoint).init(allocator),
            .pattern_binding_keys = .empty,
        };
    }

    pub fn deinit(self: *Network) void {
        for (self.pattern_binding_keys.items) |key| {
            self.allocator.free(key);
        }
        self.pattern_binding_keys.deinit(self.allocator);
        self.pattern_bindings.deinit();
        self.bound.deinit();
        for (self.endpoints.items) |*state| {
            state.deinit(self.allocator);
        }
        self.endpoints.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn bind(self: *Network, address: []const u8, options: EndpointOptions) (Error || std.mem.Allocator.Error)!BoundEndpoint {
        if (address.len == 0) return error.InvalidEndpoint;
        if (self.bound.contains(address)) return error.EndpointInUse;

        const id = try self.addEndpoint(address, options);
        errdefer {
            var state = self.endpoints.pop().?;
            state.deinit(self.allocator);
        }

        try self.bound.put(self.endpoints.items[id].address.?, id);
        return .{
            .network = self,
            .id = id,
        };
    }

    pub fn bindPattern(self: *Network, address: []const u8, endpoint: PatternEndpoint) (Error || std.mem.Allocator.Error)!void {
        if (address.len == 0) return error.InvalidEndpoint;
        if (self.pattern_bindings.contains(address)) return error.EndpointInUse;

        const owned_address = try self.allocator.dupe(u8, address);
        errdefer self.allocator.free(owned_address);
        try self.pattern_bindings.put(owned_address, endpoint);
        errdefer _ = self.pattern_bindings.remove(owned_address);
        try self.pattern_binding_keys.append(self.allocator, owned_address);
    }

    pub fn dialPattern(self: *Network, address: []const u8, endpoint: PatternEndpoint) anyerror!void {
        const remote = self.pattern_bindings.get(address) orelse return error.EndpointNotFound;
        if (!endpoint.pattern.canSendTo(remote.pattern)) return error.InvalidEndpoint;

        try endpoint.connect_peer(endpoint.context, remote);
        if (remote.pattern.canSendTo(endpoint.pattern)) {
            try remote.connect_peer(remote.context, endpoint);
        }
    }

    pub fn connect(self: *Network, address: []const u8, options: EndpointOptions) (Error || std.mem.Allocator.Error)!Connection {
        const remote_id = self.bound.get(address) orelse return error.EndpointNotFound;
        const local_id = try self.addEndpoint(null, options);
        self.endpoints.items[local_id].remote = remote_id;

        return .{
            .network = self,
            .local_id = local_id,
            .remote_id = remote_id,
        };
    }

    pub fn send(self: *Network, from: EndpointId, to: EndpointId, msg: Message) (Error || std.mem.Allocator.Error)!PushResult {
        _ = try self.endpointState(from);
        var destination = try self.endpointState(to);

        var cloned = try queue.cloneOwnedMessage(self.allocator, msg);
        const result = destination.messages.push(cloned) catch |err| {
            queue.deinitOwnedMessage(&cloned);
            return err;
        };
        destination.sources.recordPush(result, from);
        return result;
    }

    pub fn recv(self: *Network, id: EndpointId) (Error || std.mem.Allocator.Error)!Delivery {
        var endpoint_state = try self.endpointState(id);
        const msg = try endpoint_state.messages.pop();
        const from = endpoint_state.sources.pop();
        return .{
            .from = from,
            .to = id,
            .message = msg,
        };
    }

    pub fn queueLen(self: *Network, id: EndpointId) Error!usize {
        const endpoint_state = try self.endpointState(id);
        return endpoint_state.messages.len();
    }

    fn addEndpoint(self: *Network, address: ?[]const u8, options: EndpointOptions) std.mem.Allocator.Error!EndpointId {
        var state = try EndpointState.init(self.allocator, address, options);
        errdefer state.deinit(self.allocator);

        const id = self.endpoints.items.len;
        try self.endpoints.append(self.allocator, state);
        return id;
    }

    fn endpointState(self: *Network, id: EndpointId) Error!*EndpointState {
        if (id >= self.endpoints.items.len) return error.EndpointNotFound;
        return &self.endpoints.items[id];
    }
};

const EndpointState = struct {
    address: ?[]u8,
    remote: ?EndpointId = null,
    messages: queue.Queue,
    sources: SourceRing,

    fn init(allocator: std.mem.Allocator, address: ?[]const u8, options: EndpointOptions) std.mem.Allocator.Error!EndpointState {
        const owned_address = if (address) |addr| try allocator.dupe(u8, addr) else null;
        errdefer if (owned_address) |addr| allocator.free(addr);

        var messages = try queue.Queue.init(allocator, options.queue);
        errdefer messages.deinit();

        var sources = try SourceRing.init(allocator, options.queue.max_messages);
        errdefer sources.deinit(allocator);

        return .{
            .address = owned_address,
            .messages = messages,
            .sources = sources,
        };
    }

    fn deinit(self: *EndpointState, allocator: std.mem.Allocator) void {
        self.messages.deinit();
        self.sources.deinit(allocator);
        if (self.address) |addr| allocator.free(addr);
        self.* = undefined;
    }
};

const SourceRing = struct {
    items: []EndpointId,
    head: usize = 0,
    count: usize = 0,

    fn init(allocator: std.mem.Allocator, capacity: usize) std.mem.Allocator.Error!SourceRing {
        return .{
            .items = try allocator.alloc(EndpointId, capacity),
        };
    }

    fn deinit(self: *SourceRing, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }

    fn recordPush(self: *SourceRing, result: PushResult, from: EndpointId) void {
        switch (result) {
            .enqueued => self.pushBack(from),
            .dropped_oldest => |dropped| {
                self.dropOldest(dropped);
                self.pushBack(from);
            },
            .dropped_newest => {},
        }
    }

    fn pop(self: *SourceRing) EndpointId {
        std.debug.assert(self.count > 0);
        const value = self.items[self.head];
        self.head = (self.head + 1) % self.items.len;
        self.count -= 1;
        if (self.count == 0) self.head = 0;
        return value;
    }

    fn dropOldest(self: *SourceRing, count: usize) void {
        std.debug.assert(count <= self.count);
        if (count == 0) return;
        self.head = (self.head + count) % self.items.len;
        self.count -= count;
        if (self.count == 0) self.head = 0;
    }

    fn pushBack(self: *SourceRing, value: EndpointId) void {
        std.debug.assert(self.count < self.items.len);
        const index = (self.head + self.count) % self.items.len;
        self.items[index] = value;
        self.count += 1;
    }
};

test {
    std.testing.refAllDecls(@This());
}

test "inproc delivers owned clones from a connection to a bound endpoint" {
    const allocator = std.testing.allocator;
    var network = Network.init(allocator);
    defer network.deinit();

    const server = try network.bind("svc.echo", .{
        .queue = .{
            .max_messages = 4,
            .max_bytes = 1024,
            .on_full = .fail,
        },
    });
    const client = try network.connect("svc.echo", .{
        .queue = .{
            .max_messages = 4,
            .max_bytes = 1024,
            .on_full = .fail,
        },
    });

    var request = try testMessage(allocator, "echo", "one", &.{});
    defer queue.deinitOwnedMessage(&request);

    try expectPushResult(.enqueued, try client.send(request));
    request.body[0] = 'X';

    var delivery = try server.recv();
    defer delivery.deinit();
    try std.testing.expectEqual(client.localId(), delivery.from);
    try std.testing.expectEqual(server.endpointId(), delivery.to);
    try std.testing.expectEqualStrings("echo", delivery.message.subject);
    try std.testing.expectEqualStrings("one", delivery.message.body);
}

test "inproc supports deterministic replies to sender ids" {
    const allocator = std.testing.allocator;
    var network = Network.init(allocator);
    defer network.deinit();

    const server = try network.bind("svc.reply", .{});
    const client = try network.connect("svc.reply", .{});

    var request = try testMessage(allocator, "user.get", "42", &.{});
    defer queue.deinitOwnedMessage(&request);
    try expectPushResult(.enqueued, try client.send(request));

    var delivery = try server.recv();
    defer delivery.deinit();

    var reply = try testMessage(allocator, "user.get.ok", "Ada", &.{});
    defer queue.deinitOwnedMessage(&reply);
    try expectPushResult(.enqueued, try server.reply(delivery, reply));

    var received_reply = try client.recv();
    defer received_reply.deinit();
    try std.testing.expectEqual(server.endpointId(), received_reply.from);
    try std.testing.expectEqualStrings("user.get.ok", received_reply.message.subject);
    try std.testing.expectEqualStrings("Ada", received_reply.message.body);
}

test "inproc endpoint queues enforce fail backpressure" {
    const allocator = std.testing.allocator;
    var network = Network.init(allocator);
    defer network.deinit();

    const server = try network.bind("svc.full", .{
        .queue = .{
            .max_messages = 1,
            .max_bytes = 1024,
            .on_full = .fail,
        },
    });
    const client = try network.connect("svc.full", .{});

    var first = try testMessage(allocator, "a", "1", &.{});
    defer queue.deinitOwnedMessage(&first);
    try expectPushResult(.enqueued, try client.send(first));

    var second = try testMessage(allocator, "b", "2", &.{});
    defer queue.deinitOwnedMessage(&second);
    try std.testing.expectError(error.QueueFull, client.send(second));

    try std.testing.expectEqual(@as(usize, 1), try network.queueLen(server.endpointId()));
}

test "inproc drop_oldest keeps sender metadata aligned with messages" {
    const allocator = std.testing.allocator;
    var network = Network.init(allocator);
    defer network.deinit();

    const server = try network.bind("svc.drop", .{
        .queue = .{
            .max_messages = 1,
            .max_bytes = 1024,
            .on_full = .drop_oldest,
        },
    });
    const first_client = try network.connect("svc.drop", .{});
    const second_client = try network.connect("svc.drop", .{});

    var first = try testMessage(allocator, "event", "first", &.{});
    defer queue.deinitOwnedMessage(&first);
    try expectPushResult(.enqueued, try first_client.send(first));

    var second = try testMessage(allocator, "event", "second", &.{});
    defer queue.deinitOwnedMessage(&second);
    try expectPushResult(.{ .dropped_oldest = 1 }, try second_client.send(second));

    var delivery = try server.recv();
    defer delivery.deinit();
    try std.testing.expectEqual(second_client.localId(), delivery.from);
    try std.testing.expectEqualStrings("second", delivery.message.body);
}

test "inproc rejects duplicate or missing endpoints and empty receives are nonblocking" {
    const allocator = std.testing.allocator;
    var network = Network.init(allocator);
    defer network.deinit();

    const server = try network.bind("svc.once", .{});
    try std.testing.expectError(error.EndpointInUse, network.bind("svc.once", .{}));
    try std.testing.expectError(error.EndpointNotFound, network.connect("svc.missing", .{}));
    try std.testing.expectError(error.WouldBlock, server.recv());
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
    headers: []const queue.Header,
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

    msg.headers = try allocator.alloc(queue.Header, headers.len);
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
