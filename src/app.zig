const std = @import("std");
const message = @import("message.zig");
const node = @import("node.zig");
const session = @import("session.zig");
const subject = @import("subject.zig");
const socket = @import("socket.zig");

pub const TlsConfig = struct {};

pub const AppOptions = struct {
    alpn: []const []const u8 = &.{"qmsg/1"},
    node: node.NodeOptions = .{},
};

pub const ConnectHandler = *const fn (*Context) anyerror!void;
pub const CloseHandler = *const fn (*Context) anyerror!void;
pub const MessageHandler = *const fn (*Context, message.Message) anyerror!void;
pub const EmitHandler = *const fn (*Context, message.OutgoingMessage) anyerror!void;

pub const RouteKind = enum {
    rep,
    pull,
    sub,
    datagram,

    pub fn pattern(self: RouteKind) ?socket.Pattern {
        return switch (self) {
            .rep => .rep,
            .pull => .pull,
            .sub => .sub,
            .datagram => null,
        };
    }
};

pub const RouteMatch = struct {
    kind: RouteKind,
    filter: []const u8,
    handler: MessageHandler,
    order: usize,
};

pub const DispatchOptions = struct {
    session: ?*session.Session = null,
    reply_hook: ?EmitHandler = null,
    publish_hook: ?EmitHandler = null,
};

pub const ResponseSink = struct {
    allocator: std.mem.Allocator,
    replies: std.ArrayList(message.Message) = .empty,
    publications: std.ArrayList(message.Message) = .empty,

    pub fn init(allocator: std.mem.Allocator) ResponseSink {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ResponseSink) void {
        deinitMessages(self.allocator, &self.publications);
        deinitMessages(self.allocator, &self.replies);
        self.* = undefined;
    }

    pub fn appendReply(self: *ResponseSink, outgoing: message.OutgoingMessage) !void {
        try appendMessage(self.allocator, &self.replies, outgoing);
    }

    pub fn appendPublication(self: *ResponseSink, outgoing: message.OutgoingMessage) !void {
        try appendMessage(self.allocator, &self.publications, outgoing);
    }

    fn appendMessage(
        allocator: std.mem.Allocator,
        list: *std.ArrayList(message.Message),
        outgoing: message.OutgoingMessage,
    ) !void {
        var owned = try message.Message.init(allocator, outgoing);
        errdefer owned.deinit();
        try list.append(allocator, owned);
    }

    fn deinitMessages(allocator: std.mem.Allocator, list: *std.ArrayList(message.Message)) void {
        for (list.items) |*msg| {
            msg.deinit();
        }
        list.deinit(allocator);
    }
};

pub const DispatchResult = ResponseSink;

pub const Context = struct {
    app: *App,
    session: ?*session.Session = null,
    pattern: ?socket.Pattern = null,
    route_kind: ?RouteKind = null,
    request_subject: []const u8 = "",
    request_id: message.MessageId = 0,
    request_deadline_ms: ?u64 = null,
    response_sink: ?*ResponseSink = null,
    reply_hook: ?EmitHandler = null,
    publish_hook: ?EmitHandler = null,

    pub fn allocator(self: *const Context) std.mem.Allocator {
        return self.app.allocator;
    }

    pub fn authorization(self: *const Context) ?*const @import("auth.zig").Authorization {
        const sess = self.session orelse return null;
        return if (sess.authorization) |*authz| authz else null;
    }

    pub fn reply(self: *Context, outgoing: message.OutgoingMessage) !void {
        if (self.route_kind) |kind| {
            if (kind != .rep) return error.InvalidPattern;
        }

        var effective = outgoing;
        if (effective.subject.len == 0) {
            if (self.request_subject.len == 0) return error.InvalidState;
            effective.subject = self.request_subject;
        }
        if (effective.id == 0 and self.request_id != 0) {
            effective.id = self.request_id;
        }
        if (effective.deadline_ms == null) {
            effective.deadline_ms = self.request_deadline_ms;
        }

        if (self.reply_hook) |hook| {
            try hook(self, effective);
            return;
        }
        if (self.response_sink) |sink| {
            try sink.appendReply(effective);
            return;
        }
        return error.InvalidState;
    }

    pub fn publish(self: *Context, outgoing: message.OutgoingMessage) !void {
        if (self.publish_hook) |hook| {
            try hook(self, outgoing);
            return;
        }
        if (self.response_sink) |sink| {
            try sink.appendPublication(outgoing);
            return;
        }
        return error.InvalidState;
    }
};

pub const App = struct {
    allocator: std.mem.Allocator,
    node: node.Node,
    rep_routes: subject.Router(MessageHandler),
    pull_routes: subject.Router(MessageHandler),
    sub_routes: subject.Router(MessageHandler),
    datagram_routes: subject.Router(MessageHandler),
    connect_handler: ?ConnectHandler = null,
    close_handler: ?CloseHandler = null,
    reply_hook: ?EmitHandler = null,
    publish_hook: ?EmitHandler = null,

    pub fn init(allocator: std.mem.Allocator, options: AppOptions) !App {
        return .{
            .allocator = allocator,
            .node = try node.Node.init(allocator, options.node),
            .rep_routes = subject.Router(MessageHandler).init(allocator),
            .pull_routes = subject.Router(MessageHandler).init(allocator),
            .sub_routes = subject.Router(MessageHandler).init(allocator),
            .datagram_routes = subject.Router(MessageHandler).init(allocator),
        };
    }

    pub fn deinit(self: *App) void {
        self.datagram_routes.deinit();
        self.sub_routes.deinit();
        self.pull_routes.deinit();
        self.rep_routes.deinit();
        self.node.deinit();
    }

    pub fn onConnect(self: *App, handler: ConnectHandler) void {
        self.connect_handler = handler;
    }

    pub fn onClose(self: *App, handler: CloseHandler) void {
        self.close_handler = handler;
    }

    pub fn onReply(self: *App, handler: EmitHandler) void {
        self.reply_hook = handler;
    }

    pub fn onPublish(self: *App, handler: EmitHandler) void {
        self.publish_hook = handler;
    }

    pub fn rep(self: *App, filter: []const u8, handler: MessageHandler) !void {
        try self.rep_routes.add(filter, handler);
    }

    pub fn pull(self: *App, filter: []const u8, handler: MessageHandler) !void {
        try self.pull_routes.add(filter, handler);
    }

    pub fn sub(self: *App, filter: []const u8, handler: MessageHandler) !void {
        try self.sub_routes.add(filter, handler);
    }

    pub fn datagram(self: *App, filter: []const u8, handler: MessageHandler) !void {
        try self.datagram_routes.add(filter, handler);
    }

    pub fn routeCount(self: *const App, kind: RouteKind) usize {
        return switch (kind) {
            .rep => self.rep_routes.len(),
            .pull => self.pull_routes.len(),
            .sub => self.sub_routes.len(),
            .datagram => self.datagram_routes.len(),
        };
    }

    pub fn lookup(self: *const App, kind: RouteKind, subject_name: []const u8) !?RouteMatch {
        const matched = switch (kind) {
            .rep => try self.rep_routes.route(subject_name),
            .pull => try self.pull_routes.route(subject_name),
            .sub => try self.sub_routes.route(subject_name),
            .datagram => try self.datagram_routes.route(subject_name),
        } orelse return null;

        return .{
            .kind = kind,
            .filter = matched.filter.text,
            .handler = matched.value.*,
            .order = matched.order,
        };
    }

    pub fn lookupRep(self: *const App, subject_name: []const u8) !?RouteMatch {
        return self.lookup(.rep, subject_name);
    }

    pub fn lookupPull(self: *const App, subject_name: []const u8) !?RouteMatch {
        return self.lookup(.pull, subject_name);
    }

    pub fn lookupSub(self: *const App, subject_name: []const u8) !?RouteMatch {
        return self.lookup(.sub, subject_name);
    }

    pub fn lookupDatagram(self: *const App, subject_name: []const u8) !?RouteMatch {
        return self.lookup(.datagram, subject_name);
    }

    pub fn dispatchRep(self: *App, incoming: message.Message, options: DispatchOptions) !DispatchResult {
        return self.dispatchMessage(.rep, incoming, options);
    }

    pub fn dispatchPull(self: *App, incoming: message.Message, options: DispatchOptions) !DispatchResult {
        return self.dispatchMessage(.pull, incoming, options);
    }

    pub fn dispatchSub(self: *App, incoming: message.Message, options: DispatchOptions) !DispatchResult {
        return self.dispatchMessage(.sub, incoming, options);
    }

    pub fn dispatchDatagram(self: *App, incoming: message.Message, options: DispatchOptions) !DispatchResult {
        return self.dispatchMessage(.datagram, incoming, options);
    }

    pub fn dispatchOutgoing(self: *App, kind: RouteKind, outgoing: message.OutgoingMessage, options: DispatchOptions) !DispatchResult {
        const incoming = try message.Message.init(self.allocator, outgoing);
        return self.dispatchMessage(kind, incoming, options);
    }

    /// Takes ownership of `incoming` when a route is matched. Message handlers
    /// receive that owned value and are responsible for calling `deinit`.
    pub fn dispatchMessage(self: *App, kind: RouteKind, incoming: message.Message, options: DispatchOptions) !DispatchResult {
        var owned = incoming;
        const route = self.lookup(kind, owned.subject) catch |err| {
            owned.deinit();
            return err;
        } orelse {
            owned.deinit();
            return error.NoRoute;
        };

        var result = ResponseSink.init(self.allocator);
        errdefer result.deinit();

        var ctx = Context{
            .app = self,
            .session = options.session,
            .pattern = kind.pattern(),
            .route_kind = kind,
            .request_subject = owned.subject,
            .request_id = owned.id,
            .request_deadline_ms = owned.deadline_ms,
            .response_sink = &result,
            .reply_hook = options.reply_hook orelse self.reply_hook,
            .publish_hook = options.publish_hook orelse self.publish_hook,
        };

        try route.handler(&ctx, owned);
        return result;
    }

    pub fn dispatchConnect(self: *App, sess: ?*session.Session) !void {
        if (sess) |active| {
            try self.node.emit(.{ .connected = active.id });
        }
        const handler = self.connect_handler orelse return;
        var ctx = Context{
            .app = self,
            .session = sess,
        };
        try handler(&ctx);
    }

    pub fn dispatchClose(self: *App, sess: ?*session.Session) !void {
        if (sess) |active| {
            try self.node.emit(.{ .closed = active.id });
        }
        const handler = self.close_handler orelse return;
        var ctx = Context{
            .app = self,
            .session = sess,
        };
        try handler(&ctx);
    }

    pub fn listenQuic(self: *App, addr: []const u8, tls: TlsConfig) !void {
        _ = self;
        _ = addr;
        _ = tls;
        return error.UnsupportedTransport;
    }

    pub fn run(self: *App) !void {
        _ = self;
    }
};

test {
    std.testing.refAllDecls(@This());
}

test "App route lookup chooses the router winner per pattern" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Handler = struct {
        fn generic(ctx: *Context, msg: message.Message) !void {
            _ = ctx;
            var owned = msg;
            owned.deinit();
        }

        fn exact(ctx: *Context, msg: message.Message) !void {
            _ = ctx;
            var owned = msg;
            owned.deinit();
        }
    };

    try app.rep("jobs.>", Handler.generic);
    try app.rep("jobs.image.resize", Handler.exact);
    try app.pull("jobs.*", Handler.generic);
    try app.sub("metrics.*", Handler.generic);
    try app.datagram("presence.>", Handler.generic);

    try std.testing.expectEqual(@as(usize, 2), app.routeCount(.rep));
    try std.testing.expectEqualStrings("jobs.image.resize", (try app.lookupRep("jobs.image.resize")).?.filter);
    try std.testing.expectEqualStrings("jobs.*", (try app.lookupPull("jobs.thumbnail")).?.filter);
    try std.testing.expectEqualStrings("metrics.*", (try app.lookupSub("metrics.cpu")).?.filter);
    try std.testing.expectEqualStrings("presence.>", (try app.lookupDatagram("presence.user.1")).?.filter);
    try std.testing.expect((try app.lookupRep("metrics.cpu")) == null);
}

test "App dispatches rep handler and captures reply" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Handler = struct {
        fn getUser(ctx: *Context, msg: message.Message) !void {
            var owned = msg;
            defer owned.deinit();

            try std.testing.expectEqual(socket.Pattern.rep, ctx.pattern.?);
            try std.testing.expectEqualStrings("user.get", owned.subject);
            try ctx.reply(.{
                .subject = "",
                .body = "Ada",
            });
        }
    };

    try app.rep("user.*", Handler.getUser);

    var result = try app.dispatchOutgoing(.rep, .{
        .subject = "user.get",
        .id = 42,
        .deadline_ms = 1234,
        .body = "id=42",
    }, .{});
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.replies.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.publications.items.len);
    try std.testing.expectEqualStrings("user.get", result.replies.items[0].subject);
    try std.testing.expectEqual(@as(message.MessageId, 42), result.replies.items[0].id);
    try std.testing.expectEqual(@as(?u64, 1234), result.replies.items[0].deadline_ms);
    try std.testing.expectEqualStrings("Ada", result.replies.items[0].body);
}

test "App dispatch captures publications for pull sub and datagram handlers" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Handler = struct {
        fn publishDone(ctx: *Context, msg: message.Message) !void {
            var owned = msg;
            defer owned.deinit();

            try ctx.publish(.{
                .subject = "jobs.done",
                .body = owned.body,
            });
        }
    };

    try app.pull("jobs.*", Handler.publishDone);
    try app.sub("metrics.*", Handler.publishDone);
    try app.datagram("presence.*", Handler.publishDone);

    var pull_result = try app.dispatchOutgoing(.pull, .{ .subject = "jobs.resize", .body = "ok" }, .{});
    defer pull_result.deinit();
    try std.testing.expectEqual(@as(usize, 1), pull_result.publications.items.len);
    try std.testing.expectEqualStrings("jobs.done", pull_result.publications.items[0].subject);
    try std.testing.expectEqualStrings("ok", pull_result.publications.items[0].body);

    var sub_result = try app.dispatchOutgoing(.sub, .{ .subject = "metrics.cpu", .body = "91" }, .{});
    defer sub_result.deinit();
    try std.testing.expectEqual(@as(usize, 1), sub_result.publications.items.len);

    var datagram_result = try app.dispatchOutgoing(.datagram, .{ .subject = "presence.ada", .body = "online" }, .{});
    defer datagram_result.deinit();
    try std.testing.expectEqual(@as(usize, 1), datagram_result.publications.items.len);
    try std.testing.expect(datagram_result.replies.items.len == 0);
}

test "App dispatch cleans up unrouted messages" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    try std.testing.expectError(error.NoRoute, app.dispatchOutgoing(.rep, .{
        .subject = "missing.route",
        .body = "drop me",
    }, .{}));
}

test "Context reply hook overrides internal sink" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Recorder = struct {
        count: usize = 0,

        fn replyHook(ctx: *Context, outgoing: message.OutgoingMessage) !void {
            const recorder: *@This() = @ptrCast(@alignCast(ctx.session.?.user_data.?));
            recorder.count += 1;
            try std.testing.expectEqualStrings("user.get", outgoing.subject);
            try std.testing.expectEqual(@as(message.MessageId, 7), outgoing.id);
            try std.testing.expectEqualStrings("hooked", outgoing.body);
        }

        fn handler(ctx: *Context, msg: message.Message) !void {
            var owned = msg;
            defer owned.deinit();

            try ctx.reply(.{ .subject = "", .body = "hooked" });
        }
    };

    var recorder = Recorder{};
    var sess = session.Session{
        .id = 9,
        .transport = .inproc,
        .user_data = @ptrCast(&recorder),
    };

    app.onReply(Recorder.replyHook);
    try app.rep("user.*", Recorder.handler);

    var result = try app.dispatchOutgoing(.rep, .{
        .subject = "user.get",
        .id = 7,
    }, .{ .session = &sess });
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), recorder.count);
    try std.testing.expectEqual(@as(usize, 0), result.replies.items.len);
}

test "App connect and close dispatch handlers through node events" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Recorder = struct {
        connects: usize = 0,
        closes: usize = 0,

        fn onConnect(ctx: *Context) !void {
            const recorder: *@This() = @ptrCast(@alignCast(ctx.session.?.user_data.?));
            recorder.connects += 1;
        }

        fn onClose(ctx: *Context) !void {
            const recorder: *@This() = @ptrCast(@alignCast(ctx.session.?.user_data.?));
            recorder.closes += 1;
        }
    };

    var recorder = Recorder{};
    var sess = session.Session{
        .id = 11,
        .transport = .inproc,
        .user_data = @ptrCast(&recorder),
    };

    app.onConnect(Recorder.onConnect);
    app.onClose(Recorder.onClose);

    try app.dispatchConnect(&sess);
    try app.dispatchClose(&sess);

    try std.testing.expectEqual(@as(usize, 1), recorder.connects);
    try std.testing.expectEqual(@as(usize, 1), recorder.closes);

    var events: [2]node.Event = undefined;
    try std.testing.expectEqual(@as(usize, 2), try app.node.poll(&events));
    try std.testing.expectEqual(@as(session.SessionId, 11), events[0].connected);
    try std.testing.expectEqual(@as(session.SessionId, 11), events[1].closed);
}
