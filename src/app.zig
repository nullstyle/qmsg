const std = @import("std");
const auth = @import("auth.zig");
const message = @import("message.zig");
const node = @import("node.zig");
const session = @import("session.zig");
const subject = @import("subject.zig");
const socket = @import("socket.zig");
const transport = @import("transport/root.zig");

pub const TlsConfig = struct {
    quic: transport.quic.QuicOptions = .{},
};

pub const ErrorPolicy = enum {
    propagate,
    reply_error,
};

pub const AppOptions = struct {
    alpn: []const []const u8 = &.{"qmsg/1"},
    node: node.NodeOptions = .{},
    error_policy: ErrorPolicy = .reply_error,
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

pub const QuicDispatchOptions = struct {
    reply_hook: ?EmitHandler = null,
    publish_hook: ?EmitHandler = null,
};

pub const InprocRepOptions = struct {
    socket: socket.SocketOptions(.rep) = .{},
    session: ?session.Session = null,
};

pub const RunOnceResult = node.RunOnceResult;

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
    request_message_size: usize = 0,
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

    pub fn requireAuthenticated(self: *const Context) auth.Error!void {
        const sess = self.session orelse return auth.Error.AuthenticationRequired;
        try sess.requireAuthenticated();
    }

    pub fn requirePattern(self: *const Context, pattern: auth.Pattern) auth.Error!void {
        const sess = self.session orelse return auth.Error.AuthenticationRequired;
        try sess.requirePattern(pattern);
    }

    pub fn requireSubject(self: *const Context, subject_name: []const u8) auth.Error!void {
        const sess = self.session orelse return auth.Error.AuthenticationRequired;
        try sess.requireSubject(subject_name);
    }

    pub fn requireRouteAccess(self: *const Context) auth.Error!void {
        const sess = self.session orelse return auth.Error.AuthenticationRequired;
        const datagram = self.route_kind == .datagram;
        try sess.check(.{
            .pattern = if (self.pattern) |pattern| authPattern(pattern) else null,
            .subject = if (self.request_subject.len == 0) null else self.request_subject,
            .datagram = datagram,
            .message_size = self.request_message_size,
        });
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
    error_policy: ErrorPolicy,
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
            .error_policy = options.error_policy,
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

    pub fn setErrorPolicy(self: *App, policy: ErrorPolicy) void {
        self.error_policy = policy;
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

    /// QUIC integration hook for already-decoded reliable stream or datagram
    /// messages. Node/session transport code supplies the route kind it derived
    /// from stream/datagram context, and this facade returns any app replies or
    /// publications in a socket-free ResponseSink for the QUIC writer to encode.
    pub fn dispatchQuic(
        self: *App,
        kind: RouteKind,
        incoming: message.Message,
        sess: *session.Session,
        options: QuicDispatchOptions,
    ) !DispatchResult {
        if (sess.transport != .quic) {
            var owned = incoming;
            owned.deinit();
            return error.InvalidState;
        }

        var error_subject: ?[]u8 = null;
        defer if (error_subject) |subject_name| self.allocator.free(subject_name);
        if (self.error_policy == .reply_error and kind == .rep) {
            error_subject = self.allocator.dupe(u8, incoming.subject) catch |err| {
                var owned = incoming;
                owned.deinit();
                return err;
            };
        }

        const request_id = incoming.id;
        const request_deadline_ms = incoming.deadline_ms;

        return self.dispatchMessage(kind, incoming, .{
            .session = sess,
            .reply_hook = options.reply_hook,
            .publish_hook = options.publish_hook,
        }) catch |err| try self.dispatchRepErrorResult(
            kind,
            error_subject orelse "",
            request_id,
            request_deadline_ms,
            err,
        );
    }

    pub fn runQuicMessage(
        self: *App,
        kind: RouteKind,
        incoming: message.Message,
        sess: *session.Session,
        options: QuicDispatchOptions,
    ) !DispatchResult {
        return self.dispatchQuic(kind, incoming, sess, options);
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
            .request_message_size = messageSize(owned),
            .response_sink = &result,
            .reply_hook = options.reply_hook orelse self.reply_hook,
            .publish_hook = options.publish_hook orelse self.publish_hook,
        };

        try route.handler(&ctx, owned);
        return result;
    }

    fn dispatchRepErrorResult(
        self: *App,
        kind: RouteKind,
        request_subject: []const u8,
        request_id: message.MessageId,
        request_deadline_ms: ?u64,
        err: anyerror,
    ) !DispatchResult {
        switch (self.error_policy) {
            .propagate => return err,
            .reply_error => {
                if (kind != .rep) return err;

                var result = ResponseSink.init(self.allocator);
                errdefer result.deinit();
                try appendRepError(&result, request_subject, request_id, request_deadline_ms, err);
                return result;
            },
        }
    }

    pub fn dispatchConnect(self: *App, sess: ?*session.Session) !void {
        if (sess) |active| {
            try self.node.emit(.{ .connected = active.id });
        }
        try self.dispatchConnectHandler(sess);
    }

    fn dispatchConnectHandler(self: *App, sess: ?*session.Session) !void {
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
        try self.dispatchCloseHandler(sess);
    }

    fn dispatchCloseHandler(self: *App, sess: ?*session.Session) !void {
        const handler = self.close_handler orelse return;
        var ctx = Context{
            .app = self,
            .session = sess,
        };
        try handler(&ctx);
    }

    pub fn listenQuic(self: *App, addr: []const u8, tls: TlsConfig) !node.QuicListenerId {
        return self.node.listenQuic(addr, .{ .transport = tls.quic });
    }

    pub fn openQuicSession(self: *App, options: node.QuicSessionOptions) !*node.QuicSessionRuntime {
        const runtime = try self.node.openQuicSession(options);
        try self.dispatchConnectHandler(runtime.appSession());
        return runtime;
    }

    pub fn closeQuicSession(self: *App, id: session.SessionId) !void {
        const runtime = self.node.quicSession(id) orelse return error.EndpointNotFound;
        try self.dispatchCloseHandler(runtime.appSession());
        try self.node.closeQuicSession(id);
    }

    pub fn listenInprocRep(
        self: *App,
        network: *transport.inproc.Network,
        address: []const u8,
        options: InprocRepOptions,
    ) !node.InprocRepId {
        return self.node.listenInprocRep(network, address, .{
            .socket = options.socket,
            .session = options.session,
        });
    }

    pub fn runOnce(self: *App) !RunOnceResult {
        var dispatcher = InprocDispatcher{ .app = self };
        return self.node.runOnce(&dispatcher);
    }

    pub fn tick(self: *App, now_us: u64) !RunOnceResult {
        try self.node.tick(now_us);
        return self.runOnce();
    }

    pub fn run(self: *App) !void {
        while (true) {
            const result = try self.runOnce();
            if (!result.didWork()) break;
        }
    }
};

const InprocDispatcher = struct {
    app: *App,

    pub fn dispatchInprocRep(self: *@This(), endpoint: *node.InprocRepEndpoint) !bool {
        var request = (try endpoint.socket.tryRecv()) orelse return false;
        defer request.deinit();

        const incoming = try request.message.clone(self.app.allocator);
        var result = self.app.dispatchMessage(.rep, incoming, .{
            .session = &endpoint.session,
        }) catch |err| {
            try handleRepError(self.app, &endpoint.socket, request, err);
            return true;
        };
        defer result.deinit();

        for (result.replies.items) |reply| {
            try endpoint.socket.reply(request, reply.outgoing());
        }

        return true;
    }
};

fn handleRepError(self: *App, rep_socket: *socket.Socket(.rep), request: socket.Request, err: anyerror) !void {
    switch (self.error_policy) {
        .propagate => return err,
        .reply_error => return rep_socket.replyError(request, .{
            .code = @errorName(err),
            .message = @errorName(err),
        }),
    }
}

fn appendRepError(
    sink: *ResponseSink,
    request_subject: []const u8,
    request_id: message.MessageId,
    request_deadline_ms: ?u64,
    err: anyerror,
) !void {
    const headers = [_]message.Header{
        .{ .name = socket.ErrorReply.code_header, .value = @errorName(err) },
        .{ .name = socket.ErrorReply.message_header, .value = @errorName(err) },
    };

    try sink.appendReply(.{
        .subject = request_subject,
        .id = request_id,
        .deadline_ms = request_deadline_ms,
        .flags = .{ .err = true },
        .headers = &headers,
        .body = @errorName(err),
    });
}

fn authPattern(pattern: socket.Pattern) auth.Pattern {
    return switch (pattern) {
        .pair => .pair,
        .req => .req,
        .rep => .rep,
        .@"pub" => .@"pub",
        .sub => .sub,
        .push => .push,
        .pull => .pull,
    };
}

fn messageSize(msg: message.Message) usize {
    var total = msg.subject.len + msg.body.len;
    for (msg.headers) |header| {
        total += header.name.len + header.value.len;
    }
    return total;
}

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

test "App dispatchQuic routes REP reply with session auth" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Handler = struct {
        fn getUser(ctx: *Context, msg: message.Message) !void {
            var owned = msg;
            defer owned.deinit();

            try std.testing.expectEqual(session.TransportKind.quic, ctx.session.?.transport);
            try std.testing.expectEqual(socket.Pattern.rep, ctx.pattern.?);
            try ctx.requireRouteAccess();
            try ctx.reply(.{
                .subject = "",
                .body = "Ada",
            });
        }
    };

    var sess = session.Session{
        .id = 21,
        .transport = .quic,
    };
    sess.setAuthorization(.{
        .subject = "service:users",
        .issuer = "test",
        .allowed_patterns = auth.PatternSet.init(&.{.rep}),
        .allowed_subjects = .{ .filters = &.{"user.*"} },
    });

    try app.rep("user.*", Handler.getUser);

    const incoming = try message.Message.init(allocator, .{
        .subject = "user.get",
        .id = 42,
        .deadline_ms = 1234,
        .body = "id=42",
    });
    var result = try app.dispatchQuic(.rep, incoming, &sess, .{});
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.replies.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.publications.items.len);
    try std.testing.expectEqualStrings("user.get", result.replies.items[0].subject);
    try std.testing.expectEqual(@as(message.MessageId, 42), result.replies.items[0].id);
    try std.testing.expectEqual(@as(?u64, 1234), result.replies.items[0].deadline_ms);
    try std.testing.expectEqualStrings("Ada", result.replies.items[0].body);
}

test "App dispatchQuic default REP error policy returns ResponseSink error reply" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Handler = struct {
        fn needsAuth(ctx: *Context, msg: message.Message) !void {
            var owned = msg;
            defer owned.deinit();
            try ctx.requireRouteAccess();
        }
    };

    var sess = session.Session{
        .id = 22,
        .transport = .quic,
    };

    try app.rep("user.*", Handler.needsAuth);

    const incoming = try message.Message.init(allocator, .{
        .subject = "user.get",
        .id = 7,
        .deadline_ms = 500,
    });
    var result = try app.dispatchQuic(.rep, incoming, &sess, .{});
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.replies.items.len);
    const reply = result.replies.items[0];
    try std.testing.expect(reply.flags.err);
    try std.testing.expectEqualStrings("user.get", reply.subject);
    try std.testing.expectEqual(@as(message.MessageId, 7), reply.id);
    try std.testing.expectEqual(@as(?u64, 500), reply.deadline_ms);
    try std.testing.expectEqualStrings("AuthenticationRequired", reply.body);
    try std.testing.expectEqual(@as(usize, 2), reply.headers.len);
    try std.testing.expectEqualStrings(socket.ErrorReply.code_header, reply.headers[0].name);
    try std.testing.expectEqualStrings("AuthenticationRequired", reply.headers[0].value);
}

test "App dispatchQuic datagram route captures publications" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Handler = struct {
        fn presence(ctx: *Context, msg: message.Message) !void {
            var owned = msg;
            defer owned.deinit();

            try std.testing.expect(ctx.pattern == null);
            try std.testing.expectEqual(RouteKind.datagram, ctx.route_kind.?);
            try ctx.requireRouteAccess();
            try ctx.publish(.{
                .subject = "presence.seen",
                .body = owned.body,
            });
        }
    };

    var sess = session.Session{
        .id = 23,
        .transport = .quic,
        .datagram_enabled = true,
    };
    sess.setAuthorization(.{
        .subject = "service:presence",
        .issuer = "test",
        .allowed_subjects = .{ .filters = &.{"presence.*"} },
        .datagram_allowed = true,
    });

    try app.datagram("presence.*", Handler.presence);

    const incoming = try message.Message.init(allocator, .{
        .subject = "presence.ada",
        .body = "online",
        .flags = .{ .unreliable = true },
    });
    var result = try app.dispatchQuic(.datagram, incoming, &sess, .{});
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.replies.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.publications.items.len);
    try std.testing.expectEqualStrings("presence.seen", result.publications.items[0].subject);
    try std.testing.expectEqualStrings("online", result.publications.items[0].body);
}

test "App dispatchQuic no-route behavior follows reply error policy" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    var sess = session.Session{
        .id = 24,
        .transport = .quic,
    };

    const missing_rep = try message.Message.init(allocator, .{
        .subject = "missing.route",
        .id = 99,
    });
    var default_result = try app.dispatchQuic(.rep, missing_rep, &sess, .{});
    defer default_result.deinit();

    try std.testing.expectEqual(@as(usize, 1), default_result.replies.items.len);
    try std.testing.expect(default_result.replies.items[0].flags.err);
    try std.testing.expectEqualStrings("NoRoute", default_result.replies.items[0].body);

    app.setErrorPolicy(.propagate);
    const propagate_missing = try message.Message.init(allocator, .{
        .subject = "missing.route",
    });
    try std.testing.expectError(error.NoRoute, app.dispatchQuic(.rep, propagate_missing, &sess, .{}));

    const missing_datagram = try message.Message.init(allocator, .{
        .subject = "presence.missing",
    });
    try std.testing.expectError(error.NoRoute, app.dispatchQuic(.datagram, missing_datagram, &sess, .{}));
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

test "App listenQuic and QUIC session hooks are socket-free" {
    const allocator = std.testing.allocator;

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Recorder = struct {
        connects: usize = 0,
        closes: usize = 0,

        fn onConnect(ctx: *Context) !void {
            const recorder: *@This() = @ptrCast(@alignCast(ctx.session.?.user_data.?));
            recorder.connects += 1;
            try std.testing.expectEqual(session.TransportKind.quic, ctx.session.?.transport);
        }

        fn onClose(ctx: *Context) !void {
            const recorder: *@This() = @ptrCast(@alignCast(ctx.session.?.user_data.?));
            recorder.closes += 1;
            try std.testing.expectEqual(session.TransportKind.quic, ctx.session.?.transport);
        }
    };

    const listener_id = try app.listenQuic("127.0.0.1:4433", .{
        .quic = .{ .peer_id = "server-a" },
    });
    try std.testing.expectEqual(@as(node.QuicListenerId, 0), listener_id);
    try std.testing.expectEqual(transport.quic.State.listening, app.node.quic_listeners.items[listener_id].listener.state());

    var recorder = Recorder{};
    app.onConnect(Recorder.onConnect);
    app.onClose(Recorder.onClose);

    const runtime = try app.openQuicSession(.{
        .role = .server,
        .transport = .{
            .peer_id = "server-a",
            .datagram_enabled = true,
        },
        .user_data = @ptrCast(&recorder),
    });
    const id = runtime.id();

    try app.closeQuicSession(id);

    try std.testing.expectEqual(@as(usize, 1), recorder.connects);
    try std.testing.expectEqual(@as(usize, 1), recorder.closes);

    var events: [2]node.Event = undefined;
    try std.testing.expectEqual(@as(usize, 2), try app.node.poll(&events));
    try std.testing.expectEqual(id, events[0].connected);
    try std.testing.expectEqual(id, events[1].closed);
}

test "App runOnce serves real req rep through inproc facade with handler auth check" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Handler = struct {
        fn getUser(ctx: *Context, msg: message.Message) !void {
            var owned = msg;
            defer owned.deinit();

            try ctx.requireRouteAccess();
            try ctx.reply(.{
                .subject = "",
                .body = "Ada",
            });
        }
    };

    var sess = session.Session{
        .id = 41,
        .transport = .inproc,
    };
    sess.setAuthorization(.{
        .subject = "service:users",
        .issuer = "test",
        .allowed_patterns = auth.PatternSet.init(&.{.rep}),
        .allowed_subjects = .{ .filters = &.{"user.*"} },
    });

    try app.rep("user.*", Handler.getUser);
    _ = try app.listenInprocRep(&network, "users", .{ .session = sess });

    var req = try socket.Socket(.req).init(allocator, .{});
    defer req.deinit();
    try req.dialInproc(&network, "users");

    const id = try req.sendRequest(.{
        .subject = "user.get",
        .body = "42",
        .deadline_ms = 250,
    });

    const result = try app.runOnce();
    try std.testing.expect(result.didWork());

    var reply = try req.recv();
    defer reply.deinit();
    try std.testing.expectEqual(id, reply.id);
    try std.testing.expectEqual(@as(?u64, 250), reply.deadline_ms);
    try std.testing.expectEqualStrings("user.get", reply.subject);
    try std.testing.expectEqualStrings("Ada", reply.body);
    try std.testing.expect(!reply.flags.err);
}

test "App default inproc rep error policy returns message error replies" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var app = try App.init(allocator, .{});
    defer app.deinit();

    const Handler = struct {
        fn needsAuth(ctx: *Context, msg: message.Message) !void {
            var owned = msg;
            defer owned.deinit();
            try ctx.requireRouteAccess();
        }
    };

    try app.rep("user.*", Handler.needsAuth);
    _ = try app.listenInprocRep(&network, "users", .{});

    var req = try socket.Socket(.req).init(allocator, .{});
    defer req.deinit();
    try req.dialInproc(&network, "users");

    _ = try req.sendRequest(.{ .subject = "user.get" });

    const result = try app.runOnce();
    try std.testing.expect(result.didWork());

    var reply = try req.recv();
    defer reply.deinit();
    try std.testing.expect(reply.flags.err);
    try std.testing.expectEqualStrings("user.get", reply.subject);
    try std.testing.expectEqualStrings("AuthenticationRequired", reply.body);
}
