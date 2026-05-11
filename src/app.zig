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

pub const Context = struct {
    app: *App,
    session: ?*session.Session = null,
    pattern: ?socket.Pattern = null,

    pub fn allocator(self: *const Context) std.mem.Allocator {
        return self.app.allocator;
    }

    pub fn authorization(self: *const Context) ?*const @import("auth.zig").Authorization {
        const sess = self.session orelse return null;
        return if (sess.authorization) |*authz| authz else null;
    }

    pub fn reply(self: *Context, outgoing: message.OutgoingMessage) !void {
        _ = self;
        _ = outgoing;
        return error.InvalidState;
    }

    pub fn publish(self: *Context, outgoing: message.OutgoingMessage) !void {
        _ = self;
        _ = outgoing;
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
