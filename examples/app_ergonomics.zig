const std = @import("std");
const qmsg = @import("qmsg");

// App facade over inproc req/rep. QUIC listeners are the next integration
// layer, but the handler/runtime shape is the same.

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var network = qmsg.InprocNetwork.init(allocator);
    defer network.deinit();

    var app = try qmsg.App.init(allocator, .{});
    defer app.deinit();

    try app.rep("user.*", getUser);
    try app.pull("jobs.image.resize", resizeImage);
    try app.sub("metrics.*", observeMetric);

    var service_session = qmsg.Session{
        .id = 7,
        .transport = .inproc,
    };
    service_session.setAuthorization(.{
        .subject = "service:users",
        .issuer = "example",
        .allowed_patterns = qmsg.auth.PatternSet.init(&.{.rep}),
        .allowed_subjects = .{ .filters = &.{"user.*"} },
    });

    _ = try app.listenInprocRep(&network, "users", .{ .session = service_session });

    var req = try qmsg.Socket(.req).init(allocator, .{});
    defer req.deinit();
    try req.dialInproc(&network, "users");

    _ = try req.sendRequest(.{
        .subject = "user.get",
        .headers = &.{.{ .name = "accept", .value = "application/json" }},
        .body = "user-42",
        .deadline_ms = 250,
    });

    _ = try app.runOnce();

    var reply = try req.recv();
    defer reply.deinit();
    std.debug.print("app facade received {s}: {s}\n", .{ reply.subject, reply.body });
}

fn getUser(ctx: *qmsg.Context, msg: qmsg.Message) !void {
    var owned = msg;
    defer owned.deinit();

    try ctx.requireRouteAccess();

    try ctx.reply(.{
        .subject = "",
        .headers = &.{
            .{ .name = "content-type", .value = "application/json" },
        },
        .body = "{\"id\":\"user-42\",\"name\":\"Ada\"}",
    });
}

fn resizeImage(ctx: *qmsg.Context, msg: qmsg.Message) !void {
    var owned = msg;
    defer owned.deinit();
    _ = ctx;

    std.debug.print("resize job: {s} ({d} bytes)\n", .{ owned.subject, owned.body.len });
}

fn observeMetric(ctx: *qmsg.Context, msg: qmsg.Message) !void {
    var owned = msg;
    defer owned.deinit();
    _ = ctx;

    std.debug.print("metric: {s} = {s}\n", .{ owned.subject, owned.body });
}
