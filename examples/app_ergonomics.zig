const std = @import("std");
const qmsg = @import("qmsg");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var app = try qmsg.App.init(allocator, .{});
    defer app.deinit();

    if (comptime appFacadeReady()) {
        try installRoutes(&app);
        std.debug.print("qmsg app facade routes registered\n", .{});
    } else {
        printRoutePlan(&.{
            .{
                .pattern = .rep,
                .subject_filter = "user.get",
                .handler_name = "getUser",
                .queue = .{ .max_messages = 32, .max_bytes = 512 * 1024, .on_full = .fail },
            },
            .{
                .pattern = .pull,
                .subject_filter = "jobs.image.resize",
                .handler_name = "resizeImage",
                .queue = .{ .max_messages = 64, .max_bytes = 8 * 1024 * 1024, .on_full = .block },
            },
            .{
                .pattern = .sub,
                .subject_filter = "metrics.*",
                .handler_name = "observeMetric",
                .queue = .{ .max_messages = 256, .max_bytes = 2 * 1024 * 1024, .on_full = .drop_oldest },
            },
        }, .{
            .required = true,
            .max_token_bytes = 4096,
            .max_clock_skew_ms = 30_000,
        });
    }
}

const RoutePlan = struct {
    pattern: qmsg.Pattern,
    subject_filter: []const u8,
    handler_name: []const u8,
    queue: qmsg.QueueOptions,
};

fn appFacadeReady() bool {
    return @hasDecl(qmsg.App, "rep") and
        @hasDecl(qmsg.App, "pull") and
        @hasDecl(qmsg.App, "sub") and
        @hasDecl(qmsg.Context, "reply");
}

fn printRoutePlan(routes: []const RoutePlan, auth: qmsg.AuthConfig) void {
    std.debug.print(
        \\qmsg app facade example
        \\  auth required: {}
        \\  token cap:     {d} bytes
        \\
    , .{ auth.required, auth.max_token_bytes });

    for (routes) |route| {
        std.debug.print(
            "  {s: <4} {s: <24} -> {s} (queue {d} msgs, {d} bytes, on_full={s})\n",
            .{
                @tagName(route.pattern),
                route.subject_filter,
                route.handler_name,
                route.queue.max_messages,
                route.queue.max_bytes,
                @tagName(route.queue.on_full),
            },
        );
    }

    std.debug.print(
        \\
        \\The App facade is intentionally thin: it registers message handlers by
        \\pattern and subject filter, then delegates transport and backpressure
        \\behavior to qmsg Node and Socket internals. It is not an HTTP/3 router.
        \\
    , .{});
}

fn installRoutes(app: *qmsg.App) !void {
    try app.rep("user.get", getUser);
    try app.pull("jobs.image.resize", resizeImage);
    try app.sub("metrics.*", observeMetric);
}

fn getUser(ctx: *qmsg.Context, msg: qmsg.Message) !void {
    var owned = msg;
    defer owned.deinit();

    try ctx.reply(.{
        .subject = "user.get",
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
