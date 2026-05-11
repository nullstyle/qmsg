const std = @import("std");
const qmsg = @import("qmsg");

// This example is intentionally inproc-only. The same socket pattern API is the
// shape QUIC should use later, but no QUIC listener is implied here.

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    if (comptime inprocSocketsReady()) {
        try runInprocPair(allocator);
        try runInprocReqRep(allocator);
    } else {
        showIntendedShape();
    }
}

fn inprocSocketsReady() bool {
    const Pair = qmsg.Socket(.pair);
    const Req = qmsg.Socket(.req);
    const Rep = qmsg.Socket(.rep);

    return @hasDecl(Pair, "deinit") and
        @hasDecl(Pair, "listen") and
        @hasDecl(Pair, "dial") and
        @hasDecl(Pair, "send") and
        @hasDecl(Pair, "recv") and
        @hasDecl(Req, "deinit") and
        @hasDecl(Req, "dial") and
        @hasDecl(Req, "request") and
        @hasDecl(Rep, "deinit") and
        @hasDecl(Rep, "listen") and
        @hasDecl(Rep, "recv") and
        @hasDecl(Rep, "reply");
}

fn showIntendedShape() void {
    const endpoint = "users";
    const request = qmsg.OutgoingMessage{
        .subject = "user.get",
        .headers = &.{
            .{ .name = "accept", .value = "application/json" },
        },
        .body = "user-42",
        .deadline_ms = 250,
    };

    std.debug.print(
        \\qmsg inproc example
        \\  endpoint: {s}
        \\  request:  {s} ({d} bytes)
        \\
        \\The socket workers have not landed the full inproc API in this checkout yet.
        \\Once Socket(.pair), Socket(.req), and Socket(.rep) expose listen/dial/send/recv/request/reply,
        \\this example will run the pair and req/rep paths below.
        \\
    , .{ endpoint, request.subject, request.body.len });
}

fn runInprocPair(allocator: std.mem.Allocator) !void {
    const Pair = qmsg.Socket(.pair);
    const queue = qmsg.QueueOptions{
        .max_messages = 8,
        .max_bytes = 64 * 1024,
        .on_full = .fail,
    };

    var network = qmsg.InprocNetwork.init(allocator);
    defer network.deinit();

    var left = try Pair.init(allocator, .{ .recv_queue = queue });
    defer left.deinit();

    var right = try Pair.init(allocator, .{ .recv_queue = queue });
    defer right.deinit();

    try left.listenInproc(&network, "pair-demo");
    try right.dialInproc(&network, "pair-demo");

    try left.send(.{
        .subject = "control.ping",
        .body = "ping",
        .deadline_ms = 100,
    });

    var received = try right.recv();
    defer received.deinit();

    std.debug.print("pair received {s}: {s}\n", .{ received.subject, received.body });
}

fn runInprocReqRep(allocator: std.mem.Allocator) !void {
    const Req = qmsg.Socket(.req);
    const Rep = qmsg.Socket(.rep);
    const queue = qmsg.QueueOptions{
        .max_messages = 16,
        .max_bytes = 128 * 1024,
        .on_full = .fail,
    };

    var network = qmsg.InprocNetwork.init(allocator);
    defer network.deinit();

    var rep = try Rep.init(allocator, .{ .recv_queue = queue });
    defer rep.deinit();

    var req = try Req.init(allocator, .{ .recv_queue = queue });
    defer req.deinit();

    try rep.listenInproc(&network, "users");
    try req.dialInproc(&network, "users");

    const id = try req.sendRequest(.{
        .subject = "user.get",
        .headers = &.{
            .{ .name = "accept", .value = "application/json" },
        },
        .body = "user-42",
        .deadline_ms = 250,
    });

    var request = try rep.recv();
    defer request.deinit();

    try rep.reply(request, .{
        .subject = "user.get.ok",
        .headers = &.{
            .{ .name = "content-type", .value = "application/json" },
        },
        .body = "{\"id\":\"user-42\",\"name\":\"Ada\"}",
    });

    var reply = try req.recv();
    defer reply.deinit();

    std.debug.assert(reply.id == id);
    std.debug.print("req/rep received {s}: {s}\n", .{ reply.subject, reply.body });
}
