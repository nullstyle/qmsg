//! Public standalone Node client + App route server over localhost UDP.
//! The application owns clock, pump, event drain, readiness wait, and teardown.
const std = @import("std");
const qmsg = @import("qmsg");
const tls = @import("local_tls_fixture.zig");
const owner = @import("owner_wait.zig");

pub fn main(init: std.process.Init) !void {
    if (init.environ_map.get("QMSG_RUN_LIVE_UDP") == null) {
        std.debug.print("set QMSG_RUN_LIVE_UDP=1 to run the localhost Node/App example\n", .{});
        return;
    }
    var app = try qmsg.App.init(init.gpa, .{ .node = .{ .io = init.io } });
    defer app.deinit();
    try app.rep("user.*", getUser);
    const listener = try app.listenQuic("127.0.0.1:0", .{ .cert_pem = tls.cert, .key_pem = tls.key, .quic = .{
        .supported_patterns = qmsg.control.PatternBits.rep,
        .required_peer_patterns = qmsg.control.PatternBits.req,
    } });
    const address = try app.quicListenerAddress(listener);
    var endpoint: [64]u8 = undefined;
    const target = try std.fmt.bufPrint(&endpoint, "127.0.0.1:{d}", .{address.ip4.port});
    // Node keeps a stable address from dial until deinit. Only it consumes its
    // canonical events; App consumes its own legacy dispatcher internally.
    var client = try qmsg.Node.init(init.gpa, .{ .io = init.io });
    defer client.deinit();
    const session = try client.dialQuic(target, .{ .server_name = "localhost", .ca_pem = tls.cert, .transport = .{
        .supported_patterns = qmsg.control.PatternBits.req,
        .required_peer_patterns = qmsg.control.PatternBits.rep,
    } });
    const stop_at = owner.nowUs(init.io) + 15_000_000;
    var sent: ?qmsg.node.RequestId = null;
    while (owner.nowUs(init.io) < stop_at) {
        const now = owner.nowUs(init.io);
        try client.tick(now);
        const app_result = try app.tick(now);
        var did_work = app_result.didWork();
        if (sent == null) if (client.sessionStatus(session)) |status| {
            if (status.state == .ready) {
                sent = try client.request(.{ .quic = session }, .{
                    .subject = "user.get",
                    .body = "user-42",
                    .deadline_ms = 2000,
                });
                did_work = true;
            }
        };
        var events: [16]qmsg.NodeEvent = undefined;
        const count = try client.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        did_work = did_work or count > 0;
        for (events[0..count]) |event| switch (event) {
            .reply => |reply| {
                if (reply.request_id != sent.?) return error.UnexpectedReply;
                if (reply.msg.flags.err) return error.RemoteFailure;
                std.debug.print("Node/App QUIC reply: {s}\n", .{reply.msg.body});
                return;
            },
            .request_failed => return error.RequestFailed,
            else => {},
        };
        // A mutation queues work; events created by the next pump must also
        // be polled before waiting. Park only after a quiet serving iteration.
        if (did_work) continue;
        var handles: [16]std.Io.net.Socket.Handle = undefined;
        var used = try client.readableSockets(&handles);
        used += try app.readableSockets(handles[used..]);
        const deadline = owner.earliest(owner.earliest(client.nextTimer(), app.nextTimer()), stop_at).?;
        try owner.wait(init.io, handles[0..used], deadline);
    }
    return error.DemoTimeout;
}

fn getUser(ctx: *qmsg.Context, incoming: qmsg.Message) !void {
    var msg = incoming;
    defer msg.deinit();
    try ctx.reply(.{ .subject = "", .body = "Ada" });
}
