//! Movable owned Req/Rep handles, explicit pump and a deferred reply.
const std = @import("std");
const qmsg = @import("qmsg");
const tls = @import("local_tls_fixture.zig");
const owner = @import("owner_wait.zig");

pub fn main(init: std.process.Init) !void {
    if (init.environ_map.get("QMSG_RUN_LIVE_UDP") == null) {
        std.debug.print("set QMSG_RUN_LIVE_UDP=1 to run the owned QUIC example\n", .{});
        return;
    }
    var req = try qmsg.QuicSocket(.req).init(init.gpa, .{ .node = .{ .io = init.io } });
    defer req.deinit();
    var rep = try qmsg.QuicSocket(.rep).init(init.gpa, .{ .node = .{ .io = init.io } });
    defer rep.deinit();
    const listener = try rep.listen("127.0.0.1:0", .{ .tls_cert_pem = tls.cert, .tls_key_pem = tls.key });
    const address = try rep.localAddress(listener);
    var endpoint: [64]u8 = undefined;
    const target = try std.fmt.bufPrint(&endpoint, "127.0.0.1:{d}", .{address.ip4.port});
    const session = try req.dial(target, .{ .server_name = "localhost", .ca_pem = tls.cert });
    const stop_at = owner.nowUs(init.io) + 15_000_000;
    var sent: ?qmsg.node.RequestId = null;
    var deferred: ?qmsg.ReplyHandle = null;
    defer if (deferred) |*handle| handle.deinit();
    while (owner.nowUs(init.io) < stop_at) {
        const now = owner.nowUs(init.io);
        var did_work = false;
        try req.pump(now);
        try rep.pump(now);
        if (sent == null) if (req.sessionStatus(session)) |status| {
            if (status.state == .ready) {
                sent = try req.request(session, .{ .subject = "echo", .body = "hello", .deadline_ms = 2000 });
                did_work = true;
            }
        };
        {
            var events: [16]qmsg.NodeEvent = undefined;
            const count = try rep.poll(&events);
            did_work = did_work or count > 0;
            defer for (events[0..count]) |*event| event.deinit();
            for (events[0..count]) |event| if (event == .request) {
                // Keep the route after the entire message/event batch is freed.
                deferred = event.request.msg.reply_handle.?.retain();
            };
        }
        if (deferred) |handle| try rep.reply(handle, .{ .subject = "", .body = "deferred hello" });
        if (deferred) |*handle| {
            handle.deinit();
            deferred = null;
        }
        var events: [16]qmsg.NodeEvent = undefined;
        const count = try req.poll(&events);
        did_work = did_work or count > 0;
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| switch (event) {
            .reply => |reply| {
                if (reply.request_id != sent.?) return error.UnexpectedReply;
                if (reply.msg.flags.err) return error.RemoteFailure;
                std.debug.print("owned QUIC reply: {s}\n", .{reply.msg.body});
                return;
            },
            .request_failed => return error.RequestFailed,
            else => {},
        };
        // Flush mutations and consume any resulting events on the next turn;
        // nextTimer is a deadline source, not a local application work queue.
        if (did_work) continue;
        var handles: [16]std.Io.net.Socket.Handle = undefined;
        var used = try req.readableSockets(&handles);
        used += try rep.readableSockets(handles[used..]);
        const deadline = owner.earliest(owner.earliest(req.nextTimer(), rep.nextTimer()), stop_at).?;
        try owner.wait(init.io, handles[0..used], deadline);
    }
    return error.DemoTimeout;
}
