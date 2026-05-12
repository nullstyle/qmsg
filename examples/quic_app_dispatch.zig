const std = @import("std");
const qmsg = @import("qmsg");

// Hermetic App-over-QUIC example. A transport driver has already decoded qmsg
// messages from QUIC streams/datagrams and hands owned Message values to App.

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = try qmsg.App.init(allocator, .{});
    defer app.deinit();

    try app.rep("user.*", getUser);
    try app.datagram("presence.*", observePresence);

    const runtime = try app.openQuicSession(.{
        .role = .server,
        .transport = .{
            .peer_id = "app-server",
            .role_flags = qmsg.control.RoleFlags.server,
            .supported_patterns = qmsg.control.PatternBits.rep,
            .datagram_enabled = true,
        },
    });
    const session_id = runtime.id();
    defer app.closeQuicSession(session_id) catch {};

    const request = try qmsg.Message.init(allocator, .{
        .subject = "user.get",
        .id = 42,
        .deadline_ms = 250,
        .headers = &.{.{ .name = "accept", .value = "application/json" }},
        .body = "user-42",
    });

    var reliable = try app.dispatchQuicReliable(.rep, request, runtime.appSession(), .{});
    defer reliable.deinit();
    if (reliable.replies.items.len != 1) return error.InvalidState;

    const reply = reliable.replies.items[0];
    std.debug.print("app QUIC reliable reply {s}: {s}\n", .{ reply.subject, reply.body });

    const datagram = try qmsg.Message.init(allocator, .{
        .subject = "presence.ada",
        .body = "online",
    });

    var datagram_result = try app.dispatchQuicDatagram(datagram, runtime.appSession(), .{});
    defer datagram_result.deinit();
    if (datagram_result.publications.items.len != 1) return error.InvalidState;

    const publication = datagram_result.publications.items[0];
    std.debug.print("app QUIC datagram publication {s}: {s}\n", .{ publication.subject, publication.body });
}

fn getUser(ctx: *qmsg.Context, msg: qmsg.Message) !void {
    var owned = msg;
    defer owned.deinit();

    try ctx.reply(.{
        .subject = "",
        .headers = &.{.{ .name = "content-type", .value = "application/json" }},
        .body = "{\"id\":\"user-42\",\"name\":\"Ada\"}",
    });
}

fn observePresence(ctx: *qmsg.Context, msg: qmsg.Message) !void {
    var owned = msg;
    defer owned.deinit();

    try ctx.publish(.{
        .subject = owned.subject,
        .body = owned.body,
    });
}
