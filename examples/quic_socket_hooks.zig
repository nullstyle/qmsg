const std = @import("std");
const qmsg = @import("qmsg");

const CapturedSend = struct {
    msg: qmsg.Message,
    meta: qmsg.QuicSendMeta,

    fn deinit(self: *CapturedSend) void {
        self.msg.deinit();
        self.* = undefined;
    }
};

const EmbeddableDriver = struct {
    allocator: std.mem.Allocator,
    sent: std.ArrayList(CapturedSend) = .empty,

    fn init(allocator: std.mem.Allocator) EmbeddableDriver {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *EmbeddableDriver) void {
        for (self.sent.items) |*captured| {
            captured.deinit();
        }
        self.sent.deinit(self.allocator);
    }

    fn session(self: *EmbeddableDriver) qmsg.QuicSocketSession {
        return .{
            .context = self,
            .send = EmbeddableDriver.send,
        };
    }

    fn send(context: *anyopaque, msg: qmsg.Message, meta: qmsg.QuicSendMeta) anyerror!void {
        const self: *EmbeddableDriver = @ptrCast(@alignCast(context));
        try self.sent.append(self.allocator, .{
            .msg = msg,
            .meta = meta,
        });
    }

    fn takeFirst(self: *EmbeddableDriver) CapturedSend {
        return self.sent.orderedRemove(0);
    }
};

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var req = try qmsg.Socket(.req).init(allocator, .{});
    defer req.deinit();

    var rep = try qmsg.Socket(.rep).init(allocator, .{});
    defer rep.deinit();

    var client_to_server = EmbeddableDriver.init(allocator);
    defer client_to_server.deinit();

    var server_to_client = EmbeddableDriver.init(allocator);
    defer server_to_client.deinit();

    try req.attachQuicSession(client_to_server.session());
    try rep.attachQuicSession(server_to_client.session());

    const id = try req.sendRequestAt(.{
        .subject = "user.get",
        .headers = &.{.{ .name = "accept", .value = "application/json" }},
        .deadline_ms = 250,
        .body = "user-42",
    }, 10_000);

    var outbound_request = client_to_server.takeFirst();
    defer outbound_request.deinit();

    try expectMeta(outbound_request.meta, .{
        .local_pattern = .req,
        .peer_pattern = .rep,
        .operation = qmsg.protocol.Operation.request,
        .delivery = .reliable,
        .id = id,
        .deadline_ms = 250,
        .subject = "user.get",
    });

    try rep.receiveQuicMessage(try outbound_request.msg.clone(allocator));

    var request = try rep.recv();
    defer request.deinit();

    try rep.reply(request, .{
        .subject = "user.get.ok",
        .headers = &.{.{ .name = "content-type", .value = "application/json" }},
        .body = "{\"id\":\"user-42\",\"name\":\"Ada\"}",
    });

    var outbound_reply = server_to_client.takeFirst();
    defer outbound_reply.deinit();

    try expectMeta(outbound_reply.meta, .{
        .local_pattern = .rep,
        .peer_pattern = .req,
        .operation = qmsg.protocol.Operation.reply,
        .delivery = .reliable,
        .id = id,
        .deadline_ms = 250,
        .subject = "user.get.ok",
    });

    try req.receiveQuicMessage(try outbound_reply.msg.clone(allocator));

    var reply = try req.recvAt(10_100);
    defer reply.deinit();

    std.debug.print("socket hook req/rep received {s}: {s}\n", .{ reply.subject, reply.body });
}

fn expectMeta(actual: qmsg.QuicSendMeta, expected: qmsg.QuicSendMeta) !void {
    if (actual.local_pattern != expected.local_pattern) return error.UnexpectedMeta;
    if (actual.peer_pattern != expected.peer_pattern) return error.UnexpectedMeta;
    if (actual.operation != expected.operation) return error.UnexpectedMeta;
    if (actual.delivery != expected.delivery) return error.UnexpectedMeta;
    if (actual.id != expected.id) return error.UnexpectedMeta;
    if (actual.deadline_ms != expected.deadline_ms) return error.UnexpectedMeta;
    if (!std.mem.eql(u8, actual.subject, expected.subject)) return error.UnexpectedMeta;
}
