//! Executable public owned-socket contract. No raw Node/runtime access.
const std = @import("std");
const owned = @import("quic_socket.zig");
const node = @import("node.zig");
const message = @import("message.zig");
const protocol = @import("protocol/root.zig");
const transport = @import("transport/quic.zig");
const auth = @import("auth.zig");

const cert = @embedFile("testdata/test_cert.pem");
const key = @embedFile("testdata/test_key.pem");
const a = std.testing.allocator;

fn skipNoUdp(err: anyerror) !void {
    return switch (err) {
        error.AccessDenied,
        error.PermissionDenied,
        error.AddressInUse,
        error.AddressNotAvailable,
        error.NetworkSubsystemFailed,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        => error.SkipZigTest,
        else => err,
    };
}

const Settings = struct {
    left: owned.Options = .{},
    right: owned.Options = .{},
    left_transport: transport.QuicOptions = .{},
    right_transport: transport.QuicOptions = .{},
};

fn Peers(comptime left_pattern: protocol.Pattern, comptime right_pattern: protocol.Pattern) type {
    return struct {
        const Self = @This();
        left: owned.Socket(left_pattern),
        right: owned.Socket(right_pattern),
        left_session: node.QuicSessionId,
        right_session: ?node.QuicSessionId = null,
        listener: node.QuicListenerId,
        now_us: u64 = 1000,
        left_up: bool = true,
        right_up: bool = true,

        fn init(settings: Settings) !Self {
            var left = try owned.Socket(left_pattern).init(a, settings.left);
            errdefer left.deinit();
            var right = try owned.Socket(right_pattern).init(a, settings.right);
            errdefer right.deinit();
            const listener = try right.listen("127.0.0.1:0", .{ .tls_cert_pem = cert, .tls_key_pem = key, .transport = settings.right_transport });
            const address = try right.localAddress(listener);
            var endpoint: [64]u8 = undefined;
            const target = try std.fmt.bufPrint(&endpoint, "127.0.0.1:{d}", .{address.ip4.port});
            const session = try left.dial(target, .{ .server_name = "localhost", .ca_pem = cert, .transport = settings.left_transport });
            // Handles move after listen/dial; the owned Nodes remain stable.
            return .{ .left = left, .right = right, .listener = listener, .left_session = session };
        }

        fn deinit(self: *Self) void {
            if (self.left_up) self.left.deinit();
            if (self.right_up) self.right.deinit();
        }

        fn step(self: *Self) !void {
            self.now_us += 1000;
            try self.left.pump(self.now_us);
            try self.right.pump(self.now_us);
        }

        fn ready(self: *Self) !void {
            for (0..6000) |_| {
                try self.step();
                var events: [16]node.Event = undefined;
                var count = try self.right.poll(&events);
                for (events[0..count]) |*event| {
                    defer event.deinit();
                    if (event.* == .connected) self.right_session = event.connected;
                }
                count = try self.left.poll(&events);
                for (events[0..count]) |*event| event.deinit();
                const l = self.left.sessionStatus(self.left_session);
                const r = if (self.right_session) |id| self.right.sessionStatus(id) else null;
                if (l != null and r != null and l.?.state == .ready and r.?.state == .ready) return;
            }
            return error.ReadinessTimeout;
        }
    };
}

test "owned QUIC: req rep public pump preserves concurrent IDs and deferred replies after moves" {
    var peers = Peers(.req, .rep).init(.{}) catch |err| return skipNoUdp(err);
    defer peers.deinit();
    try peers.ready();
    var handles: [8]message.ReplyHandle = undefined;
    var kept: usize = 0;
    defer for (handles[0..kept]) |*handle| handle.deinit();
    var request_ids: [8]node.RequestId = undefined;
    for (&request_ids, 0..) |*id, i| id.* = try peers.left.request(peers.left_session, .{ .subject = "echo", .id = 10 + i, .body = "deferred", .deadline_ms = 2000 });
    for (0..1000) |_| {
        try peers.step();
        var events: [16]node.Event = undefined;
        const count = try peers.right.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| if (event == .request) {
            try std.testing.expect(kept < handles.len);
            handles[kept] = event.request.msg.reply_handle.?.retain();
            kept += 1;
        };
        if (kept == handles.len) break;
    }
    try std.testing.expectEqual(handles.len, kept);
    // Reply out of order after each request's event/body was released.
    var i: usize = kept;
    while (i > 0) {
        i -= 1;
        try peers.right.reply(handles[i], .{ .subject = "", .body = "after event release" });
    }
    var seen: [8]bool = @splat(false);
    var replies: usize = 0;
    for (0..1500) |_| {
        try peers.step();
        var events: [16]node.Event = undefined;
        const count = try peers.left.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| switch (event) {
            .reply => |reply| {
                var matched = false;
                for (request_ids, 0..) |id, index| if (id == reply.request_id) {
                    try std.testing.expect(!seen[index]);
                    try std.testing.expectEqual(@as(u64, 10 + index), reply.msg.id);
                    try std.testing.expectEqualStrings("after event release", reply.msg.body);
                    seen[index] = true;
                    matched = true;
                };
                try std.testing.expect(matched);
                replies += 1;
            },
            .request_failed => return error.UnexpectedFailure,
            else => {},
        };
        if (replies == request_ids.len) break;
    }
    try std.testing.expectEqual(request_ids.len, replies);
    try std.testing.expectError(error.InvalidState, peers.right.reply(handles[0], .{ .subject = "", .body = "duplicate" }));
}

test "owned QUIC: pair is bidirectional delivery with complete borrowed readiness handles" {
    var peers = Peers(.pair, .pair).init(.{}) catch |err| return skipNoUdp(err);
    defer peers.deinit();
    try peers.ready();
    var handles: [2]std.Io.net.Socket.Handle = @splat(-1);
    try std.testing.expectEqual(@as(usize, 1), try peers.left.readableSockets(&handles));
    try std.testing.expectEqual(@as(usize, 1), try peers.right.readableSockets(&handles));
    var empty: [0]std.Io.net.Socket.Handle = .{};
    try std.testing.expectError(error.BufferTooSmall, peers.right.readableSockets(&empty));
    try std.testing.expectError(error.TooManyListeners, peers.right.listen("127.0.0.1:0", .{ .tls_cert_pem = cert, .tls_key_pem = key }));
    try peers.left.send(peers.left_session, .{ .subject = "left", .body = "one" });
    try peers.right.send(peers.right_session.?, .{ .subject = "right", .body = "two" });
    var deliveries: usize = 0;
    for (0..1000) |_| {
        try peers.step();
        inline for (.{ &peers.left, &peers.right }) |peer| {
            var events: [8]node.Event = undefined;
            const count = try peer.poll(&events);
            defer for (events[0..count]) |*event| event.deinit();
            for (events[0..count]) |event| switch (event) {
                .delivery => |delivery| {
                    try std.testing.expect(delivery.msg.flags.no_reply);
                    try std.testing.expect(delivery.msg.reply_handle == null);
                    deliveries += 1;
                },
                .request, .reply, .request_failed => return error.WrongPairEvent,
                else => {},
            };
        }
        if (deliveries == 2) break;
    }
    try std.testing.expectEqual(@as(usize, 2), deliveries);
}

test "owned QUIC: identical req or rep roles fail HELLO instead of accepting unusable sessions" {
    inline for (.{ protocol.Pattern.req, protocol.Pattern.rep }) |pattern| {
        var peers = Peers(pattern, pattern).init(.{}) catch |err| return skipNoUdp(err);
        defer peers.deinit();
        for (0..400) |_| {
            try peers.step();
            if (peers.left.sessionStatus(peers.left_session)) |status| try std.testing.expect(status.state != .ready);
            var events: [8]node.Event = undefined;
            const count = try peers.right.poll(&events);
            defer for (events[0..count]) |*event| event.deinit();
            for (events[0..count]) |event| switch (event) {
                .connected => |id| if (peers.right.sessionStatus(id)) |status| {
                    try std.testing.expect(status.state != .ready);
                },
                .request, .reply, .delivery => return error.IncompatibleRolesDeliveredData,
                else => {},
            };
        }
    }
}

test "owned QUIC: cancellation deadline close and unread outcomes share one bounded tracker" {
    var peers = Peers(.req, .rep).init(.{ .left = .{ .node = .{ .max_events = 0, .max_requests = 2 } } }) catch |err| return skipNoUdp(err);
    defer peers.deinit();
    try peers.ready();
    const canceled = try peers.left.request(peers.left_session, .{ .subject = "cancel", .deadline_ms = 1000 });
    const expired = try peers.left.request(peers.left_session, .{ .subject = "expire", .deadline_ms = 20 });
    try std.testing.expectError(error.TooManyInflightRequests, peers.left.request(peers.left_session, .{ .subject = "over capacity" }));
    try std.testing.expect(try peers.left.cancelRequest(canceled));
    try std.testing.expect(!try peers.left.cancelRequest(canceled));
    // Cancellation retains its reservation until its outcome is consumed.
    try std.testing.expectError(error.TooManyInflightRequests, peers.left.request(peers.left_session, .{ .subject = "still full" }));
    var canceled_event = peers.left.takeOutcome(canceled).?;
    defer canceled_event.deinit();
    try std.testing.expectEqual(node.RequestFailure.canceled, canceled_event.request_failed.failure);
    var late: ?message.ReplyHandle = null;
    defer if (late) |*handle| handle.deinit();
    for (0..50) |_| {
        try peers.step();
        var events: [8]node.Event = undefined;
        const count = try peers.right.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| if (event == .request) {
            try std.testing.expectEqualStrings("expire", event.request.msg.subject);
            late = event.request.msg.reply_handle.?.retain();
        };
    }
    try std.testing.expect(late != null);
    var expired_event = peers.left.takeOutcome(expired).?;
    defer expired_event.deinit();
    try std.testing.expectEqual(node.RequestFailure.deadline_exceeded, expired_event.request_failed.failure);
    try std.testing.expect(peers.left.takeOutcome(expired) == null);
    // A late server reply cannot recreate the already-consumed outcome.
    try peers.right.reply(late.?, .{ .subject = "", .body = "too late" });
    const fresh = try peers.left.request(peers.left_session, .{ .subject = "fresh", .deadline_ms = 1000 });
    var fresh_replies: usize = 0;
    for (0..1000) |_| {
        try peers.step();
        var events: [8]node.Event = undefined;
        var count = try peers.right.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            if (event.* == .request) try peers.right.reply(event.request.msg.reply_handle.?, .{ .subject = "", .body = "fresh reply" });
        }
        count = try peers.left.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| switch (event) {
            .reply => |reply| {
                try std.testing.expectEqual(fresh, reply.request_id);
                fresh_replies += 1;
            },
            .request_failed => return error.DuplicateOrFreshFailure,
            else => {},
        };
        if (fresh_replies == 1) break;
    }
    try std.testing.expectEqual(@as(usize, 1), fresh_replies);
    const closed = try peers.left.request(peers.left_session, .{ .subject = "close", .deadline_ms = 10000 });
    try peers.left.closeSession(peers.left_session);
    var closed_event = peers.left.takeOutcome(closed).?;
    defer closed_event.deinit();
    try std.testing.expectEqual(node.RequestFailure.peer_closed, closed_event.request_failed.failure);
    try std.testing.expect(peers.left.takeOutcome(closed) == null);
}

test "owned QUIC: queue refusal and two-stream windows retain every admitted request" {
    const limits: transport.QuicOptions = .{ .initial_max_streams_bidi = 2, .initial_max_streams_uni = 4, .max_queued_messages = 24, .max_message_size = 4096, .max_queued_bytes = 128 * 1024 };
    var peers = Peers(.req, .rep).init(.{ .left = .{ .node = .{ .max_requests = 64 } }, .right = .{ .node = .{ .max_events = 1, .max_event_bytes = 4096 } }, .left_transport = limits, .right_transport = limits }) catch |err| return skipNoUdp(err);
    defer peers.deinit();
    try peers.ready();
    var ids: [24]node.RequestId = undefined;
    for (&ids, 0..) |*id, i| id.* = try peers.left.request(peers.left_session, .{ .subject = "burst", .id = 100 + i, .deadline_ms = 10000 });
    try std.testing.expectError(error.QueueFull, peers.left.request(peers.left_session, .{ .subject = "rejected", .id = 1000 }));
    var seen: [24]bool = @splat(false);
    var replies: usize = 0;
    for (0..4000) |_| {
        try peers.step();
        var events: [32]node.Event = undefined;
        var count = try peers.right.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            if (event.* == .request) {
                try std.testing.expectEqualStrings("burst", event.request.msg.subject);
                try peers.right.reply(event.request.msg.reply_handle.?, .{ .subject = "", .body = "ok" });
            }
        }
        count = try peers.left.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| switch (event) {
            .reply => |reply| {
                var matched = false;
                for (ids, 0..) |id, i| if (id == reply.request_id) {
                    try std.testing.expect(!seen[i]);
                    seen[i] = true;
                    matched = true;
                    replies += 1;
                };
                try std.testing.expect(matched);
            },
            .request_failed => return error.PressureLostAcceptedRequest,
            else => {},
        };
        if (replies == ids.len) break;
    }
    try std.testing.expectEqual(ids.len, replies);
    const fresh = try peers.left.request(peers.left_session, .{ .subject = "after burst", .id = 2000 });
    try std.testing.expect(try peers.left.cancelRequest(fresh));
    var outcome = peers.left.takeOutcome(fresh).?;
    defer outcome.deinit();
    try std.testing.expectEqual(node.RequestFailure.canceled, outcome.request_failed.failure);
    try std.testing.expectEqual(@as(usize, 0), peers.right.stats().dropped);
}

test "owned QUIC: completion byte pressure preserves a failure and releases its reservation" {
    var peers = Peers(.req, .rep).init(.{ .left = .{ .node = .{ .max_completion_bytes = 4, .max_requests = 1 } } }) catch |err| return skipNoUdp(err);
    defer peers.deinit();
    try peers.ready();
    const id = try peers.left.request(peers.left_session, .{ .subject = "large reply", .deadline_ms = 1000 });
    var failure: ?node.Event = null;
    defer if (failure) |*event| event.deinit();
    for (0..1000) |_| {
        try peers.step();
        var events: [8]node.Event = undefined;
        const count = try peers.right.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| if (event == .request) {
            try peers.right.reply(event.request.msg.reply_handle.?, .{ .subject = "", .body = "cannot fit in four bytes" });
        };
        // poll with no output still transfers a completed reply into its
        // reserved terminal queue, preserving pressure classification.
        var none: [0]node.Event = .{};
        _ = try peers.left.poll(&none);
        failure = peers.left.takeOutcome(id);
        if (failure != null) break;
    }
    try std.testing.expect(failure != null);
    try std.testing.expectEqual(node.RequestFailure.queue_full, failure.?.request_failed.failure);
    try std.testing.expectEqual(id, failure.?.request_failed.request_id);
    try std.testing.expect(peers.left.takeOutcome(id) == null);
    _ = try peers.left.request(peers.left_session, .{ .subject = "reservation released" });
}

test "owned QUIC: a listening req originates requests on its accepted session" {
    var peers = Peers(.rep, .req).init(.{}) catch |err| return skipNoUdp(err);
    defer peers.deinit();
    try peers.ready();
    const id = try peers.right.request(peers.right_session.?, .{ .subject = "reverse", .deadline_ms = 1000 });
    for (0..1000) |_| {
        try peers.step();
        var events: [8]node.Event = undefined;
        var count = try peers.left.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            if (event.* == .request) try peers.left.reply(event.request.msg.reply_handle.?, .{ .subject = "", .body = "dialed rep answered" });
        }
        count = try peers.right.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| switch (event) {
            .reply => |reply| {
                try std.testing.expectEqual(id, reply.request_id);
                try std.testing.expectEqualStrings("dialed rep answered", reply.msg.body);
                return;
            },
            .request_failed => return error.ReverseRequestFailed,
            else => {},
        };
    }
    return error.ReverseReplyMissing;
}

test "owned QUIC: retained reply handles fail safely after the facade owner is destroyed" {
    var peers = Peers(.req, .rep).init(.{}) catch |err| return skipNoUdp(err);
    defer peers.deinit();
    try peers.ready();
    _ = try peers.left.request(peers.left_session, .{ .subject = "retained" });
    var retained: ?message.ReplyHandle = null;
    defer if (retained) |*handle| handle.deinit();
    for (0..1000) |_| {
        try peers.step();
        var events: [8]node.Event = undefined;
        const count = try peers.right.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| if (event == .request) {
            retained = event.request.msg.reply_handle.?.retain();
        };
        if (retained != null) break;
    }
    try std.testing.expect(retained != null);
    peers.right.deinit();
    peers.right_up = false;
    try std.testing.expectError(error.EndpointClosed, retained.?.reply(.{ .subject = "", .body = "owner gone" }));
}

// Fixture credentials exercise the public authenticator contract; cryptographic
// verification is covered separately by the PASETO suite.
fn roleGrant(_: ?*anyopaque, allocator: std.mem.Allocator, credential: auth.Credential) !auth.Authorization {
    const role: auth.Pattern = if (std.mem.eql(u8, credential.token, "req")) .req else if (std.mem.eql(u8, credential.token, "rep")) .rep else if (std.mem.eql(u8, credential.token, "pair")) .pair else return error.Unauthorized;
    return (auth.Authorization{
        .subject = "fixture-peer",
        .issuer = "fixture",
        .allowed_patterns = auth.PatternSet.init(&.{role}),
        .allowed_subjects = .{ .filters = &.{"allowed.>"} },
    }).clone(allocator);
}

fn authenticatedTransport(comptime role: []const u8) transport.QuicOptions {
    return .{
        .auth = .{ .scheme = auth.hello_auth_scheme_paseto, .credential = role },
        .auth_config = .{ .required = true, .authenticator = .{ .authenticate_fn = roleGrant } },
    };
}

test "owned QUIC: authenticated req rep use minimal peer grants and deny subjects" {
    var peers = Peers(.req, .rep).init(.{ .left_transport = authenticatedTransport("req"), .right_transport = authenticatedTransport("rep") }) catch |err| return skipNoUdp(err);
    defer peers.deinit();
    try peers.ready();
    const allowed = try peers.left.request(peers.left_session, .{ .subject = "allowed.echo", .body = "minimal grants" });
    const denied = try peers.left.request(peers.left_session, .{ .subject = "forbidden.echo" });
    var admitted: usize = 0;
    var completed: usize = 0;
    for (0..2000) |_| {
        try peers.step();
        var events: [8]node.Event = undefined;
        var count = try peers.right.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            if (event.* == .request) {
                try std.testing.expectEqualStrings("allowed.echo", event.request.msg.subject);
                admitted += 1;
                try peers.right.reply(event.request.msg.reply_handle.?, .{ .subject = "", .body = "authorized" });
            }
        }
        count = try peers.left.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |*event| {
            if (event.* == .reply) {
                if (event.reply.request_id == allowed) {
                    try std.testing.expect(!event.reply.msg.flags.err);
                    try std.testing.expectEqualStrings("authorized", event.reply.msg.body);
                } else {
                    try std.testing.expectEqual(denied, event.reply.request_id);
                    try std.testing.expect(event.reply.msg.flags.err);
                    try std.testing.expectEqualStrings("Unauthorized", event.reply.msg.body);
                }
                completed += 1;
            } else if (event.* == .request_failed) return error.UnexpectedFailure;
        }
        if (completed == 2) break;
    }
    try std.testing.expectEqual(@as(usize, 1), admitted);
    try std.testing.expectEqual(@as(usize, 2), completed);
}

test "owned QUIC: authenticated pair grant permits delivery and wrong role fails HELLO" {
    var peers = Peers(.pair, .pair).init(.{ .left_transport = authenticatedTransport("pair"), .right_transport = authenticatedTransport("pair") }) catch |err| return skipNoUdp(err);
    defer peers.deinit();
    try peers.ready();
    try peers.left.send(peers.left_session, .{ .subject = "allowed.pair", .body = "authorized" });
    try peers.left.send(peers.left_session, .{ .subject = "forbidden.pair" });
    var delivered: usize = 0;
    for (0..100) |_| {
        try peers.step();
        var events: [8]node.Event = undefined;
        const count = try peers.right.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            if (event.* == .delivery) {
                try std.testing.expectEqualStrings("allowed.pair", event.delivery.msg.subject);
                delivered += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 1), delivered);
    var denied = Peers(.pair, .pair).init(.{ .left_transport = authenticatedTransport("rep"), .right_transport = authenticatedTransport("pair") }) catch |err| return skipNoUdp(err);
    defer denied.deinit();
    // The peer announces pair but presents a rep-only grant.
    for (0..100) |_| {
        try denied.step();
        var events: [8]node.Event = undefined;
        inline for (.{ &denied.left, &denied.right }) |peer| {
            const count = try peer.poll(&events);
            for (events[0..count]) |*event| {
                defer event.deinit();
                if (event.* == .connected and peer == &denied.right) denied.right_session = event.connected;
                try std.testing.expect(event.* != .delivery);
            }
        }
    }
    const status = denied.left.sessionStatus(denied.left_session);
    try std.testing.expect(status == null or status.?.state != .ready);
    if (denied.right_session) |id| {
        const server_status = denied.right.sessionStatus(id);
        try std.testing.expect(server_status == null or server_status.?.state != .ready);
    }
}

test "owned QUIC: authenticated public App route accepts req peer grant" {
    const app_module = @import("app.zig");
    const Handler = struct {
        fn echo(ctx: *app_module.Context, incoming: message.Message) !void {
            var msg = incoming;
            defer msg.deinit();
            try ctx.requireRouteAccess();
            try ctx.requirePattern(.req); // Explicit checks name the peer role.
            try ctx.reply(.{ .subject = "", .body = "App authorized" });
        }
    };
    var app = try app_module.App.init(a, .{});
    defer app.deinit();
    try app.rep("allowed.>", Handler.echo);
    var server_transport = authenticatedTransport("rep");
    server_transport.supported_patterns = @import("control.zig").PatternBits.rep;
    server_transport.required_peer_patterns = @import("control.zig").PatternBits.req;
    const listener = app.listenQuic("127.0.0.1:0", .{ .cert_pem = cert, .key_pem = key, .quic = server_transport }) catch |err| return skipNoUdp(err);
    const address = try app.quicListenerAddress(listener);
    var endpoint: [64]u8 = undefined;
    const target = try std.fmt.bufPrint(&endpoint, "127.0.0.1:{d}", .{address.ip4.port});
    var req = try owned.Socket(.req).init(a, .{});
    defer req.deinit();
    const id = try req.dial(target, .{ .server_name = "localhost", .ca_pem = cert, .transport = authenticatedTransport("req") });
    var now_us: u64 = 1000;
    var sent = false;
    for (0..3000) |_| {
        now_us += 1000;
        try req.pump(now_us);
        _ = try app.tick(now_us);
        if (!sent) if (req.sessionStatus(id)) |status| {
            if (status.state == .ready) {
                _ = try req.request(id, .{ .subject = "allowed.echo" });
                sent = true;
            }
        };
        var events: [8]node.Event = undefined;
        const count = try req.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| if (event == .reply) {
            try std.testing.expect(!event.reply.msg.flags.err);
            try std.testing.expectEqualStrings("App authorized", event.reply.msg.body);
            return;
        };
    }
    return error.ReplyTimeout;
}
