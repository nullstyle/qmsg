//! Real UDP public Node auth/ownership checks in both listen/dial directions.
const std = @import("std");
const node = @import("node.zig");
const auth = @import("auth.zig");
const quic = @import("transport/quic.zig");
const control = @import("control.zig");
const cert = @embedFile("testdata/test_cert.pem");
const key = @embedFile("testdata/test_key.pem");

fn grant(_: ?*anyopaque, allocator: std.mem.Allocator, credential: auth.Credential) !auth.Authorization {
    const role: auth.Pattern = if (std.mem.eql(u8, credential.token, "pub")) .@"pub" else if (std.mem.eql(u8, credential.token, "sub")) .sub else return error.Unauthorized;
    return (auth.Authorization{ .subject = "fixture", .issuer = "fixture", .allowed_patterns = auth.PatternSet.init(&.{role}), .allowed_subjects = .{ .filters = &.{"news.allowed"} } }).clone(allocator);
}

fn options(publisher: bool) quic.QuicOptions {
    return .{
        .supported_patterns = if (publisher) control.PatternBits.pub_ else control.PatternBits.sub,
        .required_peer_patterns = if (publisher) control.PatternBits.sub else control.PatternBits.pub_,
        .auth = .{ .scheme = auth.hello_auth_scheme_paseto, .credential = if (publisher) "pub" else "sub" },
        .auth_config = .{ .required = true, .authenticator = .{ .authenticate_fn = grant } },
        .initial_max_streams_bidi = 2,
        .max_queued_messages = 4,
        .max_message_size = 4096,
        .max_queued_bytes = 64 * 1024,
    };
}

test "reliable pubsub: authenticated public UDP publisher works on accepted and dialed sessions" {
    inline for (.{ true, false }) |publisher_listens| {
        var publisher = try node.Node.init(std.testing.allocator, .{ .quic_inbound = .refuse });
        defer publisher.deinit();
        var subscriber = try node.Node.init(std.testing.allocator, .{ .quic_inbound = .publications });
        defer subscriber.deinit();
        try subscriber.subscribeQuic("news.*", .{});
        const listener_node = if (publisher_listens) &publisher else &subscriber;
        const dialer_node = if (publisher_listens) &subscriber else &publisher;
        const listener = listener_node.listenQuic("127.0.0.1:0", .{ .tls_cert_pem = cert, .tls_key_pem = key, .transport = options(publisher_listens) }) catch |err| switch (@as(anyerror, err)) {
            error.AccessDenied, error.PermissionDenied, error.AddressInUse, error.AddressNotAvailable, error.NetworkSubsystemFailed, error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => return error.SkipZigTest,
            else => return err,
        };
        const address = try listener_node.quicListenerAddress(listener);
        var target_buffer: [64]u8 = undefined;
        const target = try std.fmt.bufPrint(&target_buffer, "127.0.0.1:{d}", .{address.ip4.port});
        const dialed = try dialer_node.dialQuic(target, .{ .server_name = "localhost", .ca_pem = cert, .transport = options(!publisher_listens) });
        var accepted: ?node.QuicSessionId = null;
        var published = false;
        var received: usize = 0;
        var after_delivery: usize = 0;
        for (0..6000) |iteration| {
            const now = (iteration + 1) * 1000;
            try publisher.tick(now);
            try subscriber.tick(now);
            var events: [16]node.Event = undefined;
            var count = try listener_node.poll(&events);
            {
                defer for (events[0..count]) |*event| event.deinit();
                for (events[0..count]) |event| switch (event) {
                    .connected => |id| accepted = id,
                    .delivery => |delivery| {
                        try std.testing.expect(!publisher_listens);
                        try std.testing.expectEqualStrings("news.allowed", delivery.msg.subject);
                        try std.testing.expectEqualStrings("authorized publication", delivery.msg.body);
                        try std.testing.expect(delivery.msg.flags.no_reply and delivery.msg.reply_handle == null);
                        received += 1;
                    },
                    .request, .reply, .request_failed => return error.WrongPublicationEvent,
                    else => {},
                };
            }
            count = try dialer_node.poll(&events);
            {
                defer for (events[0..count]) |*event| event.deinit();
                for (events[0..count]) |event| switch (event) {
                    .delivery => |delivery| {
                        try std.testing.expect(publisher_listens);
                        try std.testing.expectEqualStrings("news.allowed", delivery.msg.subject);
                        try std.testing.expectEqualStrings("authorized publication", delivery.msg.body);
                        try std.testing.expect(delivery.msg.flags.no_reply and delivery.msg.reply_handle == null);
                        received += 1;
                    },
                    .request, .reply, .request_failed => return error.WrongPublicationEvent,
                    else => {},
                };
            }
            if (!published) {
                const result = try publisher.publishQuicReliable(.{ .subject = "news.allowed", .body = "authorized publication" });
                if (result.queued == 1) {
                    published = true;
                    const denied = try publisher.publishQuicReliable(.{ .subject = "news.denied", .body = "must not cross source" });
                    try std.testing.expectEqual(@as(usize, 1), denied.dropped);
                    // A publisher bypassing its source-side admission is still
                    // denied by the subscriber's authenticated PUB subject scope.
                    const pub_session = if (publisher_listens) accepted.? else dialed;
                    try publisher.sendQuic(pub_session, .{ .subject = "news.denied", .body = "must not reach application" });
                }
            }
            if (received > 0) {
                after_delivery += 1;
                if (after_delivery == 100) break;
            }
        }
        try std.testing.expect(published);
        try std.testing.expectEqual(@as(usize, 1), received);
        try std.testing.expectEqual(@as(usize, 1), subscriber.stats().dropped);
    }
}
