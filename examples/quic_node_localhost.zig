const std = @import("std");
const qmsg = @import("qmsg");

const control = qmsg.control;

const test_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBnjCCAUOgAwIBAgIUFt1GU+R4bofYqJSYwkrpkAV20a8wCgYIKoZIzj0EAwIw
    \\FTETMBEGA1UEAwwKbnVsbHEtdGVzdDAgFw0yNjA1MDMyMTU2MzNaGA8yMTI2MDQw
    \\OTIxNTYzM1owFTETMBEGA1UEAwwKbnVsbHEtdGVzdDBZMBMGByqGSM49AgEGCCqG
    \\SM49AwEHA0IABFcmwnNrWU16PY0JrQwalnjDX/F1w0IOCv8yky4Ox8HJEV2XmDaJ
    \\ymam4Wid7icYSRYNb6fp9zXBB2B9UsfM9xqjbzBtMB0GA1UdDgQWBBSTs06H3woK
    \\Vt48NaHuysDahvgsbzAfBgNVHSMEGDAWgBSTs06H3woKVt48NaHuysDahvgsbzAP
    \\BgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggq
    \\hkjOPQQDAgNJADBGAiEAu3QuT9mHeOo94dC5y5dHrIRblt4kbwujsmGehuoxnCcC
    \\IQCOqAJ7lNk1F2TFQdXB0OefVpkgjrDEihMRYExg1JYjtQ==
    \\-----END CERTIFICATE-----
;

const test_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzUrI/FOBJi8pN/nj
    \\GEC8VX0qopctKjRupKbnSkxSmUehRANCAARXJsJza1lNej2NCa0MGpZ4w1/xdcNC
    \\Dgr/MpMuDsfByRFdl5g2icpmpuFone4nGEkWDW+n6fc1wQdgfVLHzPca
    \\-----END PRIVATE KEY-----
;

const max_drive_steps = 20_000;

// Live localhost Node/App loop using qmsg library APIs only. This example is
// opt-in because some sandboxes deny UDP bind and Zig's std.Io bind path can
// print a stack trace before returning that denial. Run with:
//
//   QMSG_RUN_LIVE_UDP=1 ./zig-out/bin/quic-node-localhost
//
// This is still a low-level example: it queues one reliable message directly
// on the current QUIC session runtime while higher-level socket convenience
// APIs settle.

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    if (init.environ_map.get("QMSG_RUN_LIVE_UDP") == null) {
        std.debug.print(
            "live UDP localhost example not run; set QMSG_RUN_LIVE_UDP=1 to enable it\n",
            .{},
        );
        return;
    }

    runLocalhost(allocator) catch |err| switch (err) {
        error.AccessDenied,
        error.PermissionDenied,
        error.AddressInUse,
        error.AddressNotAvailable,
        error.NetworkSubsystemFailed,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.ConnectionLost,
        => {
            std.debug.print(
                "live UDP localhost example unavailable in this environment: {s}\n",
                .{@errorName(err)},
            );
        },
        else => return err,
    };
}

fn runLocalhost(allocator: std.mem.Allocator) !void {
    var app = try qmsg.App.init(allocator, .{});
    defer app.deinit();

    try app.rep("user.*", getUser);

    const listener_id = try app.listenQuic("127.0.0.1:0", .{
        .cert_pem = test_cert_pem,
        .key_pem = test_key_pem,
        .quic = .{
            .peer_id = "server",
            .role_flags = control.RoleFlags.server,
            .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        },
    });
    const listener = app.node.quic_listeners.items[listener_id];
    const target = try endpointFromLocalhost(allocator, listener.localAddress());
    defer allocator.free(target);

    const client_session_id = try app.node.dialQuic(target, .{
        .server_name = "localhost",
        .transport = .{
            .peer_id = "client",
            .role_flags = control.RoleFlags.client,
            .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        },
    });
    const client = app.node.quicSession(client_session_id) orelse return error.EndpointNotFound;

    var now_us = try driveUntilReady(&app, client);
    const stream_id = try client.queueReliable(.{
        .subject = "user.get",
        .id = 42,
        .deadline_ms = 250,
        .headers = &.{.{ .name = "accept", .value = "application/json" }},
        .body = "user-42",
    });

    var step: u32 = 0;
    while (step < max_drive_steps) : (step += 1) {
        now_us += 1_000;
        try app.node.tick(now_us);

        if (try takeClientReply(client, stream_id)) return;

        _ = try app.runOnce();
    }

    return error.ConnectionLost;
}

fn driveUntilReady(app: *qmsg.App, client: *qmsg.node.QuicSessionRuntime) !u64 {
    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < max_drive_steps) : (step += 1) {
        try app.node.tick(now_us);
        if (client.state() == .ready and serverReady(app, client.id())) {
            return now_us;
        }
        now_us += 1_000;
    }
    return error.ConnectionLost;
}

fn serverReady(app: *qmsg.App, client_session_id: qmsg.SessionId) bool {
    for (app.node.quic_sessions.items) |runtime| {
        if (runtime.id() == client_session_id) continue;
        if (runtime.state() == .ready) return true;
    }
    return false;
}

fn takeClientReply(client: *qmsg.node.QuicSessionRuntime, expected_stream_id: u64) !bool {
    var received = client.runtime.recvReliable() orelse return false;
    defer received.deinit();

    if (received.stream_id != expected_stream_id) return error.UnexpectedFrame;

    std.debug.print(
        "node QUIC localhost received {s}: {s}\n",
        .{ received.message.subject, received.message.body },
    );
    return true;
}

fn endpointFromLocalhost(
    allocator: std.mem.Allocator,
    address: std.Io.net.IpAddress,
) ![]u8 {
    return switch (address) {
        .ip4 => |ip4| try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{ip4.port}),
        .ip6 => |ip6| try std.fmt.allocPrint(allocator, "[::1]:{d}", .{ip6.port}),
    };
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
