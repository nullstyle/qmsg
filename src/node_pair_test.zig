//! Two INDEPENDENT qmsg nodes, over real UDP.
//!
//! Everything else in this repository that exercises QUIC drives one
//! side, or drives both ends from a single `Node` (examples/
//! quic_node_localhost.zig listens and dials on the same node). So
//! nothing measured what happens between two separate embedders: a
//! completed request across a process boundary, a peer identity each
//! side derives from the other's certificate, or how long a live node
//! keeps a session for a peer that stopped answering.
//!
//! Each `Pair` here is two `App`s, each owning its own `Node`, its own
//! UDP socket and its own clock. The clock is VIRTUAL: `tick(now_us)`
//! takes the time as an argument, so idle-timeout behaviour that would
//! take 30 wall-clock seconds is driven in milliseconds while the
//! sockets stay real.
//!
//! MEASURED RESULT (the reason these tests exist): qmsg notices a peer
//! that stopped answering ONLY through the QUIC idle timeout. With the
//! timeout set to 2s the session is dropped 2169ms after last contact
//! — the timeout plus roughly one probe interval. `max_idle_timeout_ms`
//! defaults to 30_000, so on default settings a crashed peer occupies
//! a session for about half a minute. There is no faster path:
//! `heartbeat_interval_ms` keeps a session ALIVE, it does not shorten
//! detection.
//!
//! That is a real number to design against. A failure detector built
//! for the job is an order of magnitude quicker — qmesh-zig's SWIM
//! defaults (probe 1s, probe timeout 0.5s, indirect 0.5s, suspicion
//! 3s) confirm a death in roughly 5s, and drop it further under
//! corroboration. It is the concrete reason to run a membership layer
//! beside qmsg rather than infer liveness from qmsg sessions.

const std = @import("std");

const app_mod = @import("app.zig");
const auth = @import("auth.zig");
const control = @import("control.zig");
const message = @import("message.zig");
const node_mod = @import("node.zig");

const test_cert_pem = @embedFile("testdata/test_cert.pem");
const test_key_pem = @embedFile("testdata/test_key.pem");

/// Ceiling on drive iterations before a wait is declared failed.
const max_steps: u32 = 200_000;

/// Virtual microseconds per drive iteration.
const step_us: u64 = 1_000;

const reply_body = "{\"id\":\"user-42\",\"name\":\"Ada\"}";

fn getUser(ctx: *app_mod.Context, msg: message.Message) !void {
    var owned = msg;
    defer owned.deinit();
    try ctx.reply(.{
        .subject = "",
        .headers = &.{.{ .name = "content-type", .value = "application/json" }},
        .body = reply_body,
    });
}

const Options = struct {
    /// Announced by the dialling side in its HELLO.
    client_peer_id: []const u8 = "client",
    /// Listener policy binding the announced id to the certificate.
    cert_binding: auth.CertBinding = .off,
    /// Negotiated idle timeout, both directions.
    max_idle_timeout_ms: u64 = 30_000,
};

const Pair = struct {
    allocator: std.mem.Allocator,
    server: app_mod.App,
    client: app_mod.App,
    target: []u8,
    client_session: node_mod.QuicSessionId,
    now_us: u64 = 1_000,
    client_alive: bool = true,
    /// Which apps `tearDown` must release; set as construction
    /// progresses so a failure part-way through frees exactly what
    /// exists.
    apps_up: enum { none, server_only, both } = .none,

    /// Constructed IN PLACE. `App` (and the `Node` inside it) hold
    /// interior pointers, so a `Pair` value must never be copied after
    /// its apps are initialised — returning one by value memcpy's them
    /// and the next allocation runs through a dangling vtable.
    fn setUp(self: *Pair, allocator: std.mem.Allocator, options: Options) !void {
        self.* = .{
            .allocator = allocator,
            .server = try app_mod.App.init(allocator, .{}),
            .client = undefined,
            .target = &.{},
            .client_session = 0,
            .apps_up = .server_only,
        };
        errdefer self.tearDown();

        const server = &self.server;
        try server.rep("user.get", getUser);

        const listener_id = try server.listenQuic("127.0.0.1:0", .{
            .cert_pem = test_cert_pem,
            .key_pem = test_key_pem,
            // Mutual TLS: the listener now learns WHICH peer connected.
            .client_ca_pem = test_cert_pem,
            .quic = .{
                .peer_id = "server",
                .role_flags = control.RoleFlags.server,
                .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
                .max_idle_timeout_ms = options.max_idle_timeout_ms,
                .auth_config = .{ .cert_binding = options.cert_binding },
            },
        });
        const listener = server.node.quic_listeners.items[listener_id];
        self.target = try endpointText(allocator, listener.localAddress());

        self.client = try app_mod.App.init(allocator, .{});
        self.apps_up = .both;

        self.client_session = try self.client.dialQuic(self.target, .{
            .server_name = "localhost",
            .ca_pem = test_cert_pem,
            // Cluster posture: chain validation against the pinned CA
            // stays mandatory, the hostname check does not apply — the
            // peer is dialled by ADDRESS, and its certificate means
            // membership rather than a name.
            .identity_verification = .none,
            .client_cert_pem = test_cert_pem,
            .client_key_pem = test_key_pem,
            .transport = .{
                .peer_id = options.client_peer_id,
                .role_flags = control.RoleFlags.client,
                .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
                .max_idle_timeout_ms = options.max_idle_timeout_ms,
            },
        });
    }

    fn tearDown(self: *Pair) void {
        switch (self.apps_up) {
            .none => {},
            .server_only => self.server.deinit(),
            .both => {
                self.client.deinit();
                self.server.deinit();
            },
        }
        self.apps_up = .none;
        if (self.target.len > 0) self.allocator.free(self.target);
        self.target = &.{};
    }

    /// One iteration of both embedders' loops. After `killClient` the
    /// client stops being driven — its socket stays open but nothing
    /// answers, which is what a crashed peer looks like from here.
    fn step(self: *Pair) !void {
        self.now_us += step_us;
        try self.server.node.tick(self.now_us);
        _ = try self.server.runOnce();
        if (self.client_alive) {
            try self.client.node.tick(self.now_us);
            _ = try self.client.runOnce();
        }
    }

    /// A peer that stopped answering: no close frame, no goodbye.
    fn killClient(self: *Pair) void {
        self.client_alive = false;
    }

    fn clientRuntime(self: *Pair) !*node_mod.QuicSessionRuntime {
        return self.client.node.quicSession(self.client_session) orelse
            error.EndpointNotFound;
    }

    /// The listener's session for our client. Null once it is gone.
    fn serverRuntime(self: *Pair) ?*node_mod.QuicSessionRuntime {
        for (self.server.node.quic_sessions.items) |runtime| {
            return runtime;
        }
        return null;
    }

    fn driveUntilReady(self: *Pair) !void {
        const client = try self.clientRuntime();
        var steps: u32 = 0;
        while (steps < max_steps) : (steps += 1) {
            try self.step();
            const server_ready = if (self.serverRuntime()) |s| s.state() == .ready else false;
            if (client.state() == .ready and server_ready) return;
        }
        return error.HandshakeTimeout;
    }
};

fn endpointText(allocator: std.mem.Allocator, address: std.Io.net.IpAddress) ![]u8 {
    return switch (address) {
        .ip4 => |ip4| try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{ip4.port}),
        .ip6 => |ip6| try std.fmt.allocPrint(allocator, "[::1]:{d}", .{ip6.port}),
    };
}

/// Some sandboxes deny UDP bind. Treat that as "not runnable here"
/// rather than a failure, the way the localhost example does.
fn skipIfNoUdp(err: anyerror) !void {
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

test "two independent nodes complete a request across real UDP" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    pair.setUp(allocator, .{}) catch |err| return skipIfNoUdp(err);
    defer pair.tearDown();
    try pair.driveUntilReady();

    const client = try pair.clientRuntime();
    const stream_id = try client.queueReliable(.{
        .subject = "user.get",
        .id = 42,
        .deadline_ms = 5_000,
        .headers = &.{.{ .name = "accept", .value = "application/json" }},
        .body = "user-42",
    });

    var steps: u32 = 0;
    while (steps < max_steps) : (steps += 1) {
        try pair.step();
        if (client.runtime.recvReliable()) |recv| {
            var received = recv;
            defer received.deinit();
            try std.testing.expectEqual(stream_id, received.stream_id);
            try std.testing.expectEqualStrings(reply_body, received.message.body);
            return;
        }
    }
    return error.ReplyTimeout;
}

test "each node learns the other's certificate identity" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    pair.setUp(allocator, .{}) catch |err| return skipIfNoUdp(err);
    defer pair.tearDown();
    try pair.driveUntilReady();

    const client = try pair.clientRuntime();
    const server = pair.serverRuntime() orelse return error.EndpointNotFound;

    // Mutual TLS, so BOTH ends have an authenticated peer identity.
    // Without client_ca_pem the listener's side would be null.
    const client_view = client.runtime.session.session.peer_cert_spki;
    const server_view = server.runtime.session.session.peer_cert_spki;
    try std.testing.expect(client_view != null);
    try std.testing.expect(server_view != null);

    // Both ends present the same fixture certificate, so each side's
    // view of the other is the same digest.
    try std.testing.expectEqualSlices(u8, &client_view.?, &server_view.?);

    // And the canonical rendering is the 64-character lowercase hex
    // that qmesh-zig uses as its PeerId.
    const hex = server.runtime.session.session.certPeerIdHex().?;
    try std.testing.expectEqual(@as(usize, 64), hex.len);
    for (hex) |c| try std.testing.expect(std.ascii.isHex(c) and !std.ascii.isUpper(c));
}

test "cert binding severs a peer announcing an identity it cannot prove" {
    const allocator = std.testing.allocator;
    // The listener requires the announced id to be the certificate's
    // own hex. This client announces something else.
    var pair: Pair = undefined;
    pair.setUp(allocator, .{
        .client_peer_id = "not-the-certificate-identity",
        .cert_binding = .require_match,
    }) catch |err| return skipIfNoUdp(err);
    defer pair.tearDown();

    const client = try pair.clientRuntime();
    var steps: u32 = 0;
    var server_ever_ready = false;
    while (steps < 5_000) : (steps += 1) {
        try pair.step();
        if (pair.serverRuntime()) |s| {
            if (s.state() == .ready) server_ever_ready = true;
        }
    }

    // The QUIC handshake itself is fine — both certificates are valid.
    // The qmsg session is what must not come up: the listener rejected
    // the HELLO, so the peer never becomes a usable session.
    try std.testing.expect(!server_ever_ready);
    try std.testing.expect(client.state() != .ready);
}

test "a node keeps a dead peer's session for the idle timeout, then drops it" {
    const allocator = std.testing.allocator;
    // A short negotiated idle timeout so the measurement is quick;
    // the mechanism is the same at 30s.
    const idle_ms: u64 = 2_000;
    var pair: Pair = undefined;
    pair.setUp(allocator, .{ .max_idle_timeout_ms = idle_ms }) catch |err|
        return skipIfNoUdp(err);
    defer pair.tearDown();
    try pair.driveUntilReady();

    try std.testing.expect(pair.serverRuntime() != null);
    const died_at_us = pair.now_us;

    // The client stops answering. No CONNECTION_CLOSE, no goodbye —
    // exactly what a crash or a severed path looks like.
    pair.killClient();

    var noticed_at_us: ?u64 = null;
    var steps: u32 = 0;
    while (steps < max_steps) : (steps += 1) {
        try pair.step();
        const runtime = pair.serverRuntime();
        const gone = runtime == null or runtime.?.state() == .closed;
        if (gone) {
            noticed_at_us = pair.now_us;
            break;
        }
    }

    const detected = noticed_at_us orelse return error.PeerNeverDeclaredDead;
    const lag_ms = (detected - died_at_us) / std.time.us_per_ms;

    // The point of the test is the NUMBER, so print it.
    std.debug.print(
        "\n[node-pair] dead-peer detection: {d}ms after last contact " ++
            "(negotiated idle timeout {d}ms)\n",
        .{ lag_ms, idle_ms },
    );

    // Detection is idle-timeout driven: it must not fire early (that
    // would evict healthy peers under load) and must not exceed a
    // small multiple of the negotiated timeout.
    try std.testing.expect(lag_ms >= idle_ms);
    try std.testing.expect(lag_ms <= idle_ms * 3);
}
