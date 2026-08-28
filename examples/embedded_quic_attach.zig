//! Inbound qmsg attach on a FOREIGN embedder's listener — the Phase C
//! contract (docs/QUIC_EMBED_SEAM.md) in executable form.
//!
//! The embedder owns everything transport-level: the listener, the
//! UDP socket, and the ONE `quic.app.Driver` (quic-zig allows a
//! single will-close hook slot per Server, so there is exactly one
//! Driver, and on this seam it is the embedder's). qmsg owns only
//! the sessions riding the connections the embedder routes to it by
//! ALPN (`qmsg/1`): the embedder's Driver hooks delegate into an
//! `EmbeddedDispatch` through a per-connection `Seat` kept in the
//! embedder's own connection state.
//!
//! Inbound messages are PULL-consumed — they surface through
//! `Node.poll` events (`quic_request`, `quic_reply`,
//! `quic_delivery`), the same registry the inproc embedded surface
//! uses — never through push dispatch. Replies go back with
//! `Node.replyQuic` while the request event is alive.
//!
//! This example is hermetic (one process, an in-memory packet
//! shuttle, a virtual clock, no sockets). It is the loop an embedder
//! like mruby-quic mimics: drive its own connections, delegate
//! qmsg-ALPN ones, pump/route/deferred-deliver through poll.

const std = @import("std");
const qmsg = @import("qmsg");
const quic_zig = @import("quic");

const Node = qmsg.node.Node;
const Event = qmsg.node.Event;
const quic_embedded = qmsg.transport.quic_embedded;
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

/// The embedder application: owns the Driver, keeps one qmsg seat per
/// connection in its own connection state, and routes hooks by ALPN.
/// This is the whole embedder-side contract.
const Embedder = struct {
    allocator: std.mem.Allocator,
    node: *Node,
    dispatch: quic_embedded.EmbeddedDispatch(Node),
    driver: D,

    pub const D = quic_zig.app.Driver(@This());

    pub const ConnState = struct {
        /// The qmsg seat rides alongside the embedder's own
        /// per-connection state; absent for non-qmsg connections.
        qmsg_seat: ?quic_embedded.EmbeddedDispatch(Node).Seat = null,
    };

    pub const StreamState = struct {};

    fn create(
        allocator: std.mem.Allocator,
        node: *Node,
        transport_options: qmsg.transport.quic.QuicOptions,
    ) !*Embedder {
        const self = try allocator.create(Embedder);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .node = node,
            .dispatch = quic_embedded.EmbeddedDispatch(Node).init(
                allocator,
                node,
                transport_options,
                .events, // pull model: poll events, not push dispatch
            ),
            .driver = undefined,
        };
        self.driver = try D.init(.{
            .allocator = allocator,
            .app = self,
            .hooks = .{
                .on_handshake = onHandshake,
                .on_stream_open = onStreamOpen,
                .on_stream_data = onStreamData,
                .on_stream_end = onStreamEnd,
                .on_datagram = onDatagram,
                .on_disconnect = onDisconnect,
            },
            // Sized from the transport options so a conforming peer
            // can never overflow the table; embedders do not have to
            // re-derive this.
            .max_tracked_streams = quic_embedded.driverSizing(transport_options).max_tracked_streams,
            .datagram_buf_bytes = quic_embedded.driverSizing(transport_options).datagram_buf_bytes,
        });
        return self;
    }

    fn destroy(self: *Embedder) void {
        self.driver.deinit();
        self.allocator.destroy(self);
    }

    fn onHandshake(app: *@This(), s: *D.Session) anyerror!void {
        if (!quic_embedded.isQmsgAlpn(s.conn)) return; // not ours
        if (s.app.qmsg_seat != null) return;
        var seat = quic_embedded.EmbeddedDispatch(Node).Seat.init(app.allocator);
        try app.dispatch.onHandshake(&seat, s.conn);
        s.app.qmsg_seat = seat;
    }

    fn onStreamOpen(app: *@This(), s: *D.Session, e: *D.StreamEntry, bidi: bool) anyerror!void {
        if (s.app.qmsg_seat == null) return;
        try app.dispatch.onStreamOpen(&s.app.qmsg_seat.?, e.id, bidi);
    }

    fn onStreamData(app: *@This(), s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
        if (s.app.qmsg_seat == null) return;
        try app.dispatch.onStreamData(&s.app.qmsg_seat.?, s.conn, e.id, chunk);
    }

    fn onStreamEnd(app: *@This(), s: *D.Session, e: *D.StreamEntry, end: quic_zig.app.StreamEnd) anyerror!void {
        if (s.app.qmsg_seat == null) return;
        try app.dispatch.onStreamEnd(&s.app.qmsg_seat.?, s.conn, e.id, end);
    }

    fn onDatagram(app: *@This(), s: *D.Session, datagram: D.Datagram) anyerror!void {
        if (s.app.qmsg_seat == null) return;
        try app.dispatch.onDatagram(&s.app.qmsg_seat.?, datagram.bytes, datagram.arrived_in_early_data);
    }

    fn onDisconnect(app: *@This(), s: *D.Session) void {
        // The will-close teardown rides the embedder's own path: the
        // session frees exactly once, here, while it is still valid.
        if (s.app.qmsg_seat == null) return;
        app.dispatch.onDisconnect(&s.app.qmsg_seat.?);
        s.app.qmsg_seat = null;
    }
};

/// One iteration of the embedder's loop: shuttle packets (in this
/// hermetic example an in-memory bridge; a real embedder's UDP
/// handling stands here), service its Driver (hooks fire into qmsg),
/// then give each qmsg connection one send-side pass.
fn drive(
    allocator: std.mem.Allocator,
    listener: *qmsg.transport.quic_runtime.ListenerRuntime,
    embedder: *Embedder,
    client: *qmsg.transport.quic_runtime.ClientRuntime,
    rx: []u8,
    now_us: u64,
) !void {
    const from: qmsg.transport.quic_runtime.Address = .{ .ipv4 = .{
        .addr = .{ 0x7f, 0, 0, 1 },
        .port = 40_000,
    } };
    while (try client.drainOutbound(rx, now_us)) |out| {
        _ = try listener.feedInbound(.{ .bytes = rx[0..out.len], .from = from }, now_us);
    }
    try embedder.driver.service(&listener.server);
    for (listener.server.iterator()) |slot| {
        const ds = embedder.driver.sessionOn(slot) orelse continue;
        if (ds.app.qmsg_seat == null) continue;
        try embedder.dispatch.serviceSeat(&ds.app.qmsg_seat.?, slot.conn);
    }
    while (try listener.drainOutbound(rx, now_us)) |out| {
        try client.feedInbound(.{ .bytes = rx[0..out.len] }, now_us);
    }
    try listener.tick(now_us);
    try client.tick(now_us);
    _ = allocator;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    const server_opts: qmsg.transport.quic.QuicOptions = .{
        .peer_id = "embed-server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        .datagram_enabled = true,
    };
    const client_opts: qmsg.transport.quic.QuicOptions = .{
        .peer_id = "embed-client",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        .datagram_enabled = true,
    };

    var node = try Node.init(allocator, .{});
    defer node.deinit();

    var listener = try qmsg.transport.quic_runtime.ListenerRuntime.init(allocator, "127.0.0.1:4433", .{
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .transport = server_opts,
    });
    var embedder = try Embedder.create(allocator, &node, server_opts);
    embedder.driver.attach(&listener.server);
    // Teardown order (LIFO): listener first — its Server.deinit fires
    // the will-close hook, which destroys the embedded session
    // through the owner while the node is alive — then the embedder,
    // then the client, then the node's leftovers.
    defer embedder.destroy();
    defer listener.deinit();

    var client = try qmsg.transport.quic_runtime.ClientRuntime.init(allocator, "127.0.0.1:4433", .{
        .server_name = "localhost",
        .insecure_skip_verify = true, // self-signed example fixture
        .transport = client_opts,
    });
    defer client.deinit();

    // The requesting side: a node-owned session riding the embedder's
    // connection (in mruby-quic this is where the bridge's outbound
    // MSG.request would sit).
    const client_sess = try node.openQuicSession(.{
        .role = .client,
        .transport = client_opts,
    });

    var rx: [8192]u8 = undefined;
    var now_us: u64 = 1_000;

    // Handshake + qmsg HELLO exchange, driven by the embedder's loop.
    var step: u32 = 0;
    while (step < max_drive_steps) : (step += 1) {
        now_us += 1_000;
        try drive(allocator, &listener, embedder, &client, &rx, now_us);
        if (client.connection().handshakeDone() and
            listener.connectionCount() > 0 and
            listener.connection(0).?.handshakeDone()) break;
    }
    client_sess.transport_ready = true;
    try client_sess.runtime.onQuicReady();

    step = 0;
    var server_ready = false;
    while (step < max_drive_steps) : (step += 1) {
        now_us += 1_000;
        _ = try client_sess.runtime.pumpConnection(client.connection());
        try drive(allocator, &listener, embedder, &client, &rx, now_us);
        server_ready = false;
        for (node.quic_sessions.items) |candidate| {
            if (candidate == client_sess) continue;
            server_ready = candidate.state() == .ready;
        }
        if (client_sess.state() == .ready and server_ready) break;
    }
    if (client_sess.state() != .ready or !server_ready) return error.ConnectionLost;

    // Outbound request + datagram from the requesting side.
    _ = try client_sess.queueReliable(.{
        .subject = "user.get",
        .id = 42,
        .deadline_ms = 2_000,
        .body = "42",
    });
    _ = try qmsg.transport.quic_datagram.send(
        client.connection(),
        allocator,
        .{ .subject = "presence.ada", .flags = .{ .unreliable = true }, .body = "online" },
        .{ .fallback = .datagram_only },
    );

    // The embedder's consumption loop: pump, then route poll events.
    var got_request = false;
    var got_delivery = false;
    var got_reply = false;
    step = 0;
    while (step < max_drive_steps and (!got_request or !got_delivery or !got_reply)) : (step += 1) {
        now_us += 1_000;
        _ = try client_sess.runtime.pumpConnection(client.connection());
        try drive(allocator, &listener, embedder, &client, &rx, now_us);

        var events: [8]Event = undefined;
        const count = try node.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .quic_request => |*ev| {
                    std.debug.print("quic_request {s} ({s}) id={d} stream={d}\n", .{
                        ev.msg.subject, ev.msg.body, ev.msg.id, ev.stream_id,
                    });
                    try node.replyQuic(ev, .{ .subject = "", .body = "user-42" });
                    got_request = true;
                },
                .quic_delivery => |*ev| {
                    std.debug.print("quic_delivery {s} ({s})\n", .{ ev.msg.subject, ev.msg.body });
                    got_delivery = true;
                },
                .quic_reply => |*ev| {
                    std.debug.print("quic_reply id={d} stream={d} ({s})\n", .{
                        ev.msg.id, ev.stream_id, ev.msg.body,
                    });
                    got_reply = true;
                },
                .message_dropped => |ev| {
                    std.debug.print("message_dropped {d} bytes\n", .{ev.bytes});
                },
                else => {},
            }
        }

        if (!got_reply) {
            if (client_sess.runtime.recvReliable()) |received| {
                var got = received;
                defer got.deinit();
                std.debug.print("requester got reply id={d} ({s})\n", .{ got.message.id, got.message.body });
                got_reply = true;
            }
        }
    }

    if (!got_request or !got_delivery or !got_reply) return error.EmbeddedAttachIncomplete;

    const stats = node.stats();
    std.debug.print(
        "embedded attach stats: sent={d} recv={d} dropped={d} events_dropped={d}\n",
        .{ stats.sent, stats.recv, stats.dropped, stats.events_dropped },
    );

    // Fall off the end with the connection LIVE: the defers above
    // demonstrate the teardown ride-along (listener will-close ->
    // onDisconnect -> session freed exactly once).
}
