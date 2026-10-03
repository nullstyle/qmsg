//! One session against quic-zig's stream window, over real UDP.
//!
//! Since quic-zig v0.24.0, `initial_max_streams_bidi` / `_uni` is a
//! WINDOW: the number of streams the peer may have open at once. The
//! peer gives an id back only when its stream is closed in both
//! directions. So a stream that never closes, or a skipped id that
//! never opens, keeps its place in the window for the life of the
//! connection, and an open above the window is refused with
//! `StreamLimitExceeded` until a stream closes.
//!
//! Every test here pushes more streams through ONE session than the
//! window holds, and asserts the healthy result. Each one failed on
//! qmsg before the fix it names. Two `Node`s, events delivery, real
//! sockets on 127.0.0.1, and a virtual clock (one step is 1 ms).
//! Diagnostics print only when a test fails.

const std = @import("std");
const quic_zig = @import("quic");

const control = @import("control.zig");
const node_mod = @import("node.zig");
const quic = @import("transport/quic.zig");

const Node = node_mod.Node;

const cert_pem = @embedFile("testdata/test_cert.pem");
const key_pem = @embedFile("testdata/test_key.pem");
const step_us: u64 = 1_000;

const Pair = struct {
    allocator: std.mem.Allocator,
    server: Node,
    client: Node,
    target: []u8 = &.{},
    session: node_mod.QuicSessionId = 0,
    now_us: u64 = 1_000,

    /// Constructed in place: a `Node` holds interior pointers.
    fn setUp(self: *Pair, allocator: std.mem.Allocator, server_transport: quic.QuicOptions, client_transport: quic.QuicOptions) !void {
        self.* = .{
            .allocator = allocator,
            .server = try Node.init(allocator, .{ .delivery = .events }),
            .client = undefined,
        };
        errdefer self.server.deinit();
        var server_options = server_transport;
        server_options.peer_id = "window-server";
        server_options.role_flags = control.RoleFlags.server;
        server_options.supported_patterns = control.PatternBits.req | control.PatternBits.rep;
        const listener_id = try self.server.listenQuic("127.0.0.1:0", .{
            .tls_cert_pem = cert_pem,
            .tls_key_pem = key_pem,
            .transport = server_options,
        });
        const address = self.server.quic_listeners.items[listener_id].localAddress();
        self.target = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{address.ip4.port});
        errdefer allocator.free(self.target);

        self.client = try Node.init(allocator, .{ .delivery = .events });
        errdefer self.client.deinit();
        var client_options = client_transport;
        client_options.peer_id = "window-client";
        client_options.role_flags = control.RoleFlags.client;
        client_options.supported_patterns = control.PatternBits.req | control.PatternBits.rep;
        self.session = try self.client.dialQuic(self.target, .{
            .server_name = "localhost",
            .ca_pem = cert_pem,
            .transport = client_options,
        });
    }

    fn tearDown(self: *Pair) void {
        self.client.deinit();
        self.server.deinit();
        self.allocator.free(self.target);
    }

    fn step(self: *Pair) !void {
        self.now_us += step_us;
        try self.server.tick(self.now_us);
        try self.client.tick(self.now_us);
    }

    fn steps(self: *Pair, count: usize) !void {
        for (0..count) |_| try self.step();
    }

    fn clientRuntime(self: *Pair) !*node_mod.QuicSessionRuntime {
        return self.client.quicSession(self.session) orelse error.ClientSessionGone;
    }

    fn serverRuntime(self: *Pair) ?*node_mod.QuicSessionRuntime {
        for (self.server.quic_sessions.items) |runtime| return runtime;
        return null;
    }

    fn clientConn(self: *Pair) ?*quic_zig.Connection {
        if (self.client.quic_clients.items.len == 0) return null;
        return self.client.quic_clients.items[0].client.runtime.connection();
    }

    fn serverConn(self: *Pair) ?*quic_zig.Connection {
        if (self.server.quic_listeners.items.len == 0) return null;
        return self.server.quic_listeners.items[0].listener.runtime.connection(0);
    }

    fn driveUntilReady(self: *Pair) !void {
        for (0..20_000) |_| {
            try self.step();
            const client_ready = (try self.clientRuntime()).state() == .ready;
            const server_ready = if (self.serverRuntime()) |s| s.state() == .ready else false;
            if (client_ready and server_ready) return;
        }
        return error.HandshakeTimeout;
    }

    /// Both sessions still up: a stall or a closed connection fails here.
    fn expectSessionsReady(self: *Pair) !void {
        try std.testing.expectEqual(quic.State.ready, (try self.clientRuntime()).state());
        const server = self.serverRuntime() orelse return error.ServerSessionGone;
        try std.testing.expectEqual(quic.State.ready, server.state());
    }

    const Serve = enum { answer, drop };

    /// Server side: polls once, answers (or drops) every request that
    /// expects a reply. Returns the number of inbound messages seen.
    fn serve(self: *Pair, mode: Serve) !Seen {
        var events: [64]node_mod.Event = undefined;
        const count = try self.server.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        var seen: Seen = .{};
        for (events[0..count]) |event| switch (event) {
            .request => |inbound| {
                if (inbound.msg.flags.no_reply) {
                    seen.no_reply += 1;
                    continue;
                }
                seen.requests += 1;
                if (mode == .drop) continue;
                try self.server.reply(inbound.msg.reply_handle orelse return error.ReplyHandleMissing, .{
                    .subject = "",
                    .body = "ok",
                });
            },
            else => {},
        };
        return seen;
    }

    const Seen = struct { requests: usize = 0, no_reply: usize = 0 };

    /// Client side: polls once and counts outcomes.
    fn collect(self: *Pair, outcomes: *Outcomes) !void {
        var events: [64]node_mod.Event = undefined;
        const count = try self.client.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| switch (event) {
            .reply => outcomes.replies += 1,
            .request_failed => |failed| switch (failed.failure) {
                .canceled => outcomes.canceled += 1,
                .deadline_exceeded => outcomes.deadline_exceeded += 1,
                else => {
                    outcomes.other_failures += 1;
                    outcomes.last_failure = failed.failure;
                },
            },
            else => {},
        };
    }

    /// Sends one request on the session and returns its local id.
    fn request(self: *Pair, id: u64, deadline_ms: u64) !node_mod.RequestId {
        return self.client.request(.{ .quic = self.session }, .{
            .subject = "work",
            .id = id,
            .deadline_ms = deadline_ms,
            .body = "x",
        });
    }

    /// Sends one `no_reply` message on a new stream of the session.
    fn note(self: *Pair, id: u64) !void {
        _ = try (try self.clientRuntime()).queueReliable(.{
            .subject = "note",
            .id = id,
            .flags = .{ .no_reply = true },
            .body = "x",
        });
    }

    /// Steps both sides, answering every request, until the client
    /// has `want` outcomes or `max_steps` pass.
    fn roundTrip(self: *Pair, outcomes: *Outcomes, want: usize, max_steps: usize) !void {
        for (0..max_steps) |_| {
            try self.step();
            _ = try self.serve(.answer);
            try self.collect(outcomes);
            if (outcomes.total() >= want) return;
        }
    }

    fn report(self: *Pair, label: []const u8) void {
        std.debug.print("\n[stream-window] {s}\n", .{label});
        if (self.client.quicSession(self.session)) |r| std.debug.print(
            "  client session {s}: senders={d} receivers={d} inbox={d} pending_opens={d} next_bidi={d}\n",
            .{ @tagName(r.state()), r.runtime.pendingReliableSenders(), r.runtime.pendingReliableReceivers(), r.runtime.inboxLen(), pendingOpens(&r.runtime), r.runtime.stream_ids.next_bidi },
        ) else std.debug.print("  client session gone\n", .{});
        if (self.serverRuntime()) |r| std.debug.print(
            "  server session {s}: senders={d} receivers={d} inbox={d}\n",
            .{ @tagName(r.state()), r.runtime.pendingReliableSenders(), r.runtime.pendingReliableReceivers(), r.runtime.inboxLen() },
        ) else std.debug.print("  server session gone\n", .{});
        if (self.clientConn()) |c| reportConn("client conn", c);
        if (self.serverConn()) |c| reportConn("server conn", c);
    }
};

/// `pendingOpens` is new with the stream fixes; read it when present.
fn pendingOpens(runtime: anytype) usize {
    const T = @TypeOf(runtime.*);
    if (comptime @hasDecl(T, "pendingOpens")) return runtime.pendingOpens();
    return 0;
}

fn reportConn(label: []const u8, c: *quic_zig.Connection) void {
    std.debug.print("  {s}: closed={} local_bidi limit={d} opened={d} holes={d} | peer_bidi limit={d} opened={d} closed={d} holes={d} | live streams={d}\n", .{
        label,                        c.isClosed(),
        c.local_bidi_ids.limit,       c.local_bidi_ids.opened,
        c.local_bidi_ids.holeCount(), c.peer_bidi_ids.limit,
        c.peer_bidi_ids.opened,       c.peer_bidi_ids.closed,
        c.peer_bidi_ids.holeCount(),  c.streams.count(),
    });
}

const Outcomes = struct {
    replies: usize = 0,
    canceled: usize = 0,
    deadline_exceeded: usize = 0,
    other_failures: usize = 0,
    last_failure: ?node_mod.RequestFailure = null,

    fn total(self: Outcomes) usize {
        return self.replies + self.canceled + self.deadline_exceeded + self.other_failures;
    }
};

/// Some sandboxes deny UDP bind: not runnable here, not a failure.
fn skipIfNoUdp(err: anyerror) anyerror {
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

// A refused queueReliable must not use up a stream id: an id that is
// reserved and never opened is a stream the peer counts as open.
test "QueueFull refusals do not use up stream ids" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    p.setUp(a, .{ .initial_max_streams_bidi = 8 }, .{ .max_queued_messages = 4 }) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    errdefer p.report("QueueFull refusals");
    try p.driveUntilReady();

    // Four requests the server holds without an answer.
    var held: [4]node_mod.RequestId = undefined;
    for (&held, 0..) |*id, i| id.* = try p.request(i + 1, 60_000);
    var seen: usize = 0;
    for (0..2_000) |_| {
        try p.step();
        seen += (try p.serve(.drop)).requests;
        if (seen == held.len) break;
    }
    try std.testing.expectEqual(held.len, seen);

    // Eight refusals: the client queue is full.
    for (0..8) |i| {
        try std.testing.expectError(error.QueueFull, p.request(100 + i, 60_000));
    }

    // Cancel the held four (RESET_STREAM + STOP_SENDING closes them),
    // then ten request/reply rounds through the window of 8.
    var outcomes: Outcomes = .{};
    for (held) |id| try std.testing.expect(try p.client.cancelRequest(id));
    try p.collect(&outcomes);
    try std.testing.expectEqual(held.len, outcomes.canceled);
    try p.steps(200);
    for (0..10) |round| {
        _ = try p.request(1_000 + round, 2_000);
        try p.roundTrip(&outcomes, held.len + round + 1, 5_000);
        try std.testing.expectEqual(round + 1, outcomes.replies);
    }
    try p.expectSessionsReady();
}

// More requests than the window at once: the opens past the window
// wait for the peer to give ids back (StreamLimitExceeded is
// temporary), in id order.
test "a burst larger than the peer's window completes" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    p.setUp(a, .{ .initial_max_streams_bidi = 4 }, .{}) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    errdefer p.report("burst of 12 through a window of 4");
    try p.driveUntilReady();

    const n: usize = 12; // within the 16 receivers of the default byte budget
    for (0..n) |i| _ = try p.request(i + 1, 5_000);
    var outcomes: Outcomes = .{};
    try p.roundTrip(&outcomes, n, 10_000);
    try std.testing.expectEqual(n, outcomes.replies);
    try p.expectSessionsReady();
}

// Many messages queued before one pump. Opened out of id order, they
// leave more separate runs of skipped ids than quic-zig accepts (64):
// `TooManySkippedStreamIds`.
test "256 messages queued before one pump all arrive" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    p.setUp(a, .{}, .{}) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    errdefer p.report("256 queued before one pump");
    try p.driveUntilReady();

    const n: usize = 256;
    for (0..n) |i| try p.note(i + 1);
    var delivered: usize = 0;
    for (0..10_000) |_| {
        try p.step();
        delivered += (try p.serve(.answer)).no_reply;
        if (delivered == n) break;
    }
    try std.testing.expectEqual(n, delivered);
    try p.expectSessionsReady();
}
