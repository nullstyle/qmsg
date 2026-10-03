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
//! qmsg before the fix it names. The dropped-requests test passed before
//! too: it covers the requester's cancel plan. Two `Node`s, events
//! delivery, real sockets on 127.0.0.1, and a virtual clock (one step is
//! 1 ms) that may run at most `max_speedup` times faster than real time.
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
const start_us: u64 = 1_000;

/// An idle step takes far less than 1 ms of real time. Unpaced, the
/// virtual clock runs past deadlines and the idle timeout while a
/// datagram is late in real time, which happens under heavy machine
/// load. Paced, a lag must last 1/10 of a virtual timeout to do that.
const max_speedup: i64 = 10;

/// A deadline for requests that must succeed: far past any wait here.
const long_deadline_ms: u64 = 60_000;

const Pair = struct {
    allocator: std.mem.Allocator,
    server: Node,
    client: Node,
    target: []u8 = &.{},
    session: node_mod.QuicSessionId = 0,
    now_us: u64 = start_us,
    started: std.Io.Timestamp,

    /// Constructed in place: a `Node` holds interior pointers.
    fn setUp(self: *Pair, allocator: std.mem.Allocator, server_transport: quic.QuicOptions, client_transport: quic.QuicOptions) !void {
        self.* = .{
            .allocator = allocator,
            .server = try Node.init(allocator, .{ .delivery = .events }),
            .client = undefined,
            .started = std.Io.Timestamp.now(io(), .awake),
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
        try self.pace();
        try self.server.tick(self.now_us);
        try self.client.tick(self.now_us);
    }

    /// Sleeps while the virtual clock is more than `max_speedup` times
    /// ahead of real time.
    fn pace(self: *Pair) !void {
        const real_us = self.started.untilNow(io(), .awake).toMicroseconds();
        const virtual_us: i64 = @intCast(self.now_us - start_us);
        const ahead_us = @divTrunc(virtual_us, max_speedup) - real_us;
        if (ahead_us >= 1_000) try std.Io.sleep(io(), .fromMicroseconds(ahead_us), .awake);
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
            .{ @tagName(r.state()), r.runtime.pendingReliableSenders(), r.runtime.pendingReliableReceivers(), r.runtime.inboxLen(), r.runtime.pendingOpens(), r.runtime.stream_ids.next_bidi },
        ) else std.debug.print("  client session gone\n", .{});
        if (self.serverRuntime()) |r| std.debug.print(
            "  server session {s}: senders={d} receivers={d} inbox={d}\n",
            .{ @tagName(r.state()), r.runtime.pendingReliableSenders(), r.runtime.pendingReliableReceivers(), r.runtime.inboxLen() },
        ) else std.debug.print("  server session gone\n", .{});
        if (self.clientConn()) |c| reportConn("client conn", c);
        if (self.serverConn()) |c| reportConn("server conn", c);
    }
};

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
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

// A no_reply message rides a new bidi stream. The responder must end
// the reply half, or the stream never closes and each message keeps a
// place in the responder's window.
test "a session carries more no_reply messages than the peer's bidi window" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    p.setUp(a, .{ .initial_max_streams_bidi = 8 }, .{}) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    errdefer p.report("no_reply through a window of 8");
    try p.driveUntilReady();

    const total: usize = 40;
    var delivered: usize = 0;
    for (0..total) |i| {
        try p.note(i + 1);
        for (0..2_000) |_| {
            try p.step();
            delivered += (try p.serve(.answer)).no_reply;
            if (delivered == i + 1) break;
        }
        try std.testing.expectEqual(i + 1, delivered);
    }
    try p.expectSessionsReady();
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
    for (&held, 0..) |*id, i| id.* = try p.request(i + 1, long_deadline_ms);
    var seen: usize = 0;
    for (0..2_000) |_| {
        try p.step();
        seen += (try p.serve(.drop)).requests;
        if (seen == held.len) break;
    }
    try std.testing.expectEqual(held.len, seen);

    // Eight refusals: the client queue is full.
    for (0..8) |i| {
        try std.testing.expectError(error.QueueFull, p.request(100 + i, long_deadline_ms));
    }

    // Cancel the held four (RESET_STREAM + STOP_SENDING closes them),
    // then ten request/reply rounds through the window of 8.
    var outcomes: Outcomes = .{};
    for (held) |id| try std.testing.expect(try p.client.cancelRequest(id));
    try p.collect(&outcomes);
    try std.testing.expectEqual(held.len, outcomes.canceled);
    try p.steps(200);
    for (0..10) |round| {
        _ = try p.request(1_000 + round, long_deadline_ms);
        try p.roundTrip(&outcomes, held.len + round + 1, 5_000);
        try std.testing.expectEqual(round + 1, outcomes.replies);
    }
    try p.expectSessionsReady();
}

// A request canceled before its stream opened still owns its id. The
// responder sees the id as open (a higher id was used), arms a receiver
// for it, and keeps that receiver until the stream ends. With the
// default byte budget a session has 16 receivers.
test "requests canceled before their stream opens do not pin the responder's receivers" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    p.setUp(a, .{}, .{}) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    errdefer p.report("cancel before open");
    try p.driveUntilReady();

    for (0..16) |i| {
        const id = try p.request(i + 1, long_deadline_ms);
        try std.testing.expect(try p.client.cancelRequest(id));
    }
    var outcomes: Outcomes = .{};
    try p.collect(&outcomes);
    try std.testing.expectEqual(@as(usize, 16), outcomes.canceled);

    for (0..4) |round| {
        _ = try p.request(100 + round, long_deadline_ms);
        try p.roundTrip(&outcomes, 16 + round + 1, 5_000);
        try std.testing.expectEqual(round + 1, outcomes.replies);
    }
    try p.expectSessionsReady();
}

// A request the responder drops without an answer closes when the
// requester's deadline fires its cancel plan (RESET_STREAM +
// STOP_SENDING), so its place in the window comes back.
test "requests the responder drops unanswered give their window places back" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    p.setUp(a, .{ .initial_max_streams_bidi = 8 }, .{}) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    errdefer p.report("dropped requests");
    try p.driveUntilReady();

    var outcomes: Outcomes = .{};
    for (0..12) |i| {
        _ = try p.request(i + 1, 50);
        for (0..5_000) |_| {
            try p.step();
            _ = try p.serve(.drop);
            try p.collect(&outcomes);
            if (outcomes.total() == i + 1) break;
        }
        try std.testing.expectEqual(i + 1, outcomes.deadline_exceeded);
    }
    _ = try p.request(999, long_deadline_ms);
    try p.roundTrip(&outcomes, 13, 5_000);
    try std.testing.expectEqual(@as(usize, 1), outcomes.replies);
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
    for (0..n) |i| _ = try p.request(i + 1, long_deadline_ms);
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

// The responder answers after the requester canceled (RESET_STREAM +
// STOP_SENDING). The stream is closed or gone; the reply must be
// dropped, and the connection must stay up.
test "a reply to a request the requester canceled does not close the connection" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    p.setUp(a, .{}, .{}) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    errdefer p.report("late reply");
    try p.driveUntilReady();

    _ = try p.request(7, 20);
    var held: ?node_mod.Event = null;
    defer if (held) |*event| event.deinit();
    var outcomes: Outcomes = .{};
    for (0..2_000) |_| {
        try p.step();
        if (held == null) {
            var events: [4]node_mod.Event = undefined;
            const count = try p.server.poll(&events);
            for (events[0..count]) |*event| {
                if (held == null and event.* == .request) held = event.* else event.deinit();
            }
        }
        try p.collect(&outcomes);
        if (outcomes.deadline_exceeded > 0 and held != null) break;
    }
    try std.testing.expect(held != null);
    try std.testing.expectEqual(@as(usize, 1), outcomes.deadline_exceeded);

    // Let the cancel reach the server and the stream close there, then
    // answer late.
    try p.steps(200);
    const handle = held.?.request.msg.reply_handle orelse return error.ReplyHandleMissing;
    try p.server.reply(handle, .{ .subject = "", .body = "late" });
    try p.steps(200);
    try p.expectSessionsReady();

    // The session still carries a request.
    _ = try p.request(8, long_deadline_ms);
    try p.roundTrip(&outcomes, 2, 5_000);
    try std.testing.expectEqual(@as(usize, 1), outcomes.replies);
}

// The dial side reads its peer's streams AND the replies to its own
// requests through one Driver table. 32 requests wait for their replies
// while the server sends 256 no_reply messages back: 288 streams, more
// than the peer's windows (256 + 16) the table was sized for.
test "the dial side tracks the peer's streams and its own reply streams together" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    // 64 KiB messages: the byte budget allows 256 receivers, not 16.
    p.setUp(a, .{}, .{ .max_message_size = 64 * 1024 }) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    errdefer p.report("peer streams and reply streams in one table");
    try p.driveUntilReady();

    // 32 requests the server holds.
    const held_count: usize = 32;
    var held: std.ArrayList(node_mod.Event) = .empty;
    defer {
        for (held.items) |*event| event.deinit();
        held.deinit(a);
    }
    for (0..held_count) |i| _ = try p.request(i + 1, long_deadline_ms);
    for (0..5_000) |_| {
        try p.step();
        var events: [64]node_mod.Event = undefined;
        const count = try p.server.poll(&events);
        for (events[0..count]) |*event| {
            if (event.* == .request) try held.append(a, event.*) else event.deinit();
        }
        if (held.items.len == held_count) break;
    }
    try std.testing.expectEqual(held_count, held.items.len);

    // 256 no_reply messages from the server, queued before one pump.
    const server = p.serverRuntime() orelse return error.ServerSessionGone;
    for (0..256) |i| _ = try server.queueReliable(.{
        .subject = "note",
        .id = 1_000 + i,
        .flags = .{ .no_reply = true },
        .body = "x",
    });
    var delivered: usize = 0;
    for (0..10_000) |_| {
        try p.step();
        var events: [64]node_mod.Event = undefined;
        const count = try p.client.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| switch (event) {
            .request => |inbound| {
                if (inbound.msg.flags.no_reply) delivered += 1;
            },
            else => {},
        };
        if (delivered == 256) break;
    }
    try std.testing.expectEqual(@as(usize, 256), delivered);

    // Then the 32 replies.
    for (held.items) |event| {
        try p.server.reply(event.request.msg.reply_handle orelse return error.ReplyHandleMissing, .{ .subject = "", .body = "ok" });
    }
    var outcomes: Outcomes = .{};
    try p.roundTrip(&outcomes, held_count, 5_000);
    try std.testing.expectEqual(held_count, outcomes.replies);
    try p.expectSessionsReady();
}

// One session for thousands of streams, through a window of 16, with
// every way a stream ends mixed in: answered requests, no_reply
// messages, requests canceled before and after their stream opened,
// and requests whose deadline fires before a late answer. More streams
// than the old 4096-stream lifetime cap. At the end every stream is
// closed on both connections, no id is skipped, and both sessions are
// still up.
test "one session carries thousands of requests with aborts and no_reply messages mixed in" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    // 64 KiB messages: the byte budget allows 256 receivers, so a round
    // of 24 never meets QueueFull.
    p.setUp(a, .{ .initial_max_streams_bidi = 16 }, .{ .max_message_size = 64 * 1024 }) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    errdefer p.report("long session");
    try p.driveUntilReady();

    const Kind = enum { answered, no_reply, cancel_before_open, cancel_after_open, late_answer };
    const pattern = [_]Kind{ .answered, .no_reply, .answered, .cancel_before_open, .answered, .cancel_after_open, .answered, .late_answer };
    const rounds: usize = 250;
    const per_round: usize = 24;
    const total = rounds * per_round;

    var sent = std.EnumArray(Kind, usize).initFill(0);
    var outcomes: Outcomes = .{};
    var requests: usize = 0;
    var no_reply_seen: usize = 0;
    var held: std.ArrayList(struct { event: node_mod.Event, at_us: u64 }) = .empty;
    defer {
        for (held.items) |*entry| entry.event.deinit();
        held.deinit(a);
    }
    var cancel_later: std.ArrayList(node_mod.RequestId) = .empty;
    defer cancel_later.deinit(a);

    for (0..rounds) |round| {
        for (0..per_round) |slot| {
            const i = round * per_round + slot;
            const kind = pattern[i % pattern.len];
            sent.getPtr(kind).* += 1;
            const id: u64 = i + 1;
            switch (kind) {
                .answered => _ = try p.request(id, long_deadline_ms),
                .no_reply => try p.note(id),
                .cancel_before_open => try std.testing.expect(try p.client.cancelRequest(try p.request(id, long_deadline_ms))),
                .cancel_after_open => try cancel_later.append(a, try p.request(id, long_deadline_ms)),
                .late_answer => _ = try p.request(id, 30),
            }
            if (kind != .no_reply) requests += 1;
        }

        var round_steps: usize = 0;
        while (outcomes.total() < requests) : (round_steps += 1) {
            if (round_steps == 5_000) return error.RoundStalled;
            try p.step();
            if (round_steps == 3) {
                for (cancel_later.items) |rid| _ = try p.client.cancelRequest(rid);
                cancel_later.clearRetainingCapacity();
            }

            // Server: answer at once, or hold the late ones for 60 ms
            // (their deadline is 30 ms) and answer them then.
            var events: [64]node_mod.Event = undefined;
            const count = try p.server.poll(&events);
            for (events[0..count]) |*event| {
                if (event.* != .request) {
                    event.deinit();
                    continue;
                }
                const msg = event.request.msg;
                if (msg.flags.no_reply) {
                    no_reply_seen += 1;
                    event.deinit();
                } else if (pattern[(msg.id - 1) % pattern.len] == .late_answer) {
                    try held.append(a, .{ .event = event.*, .at_us = p.now_us });
                } else {
                    defer event.deinit();
                    try p.server.reply(msg.reply_handle orelse return error.ReplyHandleMissing, .{ .subject = "", .body = "ok" });
                }
            }
            var index: usize = 0;
            while (index < held.items.len) {
                if (p.now_us - held.items[index].at_us < 60 * step_us) {
                    index += 1;
                    continue;
                }
                var entry = held.swapRemove(index);
                defer entry.event.deinit();
                try p.server.reply(entry.event.request.msg.reply_handle orelse return error.ReplyHandleMissing, .{ .subject = "", .body = "late" });
            }
            try p.collect(&outcomes);
        }
    }

    // Drain: the last late answers and no_reply messages, then the
    // closes and their acknowledgements.
    for (0..1_000) |_| {
        try p.step();
        no_reply_seen += (try p.serve(.answer)).no_reply;
        while (held.pop()) |entry| {
            var owned = entry;
            defer owned.event.deinit();
            try p.server.reply(owned.event.request.msg.reply_handle orelse return error.ReplyHandleMissing, .{ .subject = "", .body = "late" });
        }
        try p.collect(&outcomes);
    }

    // Exactly one outcome per request, and the right one.
    try std.testing.expectEqual(requests, outcomes.total());
    try std.testing.expectEqual(@as(usize, 0), outcomes.other_failures);
    try std.testing.expectEqual(sent.get(.late_answer), outcomes.deadline_exceeded);
    try std.testing.expect(outcomes.canceled >= sent.get(.cancel_before_open));
    try std.testing.expect(outcomes.replies >= sent.get(.answered));
    try std.testing.expectEqual(sent.get(.no_reply), no_reply_seen);
    try p.expectSessionsReady();

    // Every stream opened and closed: no id skipped, nothing left.
    const client = try p.clientRuntime();
    try std.testing.expectEqual(@as(usize, 0), client.runtime.pendingOpens());
    try std.testing.expectEqual(@as(usize, 0), client.runtime.pendingReliableSenders());
    try std.testing.expectEqual(@as(usize, 0), client.runtime.pendingReliableReceivers());
    const server = p.serverRuntime() orelse return error.ServerSessionGone;
    try std.testing.expectEqual(@as(usize, 0), server.runtime.pendingReliableSenders());
    try std.testing.expectEqual(@as(usize, 0), server.runtime.pendingReliableReceivers());
    const client_conn = p.clientConn() orelse return error.ClientConnGone;
    const server_conn = p.serverConn() orelse return error.ServerConnGone;
    try std.testing.expectEqual(@as(u64, total), client_conn.local_bidi_ids.opened);
    try std.testing.expectEqual(@as(usize, 0), client_conn.local_bidi_ids.holeCount());
    try std.testing.expectEqual(@as(usize, 0), server_conn.peer_bidi_ids.holeCount());
    try std.testing.expectEqual(@as(u64, total), server_conn.peer_bidi_ids.closed);
    try std.testing.expectEqual(@as(usize, 0), client_conn.streams.count());
    try std.testing.expectEqual(@as(usize, 0), server_conn.streams.count());
}
