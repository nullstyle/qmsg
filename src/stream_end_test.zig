//! The end of a reply that arrives ALONE, after the requester read every
//! byte of it.
//!
//! quic-zig reclaims a stream at the end of `tick`, once both halves are
//! done. When the peer's end comes in a frame of its own (a FIN with no
//! data, or a RESET_STREAM) after the application read every byte,
//! `handle` makes the receive half terminal with nothing left to read, and
//! the next `tick` destroys the stream. A read after that `tick` finds no
//! stream, and cannot tell a clean end from a reset (`quic.app` reports
//! `.reaped`). So a loop must read its streams between feeding datagrams
//! and `tick`.
//!
//! qmsg's dial loop (`Node.tickQuicClients`) used to feed, tick, then
//! read. A complete reply whose FIN came alone was then reported as
//! `request_failed{peer_closed}`. Here the responder writes the whole reply
//! without FIN, waits until the requester has read it and every byte is
//! acknowledged, and then sends the end alone. Two `Node`s, events
//! delivery, real sockets on 127.0.0.1, and a virtual clock (one step is
//! 1 ms) that may run at most `max_speedup` times faster than real time.

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
const max_speedup: i64 = 10;
const long_deadline_ms: u64 = 60_000;

const reply_body = "the whole reply, read before its end arrives";

/// Any code: qmsg reads no reset codes. A reset is a failure whatever
/// its code.
const reset_code: u64 = 0x77;

const End = enum { fin, reset };

const Pair = struct {
    allocator: std.mem.Allocator,
    server: Node,
    client: Node,
    target: []u8 = &.{},
    session: node_mod.QuicSessionId = 0,
    now_us: u64 = start_us,
    started: std.Io.Timestamp,

    /// Constructed in place: a `Node` holds interior pointers.
    fn setUp(self: *Pair, allocator: std.mem.Allocator) !void {
        self.* = .{
            .allocator = allocator,
            .server = try Node.init(allocator, .{ .delivery = .events }),
            .client = undefined,
            .started = std.Io.Timestamp.now(io(), .awake),
        };
        errdefer self.server.deinit();
        const listener_id = try self.server.listenQuic("127.0.0.1:0", .{
            .tls_cert_pem = cert_pem,
            .tls_key_pem = key_pem,
            .transport = .{
                .peer_id = "end-server",
                .role_flags = control.RoleFlags.server,
                .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
            },
        });
        const address = self.server.quic_listeners.items[listener_id].localAddress();
        self.target = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{address.ip4.port});
        errdefer allocator.free(self.target);

        self.client = try Node.init(allocator, .{ .delivery = .events });
        errdefer self.client.deinit();
        self.session = try self.client.dialQuic(self.target, .{
            .server_name = "localhost",
            .ca_pem = cert_pem,
            .transport = .{
                .peer_id = "end-client",
                .role_flags = control.RoleFlags.client,
                .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
            },
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

    fn clientRuntime(self: *Pair) !*node_mod.QuicSessionRuntime {
        return self.client.quicSession(self.session) orelse error.ClientSessionGone;
    }

    fn serverRuntime(self: *Pair) ?*node_mod.QuicSessionRuntime {
        for (self.server.quic_sessions.items) |runtime| return runtime;
        return null;
    }

    fn clientConn(self: *Pair) !*quic_zig.Connection {
        if (self.client.quic_clients.items.len == 0) return error.ClientConnectionGone;
        return self.client.quic_clients.items[0].client.runtime.connection();
    }

    fn serverConn(self: *Pair) !*quic_zig.Connection {
        if (self.server.quic_listeners.items.len == 0) return error.ServerConnectionGone;
        return self.server.quic_listeners.items[0].listener.runtime.connection(0) orelse
            error.ServerConnectionGone;
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

    /// Client side: polls once and counts the outcomes of `request_id`.
    fn collect(self: *Pair, request_id: node_mod.RequestId, outcomes: *Outcomes) !void {
        var events: [8]node_mod.Event = undefined;
        const count = try self.client.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| switch (event) {
            .reply => |reply| {
                if (reply.request_id != request_id) continue;
                outcomes.replies += 1;
                if (std.mem.eql(u8, reply.msg.body, reply_body)) outcomes.whole_replies += 1;
            },
            .request_failed => |failed| {
                if (failed.request_id != request_id) continue;
                outcomes.failures += 1;
                outcomes.last_failure = failed.failure;
            },
            else => {},
        };
    }

    fn report(self: *Pair, label: []const u8, stream_id: ?u64) void {
        std.debug.print("\n[stream-end] {s}\n", .{label});
        const id = stream_id orelse return;
        if (self.clientConn()) |c| {
            if (c.streamRecvState(id)) |st| std.debug.print(
                "  client stream {d}: read_offset={d} final_size={?d} fin_seen={} reset_seen={} terminal={}\n",
                .{ id, st.read_offset, st.final_size, st.fin_seen, st.reset_seen, st.terminal },
            ) else std.debug.print("  client stream {d}: gone (reaped={})\n", .{ id, c.streamRecvWasReaped(id) });
        } else |_| std.debug.print("  client connection gone\n", .{});
    }
};

const Outcomes = struct {
    replies: usize = 0,
    whole_replies: usize = 0,
    failures: usize = 0,
    last_failure: ?node_mod.RequestFailure = null,

    fn total(self: Outcomes) usize {
        return self.replies + self.failures;
    }
};

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

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

/// One request. The responder writes the whole reply without FIN. Once
/// the requester has read every byte, every byte is acknowledged and the
/// request half is done, the responder sends `end` alone. Returns what
/// the requester saw.
fn endAloneAfterEveryByteWasRead(p: *Pair, end: End, stream_id: *?u64) !Outcomes {
    try p.driveUntilReady();
    const request_id = try p.client.request(.{ .quic = p.session }, .{
        .subject = "work",
        .id = 7,
        .deadline_ms = long_deadline_ms,
        .body = "x",
    });

    // The responder takes the request.
    for (0..2_000) |_| {
        try p.step();
        var events: [8]node_mod.Event = undefined;
        const count = try p.server.poll(&events);
        defer for (events[0..count]) |*event| event.deinit();
        for (events[0..count]) |event| switch (event) {
            .request => |inbound| stream_id.* = inbound.stream_id,
            else => {},
        };
        if (stream_id.* != null) break;
    }
    const id = stream_id.* orelse return error.RequestMissing;

    // The whole reply, without FIN.
    const server = p.serverRuntime() orelse return error.ServerSessionGone;
    try server.runtime.queueReliableOnStream(id, .{
        .subject = "work",
        .id = 7,
        .body = reply_body,
    }, .{ .open_bidi = false, .finish = false });

    // The requester reads every byte; both ends acknowledge everything.
    var outcomes: Outcomes = .{};
    var read_all = false;
    for (0..5_000) |_| {
        try p.step();
        try p.collect(request_id, &outcomes);
        const reply_half = &((try p.serverConn()).stream(id) orelse return error.ReplyStreamGone).send;
        const client_stream = (try p.clientConn()).stream(id) orelse return error.ReplyStreamGone;
        const recv = (try p.clientConn()).streamRecvState(id) orelse return error.ReplyStreamGone;
        const written = reply_half.writtenBytes();
        if (written > 0 and reply_half.ackedFloor() == written and
            recv.read_offset == written and client_stream.send.isTerminal())
        {
            read_all = true;
            break;
        }
    }
    try std.testing.expect(read_all);
    // No end yet, so no outcome yet: qmsg waits for the end of the stream.
    const before = (try p.clientConn()).streamRecvState(id).?;
    try std.testing.expect(!before.fin_seen and !before.reset_seen and before.final_size == null);
    try std.testing.expectEqual(@as(usize, 0), outcomes.total());

    // The end, alone.
    const sconn = try p.serverConn();
    switch (end) {
        .fin => try sconn.streamFinish(id),
        .reset => try sconn.streamReset(id, reset_code),
    }
    for (0..2_000) |_| {
        try p.step();
        try p.collect(request_id, &outcomes);
        if (outcomes.total() > 0) break;
    }
    // Nothing more comes for this request.
    for (0..50) |_| {
        try p.step();
        try p.collect(request_id, &outcomes);
    }
    return outcomes;
}

test "a reply whose FIN comes alone after every byte was read is delivered" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    p.setUp(a) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    var stream_id: ?u64 = null;
    errdefer p.report("bare FIN after the whole reply", stream_id);

    const outcomes = try endAloneAfterEveryByteWasRead(&p, .fin, &stream_id);
    try std.testing.expectEqual(@as(usize, 0), outcomes.failures);
    try std.testing.expectEqual(@as(usize, 1), outcomes.replies);
    try std.testing.expectEqual(@as(usize, 1), outcomes.whole_replies);
    try std.testing.expectEqual(quic.State.ready, (try p.clientRuntime()).state());
}

test "a reset that comes alone after every reply byte was read is a failure" {
    const a = std.testing.allocator;
    var p: Pair = undefined;
    p.setUp(a) catch |err| return skipIfNoUdp(err);
    defer p.tearDown();
    var stream_id: ?u64 = null;
    errdefer p.report("bare RESET_STREAM after the whole reply", stream_id);

    const outcomes = try endAloneAfterEveryByteWasRead(&p, .reset, &stream_id);
    try std.testing.expectEqual(@as(usize, 0), outcomes.replies);
    try std.testing.expectEqual(@as(usize, 1), outcomes.failures);
    try std.testing.expectEqual(node_mod.RequestFailure.peer_closed, outcomes.last_failure.?);
    try std.testing.expectEqual(quic.State.ready, (try p.clientRuntime()).state());
}
