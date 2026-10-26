//! Bounded public-Node scenario shared by examples, composition gates and profiles.
const std = @import("std");
const qmsg = @import("qmsg");
const tls = @import("local_tls_fixture.zig");
const owner = @import("owner_wait.zig");

pub const Options = struct {
    publications: usize = 24,
    payload_bytes: usize = 128,
    queue_messages: usize = 4,
    queue_bytes: usize = 16 * 1024,
    stream_window: u64 = 2,
    timeout_us: u64 = 10_000_000,
};

pub const Report = struct {
    attempted: usize = 0,
    matched: usize = 0,
    queued: usize = 0,
    backpressured: usize = 0,
    dropped: usize = 0,
    healthy_delivered: usize = 0,
    slow_delivered: usize = 0,
    peak_pending_messages: usize = 0,
    peak_pending_bytes: usize = 0,
    configured_queue_messages_per_peer: usize = 0,
    configured_queue_bytes_per_peer: usize = 0,
    cold_handshake_us: u64 = 0,
    warm_elapsed_us: u64 = 0,
    reconnected: bool = false,
};

const State = struct {
    io: std.Io,
    publisher: *qmsg.Node,
    subscribers: *[3]qmsg.Node,
    options: Options,
    report: *Report,
    publisher_sessions: [3]?qmsg.node.QuicSessionId = @splat(null),
    subscriber_sessions: [3]qmsg.node.QuicSessionId = undefined,
    connecting_index: usize = 0,
    active: [3]bool = @splat(true),
    seen: [3][]bool,
    deadline: u64,

    fn step(self: *State) !void {
        const now = owner.nowUs(self.io);
        if (now >= self.deadline) return error.WorkloadTimeout;
        try self.publisher.tick(now);
        for (self.subscribers, self.active) |*subscriber, active| if (active) try subscriber.tick(now);
        var did_work = false;
        var events: [32]qmsg.NodeEvent = undefined;
        {
            const count = try self.publisher.poll(&events);
            defer for (events[0..count]) |*event| event.deinit();
            did_work = count > 0;
            for (events[0..count]) |event| switch (event) {
                .connected => |id| self.publisher_sessions[self.connecting_index] = id,
                .request, .reply, .delivery, .request_failed => return error.UnexpectedPublisherData,
                else => {},
            };
        }
        for (self.subscribers, self.active, 0..) |*subscriber, active, index| {
            if (!active) continue;
            const count = try subscriber.poll(&events);
            defer for (events[0..count]) |*event| event.deinit();
            did_work = did_work or count > 0;
            for (events[0..count]) |event| switch (event) {
                .delivery => |delivery| {
                    const msg = delivery.msg;
                    if (!msg.flags.no_reply or msg.flags.unreliable or msg.reply_handle != null) return error.WrongDeliveryContract;
                    if (!std.mem.startsWith(u8, msg.subject, "news.")) return error.SourceFilterFailed;
                    if (msg.id == 0) continue; // Subscription synchronization probe.
                    if (msg.id == self.options.publications + 1) {
                        if (index == 0) self.report.reconnected = true;
                        continue;
                    }
                    if (msg.id > self.options.publications or msg.body.len != self.options.payload_bytes) return error.CorruptPublication;
                    for (msg.body) |byte| if (byte != @as(u8, @intCast(msg.id % 251))) return error.CorruptPublication;
                    if (self.seen[index][@intCast(msg.id - 1)]) return error.DuplicatePublication;
                    self.seen[index][@intCast(msg.id - 1)] = true;
                    if (index < 2) self.report.healthy_delivered += 1 else self.report.slow_delivered += 1;
                },
                .request, .reply, .request_failed => return error.WrongPublicationEvent,
                else => {},
            };
        }
        const stats = self.publisher.publicationStats();
        self.report.peak_pending_messages = @max(self.report.peak_pending_messages, stats.high_water_messages);
        self.report.peak_pending_bytes = @max(self.report.peak_pending_bytes, stats.high_water_bytes);
        if (stats.pending_messages > 3 * self.options.queue_messages or stats.pending_bytes > 3 * self.options.queue_bytes) return error.UnboundedPublicationQueue;
        if (did_work) return;
        var handles: [16]std.Io.net.Socket.Handle = undefined;
        var used = try self.publisher.readableSockets(&handles);
        var next = self.publisher.nextTimer();
        for (self.subscribers, self.active) |*subscriber, active| if (active) {
            used += try subscriber.readableSockets(handles[used..]);
            next = owner.earliest(next, subscriber.nextTimer());
        };
        try owner.wait(self.io, handles[0..used], owner.earliest(next, self.deadline).?);
    }

    fn ready(self: *State, index: usize) !void {
        self.connecting_index = index;
        while (true) {
            try self.step();
            const left = self.subscribers[index].sessionStatus(self.subscriber_sessions[index]);
            const right = if (self.publisher_sessions[index]) |id| self.publisher.sessionStatus(id) else null;
            if (left != null and right != null and left.?.state == .ready and right.?.state == .ready) return;
        }
    }
};

pub fn run(allocator: std.mem.Allocator, io: std.Io, options: Options) !Report {
    if (options.queue_messages == 0 or options.queue_messages > 64 or options.publications < options.queue_messages * 2 + 8 or options.publications > 1_000_000 or options.payload_bytes == 0 or options.payload_bytes > 2048 or options.queue_bytes < options.payload_bytes + 64 or options.queue_bytes > 64 * 1024 or options.stream_window == 0 or options.stream_window > 64 or options.timeout_us == 0 or options.timeout_us > 120_000_000) return error.InvalidWorkloadOptions;
    var report: Report = .{ .configured_queue_messages_per_peer = options.queue_messages, .configured_queue_bytes_per_peer = options.queue_bytes };
    var publisher = try qmsg.Node.init(allocator, .{ .io = io, .quic_inbound = .refuse, .quic_reliable_publications = .{ .max_messages = options.queue_messages, .max_bytes = options.queue_bytes } });
    defer publisher.deinit();
    var subscribers: [3]qmsg.Node = undefined;
    var initialized: usize = 0;
    defer for (subscribers[0..initialized]) |*subscriber| subscriber.deinit();
    for (&subscribers) |*subscriber| {
        subscriber.* = try qmsg.Node.init(allocator, .{ .io = io, .quic_inbound = .publications, .max_events = 8 });
        initialized += 1;
        try subscriber.subscribeQuic("news.*", .{ .on_full = .block });
    }
    var seen: [3][]bool = undefined;
    var seen_initialized: usize = 0;
    defer for (seen[0..seen_initialized]) |slice| allocator.free(slice);
    for (&seen) |*slice| {
        slice.* = try allocator.alloc(bool, options.publications);
        @memset(slice.*, false);
        seen_initialized += 1;
    }
    const transport: qmsg.transport.quic.QuicOptions = .{
        .supported_patterns = qmsg.control.PatternBits.pub_,
        .required_peer_patterns = qmsg.control.PatternBits.sub,
        .initial_max_streams_bidi = options.stream_window,
        .max_queued_messages = options.queue_messages,
        .max_message_size = 4096,
        .max_queued_bytes = 64 * 1024,
        .initial_max_data = 64 * 1024,
        .initial_max_stream_data_bidi_local = 16 * 1024,
        .initial_max_stream_data_bidi_remote = 16 * 1024,
    };
    const listener = try publisher.listenQuic("127.0.0.1:0", .{ .tls_cert_pem = tls.cert, .tls_key_pem = tls.key, .transport = transport });
    const address = try publisher.quicListenerAddress(listener);
    var target_buffer: [64]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buffer, "127.0.0.1:{d}", .{address.ip4.port});
    var subscriber_transport = transport;
    subscriber_transport.supported_patterns = qmsg.control.PatternBits.sub;
    subscriber_transport.required_peer_patterns = qmsg.control.PatternBits.pub_;
    const dial_options: qmsg.node.QuicDialOptions = .{ .server_name = "localhost", .ca_pem = tls.cert, .transport = subscriber_transport };
    const started = owner.nowUs(io);
    var state: State = .{ .io = io, .publisher = &publisher, .subscribers = &subscribers, .options = options, .report = &report, .seen = seen, .deadline = started +| options.timeout_us };
    for (&state.subscriber_sessions, 0..) |*id, index| {
        id.* = try subscribers[index].dialQuic(target, dial_options);
        try state.ready(index);
    }
    // The public admission result is also the source's synchronization probe;
    // zero-id probes are excluded from the measured application workload.
    while (true) {
        const sync = try publisher.publishQuicReliable(.{ .subject = "news.sync", .id = 0 });
        try state.step();
        if (sync.matched == 3) break;
    }
    report.cold_handshake_us = owner.nowUs(io) - started;
    const unmatched = try publisher.publishQuicReliable(.{ .subject = "unmatched.item", .body = "must not cross the source" });
    if (unmatched.matched != 0 or unmatched.queued != 0) return error.SourceFilterFailed;
    state.active[2] = false;
    const warm = owner.nowUs(io);
    const payload = try allocator.alloc(u8, options.payload_bytes);
    defer allocator.free(payload);
    for (0..options.publications) |index| {
        @memset(payload, @intCast((index + 1) % 251));
        const result = try publisher.publishQuicReliable(.{ .subject = "news.item", .id = index + 1, .body = payload });
        report.attempted += 1;
        report.matched += result.matched;
        report.queued += result.queued;
        report.backpressured += result.backpressured;
        report.dropped += result.dropped;
        while (!seen[0][index] or !seen[1][index]) try state.step();
    }
    report.warm_elapsed_us = owner.nowUs(io) - warm;
    if (report.healthy_delivered != 2 * options.publications or report.slow_delivered != 0 or report.backpressured == 0 or report.matched != 3 * options.publications or report.queued < 2 * options.publications) return error.SlowConsumerIsolationFailed;
    // Reconnect one healthy subscriber. Its node-level desired subscription
    // survives: deliberately do not subscribe again on the replacement session.
    try subscribers[0].closeQuicSession(state.subscriber_sessions[0]);
    try publisher.closeQuicSession(state.publisher_sessions[0].?);
    state.publisher_sessions[0] = null;
    state.subscriber_sessions[0] = try subscribers[0].dialQuic(target, dial_options);
    try state.ready(0);
    while (!report.reconnected) {
        _ = try publisher.publishQuicReliable(.{ .subject = "news.reborn", .id = options.publications + 1 });
        try state.step();
    }
    if (report.peak_pending_messages > 3 * options.queue_messages or report.peak_pending_bytes > 3 * options.queue_bytes) return error.UnboundedPublicationQueue;
    return report;
}
