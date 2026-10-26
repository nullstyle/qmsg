//! Bounded public application acceptance; no private Node/runtime access.
const std = @import("std");
const qmsg = @import("qmsg");
const tls = @import("local_tls_fixture.zig");
const owner = @import("owner_wait.zig");
const Req = qmsg.QuicSocket(.req);
const Rep = qmsg.QuicSocket(.rep);
const control_code: u64 = 0x535434;
const control_reason = "public-fault-grace";
const cert_sha = blk: {
    @setEvalBranchQuota(30_000);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(tls.cert, &digest, .{});
    break :blk std.fmt.bytesToHex(digest, .lower);
};
const Kind = enum { success, denied, canceled, deadline, closed };
pub const Options = struct { seed: u64 = 0x71534d3400000001, payload_bytes: usize = 128, stream_window: u64 = 8, deadline_ms: u64 = 100, timeout_us: u64 = 10_000_000 };
pub const Report = struct {
    tls_certificate_sha256: []const u8 = &cert_sha,
    payload_pattern: []const u8 = "seed-wire-actor-v1",
    deadline_ms: u64 = 0,
    normal_deadline_ms: u64 = 2000,
    drain_timeout_us: u64 = 200_000,
    timeout_us: u64 = 0,
    victim_event_capacity: usize = 0,
    healthy_event_capacity: usize = 8,
    server_event_capacity: usize = 4,
    control_code: u64 = control_code,
    control_reason: []const u8 = control_reason,
    max_requests_per_client: usize = 2,
    send_queue_messages: usize = 2,
    max_completion_bytes: usize = 4096,
    max_sessions_per_actor: usize = 4,
    ledger_capacity: usize = 32,
    handle_capacity: usize = 8,
    server_requests: usize = 0,
    peak_retained_handles: usize = 0,
    /// Observed public connected-session IDs, not transport half-open states.
    peak_server_sessions: usize = 0,
    late_reply_refused: usize = 0,
    completed: bool = false,
    seed: u64 = 0,
    payload_bytes: usize = 0,
    stream_window: u64 = 0,
    accepted: usize = 0,
    terminal: usize = 0,
    succeeded: usize = 0,
    canceled: usize = 0,
    deadline_exceeded: usize = 0,
    authorization_denied: usize = 0,
    peer_closed: usize = 0,
    remote_close_observed: bool = false,
    remote_loss_us: u64 = 0,
    loss_request_deadline_ms: u64 = 5000,
    queue_refused: usize = 0,
    inflight_refused: usize = 0,
    role_rejected: usize = 0,
    role_positive_control_ready: bool = false,
    healthy_succeeded: usize = 0,
    goaway_events: usize = 0,
    goaway_refused: usize = 0,
    handles_retained: usize = 0,
    handles_released: usize = 0,
    late_reply_attempts: usize = 0,
    stale_handle_rejected: usize = 0,
    reconnected: bool = false,
    drain_closed: bool = false,
    events_received: usize = 0,
    events_deinitialized: usize = 0,
    peak_outstanding_per_client: usize = 0,
    ordinary_events_dropped: usize = 0,
    pending_at_end: usize = 0,
    duplicate_terminals: usize = 0,
    loop_steps: usize = 0,
    elapsed_us: u64 = 0,
};
const Entry = struct { actor: usize, id: qmsg.RequestId, wire: u64, subject: []const u8, kind: Kind, done: bool = false, server_seen: bool = false };
const Held = struct { handle: ?qmsg.ReplyHandle = null, actor: usize = 0, wire: u64 = 0, session: qmsg.QuicSessionId = 0 };
// Deterministic application capability fixture, not token cryptography.
fn authenticate(_: ?*anyopaque, a: std.mem.Allocator, credential: qmsg.auth.Credential) !qmsg.Authorization {
    const role: qmsg.auth.Pattern = if (std.mem.eql(u8, credential.token, "fixture:req-a") or std.mem.eql(u8, credential.token, "fixture:req-b")) .req else if (std.mem.eql(u8, credential.token, "fixture:rep") or std.mem.eql(u8, credential.token, "fixture:wrong-role")) .rep else return error.Unauthorized;
    return (qmsg.Authorization{ .subject = credential.token, .issuer = "public-fault-fixture", .allowed_patterns = qmsg.auth.PatternSet.init(&.{role}), .allowed_subjects = .{ .filters = &.{"svc.*"} } }).clone(a);
}

const Harness = struct {
    io: std.Io,
    options: Options,
    clients: [2]Req,
    sessions: [2]qmsg.QuicSessionId,
    server: Rep,
    endpoint: [64]u8,
    endpoint_len: usize,
    entries: [32]Entry = undefined,
    used: usize = 0,
    held: [8]Held = @splat(.{}),
    extra: ?*Req = null,
    extra_session: ?qmsg.QuicSessionId = null,
    server_sessions: [8]qmsg.QuicSessionId = undefined,
    session_count: usize = 0,
    expect_goaway: bool = false,
    report: Report,
    start: u64,
    stop: u64,
    fn transport(options: Options, credential: []const u8) qmsg.transport.quic.QuicOptions {
        return .{ .peer_id = credential, .auth = .{ .scheme = qmsg.auth.hello_auth_scheme_paseto, .credential = credential }, .auth_config = .{ .required = true, .authenticator = .{ .authenticate_fn = authenticate } }, .initial_max_streams_bidi = options.stream_window, .initial_max_streams_uni = 8, .max_queued_messages = 2, .max_message_size = 4096, .max_queued_bytes = 32 * 1024, .drain_timeout_ms = 200 };
    }
    fn init(a: std.mem.Allocator, io: std.Io, options: Options) !Harness {
        var clients: [2]Req = undefined;
        var initialized: usize = 0;
        errdefer for (clients[0..initialized]) |*client| client.deinit();
        for (&clients, 0..) |*client, index| {
            client.* = try Req.init(a, .{ .node = .{ .io = io, .max_events = if (index == 0) 0 else 8, .max_requests = 2, .max_completion_bytes = 4096, .max_sessions = 4 } });
            initialized += 1;
        }
        var server = try Rep.init(a, .{ .node = .{ .io = io, .max_events = 4, .max_sessions = 4 } });
        errdefer server.deinit();
        const listener = try server.listen("127.0.0.1:0", .{ .tls_cert_pem = tls.cert, .tls_key_pem = tls.key, .transport = transport(options, "fixture:rep") });
        const address = try server.localAddress(listener);
        var endpoint: [64]u8 = undefined;
        const target = try std.fmt.bufPrint(&endpoint, "127.0.0.1:{d}", .{address.ip4.port});
        var sessions: [2]qmsg.QuicSessionId = undefined;
        for (&clients, &sessions, 0..) |*client, *session, actor| session.* = try client.dial(target, .{ .server_name = "localhost", .ca_pem = tls.cert, .transport = transport(options, if (actor == 0) "fixture:req-a" else "fixture:req-b") });
        const now = owner.nowUs(io);
        return .{ .io = io, .options = options, .clients = clients, .sessions = sessions, .server = server, .endpoint = endpoint, .endpoint_len = target.len, .report = .{ .seed = options.seed, .payload_bytes = options.payload_bytes, .stream_window = options.stream_window, .deadline_ms = options.deadline_ms, .timeout_us = options.timeout_us }, .start = now, .stop = now + options.timeout_us };
    }
    fn deinit(self: *Harness) void {
        for (&self.held) |*held| if (held.handle) |*handle| handle.deinit();
        for (&self.clients) |*client| client.deinit();
        self.server.deinit();
    }
    fn byte(self: *const Harness, actor: usize, wire: u64) u8 {
        return @truncate(self.options.seed ^ (wire *% 0x9e3779b97f4a7c15) ^ @as(u64, if (actor == 0) 0xa5 else 0x5a));
    }
    fn checkBody(self: *const Harness, actor: usize, wire: u64, body: []const u8) !void {
        if (body.len != self.options.payload_bytes) return error.PayloadLength;
        for (body) |value| if (value != self.byte(actor, wire)) return error.PayloadCorruption;
    }
    fn request(self: *Harness, actor: usize, wire: u64, subject: []const u8, kind: Kind, deadline_ms: u64) !usize {
        if (self.used == self.entries.len) return error.LedgerBound;
        var payload: [512]u8 = undefined;
        @memset(payload[0..self.options.payload_bytes], self.byte(actor, wire));
        const id = try self.clients[actor].request(self.sessions[actor], .{ .subject = subject, .id = wire, .body = payload[0..self.options.payload_bytes], .deadline_ms = deadline_ms });
        for (self.entries[0..self.used]) |entry| if (entry.actor == actor and entry.id == id) return error.DuplicateLocalId;
        const index = self.used;
        self.used += 1;
        self.entries[index] = .{ .actor = actor, .wire = wire, .id = id, .subject = subject, .kind = kind };
        self.report.accepted += 1;
        var pending: usize = 0;
        for (self.entries[0..self.used]) |entry| if (entry.actor == actor and !entry.done) {
            pending += 1;
        };
        self.report.peak_outstanding_per_client = @max(self.report.peak_outstanding_per_client, pending);
        if (pending > 2) return error.RequestBound;
        return index;
    }
    fn outcome(self: *Harness, actor: usize, event: qmsg.NodeEvent) !void {
        const id = switch (event) {
            .reply => |r| r.request_id,
            .request_failed => |f| f.request_id,
            else => return error.NotTerminal,
        };
        const index = for (self.entries[0..self.used], 0..) |entry, i| {
            if (entry.actor == actor and entry.id == id) break i;
        } else return error.UnknownTerminal;
        const entry = &self.entries[index];
        if (entry.done) {
            self.report.duplicate_terminals += 1;
            return error.DuplicateTerminal;
        }
        switch (event) {
            .reply => |r| {
                if (r.msg.id != entry.wire) return error.WrongWireId;
                if (entry.kind == .denied) {
                    if (!r.msg.flags.err or !std.mem.eql(u8, r.msg.body, "Unauthorized")) return error.WrongDenial;
                    self.report.authorization_denied += 1;
                } else {
                    if (entry.kind != .success or r.msg.flags.err) return error.UnexpectedReply;
                    try self.checkBody(actor, entry.wire, r.msg.body);
                    self.report.succeeded += 1;
                    if (actor == 1) self.report.healthy_succeeded += 1;
                }
            },
            .request_failed => |f| switch (entry.kind) {
                .canceled => {
                    if (f.failure != .canceled) return error.WrongFailure;
                    self.report.canceled += 1;
                },
                .deadline => {
                    if (f.failure != .deadline_exceeded) return error.WrongFailure;
                    self.report.deadline_exceeded += 1;
                },
                .closed => {
                    if (f.failure != .peer_closed) return error.WrongFailure;
                    self.report.peer_closed += 1;
                },
                else => return error.UnexpectedFailure,
            },
            else => unreachable,
        }
        entry.done = true;
        self.report.terminal += 1;
    }
    fn take(self: *Harness, index: usize) !void {
        const entry = self.entries[index];
        var event = self.clients[entry.actor].takeOutcome(entry.id) orelse return error.MissingReservedOutcome;
        self.report.events_received += 1;
        defer {
            event.deinit();
            self.report.events_deinitialized += 1;
        }
        try self.outcome(entry.actor, event);
    }
    fn step(self: *Harness) !void {
        const now = owner.nowUs(self.io);
        if (now >= self.stop or self.report.loop_steps >= 100_000) return error.FaultTimeout;
        self.report.loop_steps += 1;
        for (&self.clients) |*client| try client.pump(now);
        try self.server.pump(now);
        if (self.extra) |extra| try extra.pump(now);
        var did_work = false;
        {
            var events: [16]qmsg.NodeEvent = undefined;
            const count = try self.server.poll(&events);
            self.report.events_received += count;
            defer {
                for (events[0..count]) |*event| event.deinit();
                self.report.events_deinitialized += count;
            }
            did_work = count != 0;
            for (events[0..count]) |event| switch (event) {
                .request => |r| {
                    const actor: usize = if (std.mem.eql(u8, r.msg.subject, "svc.healthy") or std.mem.eql(u8, r.msg.subject, "svc.grace")) 1 else 0;
                    const index = for (self.entries[0..self.used], 0..) |entry, i| {
                        if (entry.actor == actor and entry.wire == r.msg.id and !entry.done and !entry.server_seen) break i;
                    } else return error.RefusedOrDuplicateRequestReachedApplication;
                    if (self.entries[index].kind == .denied or std.mem.eql(u8, r.msg.subject, "svc.cancel-before") or !std.mem.eql(u8, self.entries[index].subject, r.msg.subject)) return error.UnauthorizedRequestReachedApplication;
                    self.entries[index].server_seen = true;
                    self.report.server_requests += 1;
                    try self.checkBody(actor, r.msg.id, r.msg.body);
                    if (std.mem.eql(u8, r.msg.subject, "svc.echo") or std.mem.eql(u8, r.msg.subject, "svc.healthy")) {
                        try self.server.reply(r.msg.reply_handle.?, .{ .subject = "", .body = r.msg.body });
                    } else {
                        const slot = for (&self.held) |*held| {
                            if (held.handle == null) break held;
                        } else return error.HandleBound;
                        slot.* = .{ .handle = r.msg.reply_handle.?.retain(), .actor = actor, .wire = r.msg.id, .session = r.session_id };
                        self.report.handles_retained += 1;
                        var retained: usize = 0;
                        for (self.held) |held| if (held.handle != null) {
                            retained += 1;
                        };
                        self.report.peak_retained_handles = @max(self.report.peak_retained_handles, retained);
                    }
                },
                .connected => |id| {
                    if (self.extra != null) self.extra_session = id;
                    if (self.session_count == self.server_sessions.len) return error.SessionObservationBound;
                    self.server_sessions[self.session_count] = id;
                    self.session_count += 1;
                },
                .closed, .message_dropped => {},
                else => return error.UnexpectedServerEvent,
            };
        }
        for (&self.clients, 0..) |*client, actor| {
            var events: [16]qmsg.NodeEvent = undefined;
            const count = try client.poll(&events);
            self.report.events_received += count;
            defer {
                for (events[0..count]) |*event| event.deinit();
                self.report.events_deinitialized += count;
            }
            did_work = did_work or count != 0;
            for (events[0..count]) |event| switch (event) {
                .reply, .request_failed => try self.outcome(actor, event),
                .connected, .closed, .message_dropped => {},
                .session_goaway => |goaway| {
                    if (!self.expect_goaway or actor != 1 or goaway.code != control_code or !std.mem.eql(u8, goaway.reason, control_reason)) return error.WrongGoaway;
                    self.report.goaway_events += 1;
                },
                else => return error.NonCanonicalEvent,
            };
        }
        if (self.extra) |extra| {
            var events: [16]qmsg.NodeEvent = undefined;
            const count = try extra.poll(&events);
            self.report.events_received += count;
            defer {
                for (events[0..count]) |*event| event.deinit();
                self.report.events_deinitialized += count;
            }
            for (events[0..count]) |event| switch (event) {
                .connected, .closed, .message_dropped => {},
                else => return error.RejectedPeerDeliveredData,
            };
            did_work = did_work or count != 0;
        }
        var live_sessions: usize = 0;
        for (self.server_sessions[0..self.session_count]) |id| if (self.server.sessionStatus(id) != null) {
            live_sessions += 1;
        };
        self.report.peak_server_sessions = @max(self.report.peak_server_sessions, live_sessions);
        if (live_sessions > 4) return error.SessionBound;
        if (did_work) return;
        var handles: [16]std.Io.net.Socket.Handle = undefined;
        var used = try self.server.readableSockets(&handles);
        var next = self.server.nextTimer();
        for (&self.clients) |*client| {
            used += try client.readableSockets(handles[used..]);
            next = owner.earliest(next, client.nextTimer());
        }
        if (self.extra) |extra| {
            used += try extra.readableSockets(handles[used..]);
            next = owner.earliest(next, extra.nextTimer());
        }
        try owner.wait(self.io, handles[0..used], owner.earliest(next, self.stop).?);
    }
    fn ready(self: *Harness) !void {
        while (true) {
            try self.step();
            var all = true;
            for (&self.clients, self.sessions) |*client, id| {
                const s = client.sessionStatus(id);
                all = all and s != null and s.?.state == .ready;
            }
            if (all) return;
        }
    }
    fn requestRetry(self: *Harness, actor: usize, wire: u64, subject: []const u8, kind: Kind, deadline_ms: u64) !usize {
        while (true) return self.request(actor, wire, subject, kind, deadline_ms) catch |err| switch (err) {
            error.QueueFull => {
                self.report.queue_refused += 1;
                try self.step();
                continue;
            },
            else => return err,
        };
    }
    fn heldFor(self: *Harness, actor: usize, wire: u64) ?*Held {
        for (&self.held) |*held| if (held.handle != null and held.actor == actor and held.wire == wire) return held;
        return null;
    }
    fn waitHeld(self: *Harness, actor: usize, wire: u64) !void {
        while (self.heldFor(actor, wire) == null) try self.step();
    }
    fn release(self: *Harness, held: *Held) void {
        held.handle.?.deinit();
        held.handle = null;
        self.report.handles_released += 1;
    }
    fn replyHeld(self: *Harness, actor: usize, wire: u64, late: bool) !void {
        const held = self.heldFor(actor, wire) orelse return error.MissingDeferredHandle;
        var payload: [512]u8 = undefined;
        @memset(payload[0..self.options.payload_bytes], self.byte(actor, wire));
        if (late) self.report.late_reply_attempts += 1;
        self.server.reply(held.handle.?, .{ .subject = "", .body = payload[0..self.options.payload_bytes] }) catch |err| {
            if (!late) return err;
            switch (err) {
                error.EndpointClosed, error.InvalidState, error.StreamClosed, error.StreamNotFound, error.StreamReset => self.report.late_reply_refused += 1,
                else => return err,
            }
        };
        self.release(held);
    }
    fn healthyProbe(self: *Harness, wire: u64) !void {
        const index = try self.requestRetry(1, wire, "svc.healthy", .success, 2000);
        try self.wait(index);
    }
    fn wait(self: *Harness, index: usize) !void {
        while (!self.entries[index].done) try self.step();
    }
};

pub fn run(a: std.mem.Allocator, io: std.Io, options: Options) !Report {
    if (options.payload_bytes == 0 or options.payload_bytes > 512 or options.stream_window < 2 or options.stream_window > 16 or options.deadline_ms < 20 or options.deadline_ms > 500 or options.timeout_us < 3_000_000 or options.timeout_us > 30_000_000) return error.InvalidOptions;
    var h = try Harness.init(a, io, options);
    defer h.deinit();
    try h.ready();
    const canceled = try h.request(0, 1, "svc.cancel-before", .canceled, 2000);
    const timed = try h.request(0, 2, "svc.deadline", .deadline, options.deadline_ms);
    if (h.clients[0].request(h.sessions[0], .{ .subject = "svc.refused", .id = 999 }) catch |err| switch (err) {
        error.TooManyInflightRequests => blk: {
            h.report.inflight_refused += 1;
            break :blk null;
        },
        else => return err,
    }) |_| return error.RequestLimitMissing;
    if (!try h.clients[0].cancelRequest(h.entries[canceled].id)) return error.CancelFailed;
    if (h.clients[0].request(h.sessions[0], .{ .subject = "svc.refused", .id = 998 }) catch |err| switch (err) {
        error.TooManyInflightRequests => blk: {
            h.report.inflight_refused += 1;
            break :blk null;
        },
        else => return err,
    }) |_| return error.TerminalReservationMissing;
    try h.take(canceled);
    const echoed = while (true) {
        break h.request(0, 3, "svc.echo", .success, 2000) catch |err| switch (err) {
            error.QueueFull => {
                h.report.queue_refused += 1;
                try h.step();
                continue;
            },
            else => return err,
        };
    };
    try h.healthyProbe(3);
    try h.wait(echoed);
    try h.wait(timed);
    const denied = try h.request(0, 4, "forbidden", .denied, 2000);
    try h.wait(denied);
    {
        // Same TLS setup and two existing live clients as the negative below.
        // This prevents capacity/TLS failure from being mistaken for role denial.
        var valid = try Req.init(a, .{ .node = .{ .io = io, .max_sessions = 1 } });
        defer valid.deinit();
        h.extra = &valid;
        h.extra_session = null;
        defer h.extra = null;
        const id = try valid.dial(h.endpoint[0..h.endpoint_len], .{ .server_name = "localhost", .ca_pem = tls.cert, .transport = Harness.transport(options, "fixture:req-a") });
        while (true) {
            try h.step();
            const local = valid.sessionStatus(id);
            const remote = if (h.extra_session) |sid| h.server.sessionStatus(sid) else null;
            if (local != null and remote != null and local.?.state == .ready and remote.?.state == .ready) break;
        }
        h.report.role_positive_control_ready = true;
        const server_id = h.extra_session.?;
        try h.server.closeSession(server_id);
        while (valid.sessionStatus(id) != null or h.server.sessionStatus(server_id) != null) try h.step();
        var live: usize = 0;
        for (h.server_sessions[0..h.session_count]) |sid| if (h.server.sessionStatus(sid) != null) {
            live += 1;
        };
        if (live != 2) return error.RoleControlChangedInitialLoad;
    }
    {
        var wrong = try Req.init(a, .{ .node = .{ .io = io, .max_sessions = 1 } });
        defer wrong.deinit();
        h.extra = &wrong;
        h.extra_session = null;
        defer h.extra = null;
        const id = try wrong.dial(h.endpoint[0..h.endpoint_len], .{ .server_name = "localhost", .ca_pem = tls.cert, .transport = Harness.transport(options, "fixture:wrong-role") });
        while (true) {
            try h.step();
            if (h.extra_session) |sid| if (h.server.sessionStatus(sid)) |status| if (status.state == .ready) return error.WrongRoleAdmitted;
            const status = wrong.sessionStatus(id);
            if (status == null or status.?.state == .closing) break;
        }
        h.report.role_rejected += 1;
    }
    try h.healthyProbe(4);
    const cancel_open = try h.requestRetry(0, 5, "svc.cancel-open", .canceled, 2000);
    try h.waitHeld(0, 5);
    if (!try h.clients[0].cancelRequest(h.entries[cancel_open].id)) return error.OpenCancellationFailed;
    try h.take(cancel_open);
    try h.replyHeld(0, 5, true);
    try h.replyHeld(0, 2, true);
    try h.healthyProbe(5);

    const lost = try h.requestRetry(0, 6, "svc.loss", .closed, 5000);
    try h.waitHeld(0, 6);
    const stale = h.heldFor(0, 6).?;
    const old_session = h.sessions[0];
    const remote_close_at = owner.nowUs(io);
    // Only the server initiates loss. The client must learn closure from its
    // real UDP connection and preserve the reserved peer_closed outcome.
    try h.server.closeSession(stale.session);
    try h.healthyProbe(6);
    try h.wait(lost);
    while (h.clients[0].sessionStatus(old_session) != null) try h.step();
    h.report.remote_loss_us = owner.nowUs(io) - remote_close_at;
    h.report.remote_close_observed = true;
    var rejected = false;
    h.server.reply(stale.handle.?, .{ .subject = "", .body = "stale" }) catch |err| {
        if (err != error.EndpointClosed) return err;
        rejected = true;
        h.report.stale_handle_rejected += 1;
    };
    if (!rejected) return error.StaleHandleSurvivedClose;
    h.release(stale);
    h.sessions[0] = try h.clients[0].dial(h.endpoint[0..h.endpoint_len], .{ .server_name = "localhost", .ca_pem = tls.cert, .transport = Harness.transport(options, "fixture:req-a") });
    if (h.sessions[0] == old_session) return error.ReusedSessionId;
    try h.ready();
    const reborn = try h.requestRetry(0, 6, "svc.echo", .success, 2000);
    if (h.entries[reborn].id == h.entries[lost].id) return error.ReusedRequestId;
    try h.wait(reborn);
    h.report.reconnected = true;
    try h.healthyProbe(7);

    const graceful = try h.requestRetry(1, 8, "svc.grace", .success, 2000);
    try h.waitHeld(1, 8);
    const drain_session = h.heldFor(1, 8).?.session;
    h.expect_goaway = true;
    try h.server.goaway(drain_session, control_code, control_reason, owner.nowUs(io), 200_000);
    while (h.report.goaway_events == 0) try h.step();
    if (h.clients[1].request(h.sessions[1], .{ .subject = "svc.refused", .id = 997 }) catch |err| switch (err) {
        error.EndpointClosed => blk: {
            h.report.goaway_refused += 1;
            break :blk null;
        },
        else => return err,
    }) |_| return error.GoawayAcceptedNewRequest;
    const during = try h.requestRetry(0, 7, "svc.echo", .success, 2000);
    try h.replyHeld(1, 8, false);
    try h.wait(graceful);
    try h.wait(during);
    while (h.server.sessionStatus(drain_session) != null or h.clients[1].sessionStatus(h.sessions[1]) != null) try h.step();
    h.report.drain_closed = true;
    const after = try h.requestRetry(0, 8, "svc.echo", .success, 2000);
    try h.wait(after);
    for (h.entries[0..h.used]) |entry| {
        if (!entry.done) h.report.pending_at_end += 1;
        if (h.clients[entry.actor].takeOutcome(entry.id)) |returned| {
            var unexpected = returned;
            unexpected.deinit();
            return error.DuplicateFinalOutcome;
        }
        if (try h.clients[entry.actor].cancelRequest(entry.id)) return error.CompletedRequestStillCancelable;
    }
    h.report.ordinary_events_dropped = h.clients[0].stats().events_dropped;
    h.report.elapsed_us = owner.nowUs(io) - h.start;
    if (h.report.accepted != 15 or h.report.terminal != 15 or h.report.succeeded != 10 or h.report.authorization_denied != 1 or h.report.role_rejected != 1 or !h.report.role_positive_control_ready or h.report.healthy_succeeded != 6 or h.report.canceled != 2 or h.report.deadline_exceeded != 1 or h.report.peer_closed != 1 or !h.report.remote_close_observed or h.report.remote_loss_us >= h.report.loss_request_deadline_ms * 1000 or h.report.inflight_refused != 2 or h.report.queue_refused == 0 or h.report.goaway_events != 1 or h.report.goaway_refused != 1 or h.report.handles_retained != 4 or h.report.handles_released != 4 or h.report.late_reply_attempts != 2 or h.report.stale_handle_rejected != 1 or h.report.server_requests != 13 or h.report.pending_at_end != 0 or h.report.events_received != h.report.events_deinitialized or h.report.duplicate_terminals != 0 or h.report.ordinary_events_dropped == 0) return error.FaultInvariant;
    h.report.completed = true;
    return h.report;
}
