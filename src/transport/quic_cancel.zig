const std = @import("std");

/// qmsg application error codes carried in QUIC RESET_STREAM,
/// STOP_SENDING, and application CONNECTION_CLOSE frames.
///
/// These are intentionally outside the small QUIC transport-error space.
/// Unknown peer codes still map to stable qmsg errors below.
pub const AppErrorCode = struct {
    pub const graceful_shutdown: u64 = 0x51_00;
    pub const canceled: u64 = 0x51_01;
    pub const deadline_exceeded: u64 = 0x51_02;
    pub const queue_full: u64 = 0x51_03;
    pub const flow_controlled: u64 = 0x51_04;
};

pub const TransportErrorCode = struct {
    pub const protocol_violation: u64 = 0x0a;
};

pub const Error = error{
    Canceled,
    DeadlineExceeded,
    PeerClosed,
    ConnectionLost,
    StreamReset,
    QueueFull,
    FlowControlled,
};

pub const CancelReason = enum {
    explicit,
    deadline,
    queue_full,
    flow_controlled,
    peer_closed,

    pub fn appErrorCode(self: CancelReason) u64 {
        return switch (self) {
            .explicit, .peer_closed => AppErrorCode.canceled,
            .deadline => AppErrorCode.deadline_exceeded,
            .queue_full => AppErrorCode.queue_full,
            .flow_controlled => AppErrorCode.flow_controlled,
        };
    }

    pub fn stableError(self: CancelReason) Error {
        return switch (self) {
            .explicit => error.Canceled,
            .deadline => error.DeadlineExceeded,
            .queue_full => error.QueueFull,
            .flow_controlled => error.FlowControlled,
            .peer_closed => error.PeerClosed,
        };
    }
};

/// Which half of a QUIC stream qmsg is actively using when cancellation fires.
pub const StreamPhase = enum {
    /// Local qmsg is still writing request/message bytes.
    sending,
    /// Local qmsg is waiting for bytes from the peer.
    receiving,
    /// Both halves may still be active; reset send and stop receive.
    bidirectional,
};

pub const StreamCancelActions = packed struct {
    reset_stream: bool = false,
    stop_sending: bool = false,

    pub fn any(self: StreamCancelActions) bool {
        return self.reset_stream or self.stop_sending;
    }
};

pub const CancelPlan = struct {
    stream_id: u64,
    reason: CancelReason,
    actions: StreamCancelActions,
    app_error_code: u64,

    pub fn init(stream_id: u64, reason: CancelReason, phase: StreamPhase) CancelPlan {
        return .{
            .stream_id = stream_id,
            .reason = reason,
            .actions = actionsForPhase(phase),
            .app_error_code = reason.appErrorCode(),
        };
    }
};

pub const ApplyOptions = struct {
    /// QUIC stream GC may reclaim a stream before qmsg replays a cancel
    /// intent. Cancellation paths should normally treat that as success.
    ignore_stream_not_found: bool = true,
};

pub const ApplyResult = struct {
    /// True when the RESET_STREAM intent completed, including the
    /// configured StreamNotFound-as-success path.
    reset_stream_applied: bool = false,
    /// True when the STOP_SENDING intent completed, including the
    /// configured StreamNotFound-as-success path.
    stop_sending_applied: bool = false,
};

pub fn actionsForPhase(phase: StreamPhase) StreamCancelActions {
    return switch (phase) {
        .sending => .{ .reset_stream = true },
        .receiving => .{ .stop_sending = true },
        .bidirectional => .{ .reset_stream = true, .stop_sending = true },
    };
}

pub fn cancelPlan(stream_id: u64, reason: CancelReason, phase: StreamPhase) CancelPlan {
    return CancelPlan.init(stream_id, reason, phase);
}

pub fn deadlinePlan(
    stream_id: u64,
    deadline_ms: ?u64,
    now_ms: u64,
    phase: StreamPhase,
) ?CancelPlan {
    const deadline = deadline_ms orelse return null;
    if (now_ms < deadline) return null;
    return cancelPlan(stream_id, .deadline, phase);
}

pub fn applyCancelPlan(conn: anytype, plan: CancelPlan, options: ApplyOptions) !ApplyResult {
    var result: ApplyResult = .{};
    if (plan.actions.reset_stream) {
        conn.streamReset(plan.stream_id, plan.app_error_code) catch |err| switch (err) {
            error.StreamNotFound => if (!options.ignore_stream_not_found) return err,
            else => return err,
        };
        result.reset_stream_applied = true;
    }

    if (plan.actions.stop_sending) {
        conn.streamStopSending(plan.stream_id, plan.app_error_code) catch |err| switch (err) {
            error.StreamNotFound => if (!options.ignore_stream_not_found) return err,
            else => return err,
        };
        result.stop_sending_applied = true;
    }

    return result;
}

pub const CancellationState = struct {
    stream_id: u64,
    local_reason: ?CancelReason = null,
    actions: StreamCancelActions = .{},
    reset_stream_applied: bool = false,
    stop_sending_applied: bool = false,
    inbound_reset_code: ?u64 = null,
    peer_closed: bool = false,

    pub fn init(stream_id: u64) CancellationState {
        return .{ .stream_id = stream_id };
    }

    pub fn plan(self: *CancellationState, reason: CancelReason, phase: StreamPhase) CancelPlan {
        const out = cancelPlan(self.stream_id, reason, phase);
        self.local_reason = reason;
        self.actions = out.actions;
        return out;
    }

    pub fn planDeadline(
        self: *CancellationState,
        deadline_ms: ?u64,
        now_ms: u64,
        phase: StreamPhase,
    ) ?CancelPlan {
        const out = deadlinePlan(self.stream_id, deadline_ms, now_ms, phase) orelse return null;
        self.local_reason = out.reason;
        self.actions = out.actions;
        return out;
    }

    pub fn noteApplied(self: *CancellationState, result: ApplyResult) void {
        self.reset_stream_applied = self.reset_stream_applied or result.reset_stream_applied;
        self.stop_sending_applied = self.stop_sending_applied or result.stop_sending_applied;
    }

    pub fn noteInboundReset(self: *CancellationState, application_error_code: u64) void {
        self.inbound_reset_code = application_error_code;
    }

    pub fn notePeerClosed(self: *CancellationState) void {
        self.peer_closed = true;
    }

    pub fn locallyCanceled(self: CancellationState) bool {
        return self.local_reason != null;
    }

    pub fn stableError(self: CancellationState) Error {
        if (self.local_reason) |reason| return reason.stableError();
        if (self.peer_closed) return error.PeerClosed;
        if (self.inbound_reset_code) |code| return mapPeerResetCode(code);
        return error.Canceled;
    }
};

pub const InboundReset = struct {
    application_error_code: u64,
};

pub fn mapInboundReset(state: CancellationState, reset: InboundReset) Error {
    if (state.local_reason) |reason| return reason.stableError();
    return mapPeerResetCode(reset.application_error_code);
}

pub fn mapPeerResetCode(application_error_code: u64) Error {
    return switch (application_error_code) {
        AppErrorCode.canceled, AppErrorCode.deadline_exceeded => error.Canceled,
        AppErrorCode.queue_full => error.QueueFull,
        AppErrorCode.flow_controlled => error.FlowControlled,
        else => error.StreamReset,
    };
}

pub const CloseSource = enum {
    local,
    peer,
    idle_timeout,
    stateless_reset,
    version_negotiation,
};

pub const CloseErrorSpace = enum {
    transport,
    application,
};

pub const CloseSnapshot = struct {
    source: CloseSource,
    error_space: CloseErrorSpace,
    error_code: u64,
};

pub const CloseIntent = union(enum) {
    graceful_shutdown,
    protocol_violation,
    canceled: CancelReason,
    application_error: u64,
};

pub const CloseFrame = struct {
    is_transport: bool,
    error_code: u64,
    reason: []const u8 = "",
};

pub fn closeFrame(intent: CloseIntent) CloseFrame {
    return switch (intent) {
        .graceful_shutdown => .{
            .is_transport = false,
            .error_code = AppErrorCode.graceful_shutdown,
            .reason = "qmsg shutdown",
        },
        .protocol_violation => .{
            .is_transport = true,
            .error_code = TransportErrorCode.protocol_violation,
            .reason = "qmsg protocol violation",
        },
        .canceled => |reason| .{
            .is_transport = false,
            .error_code = reason.appErrorCode(),
            .reason = "qmsg canceled",
        },
        .application_error => |code| .{
            .is_transport = false,
            .error_code = code,
        },
    };
}

pub fn closeConnection(conn: anytype, intent: CloseIntent) void {
    const frame = closeFrame(intent);
    conn.close(frame.is_transport, frame.error_code, frame.reason);
}

pub fn mapClose(snapshot: CloseSnapshot) Error {
    return switch (snapshot.source) {
        .local => error.Canceled,
        .idle_timeout, .stateless_reset, .version_negotiation => error.ConnectionLost,
        .peer => switch (snapshot.error_space) {
            .transport => error.ConnectionLost,
            .application => switch (snapshot.error_code) {
                AppErrorCode.queue_full => error.QueueFull,
                AppErrorCode.flow_controlled => error.FlowControlled,
                else => error.PeerClosed,
            },
        },
    };
}

pub fn mapBackpressure(on_receive_half: bool, queue_full: bool) struct {
    reason: CancelReason,
    phase: StreamPhase,
} {
    return .{
        .reason = if (queue_full) .queue_full else .flow_controlled,
        .phase = if (on_receive_half) .receiving else .sending,
    };
}

const FakeConn = struct {
    missing: bool = false,
    reset_count: usize = 0,
    stop_count: usize = 0,
    last_reset: ?u64 = null,
    last_stop: ?u64 = null,
    close_is_transport: bool = false,
    close_code: u64 = 0,
    close_reason: []const u8 = "",

    fn streamReset(self: *FakeConn, stream_id: u64, code: u64) error{ StreamNotFound, Broken }!void {
        if (self.missing) return error.StreamNotFound;
        self.reset_count += 1;
        self.last_reset = stream_id ^ code;
    }

    fn streamStopSending(self: *FakeConn, stream_id: u64, code: u64) error{ StreamNotFound, Broken }!void {
        if (self.missing) return error.StreamNotFound;
        self.stop_count += 1;
        self.last_stop = stream_id ^ code;
    }

    fn close(self: *FakeConn, is_transport: bool, code: u64, reason: []const u8) void {
        self.close_is_transport = is_transport;
        self.close_code = code;
        self.close_reason = reason;
    }
};

test "deadline plans map stream phases to QUIC reset and stop-sending actions" {
    try std.testing.expect(deadlinePlan(9, 200, 199, .sending) == null);

    const sending = deadlinePlan(9, 200, 200, .sending).?;
    try std.testing.expect(sending.actions.reset_stream);
    try std.testing.expect(!sending.actions.stop_sending);
    try std.testing.expectEqual(AppErrorCode.deadline_exceeded, sending.app_error_code);

    const receiving = deadlinePlan(9, 200, 201, .receiving).?;
    try std.testing.expect(!receiving.actions.reset_stream);
    try std.testing.expect(receiving.actions.stop_sending);

    const both = deadlinePlan(9, 200, 201, .bidirectional).?;
    try std.testing.expect(both.actions.reset_stream);
    try std.testing.expect(both.actions.stop_sending);
}

test "applyCancelPlan calls reset and stop sending idempotently over QUIC-like wrapper" {
    var conn: FakeConn = .{};
    const result = try applyCancelPlan(&conn, cancelPlan(7, .explicit, .bidirectional), .{});

    try std.testing.expect(result.reset_stream_applied);
    try std.testing.expect(result.stop_sending_applied);
    try std.testing.expectEqual(@as(usize, 1), conn.reset_count);
    try std.testing.expectEqual(@as(usize, 1), conn.stop_count);
    try std.testing.expectEqual(@as(?u64, 7 ^ AppErrorCode.canceled), conn.last_reset);
    try std.testing.expectEqual(@as(?u64, 7 ^ AppErrorCode.canceled), conn.last_stop);
}

test "applyCancelPlan can ignore reclaimed streams" {
    var conn: FakeConn = .{ .missing = true };
    const result = try applyCancelPlan(&conn, cancelPlan(7, .explicit, .bidirectional), .{});

    try std.testing.expect(result.reset_stream_applied);
    try std.testing.expect(result.stop_sending_applied);
    try std.testing.expectEqual(@as(usize, 0), conn.reset_count);
    try std.testing.expectEqual(@as(usize, 0), conn.stop_count);

    try std.testing.expectError(
        error.StreamNotFound,
        applyCancelPlan(&conn, cancelPlan(7, .explicit, .sending), .{
            .ignore_stream_not_found = false,
        }),
    );
}

test "cancellation state maps local and inbound resets to stable qmsg errors" {
    var local_deadline = CancellationState.init(11);
    const plan = local_deadline.plan(.deadline, .receiving);
    try std.testing.expectEqual(error.DeadlineExceeded, local_deadline.stableError());
    try std.testing.expectEqual(error.DeadlineExceeded, mapInboundReset(
        local_deadline,
        .{ .application_error_code = plan.app_error_code },
    ));

    var inbound = CancellationState.init(12);
    inbound.noteInboundReset(AppErrorCode.deadline_exceeded);
    try std.testing.expectEqual(error.Canceled, inbound.stableError());
    try std.testing.expectEqual(error.Canceled, mapInboundReset(
        inbound,
        .{ .application_error_code = AppErrorCode.canceled },
    ));
    try std.testing.expectEqual(error.StreamReset, mapInboundReset(
        .{ .stream_id = 13 },
        .{ .application_error_code = 0xdead },
    ));
}

test "close mapping distinguishes peer close from connection loss" {
    try std.testing.expectEqual(error.PeerClosed, mapClose(.{
        .source = .peer,
        .error_space = .application,
        .error_code = AppErrorCode.graceful_shutdown,
    }));
    try std.testing.expectEqual(error.ConnectionLost, mapClose(.{
        .source = .peer,
        .error_space = .transport,
        .error_code = TransportErrorCode.protocol_violation,
    }));
    try std.testing.expectEqual(error.ConnectionLost, mapClose(.{
        .source = .idle_timeout,
        .error_space = .transport,
        .error_code = 0,
    }));
}

test "closeConnection emits transport or application close frames" {
    var conn: FakeConn = .{};
    closeConnection(&conn, .protocol_violation);
    try std.testing.expect(conn.close_is_transport);
    try std.testing.expectEqual(TransportErrorCode.protocol_violation, conn.close_code);
    try std.testing.expectEqualStrings("qmsg protocol violation", conn.close_reason);

    closeConnection(&conn, .graceful_shutdown);
    try std.testing.expect(!conn.close_is_transport);
    try std.testing.expectEqual(AppErrorCode.graceful_shutdown, conn.close_code);
}

test "backpressure intent selects stable reason and stream half" {
    const recv_full = mapBackpressure(true, true);
    try std.testing.expectEqual(CancelReason.queue_full, recv_full.reason);
    try std.testing.expectEqual(StreamPhase.receiving, recv_full.phase);
    try std.testing.expect(actionsForPhase(recv_full.phase).stop_sending);

    const send_flow = mapBackpressure(false, false);
    try std.testing.expectEqual(CancelReason.flow_controlled, send_flow.reason);
    try std.testing.expectEqual(StreamPhase.sending, send_flow.phase);
    try std.testing.expect(actionsForPhase(send_flow.phase).reset_stream);
}
