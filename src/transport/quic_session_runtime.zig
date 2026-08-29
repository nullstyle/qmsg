const std = @import("std");
const quic_zig = @import("quic");

const control = @import("../control.zig");
const envelope = @import("../envelope.zig");
const message = @import("../message.zig");
const protocol = @import("../protocol/root.zig");
const queue = @import("../queue.zig");
const session_mod = @import("../session.zig");
const quic = @import("quic.zig");
const quic_cancel = @import("quic_cancel.zig");
const quic_control = @import("quic_control.zig");
const quic_datagram = @import("quic_datagram.zig");
const quic_streams = @import("quic_streams.zig");

const pushpull = protocol.pushpull;

pub const Error = std.mem.Allocator.Error || error{
    Canceled,
    DeadlineExceeded,
    EndpointClosed,
    FlowControlled,
    InvalidState,
    MalformedFrame,
    MessageTooLarge,
    PeerClosed,
    QueueFull,
    StreamAlreadyOpen,
    StreamNotFound,
    StreamReset,
    ConnectionLost,
    UnsupportedTransport,
};

pub const DatagramSendOptions = quic_datagram.SendOptions;
pub const DatagramReceiveOptions = quic_datagram.ReceiveOptions;
pub const DatagramSendResult = quic_datagram.SendResult;
pub const ReceivedDatagram = quic_datagram.ReceivedDatagram;

pub const PumpResult = struct {
    control_frames_read: usize = 0,
    control_flush_complete: usize = 0,
    reliable_sent_complete: usize = 0,
    reliable_received: usize = 0,
};

pub const ReceivedReliable = struct {
    stream_id: u64,
    message: message.Message,

    pub fn takeMessage(self: *ReceivedReliable) message.Message {
        const msg = self.message;
        self.* = undefined;
        return msg;
    }

    pub fn deinit(self: *ReceivedReliable) void {
        self.message.deinit();
        self.* = undefined;
    }
};

pub const QuicSessionRuntime = struct {
    allocator: std.mem.Allocator,
    session: quic.QuicSession,
    /// True when this session's inbound messages are consumed
    /// through the owner's `poll` events (the embedded pull model)
    /// instead of `runOnce` dispatch. Set by the attach dispatch
    /// that created the session on a foreign embedder's connection.
    event_delivery: bool = false,
    stream_ids: quic_streams.StreamIdAllocator,
    control_sender: ?quic_streams.ControlStreamSender = null,
    control_flush_sender: ?quic_control.FlushSender = null,
    control_receiver: ?quic_streams.ControlStreamReceiver = null,
    reliable_senders: std.AutoHashMap(u64, quic_streams.ReliableMessageSender),
    reliable_receivers: std.AutoHashMap(u64, quic_streams.ReliableMessageReceiver),
    inbox: std.ArrayList(ReceivedReliable) = .empty,
    envelope_codec: envelope.CodecOptions = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        session_id: session_mod.SessionId,
        role: quic.Role,
        options: quic.QuicOptions,
    ) !QuicSessionRuntime {
        var stream_ids = quic_streams.StreamIdAllocator.init(role);
        const hello_stream_id = try stream_ids.nextUni();
        std.debug.assert(hello_stream_id == quic.localControlStreamId(role));

        return .{
            .allocator = allocator,
            .session = try quic.QuicSession.init(allocator, session_id, role, options),
            .stream_ids = stream_ids,
            .reliable_senders = std.AutoHashMap(u64, quic_streams.ReliableMessageSender).init(allocator),
            .reliable_receivers = std.AutoHashMap(u64, quic_streams.ReliableMessageReceiver).init(allocator),
            .envelope_codec = envelopeCodecFromOptions(options),
        };
    }

    pub fn deinit(self: *QuicSessionRuntime) void {
        if (self.control_sender) |*sender| sender.deinit();
        if (self.control_flush_sender) |*sender| sender.deinit();
        if (self.control_receiver) |*receiver| receiver.deinit();

        var senders = self.reliable_senders.valueIterator();
        while (senders.next()) |sender| sender.deinit();
        self.reliable_senders.deinit();

        var receivers = self.reliable_receivers.valueIterator();
        while (receivers.next()) |receiver| receiver.deinit();
        self.reliable_receivers.deinit();

        for (self.inbox.items) |*received| received.deinit();
        self.inbox.deinit(self.allocator);

        self.session.deinit();
        self.* = undefined;
    }

    pub fn id(self: QuicSessionRuntime) session_mod.SessionId {
        return self.session.session.id;
    }

    pub fn appSession(self: *QuicSessionRuntime) *session_mod.Session {
        return &self.session.session;
    }

    pub fn state(self: QuicSessionRuntime) quic.State {
        return self.session.state();
    }

    pub fn isClosing(self: QuicSessionRuntime) bool {
        return self.session.state() == .closing;
    }

    pub fn isClosed(self: QuicSessionRuntime) bool {
        return self.session.state() == .closed;
    }

    pub fn isClosingOrClosed(self: QuicSessionRuntime) bool {
        return self.isClosing() or self.isClosed();
    }

    pub fn ensureOpen(self: QuicSessionRuntime) Error!void {
        if (self.isClosingOrClosed()) return error.EndpointClosed;
    }

    pub fn beginClosing(self: *QuicSessionRuntime) void {
        if (!self.isClosed()) self.session.state_value = .closing;
    }

    pub fn markClosed(self: *QuicSessionRuntime) void {
        self.session.close();
    }

    pub fn closeConnection(
        self: *QuicSessionRuntime,
        conn: anytype,
        intent: quic_cancel.CloseIntent,
    ) void {
        self.beginClosing();
        quic_cancel.closeConnection(conn, intent);
    }

    pub fn peerId(self: QuicSessionRuntime) []const u8 {
        return self.session.peerId();
    }

    pub fn onQuicReady(self: *QuicSessionRuntime) !void {
        try self.session.onQuicReady();
        try self.armPeerControlReceiver();
        try self.queueLocalHello();
    }

    /// Queues one reliable message on a freshly opened bidi stream.
    ///
    /// A request sent on a bidi stream expects its reply on that same
    /// stream, and the requester's OWN stream id is never covered by
    /// `acceptPeerBidiStreamsConnection` (which auto-accepts only
    /// peer-initiated streams) — so the reply receiver is armed here.
    /// Without it the reply's bytes land on the connection while
    /// `recvReliable` returns null forever and the request expires.
    /// A stream that never receives its reply keeps an idle receiver
    /// until the session deinits.
    pub fn queueReliable(self: *QuicSessionRuntime, outgoing: message.OutgoingMessage) !u64 {
        try self.ensureReadyForApplicationData();

        const stream_id = try self.stream_ids.nextBidi();
        try self.queueReliableOnStream(stream_id, outgoing, .{});

        self.acceptReliableStream(stream_id) catch |err| switch (err) {
            error.StreamAlreadyOpen => {},
            else => return err,
        };
        return stream_id;
    }

    pub fn sendReliable(self: *QuicSessionRuntime, outgoing: message.OutgoingMessage) !u64 {
        return self.queueReliable(outgoing);
    }

    pub fn queueReliableOnStream(
        self: *QuicSessionRuntime,
        stream_id: u64,
        outgoing: message.OutgoingMessage,
        options: quic_streams.ReliableWriteOptions,
    ) !void {
        try self.ensureReadyForApplicationData();
        if (self.reliable_senders.contains(stream_id)) return error.StreamAlreadyOpen;

        var sender = try quic_streams.ReliableMessageSender.init(
            self.allocator,
            stream_id,
            outgoing,
            self.envelope_codec,
            options,
        );
        errdefer sender.deinit();

        try self.reliable_senders.put(stream_id, sender);
    }

    pub fn replyReliableOnStream(
        self: *QuicSessionRuntime,
        stream_id: u64,
        outgoing: message.OutgoingMessage,
    ) !void {
        try self.queueReliableOnStream(stream_id, outgoing, .{ .open_bidi = false });
    }

    pub fn acceptReliableStream(self: *QuicSessionRuntime, stream_id: u64) !void {
        try self.ensureReadyForApplicationData();
        if (self.reliable_receivers.contains(stream_id)) return error.StreamAlreadyOpen;

        const receiver = quic_streams.ReliableMessageReceiver.init(
            self.allocator,
            stream_id,
            self.envelope_codec,
        );
        try self.reliable_receivers.put(stream_id, receiver);
    }

    pub fn queueSubscribe(
        self: *QuicSessionRuntime,
        control_state: *quic_control.State,
        filter: []const u8,
        options: queue.QueueOptions,
    ) !void {
        try self.ensureReadyForApplicationData();
        try control_state.queueSubscribe(filter, options);
    }

    pub fn queueUnsubscribe(
        self: *QuicSessionRuntime,
        control_state: *quic_control.State,
        filter: []const u8,
    ) !void {
        try self.ensureReadyForApplicationData();
        try control_state.queueUnsubscribe(filter);
    }

    pub fn queueCredit(
        self: *QuicSessionRuntime,
        control_state: *quic_control.State,
        subject_filter: []const u8,
        credit: pushpull.Credit,
    ) !void {
        try self.ensureReadyForApplicationData();
        try control_state.queueCredit(subject_filter, credit);
    }

    pub fn flushQueuedControl(
        self: *QuicSessionRuntime,
        control_state: *quic_control.State,
    ) !?u64 {
        try self.ensureReadyForApplicationData();
        if (self.control_sender != null) return error.InvalidState;
        if (control_state.queuedFrameCount() == 0) return null;
        if (self.control_flush_sender != null) return error.InvalidState;

        const stream_id = try self.stream_ids.nextUni();
        var sender = try control_state.initFlushSender(
            stream_id,
            self.session.options.control_codec,
            .{},
        );
        errdefer sender.deinit();

        self.control_flush_sender = sender;
        return stream_id;
    }

    pub fn sendDatagram(
        self: *QuicSessionRuntime,
        conn: anytype,
        outgoing: message.OutgoingMessage,
        options: DatagramSendOptions,
    ) !DatagramSendResult {
        try self.ensureReadyForApplicationData();
        if (!self.session.session.datagram_enabled) {
            if (quic_datagram.shouldUseReliableFallback(error.DatagramUnavailable, options.fallback)) {
                return .use_reliable_fallback;
            }
            return error.UnsupportedTransport;
        }

        const payload = quic_datagram.encode(self.allocator, outgoing, options.codec) catch |err| {
            if (quic_datagram.shouldUseReliableFallback(err, options.fallback)) return .use_reliable_fallback;
            return mapDatagramError(err);
        };
        defer self.allocator.free(payload);

        conn.sendDatagram(payload) catch |err| {
            if (quic_datagram.shouldUseReliableFallback(err, options.fallback)) return .use_reliable_fallback;
            return mapDatagramError(quic_datagram.mapSendError(err, options.queue_full_mapping));
        };

        return .sent_datagram;
    }

    pub fn receiveDatagram(
        self: *QuicSessionRuntime,
        conn: anytype,
        options: DatagramReceiveOptions,
    ) !?ReceivedDatagram {
        try self.ensureReadyForApplicationData();
        if (!self.session.session.datagram_enabled) return error.UnsupportedTransport;

        const scratch_len = try quic_datagram.receiveScratchLen(options.codec);
        const scratch = try self.allocator.alloc(u8, scratch_len);
        defer self.allocator.free(scratch);

        const info = conn.receiveDatagramInfo(scratch) orelse return null;
        return quic_datagram.decodeIncomingDatagram(self.allocator, info, scratch, options) catch |err| {
            return mapDatagramError(err);
        };
    }

    pub fn acceptPeerBidiStreamsConnection(self: *QuicSessionRuntime, conn: *quic_zig.Connection) !usize {
        if (self.session.state() != .ready) return 0;

        var accepted: usize = 0;
        var stream_ids: std.ArrayList(u64) = .empty;
        defer stream_ids.deinit(self.allocator);

        var it = conn.streamIterator();
        while (it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (!isPeerBidiStreamId(self.session.role, stream_id)) continue;
            if (self.reliable_receivers.contains(stream_id)) continue;
            try stream_ids.append(self.allocator, stream_id);
        }

        for (stream_ids.items) |stream_id| {
            self.acceptReliableStream(stream_id) catch |err| switch (err) {
                error.StreamAlreadyOpen => continue,
                else => return err,
            };
            accepted += 1;
        }

        return accepted;
    }

    pub fn pumpConnection(self: *QuicSessionRuntime, conn: *quic_zig.Connection) !PumpResult {
        var adapter = quic_streams.QuicConnectionAdapter.init(conn);
        return self.pump(&adapter);
    }

    pub fn pump(self: *QuicSessionRuntime, transport: anytype) !PumpResult {
        var result: PumpResult = .{};

        if (self.control_sender) |*sender| {
            if (try sender.pump(transport) == .complete) {
                sender.deinit();
                self.control_sender = null;
            }
        }

        if (self.control_flush_sender) |*sender| {
            if (try sender.pump(transport) == .complete) {
                sender.deinit();
                self.control_flush_sender = null;
                result.control_flush_complete += 1;
            }
        }

        if (self.control_receiver) |*receiver| {
            var frames: std.ArrayList(control.Frame) = .empty;
            defer {
                for (frames.items) |*frame| frame.deinit();
                frames.deinit(self.allocator);
            }

            const read = receiver.pump(transport, &frames) catch |err| switch (err) {
                error.StreamNotFound => return result,
                else => return err,
            };
            result.control_frames_read += read.frames_read;
            if (frames.items.len > 0) {
                try self.acceptPeerControlFrames(frames.items);
            }
            if (read.stream_complete) {
                receiver.deinit();
                self.control_receiver = null;
            }
        }

        result.reliable_sent_complete += try self.pumpReliableSenders(transport);
        result.reliable_received += try self.pumpReliableReceivers(transport);
        return result;
    }

    pub fn recvReliable(self: *QuicSessionRuntime) ?ReceivedReliable {
        if (self.inbox.items.len == 0) return null;
        return self.inbox.orderedRemove(0);
    }

    /// The stream id of the next queued reliable message, without
    /// dequeuing it — lets a dispatcher distinguish an inbound request
    /// (peer-initiated bidi stream) from a reply to an outbound
    /// request (locally-initiated stream) before consuming anything.
    pub fn peekReliableStreamId(self: *const QuicSessionRuntime) ?u64 {
        if (self.inbox.items.len == 0) return null;
        return self.inbox.items[0].stream_id;
    }

    /// Whether a received-but-unpopped message exists for `stream_id`.
    /// The node's pending-request sweep uses this to settle a request
    /// whose reply has already landed, without consuming it.
    pub fn inboxHasStream(self: *const QuicSessionRuntime, stream_id: u64) bool {
        for (self.inbox.items) |received| {
            if (received.stream_id == stream_id) return true;
        }
        return false;
    }

    pub fn inboxLen(self: QuicSessionRuntime) usize {
        return self.inbox.items.len;
    }

    pub fn pendingReliableSenders(self: QuicSessionRuntime) usize {
        return self.reliable_senders.count();
    }

    pub fn pendingReliableReceivers(self: QuicSessionRuntime) usize {
        return self.reliable_receivers.count();
    }

    pub fn hasControlSender(self: QuicSessionRuntime) bool {
        return self.control_sender != null;
    }

    pub fn hasControlReceiver(self: QuicSessionRuntime) bool {
        return self.control_receiver != null;
    }

    pub fn hasControlFlushSender(self: QuicSessionRuntime) bool {
        return self.control_flush_sender != null;
    }

    fn ensureReadyForApplicationData(self: QuicSessionRuntime) Error!void {
        try self.ensureOpen();
        if (self.session.state() != .ready) return error.InvalidState;
    }

    fn armPeerControlReceiver(self: *QuicSessionRuntime) !void {
        if (self.control_receiver != null) return;
        self.control_receiver = quic_streams.ControlStreamReceiver.init(
            self.allocator,
            quic.peerControlStreamId(self.session.role),
            .{ .codec = self.session.options.control_codec },
        );
    }

    fn queueLocalHello(self: *QuicSessionRuntime) !void {
        if (self.session.local_hello_sent) return;
        if (self.control_sender != null) return error.InvalidState;

        const frames = [_]control.Frame{.{ .hello = helloFromOptions(self.session.options) }};
        var sender = try quic_streams.ControlStreamSender.init(
            self.allocator,
            quic.localControlStreamId(self.session.role),
            &frames,
            self.session.options.control_codec,
            .{},
        );
        errdefer sender.deinit();

        const marker = try self.session.encodeLocalHello();
        self.allocator.free(marker);

        self.control_sender = sender;
    }

    fn acceptPeerControlFrames(
        self: *QuicSessionRuntime,
        frames: []const control.Frame,
    ) !void {
        const encoded = try quic_streams.encodeControlStream(
            self.allocator,
            frames,
            self.session.options.control_codec,
        );
        defer self.allocator.free(encoded);
        try self.session.acceptPeerControl(encoded);
    }

    fn pumpReliableSenders(self: *QuicSessionRuntime, transport: anytype) !usize {
        var complete_ids: std.ArrayList(u64) = .empty;
        defer complete_ids.deinit(self.allocator);

        var senders = self.reliable_senders.iterator();
        while (senders.next()) |entry| {
            const progress = entry.value_ptr.pump(transport) catch |err| {
                // Same discipline as the receivers: a finished sender
                // left stranded by an error would re-FIN its (possibly
                // reaped) stream on the next pump.
                dropCompleted(&self.reliable_senders, complete_ids.items);
                return err;
            };
            if (progress == .complete) {
                try complete_ids.append(self.allocator, entry.key_ptr.*);
            }
        }

        dropCompleted(&self.reliable_senders, complete_ids.items);
        return complete_ids.items.len;
    }

    fn pumpReliableReceivers(self: *QuicSessionRuntime, transport: anytype) !usize {
        var complete_ids: std.ArrayList(u64) = .empty;
        defer complete_ids.deinit(self.allocator);

        var received_count: usize = 0;
        var receivers = self.reliable_receivers.iterator();
        while (receivers.next()) |entry| {
            const received_opt = entry.value_ptr.pump(transport) catch |err| {
                // Finish the removal pass for receivers that already
                // completed earlier in this iteration: an error must
                // not strand a decoded receiver (its message is in the
                // inbox; the next pump would fail on the stale
                // `decoded` flag instead of the real cause).
                dropCompleted(&self.reliable_receivers, complete_ids.items);
                return err;
            };
            const received = received_opt orelse continue;
            errdefer {
                var cleanup = received;
                cleanup.deinit();
            }
            try self.inbox.append(self.allocator, .{
                .stream_id = entry.key_ptr.*,
                .message = received,
            });
            try complete_ids.append(self.allocator, entry.key_ptr.*);
            received_count += 1;
        }

        dropCompleted(&self.reliable_receivers, complete_ids.items);
        return received_count;
    }
};

/// Removes finished entries so a value that completed its work is
/// never pumped again (a decoded receiver is an InvalidState; a
/// finished sender would re-FIN its stream).
fn dropCompleted(map: anytype, ids: []const u64) void {
    for (ids) |stream_id| {
        if (map.fetchRemove(stream_id)) |entry| {
            var value = entry.value;
            value.deinit();
        }
    }
}

pub fn mapStreamError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.DeadlineExceeded => error.DeadlineExceeded,
        error.EndpointClosed => error.EndpointClosed,
        error.FlowControlled => error.FlowControlled,
        error.StreamLimitExceeded => error.FlowControlled,
        error.InvalidState => error.InvalidState,
        error.MessageTooLarge => error.MessageTooLarge,
        error.PeerClosed => error.PeerClosed,
        error.QueueFull => error.QueueFull,
        error.StreamAlreadyOpen => error.StreamAlreadyOpen,
        error.StreamNotFound => error.StreamNotFound,
        error.StreamReset => error.StreamReset,
        error.ConnectionLost => error.ConnectionLost,
        else => error.InvalidState,
    };
}

pub fn mapDatagramError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.DatagramUnavailable,
        error.UnsupportedTransport,
        => error.UnsupportedTransport,
        error.DatagramTooLarge,
        error.HeaderBytesLimitExceeded,
        error.HeaderLimitExceeded,
        error.MessageTooLarge,
        => error.MessageTooLarge,
        error.DatagramQueueFull,
        error.QueueFull,
        => error.QueueFull,
        error.FlowControlled => error.FlowControlled,
        error.InvalidMessage,
        error.InvalidSubject,
        error.MalformedFrame,
        => error.MalformedFrame,
        error.EndpointClosed => error.EndpointClosed,
        else => error.InvalidState,
    };
}

fn envelopeCodecFromOptions(options: quic.QuicOptions) envelope.CodecOptions {
    return .{
        .max_message_size = options.max_message_size,
        .max_header_bytes = options.max_header_bytes,
        .max_headers = options.max_header_count,
    };
}

fn helloFromOptions(options: quic.QuicOptions) control.Hello {
    return .{
        .wire_version = control.default_wire_version,
        .peer_id = options.peer_id,
        .role_flags = options.role_flags,
        .supported_patterns = options.supported_patterns,
        .max_message_size = options.max_message_size,
        .max_header_bytes = options.max_header_bytes,
        .max_header_count = options.max_header_count,
        .datagram_enabled = options.datagram_enabled,
        .heartbeat_interval_ms = options.heartbeat_interval_ms,
        .auth = options.auth,
    };
}

pub fn isPeerBidiStreamId(role: quic.Role, stream_id: u64) bool {
    if ((stream_id & 0x2) != 0) return false;
    const initiated_by_server = (stream_id & 0x1) != 0;
    return switch (role) {
        .client => initiated_by_server,
        .server => !initiated_by_server,
    };
}

const FakeStream = struct {
    incoming: std.ArrayList(u8) = .empty,
    read_offset: usize = 0,
    final_size: ?u64 = null,
    reset: bool = false,
    writes: std.ArrayList(u8) = .empty,
    write_limit: usize = std.math.maxInt(usize),
    opened_bidi: bool = false,
    opened_uni: bool = false,
    finished: bool = false,

    fn deinit(self: *FakeStream, allocator: std.mem.Allocator) void {
        self.incoming.deinit(allocator);
        self.writes.deinit(allocator);
        self.* = undefined;
    }
};

const FakeTransport = struct {
    allocator: std.mem.Allocator,
    streams: std.AutoHashMap(u64, FakeStream),

    fn init(allocator: std.mem.Allocator) FakeTransport {
        return .{
            .allocator = allocator,
            .streams = std.AutoHashMap(u64, FakeStream).init(allocator),
        };
    }

    fn deinit(self: *FakeTransport) void {
        var streams = self.streams.valueIterator();
        while (streams.next()) |stream| stream.deinit(self.allocator);
        self.streams.deinit();
        self.* = undefined;
    }

    pub fn openBidi(self: *FakeTransport, stream_id: u64) !void {
        const entry = try self.getOrPutStream(stream_id);
        entry.value_ptr.opened_bidi = true;
    }

    pub fn openUni(self: *FakeTransport, stream_id: u64) !void {
        const entry = try self.getOrPutStream(stream_id);
        entry.value_ptr.opened_uni = true;
    }

    pub fn streamWrite(self: *FakeTransport, stream_id: u64, bytes: []const u8) !usize {
        const stream = (try self.getOrPutStream(stream_id)).value_ptr;
        const writable = @min(bytes.len, stream.write_limit);
        if (writable == 0) return 0;
        try stream.writes.appendSlice(self.allocator, bytes[0..writable]);
        return writable;
    }

    pub fn streamFinish(self: *FakeTransport, stream_id: u64) !void {
        const stream = (try self.getOrPutStream(stream_id)).value_ptr;
        stream.finished = true;
    }

    pub fn streamRead(self: *FakeTransport, stream_id: u64, out: []u8) !usize {
        const stream = self.streams.getPtr(stream_id) orelse return error.StreamNotFound;
        const available = stream.incoming.items.len - stream.read_offset;
        if (available == 0) return 0;
        const n = @min(available, out.len);
        std.mem.copyForwards(u8, out[0..n], stream.incoming.items[stream.read_offset..][0..n]);
        stream.read_offset += n;
        return n;
    }

    pub fn streamReceiveStatus(self: *FakeTransport, stream_id: u64) ?quic_streams.ReceiveStatus {
        const stream = self.streams.getPtr(stream_id) orelse return null;
        return .{
            .reset = stream.reset,
            .final_size = stream.final_size,
            .read_offset = @intCast(stream.read_offset),
        };
    }

    fn setWriteLimit(self: *FakeTransport, stream_id: u64, limit: usize) !void {
        const stream = (try self.getOrPutStream(stream_id)).value_ptr;
        stream.write_limit = limit;
    }

    fn takeWrites(
        self: *FakeTransport,
        stream_id: u64,
        dst: *FakeTransport,
    ) !void {
        const source = self.streams.getPtr(stream_id) orelse return error.StreamNotFound;
        const target = (try dst.getOrPutStream(stream_id)).value_ptr;
        try target.incoming.appendSlice(dst.allocator, source.writes.items);
        target.final_size = target.incoming.items.len;
    }

    fn getOrPutStream(self: *FakeTransport, stream_id: u64) !std.AutoHashMap(u64, FakeStream).GetOrPutResult {
        const entry = try self.streams.getOrPut(stream_id);
        if (!entry.found_existing) entry.value_ptr.* = .{};
        return entry;
    }
};

const FakeCloseConn = struct {
    close_is_transport: bool = false,
    close_code: u64 = 0,
    close_reason: []const u8 = "",

    pub fn close(self: *FakeCloseConn, is_transport: bool, code: u64, reason: []const u8) void {
        self.close_is_transport = is_transport;
        self.close_code = code;
        self.close_reason = reason;
    }
};

const FakeDatagramInfo = struct {
    len: usize,
    arrived_in_early_data: bool = false,
};

const FakeDatagramConn = struct {
    allocator: std.mem.Allocator,
    sent: std.ArrayList(u8) = .empty,
    send_mode: SendMode = .ok,
    incoming: []const u8 = &.{},
    incoming_early: bool = false,
    incoming_read: bool = false,

    const SendMode = enum {
        ok,
        unavailable,
        too_large,
        queue_full,
    };

    fn deinit(self: *FakeDatagramConn) void {
        self.sent.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn sendDatagram(
        self: *FakeDatagramConn,
        payload: []const u8,
    ) error{ OutOfMemory, DatagramUnavailable, DatagramTooLarge, DatagramQueueFull }!void {
        switch (self.send_mode) {
            .ok => {},
            .unavailable => return error.DatagramUnavailable,
            .too_large => return error.DatagramTooLarge,
            .queue_full => return error.DatagramQueueFull,
        }
        try self.sent.appendSlice(self.allocator, payload);
    }

    pub fn receiveDatagramInfo(self: *FakeDatagramConn, dst: []u8) ?FakeDatagramInfo {
        if (self.incoming_read or self.incoming.len == 0) return null;
        self.incoming_read = true;

        const copied = @min(dst.len, self.incoming.len);
        @memcpy(dst[0..copied], self.incoming[0..copied]);
        return .{
            .len = self.incoming.len,
            .arrived_in_early_data = self.incoming_early,
        };
    }
};

fn pumpBoth(
    client: *QuicSessionRuntime,
    client_io: *FakeTransport,
    server: *QuicSessionRuntime,
    server_io: *FakeTransport,
) !void {
    _ = try client.pump(client_io);
    _ = try server.pump(server_io);
    try client_io.takeWrites(quic.localControlStreamId(.client), server_io);
    try server_io.takeWrites(quic.localControlStreamId(.server), client_io);
    _ = try client.pump(client_io);
    _ = try server.pump(server_io);
}

fn readyRuntimePair(
    client: *QuicSessionRuntime,
    client_io: *FakeTransport,
    server: *QuicSessionRuntime,
    server_io: *FakeTransport,
) !void {
    try client.onQuicReady();
    try server.onQuicReady();
    try pumpBoth(client, client_io, server, server_io);
    try std.testing.expectEqual(quic.State.ready, client.state());
    try std.testing.expectEqual(quic.State.ready, server.state());
}

test "session runtime exchanges HELLO and reaches ready" {
    const allocator = std.testing.allocator;

    var client = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer client.deinit();
    var server = try QuicSessionRuntime.init(allocator, 2, .server, .{ .peer_id = "server-a" });
    defer server.deinit();

    var client_io = FakeTransport.init(allocator);
    defer client_io.deinit();
    var server_io = FakeTransport.init(allocator);
    defer server_io.deinit();

    try client.onQuicReady();
    try server.onQuicReady();
    try std.testing.expect(client.hasControlSender());
    try std.testing.expect(client.hasControlReceiver());

    try pumpBoth(&client, &client_io, &server, &server_io);

    try std.testing.expectEqual(quic.State.ready, client.state());
    try std.testing.expectEqual(quic.State.ready, server.state());
    try std.testing.expectEqualStrings("server-a", client.peerId());
    try std.testing.expectEqualStrings("client-a", server.peerId());
    try std.testing.expect(!client.hasControlSender());
    try std.testing.expect(!client.hasControlReceiver());
}

test "session runtime flushes queued pubsub and credit frames on follow-up control stream" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .server, .{ .peer_id = "server-a" });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try readyRuntimePair(&runtime, &io, &peer, &peer_io);

    var registry = protocol.pubsub.Registry.init(allocator);
    defer registry.deinit();
    var ledger = pushpull.CreditLedger.init(allocator);
    defer ledger.deinit();
    var control_state = quic_control.State.init(allocator, &registry, &ledger, .{});
    defer control_state.deinit();

    try runtime.queueSubscribe(&control_state, "jobs.*", .{ .on_full = .drop_newest });
    try runtime.queueUnsubscribe(&control_state, "jobs.old");
    try runtime.queueCredit(&control_state, "pull.*", .{ .messages = 4, .bytes = 512 });

    const stream_id = (try runtime.flushQueuedControl(&control_state)).?;
    try std.testing.expectEqual(@as(u64, quic.localControlStreamId(.client) + 4), stream_id);
    try std.testing.expect(runtime.hasControlFlushSender());

    try runtime.queueSubscribe(&control_state, "later.*", .{});
    const result = try runtime.pump(&io);

    try std.testing.expectEqual(@as(usize, 1), result.control_flush_complete);
    try std.testing.expect(!runtime.hasControlFlushSender());
    try std.testing.expectEqual(@as(usize, 1), control_state.queuedFrameCount());
    try std.testing.expectEqual(control.Tag.subscribe, std.meta.activeTag(control_state.queuedFrames()[0]));
    try std.testing.expectEqualStrings("later.*", control_state.queuedFrames()[0].subscribe.filter);

    const stream = io.streams.get(stream_id) orelse return error.StreamNotFound;
    try std.testing.expect(stream.opened_uni);
    try std.testing.expect(stream.finished);

    try io.takeWrites(stream_id, &peer_io);
    var receiver = quic_streams.ControlStreamReceiver.init(allocator, stream_id, .{});
    defer receiver.deinit();

    var frames: std.ArrayList(control.Frame) = .empty;
    defer {
        for (frames.items) |*frame| frame.deinit();
        frames.deinit(allocator);
    }

    const read = try receiver.pump(&peer_io, &frames);
    try std.testing.expect(read.stream_complete);
    try std.testing.expectEqual(@as(usize, 3), frames.items.len);
    try std.testing.expectEqual(control.Tag.subscribe, std.meta.activeTag(frames.items[0]));
    try std.testing.expectEqualStrings("jobs.*", frames.items[0].subscribe.filter);
    try std.testing.expectEqual(control.Tag.unsubscribe, std.meta.activeTag(frames.items[1]));
    try std.testing.expectEqualStrings("jobs.old", frames.items[1].unsubscribe.filter);
    try std.testing.expectEqual(control.Tag.credit, std.meta.activeTag(frames.items[2]));
    try std.testing.expectEqualStrings("pull.*", frames.items[2].credit.subject_filter);
    try std.testing.expectEqual(@as(u64, 4), frames.items[2].credit.messages);
    try std.testing.expectEqual(@as(u64, 512), frames.items[2].credit.bytes);
}

test "session runtime control flush is gated until ready and idle" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer runtime.deinit();

    var registry = protocol.pubsub.Registry.init(allocator);
    defer registry.deinit();
    var ledger = pushpull.CreditLedger.init(allocator);
    defer ledger.deinit();
    var control_state = quic_control.State.init(allocator, &registry, &ledger, .{});
    defer control_state.deinit();

    try std.testing.expectError(error.InvalidState, runtime.queueSubscribe(&control_state, "jobs.*", .{}));

    try runtime.onQuicReady();
    try control_state.queueSubscribe("jobs.*", .{});
    try std.testing.expectError(error.InvalidState, runtime.flushQueuedControl(&control_state));
}

test "session runtime cleans up completed reliable sender" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .server, .{ .peer_id = "server-a" });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try runtime.onQuicReady();
    try peer.onQuicReady();
    try pumpBoth(&runtime, &io, &peer, &peer_io);

    const stream_id = try runtime.queueReliable(.{
        .subject = "pair.echo",
        .id = 42,
        .body = "ping",
    });
    try io.setWriteLimit(stream_id, 3);

    while (runtime.pendingReliableSenders() != 0) {
        _ = try runtime.pump(&io);
    }

    try std.testing.expectEqual(@as(usize, 0), runtime.pendingReliableSenders());
    const stream = io.streams.get(stream_id) orelse return error.StreamNotFound;
    try std.testing.expect(stream.opened_bidi);
    try std.testing.expect(stream.finished);
}

test "session runtime transfers receiver ownership to inbox" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .server, .{ .peer_id = "server-a" });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .client, .{ .peer_id = "client-a" });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try runtime.onQuicReady();
    try peer.onQuicReady();
    try pumpBoth(&peer, &peer_io, &runtime, &io);

    const stream_id: u64 = 0;
    const encoded = try quic_streams.encodeReliableMessage(allocator, .{
        .subject = "jobs.run",
        .id = 7,
        .body = "now",
    }, .{});
    defer allocator.free(encoded);

    const entry = try io.getOrPutStream(stream_id);
    try entry.value_ptr.incoming.appendSlice(allocator, encoded);
    entry.value_ptr.final_size = encoded.len;

    try runtime.acceptReliableStream(stream_id);
    _ = try runtime.pump(&io);

    try std.testing.expectEqual(@as(usize, 0), runtime.pendingReliableReceivers());
    try std.testing.expectEqual(@as(usize, 1), runtime.inboxLen());

    var received = runtime.recvReliable().?;
    defer received.deinit();
    try std.testing.expectEqual(stream_id, received.stream_id);
    try std.testing.expectEqualStrings("jobs.run", received.message.subject);
    try std.testing.expectEqualStrings("now", received.message.body);
    try std.testing.expectEqual(@as(usize, 0), runtime.inboxLen());
}

test "queueReliable arms the reply receiver on the request's own stream" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .server, .{ .peer_id = "server-a" });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try runtime.onQuicReady();
    try peer.onQuicReady();
    try pumpBoth(&runtime, &io, &peer, &peer_io);

    const stream_id = try runtime.queueReliable(.{
        .subject = "user.get",
        .id = 7,
        .body = "42",
    });
    try std.testing.expectEqual(@as(u64, 0), stream_id);
    // The reply arrives on the requester's OWN bidi stream, which the
    // peer-initiated auto-accept never covers — queueReliable must
    // have armed the receiver itself.
    try std.testing.expectEqual(@as(usize, 1), runtime.pendingReliableReceivers());

    const encoded = try quic_streams.encodeReliableMessage(allocator, .{
        .subject = "user.get",
        .id = 7,
        .flags = .{ .final = true },
        .body = "user-42",
    }, .{});
    defer allocator.free(encoded);

    const entry = try io.getOrPutStream(stream_id);
    try entry.value_ptr.incoming.appendSlice(allocator, encoded);
    entry.value_ptr.final_size = encoded.len;

    _ = try runtime.pump(&io);
    var received = runtime.recvReliable() orelse return error.ReplyMissing;
    defer received.deinit();
    try std.testing.expectEqual(stream_id, received.stream_id);
    try std.testing.expectEqualStrings("user-42", received.message.body);
}

test "session runtime replies on an accepted peer stream" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .server, .{ .peer_id = "server-a" });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .client, .{ .peer_id = "client-a" });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try runtime.onQuicReady();
    try peer.onQuicReady();
    try pumpBoth(&peer, &peer_io, &runtime, &io);

    const stream_id: u64 = 0;
    try runtime.replyReliableOnStream(stream_id, .{
        .subject = "user.get",
        .id = 7,
        .body = "Ada",
    });

    while (runtime.pendingReliableSenders() != 0) {
        _ = try runtime.pump(&io);
    }

    const stream = io.streams.get(stream_id) orelse return error.StreamNotFound;
    try std.testing.expect(!stream.opened_bidi);
    try std.testing.expect(stream.finished);

    const encoded = try quic_streams.encodeReliableMessage(allocator, .{
        .subject = "jobs.run",
        .id = 9,
        .body = "now",
    }, .{});
    defer allocator.free(encoded);

    const entry = try io.getOrPutStream(stream_id);
    try entry.value_ptr.incoming.appendSlice(allocator, encoded);
    entry.value_ptr.final_size = encoded.len;

    try runtime.acceptReliableStream(stream_id);
    _ = try runtime.pump(&io);

    var received = runtime.recvReliable().?;
    var owned = received.takeMessage();
    defer owned.deinit();
    try std.testing.expectEqualStrings("jobs.run", owned.subject);
}

test "session runtime datagram helpers encode decode and map send backpressure" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{
        .peer_id = "client-a",
        .datagram_enabled = true,
    });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .server, .{
        .peer_id = "server-a",
        .datagram_enabled = true,
    });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try readyRuntimePair(&runtime, &io, &peer, &peer_io);
    try std.testing.expect(runtime.appSession().datagram_enabled);

    var datagrams: FakeDatagramConn = .{ .allocator = allocator };
    defer datagrams.deinit();

    try std.testing.expectEqual(
        DatagramSendResult.sent_datagram,
        try runtime.sendDatagram(&datagrams, .{
            .subject = "presence.ada",
            .id = 7,
            .flags = .{ .unreliable = true },
            .body = "online",
        }, .{ .codec = .{ .max_payload_size = 256 } }),
    );

    var sent = try quic_datagram.decode(allocator, datagrams.sent.items, .{ .max_payload_size = 256 });
    defer sent.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 7), sent.id);
    try std.testing.expect(sent.flags.unreliable);
    try std.testing.expectEqualStrings("presence.ada", sent.subject);
    try std.testing.expectEqualStrings("online", sent.body);

    const encoded = try quic_datagram.encode(allocator, .{
        .subject = "presence.bob",
        .id = 8,
        .flags = .{ .unreliable = true },
        .body = "away",
    }, .{ .max_payload_size = 256 });
    defer allocator.free(encoded);

    datagrams.incoming = encoded;
    datagrams.incoming_early = true;
    var received = (try runtime.receiveDatagram(&datagrams, .{
        .codec = .{ .max_payload_size = 256 },
    })).?;
    defer received.deinit();
    try std.testing.expect(received.arrived_in_early_data);
    try std.testing.expectEqual(@as(message.MessageId, 8), received.message.id);
    try std.testing.expectEqualStrings("presence.bob", received.message.subject);
    try std.testing.expectEqualStrings("away", received.message.body);

    datagrams.send_mode = .queue_full;
    try std.testing.expectError(error.FlowControlled, runtime.sendDatagram(&datagrams, .{
        .subject = "presence.ada",
        .flags = .{ .unreliable = true },
    }, .{
        .codec = .{ .max_payload_size = 256 },
        .queue_full_mapping = .flow_controlled,
    }));
}

test "session runtime datagram helpers honor negotiated support and fallback policy" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{
        .peer_id = "client-a",
        .datagram_enabled = false,
    });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .server, .{
        .peer_id = "server-a",
        .datagram_enabled = false,
    });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try readyRuntimePair(&runtime, &io, &peer, &peer_io);

    var datagrams: FakeDatagramConn = .{ .allocator = allocator };
    defer datagrams.deinit();

    try std.testing.expectError(error.UnsupportedTransport, runtime.sendDatagram(&datagrams, .{
        .subject = "presence.ada",
        .flags = .{ .unreliable = true },
    }, .{}));

    try std.testing.expectEqual(
        DatagramSendResult.use_reliable_fallback,
        try runtime.sendDatagram(&datagrams, .{
            .subject = "presence.ada",
            .flags = .{ .unreliable = true },
        }, .{ .fallback = .allow_reliable }),
    );
}

test "session runtime lifecycle helpers reject new application work while closing" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer runtime.deinit();

    runtime.beginClosing();
    try std.testing.expect(runtime.isClosing());
    try std.testing.expect(runtime.isClosingOrClosed());
    try std.testing.expectError(error.EndpointClosed, runtime.queueReliable(.{
        .subject = "pair.echo",
        .body = "ping",
    }));

    var conn: FakeCloseConn = .{};
    runtime.closeConnection(&conn, .graceful_shutdown);
    try std.testing.expect(!conn.close_is_transport);
    try std.testing.expectEqual(quic_cancel.AppErrorCode.graceful_shutdown, conn.close_code);
    try std.testing.expectEqualStrings("qmsg shutdown", conn.close_reason);

    runtime.markClosed();
    try std.testing.expect(runtime.isClosed());
    try std.testing.expectError(error.EndpointClosed, runtime.ensureOpen());
}

test "session runtime exposes stable stream and datagram error mapping" {
    try std.testing.expectEqual(error.StreamNotFound, mapStreamError(error.StreamNotFound));
    try std.testing.expectEqual(error.StreamReset, mapStreamError(error.StreamReset));
    try std.testing.expectEqual(error.ConnectionLost, mapStreamError(error.ConnectionLost));
    try std.testing.expectEqual(error.FlowControlled, mapStreamError(error.StreamLimitExceeded));

    try std.testing.expectEqual(error.UnsupportedTransport, mapDatagramError(error.DatagramUnavailable));
    try std.testing.expectEqual(error.MessageTooLarge, mapDatagramError(error.DatagramTooLarge));
    try std.testing.expectEqual(error.MessageTooLarge, mapDatagramError(error.HeaderLimitExceeded));
    try std.testing.expectEqual(error.QueueFull, mapDatagramError(error.DatagramQueueFull));
    try std.testing.expectEqual(error.MalformedFrame, mapDatagramError(error.InvalidMessage));
}

test "session runtime gates reliable streams until ready" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .client, .{ .peer_id = "client-a" });
    defer runtime.deinit();

    try std.testing.expectError(error.InvalidState, runtime.queueReliable(.{
        .subject = "pair.echo",
        .body = "ping",
    }));
    try std.testing.expectError(error.InvalidState, runtime.acceptReliableStream(0));
}

test "pump error does not strand receivers that completed earlier in the pass" {
    const allocator = std.testing.allocator;

    var runtime = try QuicSessionRuntime.init(allocator, 1, .server, .{ .peer_id = "server-a" });
    defer runtime.deinit();
    var peer = try QuicSessionRuntime.init(allocator, 2, .client, .{ .peer_id = "client-a" });
    defer peer.deinit();
    var io = FakeTransport.init(allocator);
    defer io.deinit();
    var peer_io = FakeTransport.init(allocator);
    defer peer_io.deinit();
    try runtime.onQuicReady();
    try peer.onQuicReady();
    try pumpBoth(&peer, &peer_io, &runtime, &io);

    // Stream 0 carries a complete message; stream 4 is reset. The
    // reset surfaces as the pass's error AFTER stream 0's receiver
    // completed and delivered to the inbox.
    const encoded = try quic_streams.encodeReliableMessage(allocator, .{
        .subject = "jobs.run",
        .id = 7,
        .body = "now",
    }, .{});
    defer allocator.free(encoded);

    const ok_entry = try io.getOrPutStream(0);
    try ok_entry.value_ptr.incoming.appendSlice(allocator, encoded);
    ok_entry.value_ptr.final_size = encoded.len;

    const reset_entry = try io.getOrPutStream(4);
    reset_entry.value_ptr.reset = true;

    try runtime.acceptReliableStream(0);
    try runtime.acceptReliableStream(4);

    try std.testing.expectError(error.StreamReset, runtime.pump(&io));

    // The completed receiver was removed despite the sibling's error
    // (its message reached the inbox), and the next pump reports the
    // reset stream again — not InvalidState from a stranded receiver.
    try std.testing.expectEqual(@as(usize, 1), runtime.inboxLen());
    try std.testing.expectEqual(@as(usize, 1), runtime.pendingReliableReceivers());
    try std.testing.expectError(error.StreamReset, runtime.pump(&io));

    var received = runtime.recvReliable().?;
    defer received.deinit();
    try std.testing.expectEqual(@as(u64, 0), received.stream_id);
    try std.testing.expectEqualStrings("now", received.message.body);
}

test "peer bidi stream id helper follows QUIC low bits" {
    try std.testing.expect(isPeerBidiStreamId(.server, 0));
    try std.testing.expect(!isPeerBidiStreamId(.server, 1));
    try std.testing.expect(!isPeerBidiStreamId(.server, 2));
    try std.testing.expect(isPeerBidiStreamId(.client, 1));
    try std.testing.expect(!isPeerBidiStreamId(.client, 0));
    try std.testing.expect(!isPeerBidiStreamId(.client, 3));
}
