//! Inbound qmsg attach for foreign embedders — the inverse of
//! `quic_app_server.ServerDispatch`.
//!
//! There is ONE `quic.app.Driver` per Server and it belongs to the
//! embedder (quic-zig allows exactly one connection-will-close hook
//! slot, and the Driver registers its teardown there). On this seam
//! qmsg therefore owns NO listener and NO Driver: the embedder's
//! Driver hooks delegate qmsg-ALPN connections into an
//! `EmbeddedDispatch`, which owns the qmsg session and the per-stream
//! inbound buffering for each such connection.
//!
//! The embedder keeps one `EmbeddedDispatch(Owner).Seat` per
//! connection in its own connection state, initializes it with
//! `Seat.init(allocator)`, routes hooks by ALPN, and calls
//! `serviceSeat` once per connection per tick for send-side pumping:
//!
//! ```zig
//! const App = struct {
//!     conn_state: struct {
//!         qmsg: qmsg.transport.quic_embedded.EmbeddedDispatch(Node).Seat,
//!         // ...the embedder's own per-connection state...
//!     },
//!
//!     fn onHandshake(app: *App, s: *Driver(App).Session) anyerror!void {
//!         if (qmsg.transport.quic_embedded.isQmsgAlpn(s.conn)) {
//!             try app.qmsg_dispatch.onHandshake(&app.conn_state.qmsg, s.conn);
//!         } else { /* embedder's own handshake */ }
//!     }
//!     // likewise on_stream_open / on_stream_data / on_stream_end /
//!     // on_datagram / on_disconnect, then per tick:
//!     //   try app.qmsg_dispatch.serviceSeat(&app.conn_state.qmsg, conn);
//! };
//! ```
//!
//! The Owner contract is the same one `ServerDispatch` uses (Node
//! satisfies it in production): `DriverSession`,
//! `driverSessionRuntime`, `driverServerSessionCreate`,
//! `driverServerSessionDestroy`, `driverSessionPass`,
//! `driverDatagramReceived`, `driverDatagramDropped`. Credentials
//! verify once at HELLO through the `auth_config` carried on the
//! transport options handed to `init`; nothing authorizes at the
//! socket layer.
//!
//! Sessions created here are pull-consumed: their inbound messages
//! surface through the owner's `poll` events (the same registry the
//! inproc embedded surface uses), never through push dispatch.

const std = @import("std");
const quic_zig = @import("quic");

const quic = @import("quic.zig");
const quic_datagram = @import("quic_datagram.zig");
const quic_session_runtime = @import("quic_session_runtime.zig");
const quic_streams = @import("quic_streams.zig");

const SessionRuntime = quic_session_runtime.QuicSessionRuntime;

/// control.zig lives a level up from the transport layer.
const quic_control_frame = @import("../control.zig").Frame;

/// Whether a connection negotiated qmsg's ALPN — the routing test
/// the embedder applies before delegating to the dispatch.
pub fn isQmsgAlpn(conn: *quic_zig.Connection) bool {
    const selected = conn.negotiatedAlpn() orelse return false;
    return std.mem.eql(u8, selected, quic.alpn);
}

/// The Driver sizing an embedder must configure for qmsg
/// connections, so they do not re-derive it from transport
/// parameters (a conforming peer must never overflow the stream
/// table; the datagram buffer must hold the advertised frame limit).
pub const DriverSizing = struct {
    max_tracked_streams: usize,
    datagram_buf_bytes: usize,
};

pub fn driverSizing(options: quic.QuicOptions) DriverSizing {
    return .{
        .max_tracked_streams = @intCast(options.initial_max_streams_bidi +
            options.initial_max_streams_uni),
        .datagram_buf_bytes = if (options.datagram_enabled)
            @intCast(@max(options.max_datagram_frame_size, 1200))
        else
            1,
    };
}

/// One embedded qmsg connection's state: the session handle, stream
/// accepts that arrived before the HELLO exchange finished, and the
/// per-stream inbound byte buffers the pull-based qmsg receivers
/// consume through `Adapter`. Stored wherever the embedder keeps
/// per-connection state; initialize with `init`, free only through
/// `EmbeddedDispatch.onDisconnect` — never by hand (the session's
/// lifecycle belongs to the teardown path).
pub fn EmbeddedSeat(comptime Owner: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        sess: ?Owner.DriverSession = null,
        pending_accepts: std.ArrayListUnmanaged(u64) = .empty,
        streams: std.AutoHashMapUnmanaged(u64, StreamBuffer) = .empty,
        /// Incremental control-frame readers for the peer's
        /// FOLLOW-UP uni streams (everything after the HELLO
        /// stream): SUBSCRIBE/UNSUBSCRIBE/CREDIT ride these. Decoded
        /// frames go to `Owner.driverControlFramesReceived`.
        control_reads: std.ArrayListUnmanaged(ControlRead) = .empty,
        /// Follow-up uni streams that opened before the session
        /// reached ready (they can ride the same flight as the HELLO
        /// tail): armed as control reads once the exchange lands.
        pending_control_reads: std.ArrayListUnmanaged(u64) = .empty,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        pub const ControlRead = struct {
            stream_id: u64,
            receiver: quic_streams.ControlStreamReceiver,
        };

        /// Inbound buffering for one stream: prefix `[0..start)` has
        /// been consumed by the adapter and compacted away;
        /// `consumed` is the read offset the receivers' completion
        /// test compares against `final_size`.
        pub const StreamBuffer = struct {
            buf: std.ArrayListUnmanaged(u8) = .empty,
            start: usize = 0,
            consumed: u64 = 0,
            delivered: u64 = 0,
            final_size: ?u64 = null,
            reset: bool = false,
        };
    };
}

/// How a session's inbound messages are consumed by its owner.
pub const Delivery = enum {
    /// Push: `Node.runOnce` hands inbound messages to a dispatcher
    /// (the qmsg-owned listener model).
    dispatch,
    /// Pull: inbound messages surface through `Node.poll` events —
    /// the embedded pull model foreign embedders use.
    events,
};

pub fn EmbeddedDispatch(comptime Owner: type) type {
    return struct {
        const Self = @This();

        pub const Seat = EmbeddedSeat(Owner);

        /// The hybrid transport the qmsg senders/receivers pump
        /// against on an embedded connection: writes go to the
        /// connection, reads are served from the seat's per-stream
        /// buffers.
        pub const Adapter = struct {
            conn: *quic_zig.Connection,
            seat: *Seat,

            pub fn openBidi(self: *Adapter, stream_id: u64) !void {
                _ = try self.conn.openBidi(stream_id);
            }

            pub fn openUni(self: *Adapter, stream_id: u64) !void {
                _ = try self.conn.openUni(stream_id);
            }

            pub fn streamWrite(self: *Adapter, stream_id: u64, bytes: []const u8) !usize {
                return self.conn.streamWrite(stream_id, bytes);
            }

            pub fn streamFinish(self: *Adapter, stream_id: u64) !void {
                try self.conn.streamFinish(stream_id);
            }

            pub fn streamRead(self: *Adapter, stream_id: u64, out: []u8) !usize {
                const state = self.seat.streams.getPtr(stream_id) orelse return 0;
                const available = state.buf.items.len - state.start;
                if (available == 0) return 0;
                const n = @min(available, out.len);
                std.mem.copyForwards(u8, out[0..n], state.buf.items[state.start..][0..n]);
                state.start += n;
                state.consumed += n;
                if (state.start == state.buf.items.len) {
                    state.buf.clearRetainingCapacity();
                    state.start = 0;
                }
                return n;
            }

            pub fn streamReceiveStatus(
                self: *Adapter,
                stream_id: u64,
            ) ?quic_streams.ReceiveStatus {
                // A stream with no seat buffer yet is "open, no bytes
                // observed": receivers are armed at onStreamOpen (and
                // the control receiver at HELLO), while the buffer
                // first exists at onStreamData — so pumps routinely
                // query streams in that window, including from OTHER
                // streams' data/end hooks in the same pass. Null here
                // would surface StreamNotFound from the receiver pump
                // and take the whole session down; "not reset, no
                // final size yet, nothing read" is the truthful
                // answer. Streams that end drop their receivers (and
                // the control receiver) in onStreamEnd BEFORE the
                // buffer is removed, so a live receiver never queries
                // a buffer that is gone because its stream ended.
                const state = self.seat.streams.getPtr(stream_id) orelse return .{
                    .reset = false,
                    .final_size = null,
                    .read_offset = 0,
                };
                return .{
                    .reset = state.reset,
                    .final_size = state.final_size,
                    .read_offset = state.consumed,
                };
            }
        };

        allocator: std.mem.Allocator,
        owner: *Owner,
        transport_options: quic.QuicOptions,
        delivery: Delivery,

        /// The transport options carry the `auth_config` credentials
        /// verify against at HELLO (once, at session establishment —
        /// there is no per-message credential check on this seam).
        /// `delivery` selects how the owner consumes the session's
        /// inbound messages: foreign embedders pass `.events` (pull,
        /// through `poll`); the qmsg-owned listener wrapper passes
        /// `.dispatch` (push, through `runOnce`). The dispatch itself
        /// is stateless — all state lives in the seats and the owner
        /// — so constructing one per hook call is free.
        pub fn init(
            allocator: std.mem.Allocator,
            owner: *Owner,
            transport_options: quic.QuicOptions,
            delivery: Delivery,
        ) Self {
            return .{
                .allocator = allocator,
                .owner = owner,
                .transport_options = transport_options,
                .delivery = delivery,
            };
        }

        pub fn deinit(self: *Self) void {
            // The embedder owns the seats; each was freed through
            // `onDisconnect` as its connection tore down. Nothing
            // else is owned here.
            _ = self;
        }

        // ---- hook bodies the embedder delegates --------------------

        /// Create the qmsg session for the connection (once; further
        /// calls are no-ops). Call from the embedder's on_handshake
        /// for qmsg-ALPN connections.
        pub fn onHandshake(self: *Self, seat: *Seat, conn: *quic_zig.Connection) !void {
            _ = conn;
            if (seat.sess != null) return;
            const sess = try self.owner.driverServerSessionCreate(self.transport_options);
            Owner.driverSessionRuntime(sess).event_delivery = self.delivery == .events;
            seat.sess = sess;
        }

        /// bidi streams carry requests; uni streams are the peer's
        /// control stream (its receiver is pre-armed by id). Call
        /// from on_stream_open.
        pub fn onStreamOpen(self: *Self, seat: *Seat, stream_id: u64, bidi: bool) !void {
            _ = self;
            const sess = seat.sess orelse return;
            const rt = Owner.driverSessionRuntime(sess);

            if (!bidi) {
                // The peer's FIRST uni stream is the HELLO control
                // stream (pre-armed by id on the runtime); every
                // later uni stream carries follow-up control frames.
                const role: quic_streams.Role = switch (rt.session.role) {
                    .client => .client,
                    .server => .server,
                };
                if (stream_id == quic_streams.peerControlStreamId(role)) return;

                // The stream may open before the session reaches
                // ready (same flight as the HELLO tail); arm it once
                // the exchange lands — onStreamOpen fires once.
                if (rt.state() != .ready) {
                    try seat.pending_control_reads.append(seat.allocator, stream_id);
                    return;
                }
                armControlRead(seat, rt, stream_id);
                return;
            }

            if (rt.state() == .ready) {
                acceptReliable(rt, stream_id);
            } else {
                // The peer may open request streams in the same
                // flight as its HELLO; accept them once the exchange
                // lands.
                try seat.pending_accepts.append(seat.allocator, stream_id);
            }
        }

        /// Buffer one ordered chunk and pump the session. Call from
        /// on_stream_data.
        pub fn onStreamData(
            self: *Self,
            seat: *Seat,
            conn: *quic_zig.Connection,
            stream_id: u64,
            chunk: []const u8,
        ) !void {
            const entry = try seat.streams.getOrPut(seat.allocator, stream_id);
            if (!entry.found_existing) entry.value_ptr.* = .{};
            try entry.value_ptr.buf.appendSlice(seat.allocator, chunk);
            entry.value_ptr.delivered += chunk.len;
            try self.pumpSeat(seat, conn);
        }

        /// The stream ended (fin) or died (reset/reaped). Call from
        /// on_stream_end.
        pub fn onStreamEnd(
            self: *Self,
            seat: *Seat,
            conn: *quic_zig.Connection,
            stream_id: u64,
            end: quic_zig.app.StreamEnd,
        ) !void {
            removePendingAccept(seat, stream_id);
            removePendingControlRead(seat, stream_id);
            removeControlRead(seat, stream_id);
            const state = seat.streams.getPtr(stream_id) orelse return;

            switch (end) {
                .fin => {
                    state.final_size = state.delivered;
                    // Final drain: the receivers observe
                    // read_offset == final_size and complete.
                    try self.pumpSeat(seat, conn);
                },
                .reset, .reaped => {
                    // Drop the affected receiver instead of letting
                    // the next pump surface StreamReset/StreamNotFound
                    // and abort the whole pass.
                    state.reset = true;
                    if (seat.sess) |sess| {
                        const rt = Owner.driverSessionRuntime(sess);
                        if (rt.reliable_receivers.fetchRemove(stream_id)) |kv| {
                            var receiver = kv.value;
                            receiver.deinit();
                        }
                        if (rt.control_receiver) |*receiver| {
                            if (receiver.stream_id == stream_id) {
                                receiver.deinit();
                                rt.control_receiver = null;
                            }
                        }
                    }
                },
            }

            if (seat.streams.fetchRemove(stream_id)) |kv| {
                var removed = kv.value;
                removed.buf.deinit(seat.allocator);
            }
        }

        /// Decode one DATAGRAM frame and hand it to the owner;
        /// undecodable frames are dropped and counted (no reliable
        /// fallback for unreliable sends). The payload fields come
        /// straight off the embedder Driver's `Datagram` hook value.
        pub fn onDatagram(
            self: *Self,
            seat: *Seat,
            data: []const u8,
            arrived_in_early_data: bool,
        ) !void {
            const sess = seat.sess orelse return;
            const rt = Owner.driverSessionRuntime(sess);
            if (!rt.appSession().datagram_enabled) return;

            var received = quic_datagram.decodeIncomingDatagram(
                self.allocator,
                .{
                    .len = data.len,
                    .arrived_in_early_data = arrived_in_early_data,
                },
                data,
                .{ .codec = quic_datagram.codecFromTransport(self.transport_options) },
            ) catch |err| switch (err) {
                error.MalformedFrame, error.MessageTooLarge => {
                    try self.owner.driverDatagramDropped(sess, data.len);
                    return;
                },
                else => return err,
            };
            errdefer received.deinit();
            try self.owner.driverDatagramReceived(sess, received);
        }

        /// Destroy the session and free the seat's state — exactly
        /// once, while the connection is tearing down. Call from
        /// on_disconnect (the will-close path delivers it).
        pub fn onDisconnect(self: *Self, seat: *Seat) void {
            seat.pending_accepts.deinit(seat.allocator);
            seat.pending_accepts = .empty;
            for (seat.control_reads.items) |*read| read.receiver.deinit();
            seat.control_reads.deinit(seat.allocator);
            seat.control_reads = .empty;
            seat.pending_control_reads.deinit(seat.allocator);
            seat.pending_control_reads = .empty;
            var it = seat.streams.valueIterator();
            while (it.next()) |state| {
                state.buf.deinit(seat.allocator);
            }
            seat.streams.deinit(seat.allocator);
            seat.streams = .empty;
            if (seat.sess) |sess| {
                self.owner.driverServerSessionDestroy(sess);
                seat.sess = null;
            }
        }

        /// One send-side service pass for the connection: drains
        /// pending stream accepts, pumps the qmsg session against the
        /// seat's buffers, then hands the connection to the owner
        /// (datagram outbox pumping). Call once per tick, AFTER the
        /// embedder's `driver.service` and BEFORE the Server's tick
        /// (the stream GC must never reap a stream whose arrived
        /// bytes qmsg has not read).
        pub fn serviceSeat(self: *Self, seat: *Seat, conn: *quic_zig.Connection) !void {
            try self.pumpSeat(seat, conn);
            if (seat.sess) |sess| {
                try self.owner.driverSessionPass(sess, conn);
            }
        }

        /// Drains pending accepts (once the session is ready) and
        /// runs one qmsg session pump against the seat adapter.
        /// Protocol errors close THIS connection instead of
        /// propagating out of the embedder's loop.
        fn pumpSeat(self: *Self, seat: *Seat, conn: *quic_zig.Connection) !void {
            const sess = seat.sess orelse return;
            const rt = Owner.driverSessionRuntime(sess);

            if (rt.state() == .ready and seat.pending_accepts.items.len > 0) {
                for (seat.pending_accepts.items) |stream_id| {
                    acceptReliable(rt, stream_id);
                }
                seat.pending_accepts.clearRetainingCapacity();
            }

            if (rt.state() == .ready and seat.pending_control_reads.items.len > 0) {
                for (seat.pending_control_reads.items) |stream_id| {
                    // The stream may have ended before the session
                    // reached ready; onStreamEnd already dropped its
                    // pending entry, and arming a removed buffer would
                    // decode nothing forever.
                    if (!seat.streams.contains(stream_id)) continue;
                    armControlRead(seat, rt, stream_id);
                }
                seat.pending_control_reads.clearRetainingCapacity();
            }

            var adapter: Adapter = .{ .conn = conn, .seat = seat };
            _ = rt.pump(&adapter) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    rt.beginClosing();
                    conn.close(false, quic.protocol_error_code, "qmsg protocol error");
                    return;
                },
            };

            // Follow-up control streams: decode complete frames and
            // hand them to the owner (registry apply is node-level).
            self.pumpControlReads(seat, &adapter) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    rt.beginClosing();
                    conn.close(false, quic.protocol_error_code, "qmsg control frame error");
                },
            };
        }

        fn pumpControlReads(self: *Self, seat: *Seat, adapter: *Adapter) !void {
            var index: usize = 0;
            var frames: std.ArrayList(quic_control_frame) = .empty;
            defer {
                for (frames.items) |*frame| frame.deinit();
                frames.deinit(seat.allocator);
            }

            while (index < seat.control_reads.items.len) {
                const read = &seat.control_reads.items[index];
                frames.clearRetainingCapacity();
                const result = read.receiver.pump(adapter, &frames) catch |err| switch (err) {
                    // The stream may have been reaped before its end
                    // was observed; the read goes with it.
                    error.StreamNotFound => {
                        read.receiver.deinit();
                        _ = seat.control_reads.orderedRemove(index);
                        continue;
                    },
                    else => return err,
                };

                if (frames.items.len > 0) {
                    // Frames are BORROWED by the owner; this defer
                    // remains their single owner.
                    try self.owner.driverControlFramesReceived(seat.sess.?, frames.items);
                }

                if (result.stream_complete) {
                    read.receiver.deinit();
                    _ = seat.control_reads.orderedRemove(index);
                    continue;
                }
                index += 1;
            }
        }

        fn acceptReliable(rt: *SessionRuntime, stream_id: u64) void {
            rt.acceptReliableStream(stream_id) catch |err| switch (err) {
                error.StreamAlreadyOpen => {},
                // Session closing or not ready: the stream ends via
                // reset/teardown paths instead.
                else => {},
            };
        }

        fn armControlRead(seat: *Seat, rt: *SessionRuntime, stream_id: u64) void {
            for (seat.control_reads.items) |*read| {
                if (read.stream_id == stream_id) return;
            }
            seat.control_reads.append(seat.allocator, .{
                .stream_id = stream_id,
                .receiver = quic_streams.ControlStreamReceiver.init(
                    seat.allocator,
                    stream_id,
                    .{ .codec = rt.session.options.control_codec },
                ),
            }) catch {
                // Allocation failure: leave the stream unread; the
                // peer's next flush re-sends the state.
            };
        }

        fn removePendingControlRead(seat: *Seat, stream_id: u64) void {
            var index: usize = 0;
            while (index < seat.pending_control_reads.items.len) {
                if (seat.pending_control_reads.items[index] == stream_id) {
                    _ = seat.pending_control_reads.swapRemove(index);
                } else {
                    index += 1;
                }
            }
        }

        fn removeControlRead(seat: *Seat, stream_id: u64) void {
            var index: usize = 0;
            while (index < seat.control_reads.items.len) {
                if (seat.control_reads.items[index].stream_id == stream_id) {
                    var removed = seat.control_reads.orderedRemove(index);
                    removed.receiver.deinit();
                } else {
                    index += 1;
                }
            }
        }

        fn removePendingAccept(seat: *Seat, stream_id: u64) void {
            var index: usize = 0;
            while (index < seat.pending_accepts.items.len) {
                if (seat.pending_accepts.items[index] == stream_id) {
                    _ = seat.pending_accepts.swapRemove(index);
                } else {
                    index += 1;
                }
            }
        }
    };
}
