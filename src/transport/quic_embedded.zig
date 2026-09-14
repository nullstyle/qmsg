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
        /// Node clock for the liveness sweep. The owner's tick sets this
        /// (`setHeartbeatClock`); zero means no sweep runs (fresh
        /// dispatches heartbeat only once the owner starts ticking).
        heartbeat_now_us: u64 = 0,

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
            if (seat.sess != null) return;
            const sess = try self.owner.driverServerSessionCreate(self.transport_options);
            const rt = Owner.driverSessionRuntime(sess);
            if (@hasDecl(Owner, "driverBindConnection")) self.owner.driverBindConnection(sess, conn);
            rt.event_delivery = self.delivery == .events;
            // Bind the handshake-authenticated identity BEFORE any
            // HELLO can be accepted, so `AuthConfig.cert_binding` has
            // something to check the announced id against. Present
            // only on a mutual-TLS listener (`client_ca_pem`).
            if (conn.peerCertSpkiDigest()) |digest| rt.session.bindCertIdentity(digest);
            seat.sess = sess;
        }

        /// bidi streams carry requests; uni streams are the peer's
        /// control stream (its receiver is pre-armed by id). Call
        /// from on_stream_open.
        pub fn onStreamOpen(self: *Self, seat: *Seat, stream_id: u64, bidi: bool) !void {
            const sess = seat.sess orelse return;
            const rt = Owner.driverSessionRuntime(sess);
            // Ended streams may still wait for HELLO or decoder capacity after
            // QUIC replenishes its stream credit. Bound these retained records
            // independently of the driver's currently live receive entries.
            if (seat.pending_accepts.items.len + seat.pending_control_reads.items.len + seat.control_reads.items.len >=
                driverSizing(self.transport_options).max_tracked_streams)
                return error.ExcessiveLoad;

            if (!bidi) {
                // The peer's FIRST uni stream is the HELLO control
                // stream (pre-armed by id on the runtime); every
                // later uni stream carries follow-up control frames.
                if (stream_id == quic_streams.peerControlStreamId(rt.session.role)) return;

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

            if (rt.state() == .ready and acceptReliable(rt, stream_id)) {
                return;
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
            const sess = seat.sess orelse return;
            try self.pumpSeat(seat, conn);
            const limit = Owner.driverSessionRuntime(sess).session.options.max_queued_bytes;
            var buffered: usize = 0;
            var it = seat.streams.valueIterator();
            while (it.next()) |state| buffered +|= state.buf.items.len - state.start;
            // Legacy drivers acknowledge a whole chunk or none. Refuse this
            // connection before staging bytes so a retry cannot duplicate a prefix.
            if (chunk.len > limit -| buffered) {
                Owner.driverSessionRuntime(sess).beginClosing();
                conn.close(false, 0x51_04, "receive capacity exhausted");
                return;
            }
            _ = try self.onStreamDataConsumed(seat, conn, stream_id, chunk);
        }

        pub fn onStreamDataConsumed(self: *Self, seat: *Seat, conn: *quic_zig.Connection, stream_id: u64, chunk: []const u8) !usize {
            const sess = seat.sess orelse return chunk.len;
            const rt = Owner.driverSessionRuntime(sess);
            // Locally initiated request receivers disappear on cancellation.
            // Drain any already-arrived late bytes without recreating a buffer.
            if ((stream_id & 2) == 0 and !quic_session_runtime.isPeerBidiStreamId(rt.session.role, stream_id) and !rt.reliable_receivers.contains(stream_id)) return chunk.len;
            try self.pumpSeat(seat, conn);
            var buffered: usize = 0;
            var it = seat.streams.valueIterator();
            while (it.next()) |state| buffered +|= state.buf.items.len - state.start;
            const room = rt.session.options.max_queued_bytes -| buffered;
            const accepted = @min(room, chunk.len);
            if (accepted == 0) return 0;
            const entry = try seat.streams.getOrPut(seat.allocator, stream_id);
            if (!entry.found_existing) entry.value_ptr.* = .{};
            try entry.value_ptr.buf.appendSlice(seat.allocator, chunk[0..accepted]);
            entry.value_ptr.delivered += accepted;
            // After accepting bytes, return their count without fallible work.
            // The next service pass pumps them; a decoder allocation failure must
            // never make the QUIC driver retry an already accepted prefix.
            return accepted;
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
            if (@hasDecl(Owner, "driverStreamEnded")) {
                if (seat.sess) |sess| self.owner.driverStreamEnded(sess, stream_id, end);
            }
            // FIN does not cancel its decoder. The last data callback only
            // staged bytes, and a pending HELLO or inbox pressure can delay
            // decoding further. Preserve every reader until it observes EOF.
            if (end == .fin) {
                const entry = try seat.streams.getOrPut(seat.allocator, stream_id);
                if (!entry.found_existing) entry.value_ptr.* = .{};
                entry.value_ptr.final_size = entry.value_ptr.delivered;
                try self.pumpSeat(seat, conn);
                return;
            }
            removePendingAccept(seat, stream_id);
            removePendingControlRead(seat, stream_id);
            removeControlRead(seat, stream_id);
            switch (end) {
                .fin => unreachable,
                .reset, .reaped => {
                    // Drop the affected receiver instead of letting
                    // the next pump surface StreamReset/StreamNotFound
                    // and abort the whole pass.
                    if (seat.streams.getPtr(stream_id)) |state| state.reset = true;
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
        /// Record the owner's clock for `pumpSeat`'s liveness sweep.
        /// Call from the owner's tick; embedders that never tick never
        /// heartbeat (their sessions live at the embedder's pleasure).
        pub fn setHeartbeatClock(self: *Self, now_us: u64) void {
            self.heartbeat_now_us = now_us;
        }

        fn pumpSeat(self: *Self, seat: *Seat, conn: *quic_zig.Connection) !void {
            const sess = seat.sess orelse return;
            const rt = Owner.driverSessionRuntime(sess);

            // Liveness sweep on the owner-supplied clock, before the
            // pump: a PING emitted here flushes in the same pass.
            if (self.heartbeat_now_us != 0) {
                var adapter: quic_streams.QuicConnectionAdapter = .{ .conn = conn };
                _ = rt.tickHeartbeat(self.heartbeat_now_us, &adapter) catch {};
            }

            if (rt.state() == .ready and seat.pending_accepts.items.len > 0) {
                var pending_index: usize = 0;
                while (pending_index < seat.pending_accepts.items.len) {
                    if (acceptReliable(rt, seat.pending_accepts.items[pending_index])) {
                        _ = seat.pending_accepts.orderedRemove(pending_index);
                    } else pending_index += 1;
                }
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
            releaseDrainedEndedStreams(seat, rt);
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
                for (frames.items) |*frame| frame.deinit();
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

        fn acceptReliable(rt: *SessionRuntime, stream_id: u64) bool {
            rt.acceptReliableStream(stream_id) catch |err| switch (err) {
                error.StreamAlreadyOpen => return true,
                else => return false,
            };
            return true;
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

        fn hasPendingAccept(seat: *Seat, stream_id: u64) bool {
            for (seat.pending_accepts.items) |id| {
                if (id == stream_id) return true;
            }
            return false;
        }

        /// Release the buffers of streams that finished before the session was
        /// ready and have since been consumed by their receiver.
        fn releaseDrainedEndedStreams(seat: *Seat, rt: *SessionRuntime) void {
            var drained: std.ArrayListUnmanaged(u64) = .empty;
            defer drained.deinit(seat.allocator);
            var it = seat.streams.iterator();
            while (it.next()) |entry| {
                const state = entry.value_ptr;
                const final_size = state.final_size orelse continue;
                if (state.consumed < final_size) continue;
                if (rt.reliable_receivers.contains(entry.key_ptr.*)) continue;
                if (hasPendingAccept(seat, entry.key_ptr.*)) continue;
                if (rt.control_receiver) |receiver| if (receiver.stream_id == entry.key_ptr.*) continue;
                var control_pending = false;
                for (seat.pending_control_reads.items) |id| if (id == entry.key_ptr.*) {
                    control_pending = true;
                    break;
                };
                for (seat.control_reads.items) |read| if (read.stream_id == entry.key_ptr.*) {
                    control_pending = true;
                    break;
                };
                if (control_pending) continue;
                drained.append(seat.allocator, entry.key_ptr.*) catch return;
            }
            for (drained.items) |stream_id| {
                if (seat.streams.fetchRemove(stream_id)) |kv| {
                    var removed = kv.value;
                    removed.buf.deinit(seat.allocator);
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

const AdmissionTestOwner = struct {
    pub const DriverSession = *SessionRuntime;
    controls: usize = 0,

    pub fn driverSessionRuntime(sess: DriverSession) *SessionRuntime {
        return sess;
    }
    pub fn driverServerSessionDestroy(_: *@This(), _: DriverSession) void {}
    pub fn driverSessionPass(_: *@This(), _: DriverSession, _: *quic_zig.Connection) !void {}
    pub fn driverControlFramesReceived(self: *@This(), _: DriverSession, frames: []quic_control_frame) !void {
        for (frames) |frame| switch (frame) {
            .subscribe => |subscription| {
                try std.testing.expectEqualStrings("jobs.*", subscription.filter);
                self.controls += 1;
            },
            else => return error.UnexpectedFrame,
        };
    }
};

// Reject decoder allocations only after admission has actually staged bytes.
// Safe bookkeeping allocations before admission remain permitted.
const AdmissionAllocator = struct {
    parent: std.mem.Allocator,
    seat: ?*EmbeddedSeat(AdmissionTestOwner) = null,
    reject_buffered: bool = true,
    rejected: bool = false,

    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn reject(self: *@This()) bool {
        if (!self.reject_buffered) return false;
        const seat = self.seat orelse return false;
        const stream = seat.streams.get(0) orelse return false;
        if (stream.delivered == 0) return false;
        self.rejected = true;
        return true;
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.reject()) return null;
        return self.parent.rawAlloc(len, alignment, ret_addr);
    }
    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ret_addr: usize) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (len > memory.len and self.reject()) return false;
        return self.parent.rawResize(memory, alignment, len, ret_addr);
    }
    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ret_addr: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (len > memory.len and self.reject()) return null;
        return self.parent.rawRemap(memory, alignment, len, ret_addr);
    }
    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.parent.rawFree(memory, alignment, ret_addr);
    }
};

test "embedded admission returns consumed bytes before decoder allocation" {
    const a = std.testing.allocator;
    var failing: AdmissionAllocator = .{ .parent = a };
    var runtime = try SessionRuntime.init(failing.allocator(), 1, .server, .{});
    defer runtime.deinit();
    runtime.session.state_value = .ready;
    try runtime.acceptReliableStream(0);
    var transport = try @import("quic_runtime.zig").ClientRuntime.init(a, "127.0.0.1:4433", .{ .server_name = "localhost" });
    defer transport.deinit();
    const Dispatch = EmbeddedDispatch(AdmissionTestOwner);
    var owner: AdmissionTestOwner = .{};
    var dispatch = Dispatch.init(a, &owner, .{}, .events);
    var seat = Dispatch.Seat.init(a);
    seat.sess = &runtime;
    failing.seat = &seat;
    defer dispatch.onDisconnect(&seat);
    const encoded = try quic_streams.encodeReliableMessage(a, .{ .id = 7, .subject = "echo", .body = "accepted once" }, .{});
    defer a.free(encoded);

    // Any attempt to allocate after accepting the chunk would fail, so
    // returning its full length proves the callback does no fallible work
    // after committing those bytes.
    try std.testing.expectEqual(encoded.len, try dispatch.onStreamDataConsumed(&seat, transport.connection(), 0, encoded));
    try std.testing.expect(!failing.rejected);
    try std.testing.expectEqualStrings(encoded, seat.streams.get(0).?.buf.items);
    try std.testing.expectEqual(@as(u64, encoded.len), seat.streams.get(0).?.delivered);
    try std.testing.expectEqual(@as(usize, 0), runtime.reliable_receivers.get(0).?.bytes.items.len);
    try std.testing.expectError(error.OutOfMemory, dispatch.serviceSeat(&seat, transport.connection()));
    try std.testing.expect(failing.rejected);
    try std.testing.expectEqualStrings(encoded, seat.streams.get(0).?.buf.items);

    // Restore decoding capacity, then finish normally. The exact payload is
    // delivered once without replaying the already accepted transport chunk.
    failing.reject_buffered = false;
    try dispatch.onStreamEnd(&seat, transport.connection(), 0, .fin);
    var received = runtime.recvReliable() orelse return error.MissingMessage;
    defer received.deinit();
    try std.testing.expectEqualStrings("accepted once", received.message.body);
    try std.testing.expect(runtime.recvReliable() == null);
    try std.testing.expectEqual(@as(usize, 0), seat.streams.count());
}

test "embedded legacy overflow refuses the whole chunk on only its connection" {
    const a = std.testing.allocator;
    const options: quic.QuicOptions = .{ .max_message_size = 4, .max_queued_bytes = 4 };
    var runtime = try SessionRuntime.init(a, 1, .server, options);
    defer runtime.deinit();
    var healthy = try SessionRuntime.init(a, 2, .server, options);
    defer healthy.deinit();
    var transport = try @import("quic_runtime.zig").ClientRuntime.init(a, "127.0.0.1:4433", .{ .server_name = "localhost" });
    defer transport.deinit();
    var healthy_transport = try @import("quic_runtime.zig").ClientRuntime.init(a, "127.0.0.1:4434", .{ .server_name = "localhost" });
    defer healthy_transport.deinit();
    const Dispatch = EmbeddedDispatch(AdmissionTestOwner);
    var owner: AdmissionTestOwner = .{};
    var dispatch = Dispatch.init(a, &owner, options, .events);
    var seat = Dispatch.Seat.init(a);
    seat.sess = &runtime;
    defer dispatch.onDisconnect(&seat);
    var healthy_seat = Dispatch.Seat.init(a);
    healthy_seat.sess = &healthy;
    defer dispatch.onDisconnect(&healthy_seat);

    try dispatch.onStreamData(&seat, transport.connection(), 0, "ab");
    try dispatch.onStreamData(&seat, transport.connection(), 0, "cde");
    try std.testing.expect(runtime.isClosing());
    try std.testing.expectEqualStrings("ab", seat.streams.get(0).?.buf.items);
    try std.testing.expectEqual(@as(u64, 2), seat.streams.get(0).?.delivered);
    try dispatch.onStreamData(&healthy_seat, healthy_transport.connection(), 0, "xy");
    try std.testing.expect(!healthy.isClosing());
    try std.testing.expectEqualStrings("xy", healthy_seat.streams.get(0).?.buf.items);
}

test "embedded FIN preserves deferred control readers through decoding" {
    const a = std.testing.allocator;
    var runtime = try SessionRuntime.init(a, 1, .server, .{});
    defer runtime.deinit();
    runtime.session.state_value = .ready;
    var transport = try @import("quic_runtime.zig").ClientRuntime.init(a, "127.0.0.1:4433", .{ .server_name = "localhost" });
    defer transport.deinit();
    const Dispatch = EmbeddedDispatch(AdmissionTestOwner);
    var owner: AdmissionTestOwner = .{};
    var dispatch = Dispatch.init(a, &owner, .{}, .events);
    var seat = Dispatch.Seat.init(a);
    seat.sess = &runtime;
    defer dispatch.onDisconnect(&seat);
    const frames = [_]quic_control_frame{.{ .subscribe = .{ .filter = "jobs.*", .options = 0 } }};
    const encoded = try quic_streams.encodeControlStream(a, &frames, .{});
    defer a.free(encoded);

    try dispatch.onStreamOpen(&seat, 6, false);
    try dispatch.onStreamOpen(&seat, 10, false);
    try std.testing.expectEqual(encoded.len, try dispatch.onStreamDataConsumed(&seat, transport.connection(), 6, encoded));
    try std.testing.expectEqual(encoded.len, try dispatch.onStreamDataConsumed(&seat, transport.connection(), 10, encoded));
    try dispatch.onStreamEnd(&seat, transport.connection(), 6, .fin);
    try dispatch.onStreamEnd(&seat, transport.connection(), 10, .fin);
    try std.testing.expectEqual(@as(usize, 2), owner.controls);
    try std.testing.expectEqual(@as(usize, 0), seat.control_reads.items.len);
    try std.testing.expectEqual(@as(usize, 0), seat.streams.count());
    try dispatch.serviceSeat(&seat, transport.connection());
    try std.testing.expectEqual(@as(usize, 2), owner.controls);
}

test "embedded pending control FIN records stay bounded before HELLO" {
    const a = std.testing.allocator;
    const options: quic.QuicOptions = .{ .initial_max_streams_bidi = 0, .initial_max_streams_uni = 1 };
    var runtime = try SessionRuntime.init(a, 1, .server, options);
    defer runtime.deinit();
    var transport = try @import("quic_runtime.zig").ClientRuntime.init(a, "127.0.0.1:4433", .{ .server_name = "localhost" });
    defer transport.deinit();
    const Dispatch = EmbeddedDispatch(AdmissionTestOwner);
    var owner: AdmissionTestOwner = .{};
    var dispatch = Dispatch.init(a, &owner, options, .events);
    var seat = Dispatch.Seat.init(a);
    seat.sess = &runtime;
    defer dispatch.onDisconnect(&seat);

    try dispatch.onStreamOpen(&seat, 6, false);
    try dispatch.onStreamEnd(&seat, transport.connection(), 6, .fin);
    try std.testing.expectEqual(@as(usize, 1), seat.pending_control_reads.items.len);
    try std.testing.expectEqual(@as(usize, 1), seat.streams.count());
    try std.testing.expectError(error.ExcessiveLoad, dispatch.onStreamOpen(&seat, 10, false));
    try std.testing.expectEqual(@as(usize, 1), seat.pending_control_reads.items.len);
    try std.testing.expectEqual(@as(usize, 1), seat.streams.count());
}
