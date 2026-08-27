//! Server-side qmsg dispatch built on `quic.app.Driver` — the typed
//! application layer quic-zig ships as of v0.14.0.
//!
//! This replaces the hand-rolled listener loop that bound qmsg
//! sessions to server connections BY SLOT INDEX (`Server.reap` uses
//! swapRemove, so indices are not stable identities: one reap could
//! cross-wire a session onto the wrong connection) and discovered
//! peer streams by rescanning `conn.streamIterator()` every tick.
//! With the Driver:
//!
//!   - a qmsg session rides `Slot.user_data` (identity-stable), is
//!     created on `on_handshake`, and is destroyed exactly once via
//!     the will-close hook's `on_disconnect` — reaps can no longer
//!     confuse sessions;
//!   - peer bidi streams are accepted from `stream_opened` events
//!     (no rescans, no missed streams);
//!   - inbound stream bytes arrive as ordered `on_stream_data`
//!     chunks with a sound exactly-once `on_stream_end`, buffered
//!     per stream in Driver-owned `StreamState` and consumed by the
//!     existing pull-based qmsg receivers through `Adapter` below —
//!     the control/reliable codecs are untouched;
//!   - a peer RESET removes the affected receiver in `on_stream_end`
//!     instead of surfacing as an error out of the next session pump
//!     (which used to abort the whole node tick);
//!   - datagrams are delivered through `on_datagram` (the Driver
//!     drains the inbound queue unconditionally, which RFC-correctly
//!     prevents queue-overflow connection kills).
//!
//! Generic over `Owner` (the session store — `node.Node` in
//! production) so this file stays in the transport layer and tests
//! can supply a minimal owner. The Owner contract:
//!
//!   pub const DriverSession = *<owner session wrapper>;
//!   pub fn driverSessionRuntime(DriverSession) *QuicSessionRuntime
//!   pub fn driverServerSessionCreate(*Owner, QuicOptions) !DriverSession
//!   pub fn driverServerSessionDestroy(*Owner, DriverSession) void
//!   pub fn driverSessionPass(*Owner, DriverSession, *Connection) !void
//!   pub fn driverDatagramReceived(*Owner, DriverSession, ReceivedDatagram) !void
//!   pub fn driverDatagramDropped(*Owner, DriverSession, usize) !void

const std = @import("std");
const quic_zig = @import("quic");

const quic = @import("quic.zig");
const quic_datagram = @import("quic_datagram.zig");
const quic_session_runtime = @import("quic_session_runtime.zig");

const SessionRuntime = quic_session_runtime.QuicSessionRuntime;

pub fn ServerDispatch(comptime Owner: type) type {
    return struct {
        const Self = @This();

        /// The Driver App: per-connection state is the owner's session
        /// handle plus stream-accepts that arrived before the qmsg
        /// HELLO exchange finished; per-stream state is the inbound
        /// byte buffer the pull-based receivers consume through
        /// `Adapter`.
        pub const App = struct {
            allocator: std.mem.Allocator,
            owner: *Owner,
            transport_options: quic.QuicOptions,

            pub const ConnState = struct {
                sess: ?Owner.DriverSession = null,
                pending_accepts: std.ArrayListUnmanaged(u64) = .empty,
            };

            pub const StreamState = struct {
                /// Unconsumed inbound bytes (prefix [0..start) already
                /// read by the adapter and compacted away).
                buf: std.ArrayListUnmanaged(u8) = .empty,
                start: usize = 0,
                /// Cumulative bytes handed to the adapter's reads —
                /// the `read_offset` the receivers' completion test
                /// compares against `final_size`.
                consumed: u64 = 0,
                /// Cumulative bytes delivered by on_stream_data.
                delivered: u64 = 0,
                final_size: ?u64 = null,
                reset: bool = false,
            };
        };

        pub const D = quic_zig.app.Driver(App);

        /// The hybrid transport the qmsg senders/receivers pump
        /// against on the server side: writes go to the connection
        /// (same as `QuicConnectionAdapter`), reads are served from
        /// the Driver's per-stream buffers.
        pub const Adapter = struct {
            conn: *quic_zig.Connection,
            session: *D.Session,

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
                const entry = self.session.table.get(stream_id) orelse return 0;
                const state = &entry.state;
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
            ) ?@import("quic_streams.zig").ReceiveStatus {
                const entry = self.session.table.get(stream_id) orelse return null;
                return .{
                    .reset = entry.state.reset,
                    .final_size = entry.state.final_size,
                    .read_offset = entry.state.consumed,
                };
            }
        };

        app: App,
        driver: D,

        /// In-place init: `self` must already sit at its final address
        /// (the Driver stores `&self.app`).
        pub fn init(
            self: *Self,
            allocator: std.mem.Allocator,
            owner: *Owner,
            transport_options: quic.QuicOptions,
        ) !void {
            self.app = .{
                .allocator = allocator,
                .owner = owner,
                .transport_options = transport_options,
            };
            self.driver = try D.init(.{
                .allocator = allocator,
                .app = &self.app,
                .hooks = .{
                    .on_handshake = onHandshake,
                    .on_stream_open = onStreamOpen,
                    .on_stream_data = onStreamData,
                    .on_stream_end = onStreamEnd,
                    .on_datagram = onDatagram,
                    .on_disconnect = onDisconnect,
                },
                // Sized to what the listener advertises, so a
                // conforming peer can never overflow the table.
                .max_tracked_streams = @intCast(transport_options.initial_max_streams_bidi +
                    transport_options.initial_max_streams_uni),
                .datagram_buf_bytes = if (transport_options.datagram_enabled)
                    @intCast(@max(transport_options.max_datagram_frame_size, 1200))
                else
                    1,
            });
        }

        pub fn deinit(self: *Self) void {
            self.driver.deinit();
            self.* = undefined;
        }

        /// Wire the Driver's will-close hook into `server`, so
        /// sessions tear down (exactly once) from `Server.reap`.
        pub fn attach(self: *Self, server: *quic_zig.Server) void {
            server.on_connection_will_close = D.willCloseHook;
            server.on_connection_will_close_user_data = &self.driver;
        }

        /// One full service pass: the Driver drains events, pumps
        /// stream bytes into the per-stream buffers (firing the hooks
        /// below), then every session gets a send-side pump and the
        /// owner's per-pass work. Call once per listener tick, BEFORE
        /// `Server.tick` (the ordering that keeps the stream GC away
        /// from unread bytes).
        pub fn service(self: *Self, server: *quic_zig.Server) !void {
            try self.driver.service(server);
            for (server.iterator()) |slot| {
                const ds = self.driver.sessionOn(slot) orelse continue;
                const sess = ds.app.sess orelse continue;
                try pumpSession(ds);
                try self.app.owner.driverSessionPass(sess, slot.conn);
            }
        }

        // ---- Driver hooks -------------------------------------------

        fn onHandshake(app: *App, s: *D.Session) anyerror!void {
            if (s.app.sess != null) return;
            s.app.sess = try app.owner.driverServerSessionCreate(app.transport_options);
        }

        fn onStreamOpen(app: *App, s: *D.Session, e: *D.StreamEntry, bidi: bool) anyerror!void {
            if (!bidi) return; // uni = control stream; receiver is pre-armed by id
            const sess = s.app.sess orelse return;
            const rt = Owner.driverSessionRuntime(sess);
            if (rt.state() == .ready) {
                acceptReliable(rt, e.id);
            } else {
                // The peer may open request streams in the same flight
                // as its HELLO; accept them once the exchange lands.
                try s.app.pending_accepts.append(app.allocator, e.id);
            }
        }

        fn onStreamData(app: *App, s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
            try e.state.buf.appendSlice(app.allocator, chunk);
            e.state.delivered += chunk.len;
            try pumpSession(s);
        }

        fn onStreamEnd(app: *App, s: *D.Session, e: *D.StreamEntry, end: quic_zig.app.StreamEnd) anyerror!void {
            // The entry is released right after this hook; free the
            // buffer on every path.
            defer {
                e.state.buf.deinit(app.allocator);
                e.state.buf = .empty;
                e.state.start = 0;
            }
            removePendingAccept(s, e.id);

            const sess = s.app.sess orelse return;
            const rt = Owner.driverSessionRuntime(sess);
            switch (end) {
                .fin => {
                    e.state.final_size = e.state.delivered;
                    // Final drain: the receivers observe
                    // read_offset == final_size and complete.
                    try pumpSession(s);
                },
                .reset, .reaped => {
                    // Drop the affected receiver instead of letting the
                    // next pump surface StreamReset/StreamNotFound and
                    // abort the whole pass.
                    e.state.reset = true;
                    if (rt.reliable_receivers.fetchRemove(e.id)) |kv| {
                        var receiver = kv.value;
                        receiver.deinit();
                    }
                    if (rt.control_receiver) |*receiver| {
                        if (receiver.stream_id == e.id) {
                            receiver.deinit();
                            rt.control_receiver = null;
                        }
                    }
                },
            }
        }

        fn onDatagram(app: *App, s: *D.Session, datagram: D.Datagram) anyerror!void {
            const sess = s.app.sess orelse return;
            const rt = Owner.driverSessionRuntime(sess);
            if (!rt.appSession().datagram_enabled) return;

            const codec = datagramCodecOptions(app.transport_options);
            var received = quic_datagram.decodeIncomingDatagram(
                app.allocator,
                // The Driver hands full payloads (the delivery buffer
                // is sized to the advertised frame limit above).
                .{
                    .len = datagram.bytes.len,
                    .arrived_in_early_data = datagram.arrived_in_early_data,
                },
                datagram.bytes,
                .{ .codec = codec },
            ) catch |err| switch (err) {
                error.MalformedFrame, error.MessageTooLarge => {
                    try app.owner.driverDatagramDropped(sess, datagram.bytes.len);
                    return;
                },
                else => return err,
            };
            errdefer received.deinit();
            try app.owner.driverDatagramReceived(sess, received);
        }

        fn onDisconnect(app: *App, s: *D.Session) void {
            s.app.pending_accepts.deinit(app.allocator);
            s.app.pending_accepts = .empty;
            if (s.app.sess) |sess| {
                app.owner.driverServerSessionDestroy(sess);
                s.app.sess = null;
            }
        }

        // ---- internals ----------------------------------------------

        /// Drain pending accepts (once the session is ready) and run
        /// one qmsg session pump against the hybrid adapter. Protocol
        /// errors close THIS connection instead of propagating out of
        /// the node tick.
        fn pumpSession(s: *D.Session) anyerror!void {
            const sess = s.app.sess orelse return;
            const rt = Owner.driverSessionRuntime(sess);

            if (rt.state() == .ready and s.app.pending_accepts.items.len > 0) {
                for (s.app.pending_accepts.items) |stream_id| {
                    acceptReliable(rt, stream_id);
                }
                s.app.pending_accepts.clearRetainingCapacity();
            }

            var adapter: Adapter = .{ .conn = s.conn, .session = s };
            _ = rt.pump(&adapter) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    rt.beginClosing();
                    s.conn.close(false, quic.protocol_error_code, "qmsg protocol error");
                },
            };
        }

        fn acceptReliable(rt: *SessionRuntime, stream_id: u64) void {
            rt.acceptReliableStream(stream_id) catch |err| switch (err) {
                error.StreamAlreadyOpen => {},
                // Session closing or not ready: the stream ends via
                // reset/teardown paths instead.
                else => {},
            };
        }

        fn removePendingAccept(s: *D.Session, stream_id: u64) void {
            var index: usize = 0;
            while (index < s.app.pending_accepts.items.len) {
                if (s.app.pending_accepts.items[index] == stream_id) {
                    _ = s.app.pending_accepts.swapRemove(index);
                } else {
                    index += 1;
                }
            }
        }

        fn datagramCodecOptions(options: quic.QuicOptions) quic_datagram.CodecOptions {
            const default_codec = quic_datagram.CodecOptions{};
            const negotiated_max = if (options.max_datagram_frame_size == 0)
                default_codec.max_payload_size
            else
                std.math.cast(usize, options.max_datagram_frame_size) orelse std.math.maxInt(usize);

            return .{
                .max_payload_size = @min(options.max_message_size, negotiated_max),
                .max_headers = options.max_header_count,
                .max_header_bytes = options.max_header_bytes,
            };
        }
    };
}
