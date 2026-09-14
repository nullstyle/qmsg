//! Server-side qmsg dispatch built on `quic.app.Driver` — the typed
//! application layer quic-zig ships as of v0.14.0.
//!
//! This is the qmsg-OWNED-listener shape: one dispatch owns the
//! Driver for a listener it is attached to, creating sessions on
//! handshake and destroying them exactly once through the will-close
//! teardown. The hook mechanics (per-stream inbound buffering, the
//! hybrid adapter the pull-based qmsg receivers read through,
//! reset-tolerant teardown, datagram decode) live in
//! `quic_embedded.EmbeddedDispatch`; this file is the Driver-owning
//! wrapper that feeds them from the Driver's own event delivery.
//!
//! Foreign embedders that own their listener and Driver use
//! `quic_embedded.EmbeddedDispatch` directly instead of this
//! wrapper — there is only one will-close hook slot per Server, so
//! there can only be one Driver, and on the inbound attach seam it
//! is the embedder's.
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
const quic_embedded = @import("quic_embedded.zig");

pub fn ServerDispatch(comptime Owner: type) type {
    return struct {
        const Self = @This();
        const Embedded = quic_embedded.EmbeddedDispatch(Owner);

        /// The Driver App: per-connection state is the embedded
        /// dispatch's seat; per-stream state is unused (the seat
        /// buffers inbound bytes itself).
        pub const App = struct {
            allocator: std.mem.Allocator,
            owner: *Owner,
            transport_options: quic.QuicOptions,

            pub const ConnState = struct {
                /// Absent until the handshake delegates the connection
                /// to qmsg; absent seats make every later hook (and
                /// the disconnect teardown) a no-op, so connections
                /// that die mid-handshake are safe.
                seat: ?Embedded.Seat = null,
            };

            pub const StreamState = struct {};
        };

        pub const D = quic_zig.app.Driver(App);

        app: App,
        driver: D,
        /// Owner clock for the liveness sweep (see ).
        heartbeat_now_us: u64 = 0,

        /// In place: `self` must already sit at its final address
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
            var hooks: D.Hooks = .{
                .on_handshake = onHandshake,
                .on_stream_open = onStreamOpen,
                .on_stream_end = onStreamEnd,
                .on_datagram = onDatagram,
                .on_disconnect = onDisconnect,
            };
            if (comptime @hasField(D.Hooks, "on_stream_data_consumed")) {
                hooks.on_stream_data_consumed = onStreamDataConsumed;
            } else hooks.on_stream_data = onStreamData;
            self.driver = try D.init(.{
                .allocator = allocator,
                .app = &self.app,
                .hooks = hooks,
                // Sized to what the listener advertises, so a
                // conforming peer can never overflow the table.
                // Include locally originated request streams as well as the
                // peer stream credit advertised by this listener.
                .max_tracked_streams = try std.math.add(usize, quic_embedded.driverSizing(transport_options).max_tracked_streams, transport_options.max_queued_messages),
                .datagram_buf_bytes = quic_embedded.driverSizing(transport_options).datagram_buf_bytes,
            });
        }

        pub fn deinit(self: *Self) void {
            self.driver.deinit();
            self.* = undefined;
        }

        /// Wire the Driver's will-close hook into `server`, so
        /// sessions tear down (exactly once) from `Server.reap`.
        pub fn attach(self: *Self, server: *quic_zig.Server) void {
            self.driver.attach(server);
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
                if (ds.app.seat == null) continue;
                var dispatch = self.embedded();
                dispatch.heartbeat_now_us = self.heartbeat_now_us;
                try dispatch.serviceSeat(&ds.app.seat.?, slot.conn);
                // A server can originate requests on an accepted connection.
                // QUIC does not emit peer stream-open events for those local
                // streams, so the driver otherwise never reads their replies.
                // Register after serviceSeat has opened the reserved wire IDs,
                // and before the owner can tick/reap the connection.
                self.trackLocalReceivers(ds) catch |err| switch (err) {
                    error.ExcessiveLoad => slot.conn.close(true, quic_zig.Connection.transport_error_excessive_load, "stream tracking capacity"),
                    else => return err,
                };
            }
        }

        fn trackLocalReceivers(self: *Self, ds: *D.Session) !void {
            const sess = ds.app.seat.?.sess orelse return;
            const runtime = Owner.driverSessionRuntime(sess);
            var ids = runtime.reliable_receivers.keyIterator();
            while (ids.next()) |id| {
                if ((id.* & 3) != 1 or ds.conn.streamRecvState(id.*) == null or ds.table.get(id.*) != null) continue;
                // Driver's public StreamTable supports the released QUIC
                // version as well as ConnectionDriver-era releases. The
                // wrapper owns StreamState, so it initializes that state
                // and delegates the same open hook as peer-opened streams.
                const entry = ds.table.track(id.*) orelse return error.ExcessiveLoad;
                entry.bidi = true;
                entry.state = .{};
                try onStreamOpen(&self.app, ds, entry, true);
            }
        }

        /// Record the owner's clock for the per-seat liveness sweep in
        /// `service`. Call from the owner's tick; zero (the default)
        /// means no sweep runs.
        pub fn setHeartbeatClock(self: *Self, now_us: u64) void {
            self.heartbeat_now_us = now_us;
        }

        fn embedded(self: *Self) Embedded {
            return Embedded.init(self.app.allocator, self.app.owner, self.app.transport_options, .dispatch);
        }

        // ---- Driver hooks: delegate to the embedded dispatch ------

        fn embeddedFor(app: *App) Embedded {
            return Embedded.init(app.allocator, app.owner, app.transport_options, .dispatch);
        }

        fn onHandshake(app: *App, s: *D.Session) anyerror!void {
            if (s.app.seat != null) return;
            var seat = Embedded.Seat.init(app.allocator);
            var dispatch = embeddedFor(app);
            try dispatch.onHandshake(&seat, s.conn);
            s.app.seat = seat;
        }

        fn onStreamOpen(app: *App, s: *D.Session, e: *D.StreamEntry, bidi: bool) anyerror!void {
            if (s.app.seat == null) return;
            var dispatch = embeddedFor(app);
            try dispatch.onStreamOpen(&s.app.seat.?, e.id, bidi);
        }

        fn onStreamData(app: *App, s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
            if (s.app.seat == null) return;
            var dispatch = embeddedFor(app);
            try dispatch.onStreamData(&s.app.seat.?, s.conn, e.id, chunk);
        }

        fn onStreamDataConsumed(app: *App, s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!usize {
            if (s.app.seat == null) return chunk.len;
            var dispatch = embeddedFor(app);
            return dispatch.onStreamDataConsumed(&s.app.seat.?, s.conn, e.id, chunk);
        }

        fn onStreamEnd(app: *App, s: *D.Session, e: *D.StreamEntry, end: quic_zig.app.StreamEnd) anyerror!void {
            if (s.app.seat == null) return;
            var dispatch = embeddedFor(app);
            try dispatch.onStreamEnd(&s.app.seat.?, s.conn, e.id, end);
        }

        fn onDatagram(app: *App, s: *D.Session, datagram: D.Datagram) anyerror!void {
            if (s.app.seat == null) return;
            var dispatch = embeddedFor(app);
            try dispatch.onDatagram(&s.app.seat.?, datagram.bytes, datagram.arrived_in_early_data);
        }

        fn onDisconnect(app: *App, s: *D.Session) void {
            if (s.app.seat == null) return;
            var dispatch = embeddedFor(app);
            dispatch.onDisconnect(&s.app.seat.?);
            s.app.seat = null;
        }
    };
}
