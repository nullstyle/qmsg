//! Dial-side adapter for the shared QUIC connection driver. Protocol/session
//! semantics stay in EmbeddedDispatch; neither adapter owns the Connection.
const std = @import("std");
const quic_zig = @import("quic");
const embedded = @import("quic_embedded.zig");

pub const available = @hasDecl(quic_zig.app, "ConnectionDriver");

pub fn ClientDispatch(comptime Owner: type) type {
    if (!available) return struct {};
    return struct {
        const Self = @This();
        const Embedded = embedded.EmbeddedDispatch(Owner);
        const App = struct {
            owner: *Owner,
            sess: Owner.DriverSession,
            dispatch: Embedded,
            pub const ConnState = struct { seat: ?Embedded.Seat = null };
            pub const StreamState = struct {};
        };
        pub const D = quic_zig.app.ConnectionDriver(App);
        app: App,
        driver: D,

        pub fn init(self: *Self, allocator: std.mem.Allocator, owner: *Owner, sess: Owner.DriverSession, conn: *quic_zig.Connection) !void {
            const options = Owner.driverSessionRuntime(sess).session.options;
            self.app = .{ .owner = owner, .sess = sess, .dispatch = Embedded.init(allocator, owner, options, .events) };
            self.driver = try D.init(.{
                .allocator = allocator,
                .app = &self.app,
                .conn = conn,
                .max_tracked_streams = embedded.driverSizing(options).max_tracked_streams,
                .datagram_buf_bytes = embedded.driverSizing(options).datagram_buf_bytes,
                .outbox_limits = .{ .max_streams = options.max_queued_messages, .max_bytes = options.max_queued_bytes },
                .hooks = .{
                    .on_stream_open = onStreamOpen,
                    .on_stream_data = onStreamData,
                    .on_stream_end = onStreamEnd,
                    .on_datagram = onDatagram,
                    .on_disconnect = onDisconnect,
                },
            });
            self.driver.state.seat = Embedded.Seat.init(allocator);
            self.driver.state.seat.?.sess = sess;
        }

        pub fn deinit(self: *Self) void {
            self.driver.deinit();
        }

        pub fn service(self: *Self, now_us: u64) !void {
            self.app.dispatch.setHeartbeatClock(now_us);
            try self.app.dispatch.serviceSeat(&self.driver.state.seat.?, self.driver.conn);
            // queueReliable reserves local IDs before opening the wire stream.
            // Register readable streams only after the protocol pump opens them.
            const runtime = Owner.driverSessionRuntime(self.app.sess);
            var ids = runtime.reliable_receivers.keyIterator();
            while (ids.next()) |id| {
                if (self.driver.conn.streamRecvState(id.*) != null) try self.driver.trackStream(id.*);
            }
            try self.driver.service();
            try self.app.dispatch.serviceSeat(&self.driver.state.seat.?, self.driver.conn);
        }

        fn onStreamOpen(app: *App, driver: *D, entry: *D.StreamEntry, bidi: bool) !void {
            try app.dispatch.onStreamOpen(&driver.state.seat.?, entry.id, bidi);
        }
        fn onStreamData(app: *App, driver: *D, entry: *D.StreamEntry, bytes: []const u8) !usize {
            return app.dispatch.onStreamDataConsumed(&driver.state.seat.?, driver.conn, entry.id, bytes);
        }
        fn onStreamEnd(app: *App, driver: *D, entry: *D.StreamEntry, end: quic_zig.app.StreamEnd) !void {
            try app.dispatch.onStreamEnd(&driver.state.seat.?, driver.conn, entry.id, end);
        }
        fn onDatagram(app: *App, driver: *D, datagram: D.Datagram) !void {
            try app.dispatch.onDatagram(&driver.state.seat.?, datagram.bytes, datagram.arrived_in_early_data);
        }
        fn onDisconnect(app: *App, driver: *D) void {
            // The Node owns the dial runtime. Free only this adapter's buffers;
            // Node's close/reap path invalidates handles and destroys the runtime.
            driver.state.seat.?.sess = null;
            app.dispatch.onDisconnect(&driver.state.seat.?);
            driver.state.seat = null;
        }
    };
}
