const std = @import("std");
const message = @import("message.zig");
const socket = @import("socket.zig");
const session = @import("session.zig");
const transport = @import("transport/root.zig");

pub const NodeOptions = struct {
    max_sessions: usize = 1024,
    io: std.Io = std.Io.Threaded.global_single_threaded.io(),
};

pub const Event = union(enum) {
    connected: session.SessionId,
    closed: session.SessionId,
    message_dropped: struct {
        session_id: ?session.SessionId = null,
        bytes: usize,
    },
};

pub const InprocRepId = usize;
pub const QuicListenerId = usize;
pub const QuicSessionId = session.SessionId;

pub const InprocRepOptions = struct {
    socket: socket.SocketOptions(.rep) = .{},
    session: ?session.Session = null,
};

pub const RunOnceResult = struct {
    messages: usize = 0,
    events_pending: usize = 0,

    pub fn didWork(self: RunOnceResult) bool {
        return self.messages != 0;
    }
};

pub const InprocRepEndpoint = struct {
    id: InprocRepId,
    network: *transport.inproc.Network,
    address: []u8,
    socket: socket.Socket(.rep),
    session: session.Session,

    fn deinit(self: *InprocRepEndpoint, allocator: std.mem.Allocator) void {
        self.network.unbindPattern(self.address) catch {};
        self.socket.deinit();
        allocator.free(self.address);
        self.* = undefined;
    }
};

pub const QuicListenOptions = struct {
    tls_cert_pem: []const u8 = "",
    tls_key_pem: []const u8 = "",
    transport: transport.quic.QuicOptions = .{},
    rx_buffer_bytes: usize = transport.quic_runtime.default_rx_buffer_bytes,
    tx_buffer_bytes: usize = transport.quic_runtime.default_tx_buffer_bytes,
    receive_timeout: std.Io.Timeout = transport.quic_udp.default_receive_timeout,
};

pub const QuicDialOptions = struct {
    server_name: []const u8,
    ca_pem: ?[]const u8 = null,
    transport: transport.quic.QuicOptions = .{},
    bind_literal: []const u8 = transport.quic_udp.default_bind_literal,
    rx_buffer_bytes: usize = transport.quic_runtime.default_rx_buffer_bytes,
    tx_buffer_bytes: usize = transport.quic_runtime.default_tx_buffer_bytes,
    receive_timeout: std.Io.Timeout = transport.quic_udp.default_receive_timeout,
};

pub const QuicSessionOptions = struct {
    role: transport.quic.Role,
    transport: transport.quic.QuicOptions = .{},
    user_data: ?*anyopaque = null,
};

pub const QuicListenerRuntime = struct {
    id: QuicListenerId,
    listener: transport.quic_udp.Listener,
    transport_options: transport.quic.QuicOptions,
    /// quic.app.Driver-based session dispatch: sessions ride
    /// `Slot.user_data` (identity-stable across reaps) instead of the
    /// old slot-INDEX binding, which `Server.reap`'s swapRemove could
    /// silently cross-wire onto the wrong connection.
    dispatch: NodeServerDispatch,

    pub fn localAddress(self: QuicListenerRuntime) std.Io.net.IpAddress {
        return self.listener.localAddress();
    }

    fn deinit(self: *QuicListenerRuntime, allocator: std.mem.Allocator) void {
        _ = allocator;
        self.dispatch.deinit();
        self.listener.deinit();
        self.* = undefined;
    }
};

pub const NodeServerDispatch = transport.quic_app_server.ServerDispatch(Node);

pub const QuicClientRuntime = struct {
    client: transport.quic_udp.Client,
    runtime: *QuicSessionRuntime,

    pub fn id(self: QuicClientRuntime) QuicSessionId {
        return self.runtime.id();
    }

    fn deinit(self: *QuicClientRuntime) void {
        self.client.deinit();
        self.* = undefined;
    }
};

pub const QuicSessionRuntime = struct {
    runtime: transport.quic_session_runtime.QuicSessionRuntime,
    transport_ready: bool = false,
    /// True when the listener-side Driver owns this session's
    /// lifecycle (created on handshake, destroyed via will-close).
    driver_owned: bool = false,
    datagram_inbox: std.ArrayList(transport.quic_datagram.ReceivedDatagram) = .empty,
    datagram_outbox: std.ArrayList(message.Message) = .empty,

    pub fn id(self: QuicSessionRuntime) QuicSessionId {
        return self.runtime.id();
    }

    pub fn appSession(self: *QuicSessionRuntime) *session.Session {
        return self.runtime.appSession();
    }

    pub fn state(self: QuicSessionRuntime) transport.quic.State {
        return self.runtime.state();
    }

    pub fn queueReliable(self: *QuicSessionRuntime, outgoing: message.OutgoingMessage) !u64 {
        return self.runtime.queueReliable(outgoing);
    }

    pub fn replyReliableOnStream(self: *QuicSessionRuntime, stream_id: u64, outgoing: message.OutgoingMessage) !void {
        try self.runtime.replyReliableOnStream(stream_id, outgoing);
    }

    pub fn socketDriver(self: *QuicSessionRuntime) socket.QuicSessionDriver {
        return .{
            .context = @ptrCast(self),
            .send = sendSocketMessage,
        };
    }

    pub fn queueDatagram(self: *QuicSessionRuntime, outgoing: message.OutgoingMessage) !void {
        _ = try transport.quic_datagram.encodedSize(outgoing, datagramCodecOptions(self.runtime.session.options));
        var owned = try message.Message.init(self.runtime.allocator, outgoing);
        errdefer owned.deinit();
        try self.datagram_outbox.append(self.runtime.allocator, owned);
    }

    pub fn recvDatagram(self: *QuicSessionRuntime) ?transport.quic_datagram.ReceivedDatagram {
        if (self.datagram_inbox.items.len == 0) return null;
        return self.datagram_inbox.orderedRemove(0);
    }

    pub fn datagramInboxLen(self: QuicSessionRuntime) usize {
        return self.datagram_inbox.items.len;
    }

    pub fn pendingDatagrams(self: QuicSessionRuntime) usize {
        return self.datagram_outbox.items.len;
    }

    fn pumpDatagramOutbox(self: *QuicSessionRuntime, conn: *transport.quic_runtime.Connection) !usize {
        if (self.runtime.state() != .ready) return 0;
        if (!self.runtime.appSession().datagram_enabled) return 0;

        var sent: usize = 0;
        var index: usize = 0;
        while (index < self.datagram_outbox.items.len) {
            const out = self.datagram_outbox.items[index].outgoing();
            const result = transport.quic_datagram.send(conn, self.runtime.allocator, out, .{
                .codec = datagramCodecOptions(self.runtime.session.options),
                .fallback = .datagram_only,
                .queue_full_mapping = .flow_controlled,
            }) catch |err| switch (err) {
                error.FlowControlled, error.QueueFull, error.WouldBlock => return sent,
                else => return err,
            };

            switch (result) {
                .sent_datagram => {
                    var owned = self.datagram_outbox.orderedRemove(index);
                    owned.deinit();
                    sent += 1;
                },
                .use_reliable_fallback => {
                    index += 1;
                },
            }
        }
        return sent;
    }

    fn deinit(self: *QuicSessionRuntime) void {
        for (self.datagram_outbox.items) |*msg| {
            msg.deinit();
        }
        self.datagram_outbox.deinit(self.runtime.allocator);
        for (self.datagram_inbox.items) |*received| {
            received.deinit();
        }
        self.datagram_inbox.deinit(self.runtime.allocator);
        self.runtime.deinit();
        self.* = undefined;
    }
};

pub const QuicSocketAttachment = struct {
    session_id: QuicSessionId,
    endpoint: socket.QuicSocketEndpoint,
};

pub const Node = struct {
    allocator: std.mem.Allocator,
    options: NodeOptions,
    events: std.ArrayList(Event) = .empty,
    inproc_rep_endpoints: std.ArrayList(*InprocRepEndpoint) = .empty,
    quic_listeners: std.ArrayList(*QuicListenerRuntime) = .empty,
    quic_clients: std.ArrayList(*QuicClientRuntime) = .empty,
    quic_sessions: std.ArrayList(*QuicSessionRuntime) = .empty,
    quic_socket_attachments: std.ArrayList(QuicSocketAttachment) = .empty,
    now_us: u64 = 0,
    next_session_id: session.SessionId = 1,

    pub fn init(allocator: std.mem.Allocator, options: NodeOptions) !Node {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    pub fn deinit(self: *Node) void {
        for (self.quic_clients.items) |client| {
            client.deinit();
            self.allocator.destroy(client);
        }
        self.quic_clients.deinit(self.allocator);
        for (self.quic_sessions.items) |runtime| {
            runtime.deinit();
            self.allocator.destroy(runtime);
        }
        self.quic_sessions.deinit(self.allocator);
        self.quic_socket_attachments.deinit(self.allocator);
        for (self.quic_listeners.items) |runtime| {
            runtime.deinit(self.allocator);
            self.allocator.destroy(runtime);
        }
        self.quic_listeners.deinit(self.allocator);
        for (self.inproc_rep_endpoints.items) |endpoint| {
            endpoint.deinit(self.allocator);
            self.allocator.destroy(endpoint);
        }
        self.inproc_rep_endpoints.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn listen(self: *Node, kind: transport.Kind, endpoint: transport.Endpoint) !void {
        return switch (kind) {
            .inproc => error.UnsupportedTransport,
            .quic => {
                if (std.meta.activeTag(endpoint) != .quic) return error.InvalidEndpoint;
                _ = try self.listenQuic(endpoint.quic, .{});
            },
        };
    }

    pub fn dial(self: *Node, kind: transport.Kind, endpoint: transport.Endpoint) !session.SessionId {
        return switch (kind) {
            .inproc => error.UnsupportedTransport,
            .quic => {
                if (std.meta.activeTag(endpoint) != .quic) return error.InvalidEndpoint;
                return self.dialQuic(endpoint.quic, .{ .server_name = "localhost" });
            },
        };
    }

    pub fn tick(self: *Node, now_us: u64) !void {
        self.now_us = now_us;
        try self.tickQuicListeners(now_us);
        try self.tickQuicClients(now_us);
    }

    pub fn listenQuic(self: *Node, endpoint: []const u8, options: QuicListenOptions) !QuicListenerId {
        if (self.quic_listeners.items.len >= self.options.max_sessions) return error.TooManySessions;

        const id = self.quic_listeners.items.len;
        const runtime = try self.allocator.create(QuicListenerRuntime);
        var owns_runtime = true;
        errdefer if (owns_runtime) self.allocator.destroy(runtime);

        runtime.* = .{
            .id = id,
            .listener = try transport.quic_udp.Listener.start(self.allocator, self.options.io, .{
                .bind_literal = endpoint,
                .runtime = .{
                    .tls_cert_pem = options.tls_cert_pem,
                    .tls_key_pem = options.tls_key_pem,
                    .transport = options.transport,
                },
                .rx_buffer_bytes = options.rx_buffer_bytes,
                .tx_buffer_bytes = options.tx_buffer_bytes,
                .receive_timeout = options.receive_timeout,
            }),
            .transport_options = options.transport,
            .dispatch = undefined,
        };
        errdefer if (owns_runtime) runtime.listener.deinit();

        // In place: the runtime is at its final heap address, which
        // the Driver requires (it stores &dispatch.app).
        try runtime.dispatch.init(self.allocator, self, options.transport);
        errdefer if (owns_runtime) runtime.dispatch.deinit();
        runtime.dispatch.attach(&runtime.listener.runtime.server);

        try self.quic_listeners.append(self.allocator, runtime);
        owns_runtime = false;
        return id;
    }

    pub fn dialQuic(self: *Node, endpoint: []const u8, options: QuicDialOptions) !QuicSessionId {
        if (self.quic_sessions.items.len >= self.options.max_sessions) return error.TooManySessions;

        const runtime = try self.createQuicSession(.client, options.transport, null);
        var owns_runtime = true;
        errdefer if (owns_runtime) self.destroyQuicSession(runtime);

        const client = try self.allocator.create(QuicClientRuntime);
        var owns_client = true;
        errdefer if (owns_client) self.allocator.destroy(client);

        client.* = .{
            .client = try transport.quic_udp.Client.start(self.allocator, self.options.io, .{
                .target_literal = endpoint,
                .bind_literal = options.bind_literal,
                .runtime = .{
                    .server_name = options.server_name,
                    .ca_pem = options.ca_pem,
                    .transport = options.transport,
                },
                .rx_buffer_bytes = options.rx_buffer_bytes,
                .tx_buffer_bytes = options.tx_buffer_bytes,
                .receive_timeout = options.receive_timeout,
            }),
            .runtime = runtime,
        };
        errdefer if (owns_client) client.deinit();

        try self.quic_clients.append(self.allocator, client);
        owns_client = false;
        owns_runtime = false;
        return runtime.id();
    }

    pub fn openQuicSession(self: *Node, options: QuicSessionOptions) !*QuicSessionRuntime {
        return self.createQuicSession(options.role, options.transport, options.user_data);
    }

    pub fn quicSession(self: *Node, id: QuicSessionId) ?*QuicSessionRuntime {
        for (self.quic_sessions.items) |runtime| {
            if (runtime.id() == id) return runtime;
        }
        return null;
    }

    pub fn attachQuicSocket(self: *Node, id: QuicSessionId, endpoint: socket.QuicSocketEndpoint) !void {
        const runtime = self.quicSession(id) orelse return error.EndpointNotFound;
        if (!quicSocketAttachmentSupported(endpoint.pattern)) return error.UnsupportedTransport;

        for (self.quic_socket_attachments.items) |attachment| {
            if (attachment.session_id == id and attachment.endpoint.context == endpoint.context) return;
        }

        try self.quic_socket_attachments.append(self.allocator, .{
            .session_id = id,
            .endpoint = endpoint,
        });
        var appended = true;
        errdefer if (appended) {
            _ = self.quic_socket_attachments.pop();
        };

        try endpoint.attach(endpoint.context, runtime.socketDriver());
        appended = false;
    }

    pub fn closeQuicSession(self: *Node, id: QuicSessionId) !void {
        for (self.quic_clients.items, 0..) |client, index| {
            if (client.id() != id) continue;
            _ = self.quic_clients.orderedRemove(index);
            client.deinit();
            self.allocator.destroy(client);
            break;
        }

        for (self.quic_sessions.items, 0..) |runtime, index| {
            if (runtime.id() != id) continue;

            // Driver-owned (listener-side) sessions are destroyed by
            // the will-close teardown when their connection reaps;
            // freeing them here would leave the Driver's ConnState
            // dangling and double-free on disconnect.
            if (runtime.driver_owned) return error.InvalidState;

            runtime.runtime.session.close();
            try self.emit(.{ .closed = id });
            _ = self.quic_sessions.orderedRemove(index);
            self.removeSocketSessionRefs(id);
            runtime.deinit();
            self.allocator.destroy(runtime);
            return;
        }
        return error.EndpointNotFound;
    }

    pub fn listenInprocRep(
        self: *Node,
        network: *transport.inproc.Network,
        address: []const u8,
        options: InprocRepOptions,
    ) !InprocRepId {
        if (self.inproc_rep_endpoints.items.len >= self.options.max_sessions) return error.TooManySessions;

        const owned_address = try self.allocator.dupe(u8, address);
        var owns_address = true;
        errdefer if (owns_address) self.allocator.free(owned_address);

        const id = self.inproc_rep_endpoints.items.len;
        const sess = options.session orelse self.nextInprocSession();
        const endpoint = try self.allocator.create(InprocRepEndpoint);
        var owns_endpoint = true;
        errdefer if (owns_endpoint) self.allocator.destroy(endpoint);

        endpoint.* = .{
            .id = id,
            .network = network,
            .address = owned_address,
            .socket = try socket.Socket(.rep).init(self.allocator, options.socket),
            .session = sess,
        };
        owns_address = false;
        errdefer if (owns_endpoint) endpoint.deinit(self.allocator);

        try endpoint.socket.listenInproc(network, address);
        try self.inproc_rep_endpoints.append(self.allocator, endpoint);
        owns_endpoint = false;

        var appended = true;
        errdefer if (appended) {
            const removed = self.inproc_rep_endpoints.orderedRemove(id);
            removed.deinit(self.allocator);
            self.allocator.destroy(removed);
        };

        try self.emit(.{ .connected = sess.id });
        appended = false;
        return id;
    }

    pub fn runOnce(self: *Node, dispatcher: anytype) !RunOnceResult {
        if (comptime dispatcherHas(@TypeOf(dispatcher), "dispatchInprocRep")) {
            for (self.inproc_rep_endpoints.items) |endpoint| {
                if (try dispatcher.dispatchInprocRep(endpoint)) {
                    return .{
                        .messages = 1,
                        .events_pending = self.eventCount(),
                    };
                }
            }
        }

        for (self.quic_sessions.items) |runtime| {
            const attachment = self.quicSocketAttachment(runtime.id());
            const can_dispatch_reliable = comptime dispatcherHas(@TypeOf(dispatcher), "dispatchQuicReliable");
            if (attachment == null and !can_dispatch_reliable) continue;

            var received = runtime.runtime.recvReliable() orelse continue;
            const stream_id = received.stream_id;
            var incoming = received.takeMessage();

            if (attachment) |endpoint| {
                endpoint.receive(endpoint.context, incoming) catch |err| {
                    incoming.deinit();
                    return err;
                };
                return .{
                    .messages = 1,
                    .events_pending = self.eventCount(),
                };
            }

            if (comptime dispatcherHas(@TypeOf(dispatcher), "dispatchQuicReliable")) {
                var result = try dispatcher.dispatchQuicReliable(.rep, incoming, runtime.appSession());
                defer result.deinit();

                for (result.replies.items) |reply| {
                    try runtime.replyReliableOnStream(stream_id, reply.outgoing());
                }

                for (result.publications.items) |publication| {
                    try runtime.queueDatagram(publication.outgoing());
                }

                return .{
                    .messages = 1,
                    .events_pending = self.eventCount(),
                };
            } else {
                incoming.deinit();
                return error.InvalidState;
            }
        }

        for (self.quic_sessions.items) |runtime| {
            const attachment = self.quicSocketAttachment(runtime.id());
            const can_dispatch_datagram = comptime dispatcherHas(@TypeOf(dispatcher), "dispatchQuicDatagram");
            if (attachment == null and !can_dispatch_datagram) continue;

            var received = runtime.recvDatagram() orelse continue;
            var incoming = received.takeMessage();

            if (attachment) |endpoint| {
                endpoint.receive(endpoint.context, incoming) catch |err| {
                    incoming.deinit();
                    return err;
                };
                return .{
                    .messages = 1,
                    .events_pending = self.eventCount(),
                };
            }

            if (comptime dispatcherHas(@TypeOf(dispatcher), "dispatchQuicDatagram")) {
                var result = try dispatcher.dispatchQuicDatagram(incoming, runtime.appSession());
                defer result.deinit();

                for (result.publications.items) |publication| {
                    try runtime.queueDatagram(publication.outgoing());
                }

                return .{
                    .messages = 1,
                    .events_pending = self.eventCount(),
                };
            } else {
                incoming.deinit();
                return error.InvalidState;
            }
        }

        return .{ .events_pending = self.eventCount() };
    }

    pub fn poll(self: *Node, out: []Event) !usize {
        const count = @min(out.len, self.events.items.len);
        for (out[0..count], 0..) |*slot, index| {
            slot.* = self.events.items[index];
        }
        for (0..count) |_| {
            _ = self.events.orderedRemove(0);
        }
        return count;
    }

    pub fn nextTimer(self: *const Node) ?u64 {
        var best: ?u64 = null;
        for (self.quic_listeners.items) |listener| {
            if (listener.listener.nextTimer(self.now_us)) |timer| {
                bestTimer(&best, timer.deadline.at_us);
            }
        }
        for (self.quic_clients.items) |client| {
            if (client.client.nextTimer(self.now_us)) |timer| {
                bestTimer(&best, timer.deadline.at_us);
            }
        }
        return best;
    }

    pub fn emit(self: *Node, event: Event) !void {
        try self.events.append(self.allocator, event);
    }

    pub fn eventCount(self: *const Node) usize {
        return self.events.items.len;
    }

    // ---- ServerDispatch owner contract (quic.app.Driver hooks) ----

    pub const DriverSession = *QuicSessionRuntime;

    pub fn driverSessionRuntime(sess: DriverSession) *transport.quic_session_runtime.QuicSessionRuntime {
        return &sess.runtime;
    }

    pub fn driverServerSessionCreate(
        self: *Node,
        options: transport.quic.QuicOptions,
    ) !DriverSession {
        const runtime = try self.createQuicSession(.server, options, null);
        errdefer self.destroyQuicSession(runtime);
        runtime.driver_owned = true;
        runtime.transport_ready = true;
        try runtime.runtime.onQuicReady();
        return runtime;
    }

    pub fn driverServerSessionDestroy(self: *Node, sess: DriverSession) void {
        self.destroyQuicSession(sess);
    }

    pub fn driverSessionPass(
        self: *Node,
        sess: DriverSession,
        conn: *transport.quic_runtime.Connection,
    ) !void {
        _ = self;
        _ = try sess.pumpDatagramOutbox(conn);
    }

    pub fn driverDatagramReceived(
        self: *Node,
        sess: DriverSession,
        received: transport.quic_datagram.ReceivedDatagram,
    ) !void {
        var owned = received;
        errdefer owned.deinit();
        try sess.datagram_inbox.append(self.allocator, owned);
    }

    pub fn driverDatagramDropped(self: *Node, sess: DriverSession, bytes: usize) !void {
        try self.emit(.{ .message_dropped = .{
            .session_id = sess.id(),
            .bytes = bytes,
        } });
    }

    fn tickQuicListeners(self: *Node, now_us: u64) !void {
        for (self.quic_listeners.items) |listener| {
            _ = try listener.listener.recvAndFeedOne(now_us);
            // Service BEFORE tick: quic-zig's ordering contract — the
            // stream GC inside tick must never reap a stream whose
            // arrived bytes the app has not read yet.
            try listener.dispatch.service(&listener.listener.runtime.server);
            while (try listener.listener.drainAndSendOne(now_us)) |_| {}
            try listener.listener.tick(now_us);
            _ = listener.listener.runtime.reap();
        }
    }

    fn tickQuicClients(self: *Node, now_us: u64) !void {
        for (self.quic_clients.items) |client| {
            _ = try client.client.recvAndFeedOne(now_us);
            try client.client.tick(now_us);
            try self.ensureClientReady(client);
            try self.pumpClientSession(client);
            while (try client.client.drainAndSendOne(now_us)) |_| {}
        }
    }

    fn ensureClientReady(_: *Node, client: *QuicClientRuntime) !void {
        if (client.runtime.transport_ready) return;
        if (!client.client.runtime.connection().handshakeDone()) return;
        client.runtime.transport_ready = true;
        try client.runtime.runtime.onQuicReady();
    }

    fn pumpClientSession(self: *Node, client: *QuicClientRuntime) !void {
        if (!client.runtime.transport_ready) return;
        const conn = client.client.runtime.connection();
        try self.pumpQuicSessionConnection(client.runtime, conn);
    }

    fn pumpQuicSessionConnection(
        self: *Node,
        runtime: *QuicSessionRuntime,
        conn: *transport.quic_runtime.Connection,
    ) !void {
        if (runtime.runtime.state() == .ready) {
            _ = try runtime.runtime.acceptPeerBidiStreamsConnection(conn);
        }
        _ = try runtime.runtime.pumpConnection(conn);
        if (runtime.runtime.state() == .ready) {
            _ = try runtime.runtime.acceptPeerBidiStreamsConnection(conn);
            _ = try runtime.runtime.pumpConnection(conn);
            try self.receiveDatagrams(runtime, conn);
            _ = try runtime.pumpDatagramOutbox(conn);
        }
    }

    fn receiveDatagrams(
        self: *Node,
        runtime: *QuicSessionRuntime,
        conn: *transport.quic_runtime.Connection,
    ) !void {
        if (!runtime.runtime.appSession().datagram_enabled) return;

        while (true) {
            var received = transport.quic_datagram.receiveDatagram(conn, self.allocator, .{
                .codec = datagramCodecOptions(runtime.runtime.session.options),
            }) catch |err| switch (err) {
                error.MalformedFrame => {
                    try self.emit(.{ .message_dropped = .{
                        .session_id = runtime.id(),
                        .bytes = 0,
                    } });
                    continue;
                },
                error.MessageTooLarge => {
                    try self.emit(.{ .message_dropped = .{
                        .session_id = runtime.id(),
                        .bytes = datagramCodecOptions(runtime.runtime.session.options).max_payload_size +| 1,
                    } });
                    continue;
                },
                else => return err,
            } orelse return;
            errdefer received.deinit();
            try runtime.datagram_inbox.append(self.allocator, received);
        }
    }

    fn createQuicSession(
        self: *Node,
        role: transport.quic.Role,
        options: transport.quic.QuicOptions,
        user_data: ?*anyopaque,
    ) !*QuicSessionRuntime {
        if (self.quic_sessions.items.len >= self.options.max_sessions) return error.TooManySessions;

        const runtime = try self.allocator.create(QuicSessionRuntime);
        var owns_runtime = true;
        errdefer if (owns_runtime) self.allocator.destroy(runtime);

        runtime.* = .{
            .runtime = try transport.quic_session_runtime.QuicSessionRuntime.init(
                self.allocator,
                self.nextSessionId(),
                role,
                options,
            ),
        };
        errdefer if (owns_runtime) runtime.deinit();
        runtime.runtime.appSession().user_data = user_data;

        try self.quic_sessions.append(self.allocator, runtime);
        owns_runtime = false;
        try self.emit(.{ .connected = runtime.id() });
        return runtime;
    }

    fn destroyQuicSession(self: *Node, runtime: *QuicSessionRuntime) void {
        self.emit(.{ .closed = runtime.id() }) catch {};
        for (self.quic_sessions.items, 0..) |candidate, index| {
            if (candidate != runtime) continue;
            _ = self.quic_sessions.orderedRemove(index);
            break;
        }
        self.removeSocketSessionRefs(runtime.id());
        runtime.deinit();
        self.allocator.destroy(runtime);
    }

    fn removeSocketSessionRefs(self: *Node, id: QuicSessionId) void {
        var index: usize = 0;
        while (index < self.quic_socket_attachments.items.len) {
            if (self.quic_socket_attachments.items[index].session_id == id) {
                _ = self.quic_socket_attachments.orderedRemove(index);
            } else {
                index += 1;
            }
        }
    }

    fn quicSocketAttachment(self: *Node, id: QuicSessionId) ?socket.QuicSocketEndpoint {
        for (self.quic_socket_attachments.items) |attachment| {
            if (attachment.session_id == id) return attachment.endpoint;
        }
        return null;
    }

    fn nextInprocSession(self: *Node) session.Session {
        return .{
            .id = self.nextSessionId(),
            .transport = .inproc,
        };
    }

    fn nextSessionId(self: *Node) session.SessionId {
        const id = self.next_session_id;
        self.next_session_id +%= 1;
        if (self.next_session_id == 0) self.next_session_id = 1;
        return id;
    }
};

fn sendSocketMessage(context: *anyopaque, msg: message.Message, meta: socket.QuicSendMeta) anyerror!void {
    var owned = msg;
    defer owned.deinit();

    const runtime: *QuicSessionRuntime = @ptrCast(@alignCast(context));
    switch (meta.delivery) {
        .reliable => _ = try runtime.queueReliable(owned.outgoing()),
        .unreliable => try runtime.queueDatagram(owned.outgoing()),
    }
}

fn datagramCodecOptions(options: transport.quic.QuicOptions) transport.quic_datagram.CodecOptions {
    const default_datagram_codec = transport.quic_datagram.CodecOptions{};
    const negotiated_max = if (options.max_datagram_frame_size == 0)
        default_datagram_codec.max_payload_size
    else
        std.math.cast(usize, options.max_datagram_frame_size) orelse std.math.maxInt(usize);

    return .{
        .max_payload_size = @min(options.max_message_size, negotiated_max),
        .max_headers = options.max_header_count,
        .max_header_bytes = options.max_header_bytes,
    };
}

fn quicSocketAttachmentSupported(pattern: socket.Pattern) bool {
    return switch (pattern) {
        .pair, .req, .rep => true,
        .@"pub", .sub, .push, .pull => false,
    };
}

fn dispatcherHas(comptime Dispatcher: type, comptime name: []const u8) bool {
    const T = switch (@typeInfo(Dispatcher)) {
        .pointer => |ptr| ptr.child,
        else => Dispatcher,
    };
    return @hasDecl(T, name);
}

fn bestTimer(best: *?u64, candidate: u64) void {
    if (best.* == null or candidate < best.*.?) best.* = candidate;
}

fn readyQuicRuntimeForTest(
    runtime: *QuicSessionRuntime,
    peer_id: []const u8,
    datagram_enabled: bool,
) !void {
    try runtime.runtime.onQuicReady();

    const allocator = runtime.runtime.allocator;
    const peer_hello = try transport.quic.encodeHelloControlStream(allocator, .{
        .peer_id = peer_id,
        .datagram_enabled = datagram_enabled,
    });
    defer allocator.free(peer_hello);

    try runtime.runtime.session.acceptPeerControl(peer_hello);
}

fn queueReliableForTest(
    runtime: *QuicSessionRuntime,
    stream_id: u64,
    outgoing: message.OutgoingMessage,
) !void {
    const allocator = runtime.runtime.allocator;
    var incoming = try message.Message.init(allocator, outgoing);
    var owns_incoming = true;
    errdefer if (owns_incoming) incoming.deinit();

    try runtime.runtime.inbox.append(allocator, .{
        .stream_id = stream_id,
        .message = incoming,
    });
    owns_incoming = false;
}

test {
    std.testing.refAllDecls(@This());
}

test "Node queues and polls events in FIFO order" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    try n.emit(.{ .connected = 1 });
    try n.emit(.{ .message_dropped = .{ .session_id = 1, .bytes = 32 } });
    try n.emit(.{ .closed = 1 });

    try std.testing.expectEqual(@as(usize, 3), n.eventCount());

    var first: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&first));
    try std.testing.expectEqual(@as(session.SessionId, 1), first[0].connected);
    try std.testing.expectEqual(@as(usize, 2), n.eventCount());

    var rest: [4]Event = undefined;
    try std.testing.expectEqual(@as(usize, 2), try n.poll(&rest));
    try std.testing.expectEqual(@as(?session.SessionId, 1), rest[0].message_dropped.session_id);
    try std.testing.expectEqual(@as(usize, 32), rest[0].message_dropped.bytes);
    try std.testing.expectEqual(@as(session.SessionId, 1), rest[1].closed);
    try std.testing.expectEqual(@as(usize, 0), n.eventCount());
}

test "Node tick records current time and validates QUIC listener config" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    try n.tick(99);
    try std.testing.expectEqual(@as(u64, 99), n.now_us);
    try std.testing.expect(n.nextTimer() == null);
    try std.testing.expectError(error.InvalidEndpoint, n.listenQuic("127.0.0.1:0", .{}));
    try std.testing.expectError(error.UnsupportedTransport, n.dial(.inproc, .{ .quic = "127.0.0.1:4433" }));
}

test "Node prepares QUIC session lifecycle without opening UDP" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const runtime = try n.openQuicSession(.{
        .role = .server,
        .transport = .{
            .peer_id = "server-a",
            .datagram_enabled = true,
            .max_message_size = 4096,
        },
    });
    const id = runtime.id();
    try std.testing.expectEqual(@as(session.SessionId, 1), id);
    try std.testing.expectEqual(session.TransportKind.quic, runtime.appSession().transport);
    try std.testing.expect(runtime.appSession().datagram_enabled);
    try std.testing.expectEqual(@as(usize, 4096), runtime.appSession().max_message_size);

    var first: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&first));
    try std.testing.expectEqual(id, first[0].connected);

    try n.closeQuicSession(id);
    try std.testing.expect(n.quicSession(id) == null);

    var rest: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&rest));
    try std.testing.expectEqual(id, rest[0].closed);
}

test "Node attaches QUIC socket endpoint and queues outbound socket messages" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const runtime = try n.openQuicSession(.{
        .role = .client,
        .transport = .{ .peer_id = "client-a" },
    });
    try readyQuicRuntimeForTest(runtime, "server-a", false);

    var pair_socket = try socket.Socket(.pair).init(allocator, .{});
    defer pair_socket.deinit();
    try n.attachQuicSocket(runtime.id(), pair_socket.quicEndpoint());

    try pair_socket.send(.{
        .subject = "control.ping",
        .body = "hello",
    });

    try std.testing.expectEqual(@as(usize, 1), runtime.runtime.pendingReliableSenders());
}

test "Node runOnce delivers queued QUIC reliable message to attached socket" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const runtime = try n.openQuicSession(.{
        .role = .server,
        .transport = .{ .peer_id = "server-a" },
    });
    try readyQuicRuntimeForTest(runtime, "client-a", false);

    var pair_socket = try socket.Socket(.pair).init(allocator, .{});
    defer pair_socket.deinit();
    try n.attachQuicSocket(runtime.id(), pair_socket.quicEndpoint());

    try queueReliableForTest(runtime, 0, .{
        .subject = "control.ping",
        .body = "hello",
    });

    const Dispatcher = struct {};
    var dispatcher = Dispatcher{};
    const result = try n.runOnce(&dispatcher);
    try std.testing.expect(result.didWork());

    var received = try pair_socket.recv();
    defer received.deinit();
    try std.testing.expectEqualStrings("control.ping", received.subject);
    try std.testing.expectEqualStrings("hello", received.body);
}

test "Node runOnce dispatches queued QUIC datagram and queues publication datagram" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const runtime = try n.openQuicSession(.{
        .role = .server,
        .transport = .{
            .peer_id = "server-a",
            .datagram_enabled = true,
        },
    });
    try readyQuicRuntimeForTest(runtime, "client-a", true);

    const incoming = try message.Message.init(allocator, .{
        .subject = "presence.ada",
        .flags = .{ .unreliable = true },
        .body = "online",
    });
    try runtime.datagram_inbox.append(allocator, .{ .message = incoming });

    const Dispatcher = struct {
        calls: usize = 0,

        const Result = struct {
            allocator: std.mem.Allocator,
            replies: std.ArrayList(message.Message) = .empty,
            publications: std.ArrayList(message.Message) = .empty,

            fn init(alloc: std.mem.Allocator) Result {
                return .{ .allocator = alloc };
            }

            fn deinit(self: *Result) void {
                for (self.replies.items) |*msg| msg.deinit();
                self.replies.deinit(self.allocator);
                for (self.publications.items) |*msg| msg.deinit();
                self.publications.deinit(self.allocator);
            }
        };

        fn dispatchQuicDatagram(self: *@This(), msg: message.Message, sess: *session.Session) !Result {
            var owned = msg;
            defer owned.deinit();

            try std.testing.expectEqual(session.TransportKind.quic, sess.transport);
            try std.testing.expectEqualStrings("presence.ada", owned.subject);
            self.calls += 1;

            var result = Result.init(owned.allocator);
            errdefer result.deinit();
            const publication = try message.Message.init(owned.allocator, .{
                .subject = "presence.seen",
                .flags = .{ .unreliable = true },
                .body = owned.body,
            });
            errdefer {
                var cleanup = publication;
                cleanup.deinit();
            }
            try result.publications.append(owned.allocator, publication);
            return result;
        }
    };

    var dispatcher = Dispatcher{};
    const result = try n.runOnce(&dispatcher);
    try std.testing.expect(result.didWork());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.calls);
    try std.testing.expectEqual(@as(usize, 1), runtime.pendingDatagrams());
}

test "Node runOnce dispatches one inproc rep request through dispatcher" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    _ = try n.listenInprocRep(&network, "users", .{});

    var req = try socket.Socket(.req).init(allocator, .{});
    defer req.deinit();
    try req.dialInproc(&network, "users");

    _ = try req.sendRequest(.{ .subject = "user.get", .body = "42" });

    const Dispatcher = struct {
        fn dispatchInprocRep(_: *@This(), endpoint: *InprocRepEndpoint) !bool {
            var request = (try endpoint.socket.tryRecv()) orelse return false;
            defer request.deinit();

            try endpoint.socket.reply(request, .{
                .subject = "",
                .body = request.message.body,
            });
            return true;
        }
    };

    var dispatcher = Dispatcher{};
    const result = try n.runOnce(&dispatcher);
    try std.testing.expect(result.didWork());

    var reply = try req.recv();
    defer reply.deinit();
    try std.testing.expectEqualStrings("user.get", reply.subject);
    try std.testing.expectEqualStrings("42", reply.body);
}

// ---- ServerDispatch end-to-end (hermetic: no sockets) ----------------------

const dispatch_test_cert_pem = @embedFile("testdata/test_cert.pem");
const dispatch_test_key_pem = @embedFile("testdata/test_key.pem");

const DispatchTestPeers = struct {
    listener: transport.quic_runtime.ListenerRuntime,
    dispatch: NodeServerDispatch,
    client: transport.quic_runtime.ClientRuntime,
    rx: [8192]u8 = undefined,
    now_us: u64 = 1_000,

    fn drive(self: *DispatchTestPeers) !void {
        const from: transport.quic_runtime.Address = .{ .ipv4 = .{
            .addr = .{ 0x7f, 0, 0, 1 },
            .port = 40_000,
        } };
        while (try self.client.drainOutbound(&self.rx, self.now_us)) |out| {
            _ = try self.listener.feedInbound(.{
                .bytes = self.rx[0..out.len],
                .from = from,
            }, self.now_us);
        }
        try self.dispatch.service(&self.listener.server);
        while (try self.listener.drainOutbound(&self.rx, self.now_us)) |out| {
            try self.client.feedInbound(.{ .bytes = self.rx[0..out.len] }, self.now_us);
        }
        try self.listener.tick(self.now_us);
        try self.client.tick(self.now_us);
        self.now_us += 1_000;
    }
};

test "listener dispatch drives qmsg sessions through quic.app.Driver end to end" {
    const allocator = std.testing.allocator;
    const control = @import("control.zig");

    const server_opts: transport.quic.QuicOptions = .{
        .peer_id = "dispatch-server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };
    const client_opts: transport.quic.QuicOptions = .{
        .peer_id = "dispatch-client",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };

    var node = try Node.init(allocator, .{});
    defer node.deinit();

    var p: DispatchTestPeers = undefined;
    p.now_us = 1_000;
    p.listener = try transport.quic_runtime.ListenerRuntime.init(allocator, "127.0.0.1:4433", .{
        .tls_cert_pem = dispatch_test_cert_pem,
        .tls_key_pem = dispatch_test_key_pem,
        .transport = server_opts,
    });
    defer p.listener.deinit();
    try p.dispatch.init(allocator, &node, server_opts);
    defer p.dispatch.deinit();
    p.dispatch.attach(&p.listener.server);
    p.client = try transport.quic_runtime.ClientRuntime.init(allocator, "127.0.0.1:4433", .{
        .server_name = "localhost",
        .insecure_skip_verify = true, // self-signed test fixture
        .transport = client_opts,
    });
    defer p.client.deinit();

    // Client-side qmsg session: manual (the Driver dispatch is
    // server-side only); registered on the node so deinit owns it.
    const client_sess = try node.openQuicSession(.{
        .role = .client,
        .transport = client_opts,
    });

    // Handshake: the dispatch must create the server session on its
    // own (on_handshake) — nothing else in this test does.
    var step: u32 = 0;
    while (step < 4_000) : (step += 1) {
        try p.drive();
        if (p.client.connection().handshakeDone() and
            p.listener.connectionCount() > 0 and
            p.listener.connection(0).?.handshakeDone()) break;
    }
    try std.testing.expect(p.client.connection().handshakeDone());

    client_sess.transport_ready = true;
    try client_sess.runtime.onQuicReady();

    // HELLO exchange: client pumps manually; the server side is pumped
    // entirely by dispatch.service inside drive().
    var server_sess: ?*QuicSessionRuntime = null;
    step = 0;
    while (step < 4_000) : (step += 1) {
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        try p.drive();
        if (server_sess == null) {
            for (node.quic_sessions.items) |candidate| {
                if (candidate != client_sess) server_sess = candidate;
            }
        }
        const server_ready = if (server_sess) |sess| sess.state() == .ready else false;
        if (client_sess.state() == .ready and server_ready) break;
    }
    try std.testing.expectEqual(transport.quic.State.ready, client_sess.state());
    const srv_sess = server_sess orelse return error.ServerSessionMissing;
    try std.testing.expectEqual(transport.quic.State.ready, srv_sess.state());
    try std.testing.expect(srv_sess.driver_owned);
    try std.testing.expectEqualStrings("dispatch-client", srv_sess.runtime.peerId());

    // Request: client -> server through the dispatch-accepted stream.
    const stream_id = try client_sess.queueReliable(.{
        .subject = "user.get",
        .id = 4242,
        .deadline_ms = 1_000,
        .body = "ada",
    });
    step = 0;
    while (step < 4_000 and srv_sess.runtime.inboxLen() == 0) : (step += 1) {
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        try p.drive();
    }
    var request = srv_sess.runtime.recvReliable() orelse return error.RequestMissing;
    defer request.deinit();
    try std.testing.expectEqual(@as(u64, stream_id), request.stream_id);
    try std.testing.expectEqualStrings("user.get", request.message.subject);
    try std.testing.expectEqualStrings("ada", request.message.body);

    // Reply: server -> client on the same stream; the send side rides
    // dispatch.service's session pump.
    try srv_sess.replyReliableOnStream(stream_id, .{
        .subject = request.message.subject,
        .id = request.message.id,
        .flags = .{ .final = true },
        .body = "Ada Lovelace",
    });
    // Reply receiver on the client's own request stream: request/
    // reply correlation is app-driven on the dial side (the server
    // side is what the dispatch automates).
    try client_sess.runtime.acceptReliableStream(stream_id);
    var reply: ?transport.quic_session_runtime.ReceivedReliable = null;
    step = 0;
    while (step < 4_000 and reply == null) : (step += 1) {
        try p.drive();
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        reply = client_sess.runtime.recvReliable();
    }
    var got = reply orelse return error.ReplyMissing;
    defer got.deinit();
    try std.testing.expectEqualStrings("Ada Lovelace", got.message.body);

    // Driver-owned sessions refuse the manual close path (their
    // lifecycle belongs to the will-close teardown).
    const srv_sess_id = srv_sess.id();
    try std.testing.expectError(error.InvalidState, node.closeQuicSession(srv_sess_id));

    // Teardown: close the client connection; the reap-driven
    // will-close hook must destroy the server session exactly once.
    p.client.connection().close(false, 0, "done");
    step = 0;
    while (step < 400 and p.listener.connectionCount() > 0) : (step += 1) {
        try p.drive();
        p.now_us += 10_000;
        try p.listener.tick(p.now_us);
        _ = p.listener.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), p.listener.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), node.quic_sessions.items.len);
    try std.testing.expect(node.quic_sessions.items[0] == client_sess);

    var saw_connected_server = false;
    var saw_closed_server = false;
    for (node.events.items) |event| switch (event) {
        .connected => |id| {
            if (id == srv_sess_id) saw_connected_server = true;
        },
        .closed => |id| {
            if (id == srv_sess_id) saw_closed_server = true;
        },
        else => {},
    };
    try std.testing.expect(saw_connected_server);
    try std.testing.expect(saw_closed_server);
}
