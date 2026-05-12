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
    sessions: std.ArrayList(ListenerConnection) = .empty,

    pub fn localAddress(self: QuicListenerRuntime) std.Io.net.IpAddress {
        return self.listener.localAddress();
    }

    fn deinit(self: *QuicListenerRuntime, allocator: std.mem.Allocator) void {
        self.sessions.deinit(allocator);
        self.listener.deinit();
        self.* = undefined;
    }
};

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

pub const ListenerConnection = struct {
    connection_index: usize,
    runtime: *QuicSessionRuntime,
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
        };
        errdefer if (owns_runtime) runtime.deinit(self.allocator);

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

            runtime.runtime.session.close();
            try self.emit(.{ .closed = id });
            _ = self.quic_sessions.orderedRemove(index);
            self.removeListenerSessionRefs(runtime);
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

    fn tickQuicListeners(self: *Node, now_us: u64) !void {
        for (self.quic_listeners.items) |listener| {
            _ = try listener.listener.recvAndFeedOne(now_us);
            try listener.listener.tick(now_us);
            try self.ensureListenerSessions(listener);
            try self.pumpListenerSessions(listener);
            while (try listener.listener.drainAndSendOne(now_us)) |_| {}
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

    fn ensureListenerSessions(self: *Node, listener: *QuicListenerRuntime) !void {
        const count = listener.listener.runtime.connectionCount();
        var index: usize = 0;
        while (index < count) : (index += 1) {
            const conn = listener.listener.runtime.connection(index) orelse continue;
            if (!conn.handshakeDone()) continue;
            if (listenerSession(listener, index) != null) continue;

            const runtime = try self.createQuicSession(.server, listener.transport_options, null);
            errdefer self.destroyQuicSession(runtime);
            runtime.transport_ready = true;
            try runtime.runtime.onQuicReady();
            try listener.sessions.append(self.allocator, .{
                .connection_index = index,
                .runtime = runtime,
            });
        }
    }

    fn ensureClientReady(_: *Node, client: *QuicClientRuntime) !void {
        if (client.runtime.transport_ready) return;
        if (!client.client.runtime.connection().handshakeDone()) return;
        client.runtime.transport_ready = true;
        try client.runtime.runtime.onQuicReady();
    }

    fn pumpListenerSessions(self: *Node, listener: *QuicListenerRuntime) !void {
        for (listener.sessions.items) |entry| {
            const conn = listener.listener.runtime.connection(entry.connection_index) orelse continue;
            try self.pumpQuicSessionConnection(entry.runtime, conn);
        }
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
        for (self.quic_sessions.items, 0..) |candidate, index| {
            if (candidate != runtime) continue;
            _ = self.quic_sessions.orderedRemove(index);
            break;
        }
        self.removeListenerSessionRefs(runtime);
        self.removeSocketSessionRefs(runtime.id());
        runtime.deinit();
        self.allocator.destroy(runtime);
    }

    fn removeListenerSessionRefs(self: *Node, runtime: *QuicSessionRuntime) void {
        for (self.quic_listeners.items) |listener| {
            var index: usize = 0;
            while (index < listener.sessions.items.len) {
                if (listener.sessions.items[index].runtime == runtime) {
                    _ = listener.sessions.orderedRemove(index);
                } else {
                    index += 1;
                }
            }
        }
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

fn listenerSession(listener: *QuicListenerRuntime, connection_index: usize) ?*QuicSessionRuntime {
    for (listener.sessions.items) |entry| {
        if (entry.connection_index == connection_index) return entry.runtime;
    }
    return null;
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
