const std = @import("std");
const message = @import("message.zig");
const queue = @import("queue.zig");
const socket = @import("socket.zig");
const session = @import("session.zig");
const transport = @import("transport/root.zig");

pub const NodeOptions = struct {
    max_sessions: usize = 1024,
    /// Bound on queued `Event`s. When the embedder stops draining,
    /// new events are dropped and counted (`Stats.events_dropped`)
    /// instead of growing without limit. Message-carrying events
    /// dropped here also free their payloads and count in
    /// `Stats.dropped`.
    max_events: usize = 1024,
    /// Options for the node-owned subscription socket created by the
    /// first `dialInprocSub`/`subscribeInproc` call. Its receive-queue
    /// policy is the slow-consumer policy for embedded deliveries.
    inproc_sub: socket.SocketOptions(.sub) = .{},
    io: std.Io = std.Io.Threaded.global_single_threaded.io(),
};

/// Why an embedded request will never receive a reply event.
///
/// The tag names are the stable script/metrics vocabulary. Sync-side
/// send failures (`requestInproc`/`replyInproc` errors) classify
/// through `classifyRequestError` into the same names, so an
/// embedder renders one error space from both paths.
pub const RequestFailure = enum {
    deadline_exceeded,
    canceled,
    queue_full,
    peer_closed,
    no_route,
};

/// Maps synchronous send-path errors onto `RequestFailure` names, so
/// embedders can surface `error.QueueFull` from `requestInproc` and
/// a `request_failed` event through one vocabulary. Returns null for
/// errors that are not request-outcome classifications.
pub fn classifyRequestError(err: anyerror) ?RequestFailure {
    return switch (err) {
        error.QueueFull, error.FlowControlled => .queue_full,
        error.EndpointClosed => .peer_closed,
        error.NoPeer, error.EndpointNotFound => .no_route,
        else => null,
    };
}

/// A message qmsg received but could not deliver: queue-policy
/// drops, malformed/oversized datagrams, and late replies whose
/// request was already canceled or expired.
pub const MessageDropped = struct {
    session_id: ?session.SessionId = null,
    bytes: usize,
};

/// An incoming request on a node-served inproc endpoint.
///
/// `msg` is owned by the event. Reply through `Node.replyInproc`
/// (or `replyErrorInproc`) while the event is alive, then `deinit`.
pub const RequestEvent = struct {
    endpoint_id: InprocRepId,
    session_id: session.SessionId,
    /// `msg.id` is the reply correlation id; `msg.deadline_ms` the
    /// request deadline.
    msg: message.Message,

    pub fn deinit(self: *RequestEvent) void {
        self.msg.deinit();
        self.* = undefined;
    }
};

/// A peer reply completing one of the node's outbound requests.
///
/// `msg` is owned by the event. `msg.id` is the correlation id the
/// request was sent under. Peer error replies carry `flags.err` and
/// the `qmsg-error-code` / `qmsg-error-message` headers.
pub const ReplyEvent = struct {
    dial_id: InprocDialId,
    msg: message.Message,

    pub fn deinit(self: *ReplyEvent) void {
        self.msg.deinit();
        self.* = undefined;
    }
};

/// Terminal outcome for one of the node's outbound requests: no
/// reply event will follow this id.
pub const RequestFailedEvent = struct {
    dial_id: InprocDialId,
    id: message.MessageId,
    failure: RequestFailure,
};

/// A pub/sub delivery matching one of the node's subscriptions.
///
/// `msg` is owned by the event. `filter` is the subscription that
/// claimed the subject (first match in subscription order) and is
/// borrowed from the node's filter storage — valid until that filter
/// is unsubscribed or the node deinits. Copy it if retention is
/// needed.
pub const DeliveryEvent = struct {
    filter: []const u8,
    msg: message.Message,

    pub fn deinit(self: *DeliveryEvent) void {
        self.msg.deinit();
        self.* = undefined;
    }
};

pub const Event = union(enum) {
    connected: session.SessionId,
    closed: session.SessionId,
    message_dropped: MessageDropped,
    request: RequestEvent,
    reply: ReplyEvent,
    request_failed: RequestFailedEvent,
    delivery: DeliveryEvent,

    /// Releases memory the event owns. Every event pulled out of
    /// `Node.poll` must be deinited by the embedder after handling.
    pub fn deinit(self: *Event) void {
        switch (self.*) {
            .request => |*ev| ev.deinit(),
            .reply => |*ev| ev.deinit(),
            .delivery => |*ev| ev.deinit(),
            .connected, .closed, .message_dropped, .request_failed => {},
        }
    }
};

/// Plain, allocation-free observability snapshot for embedder
/// metrics: no metrics dependency, just readable fields.
///
/// `dropped` counts messages received but not delivered (queue
/// policy drops on node-owned queues, late replies whose request
/// already ended, message events dropped by the event-queue bound).
/// `queue_high_water` is the deepest any node-owned receive queue
/// has been.
pub const Stats = struct {
    sent: usize = 0,
    recv: usize = 0,
    dropped: usize = 0,
    queue_high_water: usize = 0,
    events_dropped: usize = 0,

    fn accumulate(self: *Stats, qs: queue.QueueStats) void {
        self.dropped += qs.dropped_oldest + qs.dropped_newest;
        self.queue_high_water = @max(self.queue_high_water, qs.high_water_messages);
    }
};

const Counters = struct {
    sent: usize = 0,
    recv: usize = 0,
    dropped: usize = 0,
    events_dropped: usize = 0,
};

pub const InprocRepId = usize;
pub const QuicListenerId = usize;
pub const QuicSessionId = session.SessionId;
/// Identifies one node-dialed inproc req transport (see
/// `Node.dialInprocReq`).
pub const InprocDialId = usize;
/// Identifies one node-bound inproc pub endpoint (see
/// `Node.listenInprocPub`).
pub const InprocPubId = usize;

pub const InprocRepOptions = struct {
    socket: socket.SocketOptions(.rep) = .{},
    session: ?session.Session = null,
};

pub const InprocDialOptions = struct {
    socket: socket.SocketOptions(.req) = .{},
};

pub const InprocPubOptions = struct {
    socket: socket.SocketOptions(.@"pub") = .{},
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

/// One node-owned inproc req socket, dialed to a serving peer.
/// Outbound requests correlate through the node's pending table; see
/// `Node.requestInproc`.
pub const InprocDial = struct {
    id: InprocDialId,
    address: []u8,
    socket: socket.Socket(.req),

    fn deinit(self: *InprocDial, allocator: std.mem.Allocator) void {
        self.socket.deinit();
        allocator.free(self.address);
        self.* = undefined;
    }
};

/// One node-owned inproc pub endpoint. Publications fan out to every
/// subscriber dialed to the bound address.
pub const InprocPubEndpoint = struct {
    id: InprocPubId,
    network: *transport.inproc.Network,
    address: []u8,
    socket: socket.Socket(.@"pub"),

    fn deinit(self: *InprocPubEndpoint, allocator: std.mem.Allocator) void {
        self.network.unbindPattern(self.address) catch {};
        self.socket.deinit();
        allocator.free(self.address);
        self.* = undefined;
    }
};

/// The node's single subscription socket. Created lazily by the
/// first `dialInprocSub`/`subscribeInproc` call, configured by
/// `NodeOptions.inproc_sub`.
const InprocSubEndpoint = struct {
    socket: socket.Socket(.sub),

    fn deinit(self: *InprocSubEndpoint) void {
        self.socket.deinit();
        self.* = undefined;
    }
};

/// One outbound request awaiting a reply event. Deadlines are
/// evaluated against the node clock (`tick`'s `now_us`).
const PendingInprocRequest = struct {
    dial_id: InprocDialId,
    id: message.MessageId,
    deadline_ms: ?u64,
    sent_at_ms: u64,

    fn isExpired(self: PendingInprocRequest, now_ms: u64) bool {
        const deadline_ms = self.deadline_ms orelse return false;
        return now_ms >= self.sent_at_ms +| deadline_ms;
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

/// Options for one outbound QUIC client session (`Node.dialQuic`).
///
/// `transport.supported_patterns` is ANNOUNCED in the qmsg HELLO and
/// is meaningful on dials: announce the patterns the dial will
/// actually use — a req/rep dial announces `req | rep` (see the
/// examples). A req-only announcement looks plausible but tells the
/// peer this client will not accept replies, which the peer's policy
/// may enforce.
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
        // Listener FIRST: quic-zig's Server.deinit fires the will-close
        // hook per live connection, and that hook's user_data is the
        // dispatch's driver — so the dispatch must still be alive (its
        // session table intact) when the Server runs. The hook then
        // destroys each driver-owned session through the owner.
        self.listener.deinit();
        self.dispatch.deinit();
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
    inproc_dials: std.ArrayList(*InprocDial) = .empty,
    inproc_pubs: std.ArrayList(*InprocPubEndpoint) = .empty,
    inproc_sub: ?*InprocSubEndpoint = null,
    inproc_pending: std.ArrayList(PendingInprocRequest) = .empty,
    counters: Counters = .{},
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
        // Listeners FIRST: a live listener's Server.deinit fires the
        // will-close hook per connection, which destroys each
        // driver-owned session through the proper path (exactly once,
        // events emitted, socket refs dropped). Tearing sessions down
        // before listeners leaves the hook's user_data pointing at
        // freed runtimes — use-after-free on any live session.
        for (self.quic_listeners.items) |runtime| {
            runtime.deinit(self.allocator);
            self.allocator.destroy(runtime);
        }
        self.quic_listeners.deinit(self.allocator);
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
        self.inproc_pending.deinit(self.allocator);
        if (self.inproc_sub) |sub| {
            sub.deinit();
            self.allocator.destroy(sub);
        }
        for (self.inproc_pubs.items) |endpoint| {
            endpoint.deinit(self.allocator);
            self.allocator.destroy(endpoint);
        }
        self.inproc_pubs.deinit(self.allocator);
        for (self.inproc_dials.items) |req_dial| {
            req_dial.deinit(self.allocator);
            self.allocator.destroy(req_dial);
        }
        self.inproc_dials.deinit(self.allocator);
        for (self.inproc_rep_endpoints.items) |endpoint| {
            endpoint.deinit(self.allocator);
            self.allocator.destroy(endpoint);
        }
        self.inproc_rep_endpoints.deinit(self.allocator);
        for (self.events.items) |*event| {
            event.deinit();
        }
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

    // ---- embedded inproc service surface -------------------------
    //
    // The socketless embedding contract: the node owns every socket,
    // the embedder owns the clock and the loop. `tick` advances the
    // clock (and pumps QUIC transports when present); `poll` pumps
    // the inproc service state into the event queue and hands events
    // out. This event-drain path and `runOnce`'s dispatcher path are
    // alternative consumption models for the same endpoints — pick
    // one per endpoint.

    /// Dials one inproc req transport to a serving peer. Requests on
    /// this dial correlate through `requestInproc`/`ReplyEvent`.
    pub fn dialInprocReq(
        self: *Node,
        network: *transport.inproc.Network,
        address: []const u8,
        options: InprocDialOptions,
    ) !InprocDialId {
        if (self.inproc_dials.items.len >= self.options.max_sessions) return error.TooManySessions;

        const owned_address = try self.allocator.dupe(u8, address);
        var owns_address = true;
        errdefer if (owns_address) self.allocator.free(owned_address);

        const id = self.inproc_dials.items.len;
        const req_dial = try self.allocator.create(InprocDial);
        var owns_dial = true;
        errdefer if (owns_dial) self.allocator.destroy(req_dial);

        req_dial.* = .{
            .id = id,
            .address = owned_address,
            .socket = try socket.Socket(.req).init(self.allocator, options.socket),
        };
        owns_address = false;
        errdefer if (owns_dial) req_dial.deinit(self.allocator);

        try req_dial.socket.dialInproc(network, address);
        try self.inproc_dials.append(self.allocator, req_dial);
        owns_dial = false;
        return id;
    }

    pub fn inprocDial(self: *Node, id: InprocDialId) ?*InprocDial {
        if (id >= self.inproc_dials.items.len) return null;
        return self.inproc_dials.items[id];
    }

    /// Sends one request on a dialed inproc transport and records it
    /// for event-side correlation. The correlation id is assigned and
    /// returned; the reply (or terminal failure) arrives later as a
    /// `poll` event keyed by that id.
    ///
    /// Send-path pressure is synchronous and observable:
    /// `error.QueueFull`/`error.FlowControlled` (peer queue full),
    /// `error.EndpointClosed` (peer closed), `error.NoPeer`. Map them
    /// through `classifyRequestError` for the shared failure
    /// vocabulary.
    pub fn requestInproc(
        self: *Node,
        dial_id: InprocDialId,
        outgoing: message.OutgoingMessage,
    ) !message.MessageId {
        const req_dial = self.inprocDial(dial_id) orelse return error.EndpointNotFound;

        // Keep the node's pending table and the socket's inflight
        // state in lockstep before adding a new entry, so a reply for
        // anything already expired classifies as late (dropped), not
        // as an unexpected correlation miss.
        try self.expireInprocPending(self.nowMs());

        const now_ms = self.nowMs();
        const id = try req_dial.socket.sendRequestAt(outgoing, now_ms);
        errdefer _ = req_dial.socket.cancelRequest(id);

        try self.inproc_pending.append(self.allocator, .{
            .dial_id = dial_id,
            .id = id,
            .deadline_ms = outgoing.deadline_ms,
            .sent_at_ms = now_ms,
        });
        self.counters.sent += 1;
        return id;
    }

    /// Cancels a pending outbound request. Emits `request_failed`
    /// with `.canceled` so the correlating consumer learns the
    /// outcome; a reply arriving later is dropped and counted.
    pub fn cancelInprocRequest(self: *Node, dial_id: InprocDialId, id: message.MessageId) !bool {
        for (self.inproc_pending.items, 0..) |pending, index| {
            if (pending.dial_id != dial_id or pending.id != id) continue;

            _ = self.inproc_pending.orderedRemove(index);
            if (self.inprocDial(dial_id)) |req_dial| {
                _ = req_dial.socket.cancelRequest(id);
            }
            try self.emit(.{ .request_failed = .{
                .dial_id = dial_id,
                .id = id,
                .failure = .canceled,
            } });
            return true;
        }
        return false;
    }

    /// Replies to a request surfaced as a `request` event, while the
    /// event is still alive (its subject is echoed when the outgoing
    /// reply leaves the subject empty).
    pub fn replyInproc(
        self: *Node,
        request: *const RequestEvent,
        outgoing: message.OutgoingMessage,
    ) !void {
        const endpoint = self.inprocRepEndpoint(request.endpoint_id) orelse return error.EndpointNotFound;
        try endpoint.socket.replyKey(.{
            .id = request.msg.id,
            .deadline_ms = request.msg.deadline_ms,
            .subject = request.msg.subject,
        }, outgoing);
        self.counters.sent += 1;
    }

    /// Replies with an error message instead of a payload; the
    /// requester's `ReplyEvent` carries `flags.err` plus the
    /// `qmsg-error-code` / `qmsg-error-message` headers.
    pub fn replyErrorInproc(
        self: *Node,
        request: *const RequestEvent,
        app_error: socket.ErrorReply,
    ) !void {
        const endpoint = self.inprocRepEndpoint(request.endpoint_id) orelse return error.EndpointNotFound;
        try endpoint.socket.replyErrorKey(.{
            .id = request.msg.id,
            .deadline_ms = request.msg.deadline_ms,
            .subject = request.msg.subject,
        }, app_error);
        self.counters.sent += 1;
    }

    /// Binds one inproc pub endpoint; subscribers dial this address
    /// to receive `publishInproc` fanout.
    pub fn listenInprocPub(
        self: *Node,
        network: *transport.inproc.Network,
        address: []const u8,
        options: InprocPubOptions,
    ) !InprocPubId {
        if (self.inproc_pubs.items.len >= self.options.max_sessions) return error.TooManySessions;

        const owned_address = try self.allocator.dupe(u8, address);
        var owns_address = true;
        errdefer if (owns_address) self.allocator.free(owned_address);

        const id = self.inproc_pubs.items.len;
        const endpoint = try self.allocator.create(InprocPubEndpoint);
        var owns_endpoint = true;
        errdefer if (owns_endpoint) self.allocator.destroy(endpoint);

        endpoint.* = .{
            .id = id,
            .network = network,
            .address = owned_address,
            .socket = try socket.Socket(.@"pub").init(self.allocator, options.socket),
        };
        owns_address = false;
        errdefer if (owns_endpoint) endpoint.deinit(self.allocator);

        try endpoint.socket.listenInproc(network, address);
        try self.inproc_pubs.append(self.allocator, endpoint);
        owns_endpoint = false;
        return id;
    }

    pub fn inprocPub(self: *Node, id: InprocPubId) ?*InprocPubEndpoint {
        if (id >= self.inproc_pubs.items.len) return null;
        return self.inproc_pubs.items[id];
    }

    /// Publishes one message to every subscriber of a node-bound pub
    /// endpoint. Slow-peer pressure is synchronous: with a `.fail`
    /// subscriber queue the error surfaces here (classify through
    /// `classifyRequestError`); with drop policies the drop is
    /// counted on the subscriber's own queue, not the node's.
    pub fn publishInproc(self: *Node, pub_id: InprocPubId, outgoing: message.OutgoingMessage) !void {
        const endpoint = self.inprocPub(pub_id) orelse return error.EndpointNotFound;
        try endpoint.socket.publish(outgoing);
        self.counters.sent += 1;
    }

    /// Dials one external inproc publisher into the node's
    /// subscription socket (created on first use with
    /// `NodeOptions.inproc_sub`).
    pub fn dialInprocSub(self: *Node, network: *transport.inproc.Network, address: []const u8) !void {
        try self.ensureInprocSub();
        try self.inproc_sub.?.socket.dialInproc(network, address);
    }

    /// Adds a subscription filter; matching deliveries arrive as
    /// `delivery` events carrying the filter that matched. Filters
    /// replay to publishers whenever they are dialed, so subscribe
    /// and dial order is free.
    pub fn subscribeInproc(self: *Node, filter: []const u8) !void {
        try self.ensureInprocSub();
        try self.inproc_sub.?.socket.subscribe(filter);
    }

    pub fn unsubscribeInproc(self: *Node, filter: []const u8) void {
        if (self.inproc_sub) |sub| sub.socket.unsubscribe(filter);
    }

    /// Live observability snapshot. Plain fields, computed from the
    /// node counters plus the queue stats of every node-owned socket.
    pub fn stats(self: *const Node) Stats {
        var out = Stats{
            .sent = self.counters.sent,
            .recv = self.counters.recv,
            .dropped = self.counters.dropped,
            .events_dropped = self.counters.events_dropped,
        };

        for (self.inproc_rep_endpoints.items) |endpoint| {
            out.accumulate(endpoint.socket.queueStats());
        }
        for (self.inproc_dials.items) |req_dial| {
            out.accumulate(req_dial.socket.queueStats());
        }
        if (self.inproc_sub) |sub| {
            out.accumulate(sub.socket.queueStats());
        }
        return out;
    }

    fn ensureInprocSub(self: *Node) !void {
        if (self.inproc_sub != null) return;

        const sub = try self.allocator.create(InprocSubEndpoint);
        var owns_sub = true;
        errdefer if (owns_sub) self.allocator.destroy(sub);

        sub.* = .{ .socket = try socket.Socket(.sub).init(self.allocator, self.options.inproc_sub) };
        errdefer if (owns_sub) sub.deinit();

        self.inproc_sub = sub;
        owns_sub = false;
    }

    fn inprocRepEndpoint(self: *Node, id: InprocRepId) ?*InprocRepEndpoint {
        if (id >= self.inproc_rep_endpoints.items.len) return null;
        return self.inproc_rep_endpoints.items[id];
    }

    fn nowMs(self: *const Node) u64 {
        return self.now_us / std.time.us_per_ms;
    }

    /// Pumps embedded inproc state into the event queue: expired
    /// request deadlines first, then served requests, request
    /// replies, and subscription deliveries. Called from `poll` so
    /// the embedder's tick/poll loop is the only driver.
    fn pumpInproc(self: *Node) !void {
        try self.expireInprocPending(self.nowMs());

        for (self.inproc_rep_endpoints.items) |endpoint| {
            while (try endpoint.socket.tryRecv()) |received| {
                try self.emit(.{ .request = .{
                    .endpoint_id = endpoint.id,
                    .session_id = endpoint.session.id,
                    .msg = received.message,
                } });
            }
        }

        for (self.inproc_dials.items) |req_dial| {
            while (try req_dial.socket.tryRecvRaw()) |received| {
                try self.completeInprocReply(req_dial, received);
            }
        }

        if (self.inproc_sub) |sub| {
            while (try sub.socket.tryRecv()) |received| {
                const filter = sub.socket.matchedFilter(received.subject) orelse {
                    // Filter removed between enqueue and pump: the
                    // delivery no longer has a claiming subscription.
                    self.counters.dropped += 1;
                    var dropped = received;
                    dropped.deinit();
                    continue;
                };
                try self.emit(.{ .delivery = .{
                    .filter = filter,
                    .msg = received,
                } });
            }
        }
    }

    /// Correlates one popped reply against the pending table. Late
    /// replies (request already canceled or expired) are dropped,
    /// counted, and surfaced as `message_dropped`.
    fn completeInprocReply(self: *Node, req_dial: *InprocDial, msg_in: message.Message) !void {
        var msg = msg_in;
        for (self.inproc_pending.items, 0..) |pending, index| {
            if (pending.dial_id != req_dial.id or pending.id != msg.id) continue;

            _ = self.inproc_pending.orderedRemove(index);
            _ = req_dial.socket.cancelRequest(msg.id);
            try self.emit(.{ .reply = .{ .dial_id = req_dial.id, .msg = msg } });
            return;
        }

        self.counters.dropped += 1;
        const dropped_bytes = queue.messageByteSize(msg);
        msg.deinit();
        try self.emit(.{ .message_dropped = .{ .bytes = dropped_bytes } });
    }

    fn expireInprocPending(self: *Node, now_ms: u64) !void {
        var index: usize = 0;
        while (index < self.inproc_pending.items.len) {
            const pending = self.inproc_pending.items[index];
            if (!pending.isExpired(now_ms)) {
                index += 1;
                continue;
            }

            _ = self.inproc_pending.orderedRemove(index);
            if (self.inprocDial(pending.dial_id)) |req_dial| {
                _ = req_dial.socket.cancelRequest(pending.id);
            }
            try self.emit(.{ .request_failed = .{
                .dial_id = pending.dial_id,
                .id = pending.id,
                .failure = .deadline_exceeded,
            } });
        }
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

    /// Drains node state into the event queue and hands events out.
    ///
    /// This is the embedder's pump: it first drives the embedded
    /// inproc service surface (request deadlines, served requests,
    /// request replies, subscription deliveries) into the event
    /// queue, then moves up to `out.len` events out (ownership of
    /// each event's payload transfers to the caller — `deinit` each
    /// one after handling). Call `tick` first so deadlines evaluate
    /// against a fresh clock.
    pub fn poll(self: *Node, out: []Event) !usize {
        try self.pumpInproc();

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

    /// Queues one event for the embedder. Enforces the
    /// `NodeOptions.max_events` bound: overflow drops the event
    /// (freeing any payload it owns, counting message drops and
    /// `Stats.events_dropped`) instead of growing without limit.
    pub fn emit(self: *Node, event: Event) !void {
        if (self.events.items.len >= self.options.max_events) {
            self.counters.events_dropped += 1;
            if (eventCarriesMessage(event)) self.counters.dropped += 1;
            var dropped = event;
            dropped.deinit();
            return;
        }

        self.events.append(self.allocator, event) catch |err| {
            var dropped = event;
            dropped.deinit();
            return err;
        };
        if (eventCarriesMessage(event)) self.counters.recv += 1;
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

fn eventCarriesMessage(event: Event) bool {
    return switch (event) {
        .request, .reply, .delivery => true,
        .connected, .closed, .message_dropped, .request_failed => false,
    };
}

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

// ---- embedded inproc service surface (socketless Node) ----------------------

test "embedded Node serves requests and replies through poll events" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    _ = try n.listenInprocRep(&network, "svc", .{});

    var req = try socket.Socket(.req).init(allocator, .{});
    defer req.deinit();
    try req.dialInproc(&network, "svc");

    const sent_id = try req.sendRequest(.{
        .subject = "user.get",
        .body = "42",
        .deadline_ms = 250,
    });

    var events: [4]Event = undefined;
    const count = try n.poll(&events);
    defer for (events[0..count]) |*event| {
        event.deinit();
    };

    var request_event: ?*RequestEvent = null;
    for (events[0..count]) |*event| switch (event.*) {
        .request => |*ev| request_event = ev,
        else => {},
    };

    const served = request_event orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(InprocRepId, 0), served.endpoint_id);
    try std.testing.expectEqual(sent_id, served.msg.id);
    try std.testing.expectEqualStrings("user.get", served.msg.subject);
    try std.testing.expectEqualStrings("42", served.msg.body);
    try std.testing.expectEqual(@as(?u64, 250), served.msg.deadline_ms);

    try n.replyInproc(served, .{ .subject = "", .body = "Ada" });

    var reply = try req.recv();
    defer reply.deinit();
    try std.testing.expectEqual(sent_id, reply.id);
    try std.testing.expectEqualStrings("user.get", reply.subject);
    try std.testing.expectEqualStrings("Ada", reply.body);
}

test "embedded Node error replies carry the stable error shape" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    _ = try n.listenInprocRep(&network, "svc", .{});

    var req = try socket.Socket(.req).init(allocator, .{});
    defer req.deinit();
    try req.dialInproc(&network, "svc");

    _ = try req.sendRequest(.{ .subject = "user.get", .body = "42" });

    var events: [2]Event = undefined;
    const count = try n.poll(&events);
    defer for (events[0..count]) |*event| {
        event.deinit();
    };

    var request_event: ?*RequestEvent = null;
    for (events[0..count]) |*event| switch (event.*) {
        .request => |*ev| request_event = ev,
        else => {},
    };

    try n.replyErrorInproc(request_event orelse return error.TestUnexpectedResult, .{
        .code = "not_found",
        .message = "user not found",
    });

    var reply = try req.recv();
    defer reply.deinit();
    try std.testing.expect(reply.flags.err);
    try std.testing.expectEqualStrings("not_found", reply.headers[0].value);
    try std.testing.expectEqualStrings("user not found", reply.body);
}

test "embedded Node outbound request completes through reply event" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    var rep = try socket.Socket(.rep).init(allocator, .{});
    defer rep.deinit();
    try rep.listenInproc(&network, "svc");

    try n.tick(1_000_000);
    const dial_id = try n.dialInprocReq(&network, "svc", .{});
    const id = try n.requestInproc(dial_id, .{
        .subject = "user.get",
        .body = "42",
        .deadline_ms = 500,
    });
    try std.testing.expectEqual(@as(usize, 1), n.inprocDial(dial_id).?.socket.inflightCount());

    var request = try rep.recv();
    defer request.deinit();
    try std.testing.expectEqual(id, request.id());
    try std.testing.expectEqualStrings("42", request.message.body);

    try rep.reply(request, .{ .subject = "user.ok", .body = "Ada" });

    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&events));
    defer events[0].deinit();

    try std.testing.expectEqual(dial_id, events[0].reply.dial_id);
    try std.testing.expectEqual(id, events[0].reply.msg.id);
    try std.testing.expectEqualStrings("user.ok", events[0].reply.msg.subject);
    try std.testing.expectEqualStrings("Ada", events[0].reply.msg.body);
    try std.testing.expectEqual(@as(usize, 0), n.inprocDial(dial_id).?.socket.inflightCount());
    try std.testing.expectEqual(@as(usize, 0), n.inproc_pending.items.len);
}

test "embedded Node request deadline expires into classified failure and drops late reply" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    var rep = try socket.Socket(.rep).init(allocator, .{});
    defer rep.deinit();
    try rep.listenInproc(&network, "svc");

    try n.tick(1_000_000);
    const dial_id = try n.dialInprocReq(&network, "svc", .{});
    const id = try n.requestInproc(dial_id, .{
        .subject = "user.get",
        .deadline_ms = 100,
    });

    var request = try rep.recv();
    defer request.deinit();

    try n.tick(1_100_000);
    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&events));

    try std.testing.expectEqual(dial_id, events[0].request_failed.dial_id);
    try std.testing.expectEqual(id, events[0].request_failed.id);
    try std.testing.expectEqual(RequestFailure.deadline_exceeded, events[0].request_failed.failure);
    events[0].deinit();

    try std.testing.expectEqual(@as(usize, 0), n.inprocDial(dial_id).?.socket.inflightCount());

    // The reply lands after the deadline already fired: dropped,
    // counted, surfaced as message_dropped.
    try rep.reply(request, .{ .subject = "user.ok", .body = "late" });
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&events));
    try std.testing.expectEqual(@as(usize, 0), events[0].message_dropped.session_id orelse 0);
    try std.testing.expect(events[0].message_dropped.bytes > 0);
    events[0].deinit();

    const stats = n.stats();
    try std.testing.expectEqual(@as(usize, 1), stats.dropped);
}

test "embedded Node cancel emits canceled failure and drops late reply" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    var rep = try socket.Socket(.rep).init(allocator, .{});
    defer rep.deinit();
    try rep.listenInproc(&network, "svc");

    try n.tick(1_000_000);
    const dial_id = try n.dialInprocReq(&network, "svc", .{});
    const id = try n.requestInproc(dial_id, .{ .subject = "user.get" });

    var request = try rep.recv();
    defer request.deinit();

    try std.testing.expect(try n.cancelInprocRequest(dial_id, id));
    try std.testing.expect(!try n.cancelInprocRequest(dial_id, id));

    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&events));
    try std.testing.expectEqual(RequestFailure.canceled, events[0].request_failed.failure);
    try std.testing.expectEqual(id, events[0].request_failed.id);
    events[0].deinit();

    try rep.reply(request, .{ .subject = "user.ok", .body = "late" });
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&events));
    try std.testing.expect(events[0] == .message_dropped);
    events[0].deinit();
}

test "embedded Node surfaces synchronous send pressure for classification" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    _ = try n.listenInprocRep(&network, "svc", .{
        .socket = .{ .recv_queue = .{
            .max_messages = 1,
            .max_bytes = 1024,
            .on_full = .fail,
        } },
    });

    const err = n.requestInproc(999, .{ .subject = "user.get" });
    try std.testing.expectError(error.EndpointNotFound, err);
    try std.testing.expectEqual(RequestFailure.no_route, classifyRequestError(error.EndpointNotFound));

    const dial_id = try n.dialInprocReq(&network, "svc", .{});
    _ = try n.requestInproc(dial_id, .{ .subject = "user.get" });
    try std.testing.expectError(error.QueueFull, n.requestInproc(dial_id, .{ .subject = "user.get" }));
    try std.testing.expectEqual(RequestFailure.queue_full, classifyRequestError(error.QueueFull));
    try std.testing.expectEqual(RequestFailure.peer_closed, classifyRequestError(error.EndpointClosed));
    try std.testing.expectEqual(@as(?RequestFailure, null), classifyRequestError(error.OutOfMemory));
}

test "embedded Node deliveries carry the matched filter and honor unsubscribe" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    var publisher = try socket.Socket(.@"pub").init(allocator, .{});
    defer publisher.deinit();
    try publisher.listenInproc(&network, "events");

    try n.subscribeInproc("metrics.*");
    try n.dialInprocSub(&network, "events");

    try publisher.publish(.{ .subject = "metrics.cpu", .body = "91" });
    try publisher.publish(.{ .subject = "jobs.resize", .body = "ignored" });

    var events: [2]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&events));
    defer events[0].deinit();

    try std.testing.expectEqualStrings("metrics.cpu", events[0].delivery.msg.subject);
    try std.testing.expectEqualStrings("91", events[0].delivery.msg.body);
    try std.testing.expectEqualStrings("metrics.*", events[0].delivery.filter);

    n.unsubscribeInproc("metrics.*");
    try publisher.publish(.{ .subject = "metrics.mem", .body = "92" });
    try std.testing.expectEqual(@as(usize, 0), try n.poll(&events));
}

test "embedded Node publishes to dialed subscribers" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const pub_id = try n.listenInprocPub(&network, "feed", .{});

    var subscriber = try socket.Socket(.sub).init(allocator, .{});
    defer subscriber.deinit();
    try subscriber.dialInproc(&network, "feed");
    try subscriber.subscribe("presence.>");

    try n.publishInproc(pub_id, .{ .subject = "presence.ada", .body = "online" });

    var received = try subscriber.recv();
    defer received.deinit();
    try std.testing.expectEqualStrings("presence.ada", received.subject);
    try std.testing.expectEqualStrings("online", received.body);

    try std.testing.expectError(error.EndpointNotFound, n.publishInproc(pub_id + 1, .{ .subject = "presence.grace" }));
}

test "embedded Node stats count sent recv dropped and queue high water" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    var rep = try socket.Socket(.rep).init(allocator, .{});
    defer rep.deinit();
    try rep.listenInproc(&network, "svc");

    try n.tick(1_000_000);
    const dial_id = try n.dialInprocReq(&network, "svc", .{});
    const id = try n.requestInproc(dial_id, .{
        .subject = "user.get",
        .body = "42",
        .deadline_ms = 500,
    });

    var request = try rep.recv();
    defer request.deinit();
    try rep.reply(request, .{ .subject = "user.ok", .body = "Ada" });

    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&events));
    defer events[0].deinit();
    try std.testing.expectEqual(id, events[0].reply.msg.id);

    const stats = n.stats();
    try std.testing.expectEqual(@as(usize, 1), stats.sent);
    try std.testing.expectEqual(@as(usize, 1), stats.recv);
    try std.testing.expectEqual(@as(usize, 0), stats.dropped);
    try std.testing.expectEqual(@as(usize, 1), stats.queue_high_water);
    try std.testing.expectEqual(@as(usize, 0), stats.events_dropped);
}

test "embedded Node slow-consumer drops are counted through sub queue policy" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{
        .inproc_sub = .{ .recv_queue = .{
            .max_messages = 1,
            .max_bytes = 1024,
            .on_full = .drop_oldest,
        } },
    });
    defer n.deinit();

    var publisher = try socket.Socket(.@"pub").init(allocator, .{});
    defer publisher.deinit();
    try publisher.listenInproc(&network, "events");

    try n.dialInprocSub(&network, "events");
    try n.subscribeInproc("metrics.*");

    try publisher.publish(.{ .subject = "metrics.cpu", .body = "first" });
    try publisher.publish(.{ .subject = "metrics.mem", .body = "second" });

    var events: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&events));
    defer events[0].deinit();
    try std.testing.expectEqualStrings("second", events[0].delivery.msg.body);

    const stats = n.stats();
    try std.testing.expectEqual(@as(usize, 1), stats.dropped);
}

test "embedded Node event queue bound drops and counts overflow" {
    const allocator = std.testing.allocator;

    var network = transport.inproc.Network.init(allocator);
    defer network.deinit();

    var n = try Node.init(allocator, .{ .max_events = 2 });
    defer n.deinit();

    _ = try n.listenInprocRep(&network, "svc", .{});

    // Drain the bind-time connected event so the queue starts empty.
    var setup: [1]Event = undefined;
    try std.testing.expectEqual(@as(usize, 1), try n.poll(&setup));
    setup[0].deinit();

    var req = try socket.Socket(.req).init(allocator, .{});
    defer req.deinit();
    try req.dialInproc(&network, "svc");

    _ = try req.sendRequest(.{ .subject = "user.one" });
    _ = try req.sendRequest(.{ .subject = "user.two" });
    _ = try req.sendRequest(.{ .subject = "user.three" });

    var events: [4]Event = undefined;
    try std.testing.expectEqual(@as(usize, 2), try n.poll(&events));
    for (events[0..2]) |*event| {
        event.deinit();
    }

    const stats = n.stats();
    try std.testing.expectEqual(@as(usize, 1), stats.events_dropped);
    try std.testing.expectEqual(@as(usize, 1), stats.dropped);
    try std.testing.expectEqual(@as(usize, 2), stats.recv);
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
    // The reply receiver on the client's own request stream was armed
    // by queueReliable itself — no explicit accept needed on the dial
    // side anymore.
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

test "Node.deinit with a live driver-owned session tears down cleanly" {
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
    try p.dispatch.init(allocator, &node, server_opts);
    // Defer order (LIFO): listener FIRST (its Server.deinit fires the
    // will-close hook that destroys the driver-owned session), then
    // the dispatch, then the client — mirroring the fixed
    // QuicListenerRuntime/Node teardown order under test.
    defer p.dispatch.deinit();
    defer p.listener.deinit();
    p.dispatch.attach(&p.listener.server);
    p.client = try transport.quic_runtime.ClientRuntime.init(allocator, "127.0.0.1:4433", .{
        .server_name = "localhost",
        .insecure_skip_verify = true, // self-signed test fixture
        .transport = client_opts,
    });
    defer p.client.deinit();

    const client_sess = try node.openQuicSession(.{
        .role = .client,
        .transport = client_opts,
    });
    client_sess.transport_ready = true;
    try client_sess.runtime.onQuicReady();

    // Drive to a fully ready pair, then deinit with the connection
    // STILL LIVE: the listener's Server.deinit must fire the
    // will-close hook (dispatch alive) and destroy the driver-owned
    // server session exactly once, before Node frees anything it
    // points at. No graceful close, no reap — plain teardown.
    var step: u32 = 0;
    while (step < 4_000) : (step += 1) {
        try p.drive();
        if (p.client.connection().handshakeDone() and
            p.listener.connectionCount() > 0 and
            p.listener.connection(0).?.handshakeDone()) break;
    }
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
    try std.testing.expectEqual(@as(usize, 2), node.quic_sessions.items.len);

    // defers above run node.deinit() first (listeners -> hook ->
    // session destroy), then the peer runtimes — exiting this test
    // without a crash, double free, or leak IS the acceptance check.
}

// ---- live-UDP acceptance (skipped when the sandbox denies binds) ------------

test "live UDP: queueReliable round trip needs no explicit accept and deinit with live sessions is clean" {
    const allocator = std.testing.allocator;
    const control = @import("control.zig");

    const server_opts: transport.quic.QuicOptions = .{
        .peer_id = "live-server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };
    const client_opts: transport.quic.QuicOptions = .{
        .peer_id = "live-client",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const listener_id = n.listenQuic("127.0.0.1:0", .{
        .tls_cert_pem = dispatch_test_cert_pem,
        .tls_key_pem = dispatch_test_key_pem,
        .transport = server_opts,
    }) catch |err| switch (err) {
        // Environments that deny UDP binds skip this test rather
        // than fail it; everywhere else it is the acceptance check
        // for both embedded-dial behaviors.
        error.AccessDenied,
        error.AddressInUse,
        error.AddressUnavailable,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        => return error.SkipZigTest,
        else => return err,
    };
    const listener = n.quic_listeners.items[listener_id];
    const target = try localhostEndpoint(allocator, listener.localAddress());
    defer allocator.free(target);

    const client_session_id = try n.dialQuic(target, .{
        .server_name = "localhost",
        // The fixture cert is a self-signed CA with a localhost SAN,
        // so it verifies against itself.
        .ca_pem = dispatch_test_cert_pem,
        .transport = client_opts,
    });
    const client = n.quicSession(client_session_id) orelse return error.EndpointNotFound;

    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < 20_000) : (step += 1) {
        now_us += 1_000;
        try n.tick(now_us);
        if (client.state() == .ready and liveServerSessionReady(&n, client_session_id)) break;
    }
    try std.testing.expectEqual(transport.quic.State.ready, client.state());

    // Ask-1 acceptance: send a request and receive its reply with NO
    // explicit acceptReliableStream anywhere — queueReliable armed the
    // reply receiver on the requester's own stream.
    const stream_id = try client.queueReliable(.{
        .subject = "user.get",
        .id = 7,
        .deadline_ms = 2_000,
        .body = "42",
    });
    var dispatcher = LiveUdpDispatcher{ .allocator = allocator };
    var reply: ?transport.quic_session_runtime.ReceivedReliable = null;
    step = 0;
    while (step < 20_000 and reply == null) : (step += 1) {
        now_us += 1_000;
        try n.tick(now_us);
        // Check the reply BEFORE runOnce: runOnce dispatches every
        // received reliable message through the .rep path, and a
        // dispatched REPLY would be answered again (the localhost
        // example checks the client reply first for the same reason).
        reply = client.runtime.recvReliable();
        if (reply == null) {
            _ = try n.runOnce(&dispatcher);
        }
    }
    var got = reply orelse return error.ReplyMissing;
    defer got.deinit();
    try std.testing.expectEqual(stream_id, got.stream_id);
    try std.testing.expectEqual(@as(message.MessageId, 7), got.message.id);
    try std.testing.expectEqualStrings("user-42", got.message.body);

    // Ask-2 acceptance: fall off the end with BOTH sessions live (the
    // server's driver-owned, the client's dial-owned) and the listener
    // still connected. node.deinit() runs on scope exit and must tear
    // down listeners (whose Server.deinit fires the will-close hook
    // into live dispatch state) before freeing any session.
}

const LiveUdpDispatcher = struct {
    allocator: std.mem.Allocator,

    const Result = struct {
        allocator: std.mem.Allocator,
        replies: std.ArrayList(message.Message) = .empty,
        publications: std.ArrayList(message.Message) = .empty,

        fn deinit(self: *Result) void {
            for (self.replies.items) |*msg| msg.deinit();
            self.replies.deinit(self.allocator);
            for (self.publications.items) |*msg| msg.deinit();
            self.publications.deinit(self.allocator);
        }
    };

    fn dispatchQuicReliable(
        self: *@This(),
        kind: socket.Pattern,
        incoming: message.Message,
        sess: *session.Session,
    ) !Result {
        _ = kind;
        _ = sess;

        var owned = incoming;
        defer owned.deinit();

        var result = Result{ .allocator = self.allocator };
        // Echo the request subject, as the App facade does for empty
        // reply subjects — the envelope layer rejects "".
        const reply = try message.Message.init(self.allocator, .{
            .subject = owned.subject,
            .id = owned.id,
            .flags = .{ .final = true },
            .deadline_ms = owned.deadline_ms,
            .body = "user-42",
        });
        errdefer {
            var cleanup = reply;
            cleanup.deinit();
        }
        try result.replies.append(self.allocator, reply);
        return result;
    }
};

fn liveServerSessionReady(n: *const Node, exclude: QuicSessionId) bool {
    for (n.quic_sessions.items) |runtime| {
        if (runtime.id() == exclude) continue;
        if (runtime.state() == .ready) return true;
    }
    return false;
}

fn localhostEndpoint(allocator: std.mem.Allocator, address: std.Io.net.IpAddress) ![]u8 {
    return switch (address) {
        .ip4 => |ip4| try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{ip4.port}),
        .ip6 => |ip6| try std.fmt.allocPrint(allocator, "[::1]:{d}", .{ip6.port}),
    };
}
