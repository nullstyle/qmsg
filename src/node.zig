const std = @import("std");
const message = @import("message.zig");
const queue = @import("queue.zig");
const socket = @import("socket.zig");
const session = @import("session.zig");
const auth = @import("auth.zig");
const transport = @import("transport/root.zig");
const protocol = @import("protocol/root.zig");

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
    /// Bound on node-level QUIC subscriptions (`subscribeQuic`).
    /// Further subscribes fail with `error.QueueFull` instead of
    /// growing without limit.
    max_quic_subscriptions: usize = 64,
    /// Per-session bound on datagram publications queued for the
    /// wire. At the bound, a subscriber's `on_full` queue policy
    /// decides drop-newest vs drop-oldest; drops surface as
    /// `message_dropped` and count in `Stats.dropped`. Slow
    /// consumers shed; fan-out never blocks.
    quic_datagram_outbox_max: usize = 64,
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

/// An inbound request on an attached embedded QUIC session. `msg`
/// is owned by the event: `msg.id` is the reply correlation id,
/// `msg.deadline_ms` the request deadline. Reply through
/// `Node.replyQuic` while the event is alive, then `deinit`.
pub const QuicRequestEvent = struct {
    session_id: QuicSessionId,
    stream_id: u64,
    msg: message.Message,

    pub fn deinit(self: *QuicRequestEvent) void {
        self.msg.deinit();
        self.* = undefined;
    }
};

/// A reply completing one of the node's outbound QUIC requests
/// (sent with `queueReliable` on the session). `stream_id` is the
/// request's own stream — the (session, stream) pair the caller's
/// pending table is keyed on. Peer error replies carry `flags.err`
/// and the `qmsg-error-code` / `qmsg-error-message` headers.
pub const QuicReplyEvent = struct {
    session_id: QuicSessionId,
    stream_id: u64,
    msg: message.Message,

    pub fn deinit(self: *QuicReplyEvent) void {
        self.msg.deinit();
        self.* = undefined;
    }
};

/// One DATAGRAM delivery on an attached embedded QUIC session.
pub const QuicDeliveryEvent = struct {
    session_id: QuicSessionId,
    msg: message.Message,

    pub fn deinit(self: *QuicDeliveryEvent) void {
        self.msg.deinit();
        self.* = undefined;
    }
};

/// Terminal outcome for one of the node's outbound QUIC requests
/// (sent with `requestQuic`): no reply event will follow this
/// `(session_id, stream_id)` pair. Classifications are first-wins and
/// idempotent with a consumer's own pending table — whichever side
/// observes an outcome first, the other ignores.
pub const QuicRequestFailedEvent = struct {
    session_id: QuicSessionId,
    stream_id: u64,
    id: message.MessageId,
    failure: RequestFailure,
};

pub const Event = union(enum) {
    connected: session.SessionId,
    closed: session.SessionId,
    message_dropped: MessageDropped,
    request: RequestEvent,
    reply: ReplyEvent,
    request_failed: RequestFailedEvent,
    delivery: DeliveryEvent,
    quic_request: QuicRequestEvent,
    quic_reply: QuicReplyEvent,
    quic_delivery: QuicDeliveryEvent,
    quic_request_failed: QuicRequestFailedEvent,

    /// Releases memory the event owns. Every event pulled out of
    /// `Node.poll` must be deinited by the embedder after handling.
    pub fn deinit(self: *Event) void {
        switch (self.*) {
            .request => |*ev| ev.deinit(),
            .reply => |*ev| ev.deinit(),
            .delivery => |*ev| ev.deinit(),
            .quic_request => |*ev| ev.deinit(),
            .quic_reply => |*ev| ev.deinit(),
            .quic_delivery => |*ev| ev.deinit(),
            .connected, .closed, .message_dropped, .request_failed, .quic_request_failed => {},
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

/// One outbound QUIC request awaiting its reply, keyed by the
/// `(session_id, stream_id)` pair the reply event carries — the same
/// key a consumer's correlation table uses. Outcomes are
/// first-classification-wins: whichever of the reply surfacing, the
/// deadline, an explicit cancel, or the session dying is observed
/// first settles the entry; later observations are no-ops.
const PendingQuicRequest = struct {
    session_id: QuicSessionId,
    stream_id: u64,
    id: message.MessageId,
    deadline_ms: ?u64,
    sent_at_ms: u64,

    fn isExpired(self: PendingQuicRequest, now_ms: u64) bool {
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
    /// RFC 9000 §10.3 stateless-reset HMAC key. Null (the default)
    /// generates a fresh random key per listener, so every qmsg
    /// listener answers orphan probes with a Stateless Reset by
    /// default. The probing peer detects the reset through the
    /// per-CID token it was advertised at handshake — no shared
    /// secret on the peer side. Pin ONE key across instances and
    /// restarts (`stateless_reset_key = same_value` on every
    /// listener) in multi-instance or replacement deployments: a
    /// reborn listener can only kill a dead instance's orphans when
    /// its reset verifies against the tokens the dead instance
    /// minted, which requires the same key.
    stateless_reset_key: ?[32]u8 = null,
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
    /// The node that owns this session, for pending-request
    /// bookkeeping (`recvReliable` settles the request a popped
    /// reply completes). Sessions only exist through node creation
    /// paths, so the pointer is always set.
    node: *Node,
    transport_ready: bool = false,
    /// True when the listener-side Driver owns this session's
    /// lifecycle (created on handshake, destroyed via will-close).
    driver_owned: bool = false,
    datagram_inbox: std.ArrayList(transport.quic_datagram.ReceivedDatagram) = .empty,
    datagram_outbox: std.ArrayList(message.Message) = .empty,
    /// Per-session control-frame state: the queue this session's
    /// SUBSCRIBE/UNSUBSCRIBE emission flushes onto a follow-up uni
    /// control stream, and the apply path for inbound frames (into
    /// the node's registry). Null only before createQuicSession
    /// finishes.
    control_state: ?transport.quic_control.State = null,
    /// True once the node's full subscription set has been queued
    /// for this session (per redial-generation session).
    subscriptions_synced: bool = false,

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

    /// Pops one received reliable message. Replies popped here settle
    /// the node's pending entry for their `(session, stream)` — a
    /// later sweep cannot misclassify a reply the consumer already
    /// holds. (Draining through `.runtime.recvReliable` directly
    /// bypasses settlement; see `Node.settleQuicRequest`.)
    pub fn recvReliable(self: *QuicSessionRuntime) ?transport.quic_session_runtime.ReceivedReliable {
        const received = self.runtime.recvReliable() orelse return null;
        _ = self.node.settleQuicRequest(self.id(), received.stream_id);
        return received;
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
        // After the runtime: a pending flush sender references the
        // control state's queued frames until it completes.
        if (self.control_state) |*ctrl| ctrl.deinit();
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
    quic_pending: std.ArrayList(PendingQuicRequest) = .empty,
    /// QUIC pub/sub state (docs/QUIC_PUBSUB.md): the registry of
    /// what PEERS want from us (peer id = session id), the node's
    /// own outbound subscription set (what WE want from peers), and
    /// the shared credit ledger the per-session control states use.
    quic_registry: protocol.pubsub.Registry = undefined,
    quic_subscriptions: protocol.pubsub.SubscriptionSet = undefined,
    quic_credit_ledger: protocol.pushpull.CreditLedger = undefined,
    counters: Counters = .{},
    quic_listeners: std.ArrayList(*QuicListenerRuntime) = .empty,
    quic_clients: std.ArrayList(*QuicClientRuntime) = .empty,
    quic_sessions: std.ArrayList(*QuicSessionRuntime) = .empty,
    quic_socket_attachments: std.ArrayList(QuicSocketAttachment) = .empty,
    now_us: u64 = 0,
    next_session_id: session.SessionId = 1,

    pub fn init(allocator: std.mem.Allocator, options: NodeOptions) !Node {
        var self = Node{
            .allocator = allocator,
            .options = options,
        };
        self.quic_registry = protocol.pubsub.Registry.init(allocator);
        self.quic_subscriptions = protocol.pubsub.SubscriptionSet.init(
            allocator,
            options.max_quic_subscriptions,
        );
        self.quic_credit_ledger = protocol.pushpull.CreditLedger.init(allocator);
        return self;
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
        self.quic_pending.deinit(self.allocator);
        self.quic_registry.deinit();
        self.quic_subscriptions.deinit();
        self.quic_credit_ledger.deinit();
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
        try self.sweepQuicPending(self.nowMs());
        self.syncQuicControl();
    }

    pub fn listenQuic(self: *Node, endpoint: []const u8, options: QuicListenOptions) !QuicListenerId {
        if (self.quic_listeners.items.len >= self.options.max_sessions) return error.TooManySessions;

        const id = self.quic_listeners.items.len;
        const runtime = try self.allocator.create(QuicListenerRuntime);
        var owns_runtime = true;
        errdefer if (owns_runtime) self.allocator.destroy(runtime);

        // Reset posture by default: a keyed listener answers
        // orphan probes (unroutable short-header datagrams) with a
        // Stateless Reset instead of silently dropping them, so a
        // probing orphan dies at its first PTO instead of probing
        // forever. Fresh random key per listener; deployments that
        // replace or scale listeners pin one via the option.
        var stateless_reset_key = options.stateless_reset_key;
        if (stateless_reset_key == null) {
            var generated: [32]u8 = undefined;
            self.options.io.random(&generated);
            stateless_reset_key = generated;
        }

        runtime.* = .{
            .id = id,
            .listener = try transport.quic_udp.Listener.start(self.allocator, self.options.io, .{
                .bind_literal = endpoint,
                .runtime = .{
                    .tls_cert_pem = options.tls_cert_pem,
                    .tls_key_pem = options.tls_key_pem,
                    .transport = options.transport,
                    .stateless_reset_key = stateless_reset_key,
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

    /// Drains attached embedded QUIC sessions into the event queue
    /// (the pull model): inbound requests on peer-initiated streams,
    /// replies on the session's own request streams, and datagram
    /// deliveries. The transport pumping that FILLS these inboxes is
    /// the embedder's loop (its Driver hooks and `serviceSeat`
    /// calls); this only drains what has arrived.
    fn pumpEmbeddedQuic(self: *Node) !void {
        for (self.quic_sessions.items) |runtime| {
            if (!runtime.runtime.event_delivery) continue;

            while (runtime.runtime.peekReliableStreamId()) |stream_id| {
                const is_request = transport.quic_session_runtime.isPeerBidiStreamId(
                    runtime.runtime.session.role,
                    stream_id,
                );
                var received = runtime.runtime.recvReliable() orelse break;
                const incoming = received.takeMessage();
                if (is_request) {
                    try self.emit(.{ .quic_request = .{
                        .session_id = runtime.id(),
                        .stream_id = stream_id,
                        .msg = incoming,
                    } });
                } else {
                    // A reply completes its pending request (if the
                    // consumer registered one): first classification
                    // wins, and the reply is the outcome.
                    _ = self.settleQuicRequest(runtime.id(), stream_id);
                    try self.emit(.{ .quic_reply = .{
                        .session_id = runtime.id(),
                        .stream_id = stream_id,
                        .msg = incoming,
                    } });
                }
            }

            while (runtime.recvDatagram()) |received_datagram| {
                var received = received_datagram;
                const incoming = received.takeMessage();
                try self.emit(.{ .quic_delivery = .{
                    .session_id = runtime.id(),
                    .msg = incoming,
                } });
            }
        }
    }

    /// Replies to a request surfaced as a `quic_request` event, while
    /// the event is alive. The reply rides the request's own stream;
    /// its subject echoes the request subject when left empty, and
    /// the request's deadline travels back on the reply.
    pub fn replyQuic(
        self: *Node,
        request: *const QuicRequestEvent,
        outgoing: message.OutgoingMessage,
    ) !void {
        const runtime = self.quicSession(request.session_id) orelse return error.EndpointNotFound;

        var effective = outgoing;
        if (effective.subject.len == 0) effective.subject = request.msg.subject;
        if (effective.id == 0) effective.id = request.msg.id;
        if (effective.deadline_ms == null) effective.deadline_ms = request.msg.deadline_ms;

        try runtime.replyReliableOnStream(request.stream_id, effective);
        self.counters.sent += 1;
    }

    /// Replies with an error message instead of a payload; the
    /// requester's `quic_reply` event carries `flags.err` plus the
    /// `qmsg-error-code` / `qmsg-error-message` headers.
    pub fn replyErrorQuic(
        self: *Node,
        request: *const QuicRequestEvent,
        app_error: socket.ErrorReply,
    ) !void {
        const runtime = self.quicSession(request.session_id) orelse return error.EndpointNotFound;

        const headers = [_]message.Header{
            .{ .name = socket.ErrorReply.code_header, .value = app_error.code },
            .{ .name = socket.ErrorReply.message_header, .value = app_error.message },
        };
        var effective_subject = app_error.subject;
        if (effective_subject.len == 0) effective_subject = request.msg.subject;

        try runtime.replyReliableOnStream(request.stream_id, .{
            .subject = effective_subject,
            .id = request.msg.id,
            .flags = .{ .err = true, .final = true },
            .deadline_ms = request.msg.deadline_ms,
            .headers = &headers,
            .body = app_error.message,
        });
        self.counters.sent += 1;
    }

    /// Publishes one unreliable message on an attached embedded QUIC
    /// session (a DATAGRAM; the session must have datagrams enabled).
    pub fn publishQuic(self: *Node, session_id: QuicSessionId, outgoing: message.OutgoingMessage) !void {
        const runtime = self.quicSession(session_id) orelse return error.EndpointNotFound;
        try runtime.queueDatagram(outgoing);
        self.counters.sent += 1;
    }

    // ---- QUIC pub/sub across the process wall (docs/QUIC_PUBSUB.md) ----

    /// Subscribes the NODE to `filter` on every QUIC session, current
    /// and future: SUBSCRIBE frames are queued for every ready
    /// session and re-emitted (the full set) on each NEW session that
    /// reaches ready — a redial's replacement session inherits the
    /// mesh's subscriptions without any re-subscribe call. State
    /// outlives sessions by construction. Unsubscribe with
    /// `unsubscribeQuic`. Emission rides follow-up uni control
    /// streams through the existing queue/flush machinery; a session
    /// that is closing or whose flush sender is busy keeps its frames
    /// queued for a later tick, and one session's failure never
    /// unwinds the set.
    pub fn subscribeQuic(
        self: *Node,
        filter: []const u8,
        options: queue.QueueOptions,
    ) !void {
        if (!try self.quic_subscriptions.add(filter)) return; // duplicate

        for (self.quic_sessions.items) |runtime| {
            if (!runtime.subscriptions_synced) continue; // full set comes at sync
            const state = &(runtime.control_state orelse continue);
            state.queueSubscribe(filter, options) catch continue;
        }
    }

    /// Removes a `subscribeQuic` subscription: the filter leaves the
    /// node set and UNSUBSCRIBE is queued for every synced session.
    pub fn unsubscribeQuic(self: *Node, filter: []const u8) void {
        if (!self.quic_subscriptions.remove(filter)) return;

        for (self.quic_sessions.items) |runtime| {
            if (!runtime.subscriptions_synced) continue;
            const state = &(runtime.control_state orelse continue);
            state.queueUnsubscribe(filter) catch continue;
        }
    }

    /// Publishes one datagram to every QUIC session whose registry
    /// entry matches `subject` — dial peers and embedded qmsg/1
    /// clients alike, one registry. Returns the number of sessions
    /// the publication was queued for. Sessions without datagram
    /// support and over-budget outboxes are skipped and counted
    /// (`message_dropped`, `Stats.dropped`); a subscriber's `on_full`
    /// policy decides drop-newest vs drop-oldest at its bound. Slow
    /// consumers shed; the loop never blocks. Publications are
    /// lossy-tolerant by design (datagram-first; reliable-stream
    /// publication is future work).
    pub fn publishQuicSubscribed(self: *Node, outgoing: message.OutgoingMessage) !usize {
        var matches: std.ArrayList(protocol.pubsub.Match) = .empty;
        defer matches.deinit(self.allocator);
        try self.quic_registry.collectMatches(outgoing.subject, &matches);

        var delivered: usize = 0;
        for (matches.items) |match| {
            const runtime = self.quicSession(@intCast(match.peer_id)) orelse continue;
            if (runtime.runtime.state() != .ready) continue;

            if (!runtime.runtime.appSession().datagram_enabled) {
                self.counters.dropped += 1;
                self.emit(.{ .message_dropped = .{
                    .session_id = runtime.id(),
                    .bytes = outgoing.body.len,
                } }) catch {};
                continue;
            }

            if (!self.roomForQuicDatagram(runtime)) {
                self.counters.dropped += 1;
                self.emit(.{ .message_dropped = .{
                    .session_id = runtime.id(),
                    .bytes = outgoing.body.len,
                } }) catch {};
                continue;
            }

            runtime.queueDatagram(outgoing) catch |err| switch (err) {
                error.MessageTooLarge => {
                    self.counters.dropped += 1;
                    self.emit(.{ .message_dropped = .{
                        .session_id = runtime.id(),
                        .bytes = outgoing.body.len,
                    } }) catch {};
                },
                else => return err,
            };
            delivered += 1;
        }
        self.counters.sent += 1;
        return delivered;
    }

    /// Makes room per the subscriber's queue policy at the outbox
    /// bound: drop-newest reports no room (the publication sheds),
    /// drop-oldest sheds the oldest queued datagram to make it.
    fn roomForQuicDatagram(self: *Node, runtime: *QuicSessionRuntime) bool {
        if (runtime.datagram_outbox.items.len < self.options.quic_datagram_outbox_max) {
            return true;
        }

        const options = self.quic_registry.peerQueueOptions(
            quicRegistryPeer(runtime.id()),
        ) orelse return false;
        switch (options.on_full) {
            .drop_newest => return false,
            else => {
                var shed = runtime.datagram_outbox.orderedRemove(0);
                shed.deinit();
                return true;
            },
        }
    }

    /// Tick-driven control sync (docs/QUIC_PUBSUB.md): every ready
    /// session not yet synced gets the FULL node subscription set
    /// queued (redial replacements inherit the mesh), then any
    /// session with queued frames and an idle flush sender flushes
    /// them onto a follow-up uni control stream. Per-session
    /// failures are contained; nothing here unwinds `tick`.
    fn syncQuicControl(self: *Node) void {
        for (self.quic_sessions.items) |runtime| {
            var state = &(runtime.control_state orelse continue);
            if (runtime.runtime.state() != .ready) continue;

            if (!runtime.subscriptions_synced) {
                for (self.quic_subscriptions.entries.items) |*entry| {
                    state.queueSubscribe(entry.filter.text, peerQueueDefaults) catch continue;
                }
                runtime.subscriptions_synced = true;
                state = &(runtime.control_state orelse continue);
            }

            if (state.queuedFrameCount() == 0) continue;
            if (runtime.runtime.hasControlFlushSender()) continue;
            _ = runtime.runtime.flushQueuedControl(state) catch continue;
        }
    }

    // ---- outbound QUIC request outcomes (docs/QUIC_REQUEST_OUTCOMES.md) ----

    /// Sends one request on a QUIC session and records it for
    /// event-side outcome classification. Returns the stream the
    /// request rides — the `(session_id, stream_id)` pair keys the
    /// reply (`quic_reply`) and every terminal outcome
    /// (`quic_request_failed`). Raw `queueReliable` sends stay
    /// untracked: a plain reliable send is not a request.
    ///
    /// Send-path pressure is synchronous (`error.QueueFull` /
    /// `FlowControlled` / `EndpointClosed` / `InvalidState` before
    /// the session is ready); map it through `classifyRequestError`.
    /// Deadlines are relative milliseconds against the node clock
    /// (`tick`'s `now_us`), exactly like `requestInproc`.
    pub fn requestQuic(
        self: *Node,
        session_id: QuicSessionId,
        outgoing: message.OutgoingMessage,
    ) !u64 {
        const runtime = self.quicSession(session_id) orelse return error.EndpointNotFound;

        // Keep the pending table in lockstep before adding a new
        // entry, so an outcome for anything already expired or
        // settled classifies before a new request joins the table.
        try self.sweepQuicPending(self.nowMs());

        const stream_id = try runtime.queueReliable(outgoing);
        try self.quic_pending.append(self.allocator, .{
            .session_id = session_id,
            .stream_id = stream_id,
            .id = outgoing.id,
            .deadline_ms = outgoing.deadline_ms,
            .sent_at_ms = self.nowMs(),
        });
        self.counters.sent += 1;
        return stream_id;
    }

    /// Cancels a pending outbound QUIC request: removes its pending
    /// entry and emits `quic_request_failed{.canceled}`. When the
    /// node owns the request's connection (dial clients) the cancel
    /// also reaches the wire — RESET of our send half plus
    /// STOP_SENDING for the reply half (app code `0x51_01`) — so a
    /// conforming peer stops computing the reply. First-wins: a
    /// request that already settled (reply observed, deadline fired,
    /// session died) returns false and nothing is emitted.
    pub fn cancelQuicRequest(
        self: *Node,
        session_id: QuicSessionId,
        stream_id: u64,
    ) !bool {
        const pending = self.takeQuicPending(session_id, stream_id) orelse return false;

        if (self.quicClientConnection(session_id)) |conn| {
            const plan = transport.quic_cancel.cancelPlan(
                stream_id,
                .explicit,
                .bidirectional,
            );
            _ = transport.quic_cancel.applyCancelPlan(conn, plan, .{}) catch {};
        }

        try self.emit(.{ .quic_request_failed = .{
            .session_id = session_id,
            .stream_id = stream_id,
            .id = pending.id,
            .failure = .canceled,
        } });
        return true;
    }

    /// Settles a pending request because its reply was observed —
    /// silently: the reply itself is the outcome. Called
    /// automatically by the session wrapper's `recvReliable` and by
    /// the `quic_reply` event drain; consumers draining replies
    /// through the inner runtime directly call this when they pop a
    /// reply they registered via `requestQuic`. Returns whether a
    /// pending entry was removed.
    pub fn settleQuicRequest(
        self: *Node,
        session_id: QuicSessionId,
        stream_id: u64,
    ) bool {
        const pending = self.takeQuicPending(session_id, stream_id) orelse return false;
        _ = pending;
        return true;
    }

    fn takeQuicPending(
        self: *Node,
        session_id: QuicSessionId,
        stream_id: u64,
    ) ?PendingQuicRequest {
        for (self.quic_pending.items, 0..) |pending, index| {
            if (pending.session_id != session_id or pending.stream_id != stream_id) continue;
            return self.quic_pending.orderedRemove(index);
        }
        return null;
    }

    /// The connection of a node-owned dial client, when one exists
    /// for `session_id`. Listener-side and embedded sessions ride
    /// connections the node does not own — no cancel plan can be
    /// applied there.
    fn quicClientConnection(self: *Node, session_id: QuicSessionId) ?*transport.quic_runtime.Connection {
        for (self.quic_clients.items) |client| {
            if (client.id() != session_id) continue;
            return client.client.runtime.connection();
        }
        return null;
    }

    /// One outcome pass over the QUIC pending table, in
    /// first-observation order per entry: a dead session classifies
    /// `.peer_closed`; a reply already sitting in the session's
    /// inbox settles silently (the consumer has not popped it yet,
    /// but the outcome is no longer in doubt); a passed deadline
    /// classifies `.deadline_exceeded`. Called from `tick` and
    /// before each `requestQuic` append.
    fn sweepQuicPending(self: *Node, now_ms: u64) !void {
        var index: usize = 0;
        while (index < self.quic_pending.items.len) {
            const pending = self.quic_pending.items[index];

            const runtime = self.quicSession(pending.session_id);
            const dead = runtime == null or
                runtime.?.runtime.isClosingOrClosed();
            if (dead) {
                _ = self.quic_pending.orderedRemove(index);
                try self.emit(.{ .quic_request_failed = .{
                    .session_id = pending.session_id,
                    .stream_id = pending.stream_id,
                    .id = pending.id,
                    .failure = .peer_closed,
                } });
                continue;
            }

            if (runtime.?.runtime.inboxHasStream(pending.stream_id)) {
                // The reply arrived; the consumer just has not popped
                // it yet. Settled — no event.
                _ = self.quic_pending.orderedRemove(index);
                continue;
            }

            if (pending.isExpired(now_ms)) {
                _ = self.quic_pending.orderedRemove(index);
                try self.emit(.{ .quic_request_failed = .{
                    .session_id = pending.session_id,
                    .stream_id = pending.stream_id,
                    .id = pending.id,
                    .failure = .deadline_exceeded,
                } });
                continue;
            }

            index += 1;
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
            // Embedded attach sessions are pull-consumed: their
            // inbound messages surface through `poll` events, never
            // through a dispatcher.
            if (runtime.runtime.event_delivery) continue;

            const attachment = self.quicSocketAttachment(runtime.id());
            const can_dispatch_reliable = comptime dispatcherHas(@TypeOf(dispatcher), "dispatchQuicReliable");
            if (attachment == null and !can_dispatch_reliable) continue;

            // Messages on the session's OWN request streams are
            // replies to outbound requests, not inbound requests:
            // leave them queued for the embedder's correlation
            // (recvReliable). Dispatching them made rep-dispatchers
            // answer replies — an echo whose sender then failed on
            // the already-reaped request stream.
            if (attachment == null) {
                const head_stream = runtime.runtime.peekReliableStreamId() orelse continue;
                if (!transport.quic_session_runtime.isPeerBidiStreamId(
                    runtime.runtime.session.role,
                    head_stream,
                )) continue;
            }

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

                if (comptime @hasField(@TypeOf(result), "publications")) {
                    for (result.publications.items) |publication| {
                        try runtime.queueDatagram(publication.outgoing());
                    }
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
            if (runtime.runtime.event_delivery) continue;

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
        try self.pumpEmbeddedQuic();

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
        options_in: transport.quic.QuicOptions,
    ) !DriverSession {
        var options = options_in;
        var minted: ?auth.HelloChallengeBinding = null;
        errdefer if (minted) |*binding| binding.deinit(self.allocator);

        // Channel binding: a listener armed with a challenge template
        // mints a fresh challenge for every accepted session so a
        // credential presented here verifies only against THIS
        // connection's implicit assertion. The session owns the
        // binding (and its bytes) for its lifetime.
        if (options.hello_challenge) |template| {
            minted = try self.mintHelloChallengeBinding(template, options.auth_config);
            options.auth_config = try minted.?.authConfig();
            options.auth.challenge = minted.?.challenge();
        }

        const runtime = try self.createQuicSession(.server, options, null);
        errdefer self.destroyQuicSession(runtime);
        if (minted) |binding| {
            runtime.runtime.session.hello_challenge_binding = binding;
            minted = null;
        }
        runtime.driver_owned = true;
        runtime.transport_ready = true;
        try runtime.runtime.onQuicReady();
        return runtime;
    }

    /// Mint a per-connection HELLO challenge from a listener
    /// template. Bytes come from the node's io (like the
    /// stateless-reset key), so no `std.Random` is needed at this
    /// seam; the binding takes ownership.
    fn mintHelloChallengeBinding(
        self: *Node,
        template: auth.HelloChallengeConfig,
        base_config: auth.AuthConfig,
    ) !auth.HelloChallengeBinding {
        try template.validate();
        const bytes = try self.allocator.alloc(u8, template.bytes);
        errdefer self.allocator.free(bytes);
        self.options.io.random(bytes);
        const state = try auth.HelloChallengeState.fromOwnedChallenge(
            template.context,
            bytes,
            .{ .required = true, .max_bytes = template.max_bytes },
        );
        return auth.HelloChallengeBinding.init(state, base_config);
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

    /// Inbound control frames from a session's follow-up uni
    /// streams (SUBSCRIBE/UNSUBSCRIBE/CREDIT): applied into the
    /// node's registry through the session's control state. Frames
    /// are BORROWED — the dispatch's control-read pump owns and
    /// frees them; the registry/ledger copy what they keep.
    pub fn driverControlFramesReceived(
        self: *Node,
        sess: DriverSession,
        frames: []@import("control.zig").Frame,
    ) !void {
        _ = self;
        const state = &(sess.control_state orelse return);
        _ = try state.applyReceivedFrames(quicRegistryPeer(sess.id()), frames);
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
            // A dial connection that reached QUIC's TERMINAL closed
            // state (peer CONNECTION_CLOSE observed through the
            // draining deadline, a stateless reset, an idle or
            // handshake timeout) will never carry bytes again: stop
            // pumping it and close the session below, through the
            // same path an explicit `closeQuicSession` takes.
            // Terminal-only on purpose — `closeState()`'s
            // closing/draining are an in-progress close, not death —
            // and detection lags the wire event by the draining
            // window: late and certain beats early and guessed.
            if (client.client.runtime.connection().isClosed()) continue;
            try self.ensureClientReady(client);
            try self.pumpClientSession(client);
            while (try client.client.drainAndSendOne(now_us)) |_| {}
        }
        try self.reapDeadQuicClients();
    }

    /// Closes every dial session whose connection is terminally dead.
    /// `closeQuicSession` removes entries from `quic_clients` — the
    /// list being scanned — so the scan restarts after each close
    /// instead of iterating a mutating list. Each close emits
    /// `.closed` and destroys the session; pending requests classify
    /// `.peer_closed` in the same tick's outcome sweep (the sweep
    /// runs after `tickQuicClients` in `tick`).
    fn reapDeadQuicClients(self: *Node) !void {
        while (true) {
            var dead: ?QuicSessionId = null;
            for (self.quic_clients.items) |client| {
                if (!client.client.runtime.connection().isClosed()) continue;
                dead = client.id();
                break;
            }
            const id = dead orelse return;
            try self.closeQuicSession(id);
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
            .node = self,
            .runtime = try transport.quic_session_runtime.QuicSessionRuntime.init(
                self.allocator,
                self.nextSessionId(),
                role,
                options,
            ),
            .control_state = transport.quic_control.State.init(
                self.allocator,
                &self.quic_registry,
                &self.quic_credit_ledger,
                .{},
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
        // A dying subscriber must not linger in the fan-out set.
        _ = self.quic_registry.removePeer(quicRegistryPeer(runtime.id()));
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

fn quicRegistryPeer(id: QuicSessionId) protocol.pubsub.PeerId {
    return @intCast(id);
}

const peerQueueDefaults: queue.QueueOptions = .{};

fn eventCarriesMessage(event: Event) bool {
    return switch (event) {
        .request, .reply, .delivery, .quic_request, .quic_reply, .quic_delivery => true,
        .connected, .closed, .message_dropped, .request_failed, .quic_request_failed => false,
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

test "Node runOnce leaves replies on own request streams undispatched" {
    const allocator = std.testing.allocator;

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const runtime = try n.openQuicSession(.{
        .role = .client,
        .transport = .{ .peer_id = "client-a" },
    });
    try readyQuicRuntimeForTest(runtime, "server-a", false);

    // A reply to the client's own request (stream 0: locally
    // initiated for the client role) queued ahead of a genuine
    // inbound request on a peer-initiated stream (stream 1).
    try queueReliableForTest(runtime, 0, .{
        .subject = "user.get",
        .id = 7,
        .flags = .{ .final = true },
        .body = "user-42",
    });
    try queueReliableForTest(runtime, 1, .{
        .subject = "time.now",
        .id = 9,
        .body = "?",
    });

    const Dispatcher = struct {
        calls: usize = 0,

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
            self.calls += 1;

            // An answering dispatcher: the echo that used to be sent
            // back onto the (already reaped) request stream.
            var owned = incoming;
            defer owned.deinit();
            var result = Result{ .allocator = owned.allocator };
            const reply = try message.Message.init(owned.allocator, .{
                .subject = owned.subject,
                .id = owned.id,
                .flags = .{ .final = true },
                .body = "echo",
            });
            errdefer {
                var cleanup = reply;
                cleanup.deinit();
            }
            try result.replies.append(owned.allocator, reply);
            return result;
        }
    };

    var dispatcher = Dispatcher{};
    const result = try n.runOnce(&dispatcher);

    // The reply at the inbox head gates dispatch for the session:
    // nothing was dispatched (an answering dispatcher would have
    // echoed onto a reaped stream), and the inbox is untouched for
    // the embedder's own correlation.
    try std.testing.expectEqual(@as(usize, 0), dispatcher.calls);
    try std.testing.expect(!result.didWork());
    try std.testing.expectEqual(@as(usize, 2), runtime.runtime.inboxLen());

    var reply = runtime.runtime.recvReliable() orelse return error.ReplyMissing;
    defer reply.deinit();
    try std.testing.expectEqual(@as(u64, 0), reply.stream_id);
    try std.testing.expectEqual(@as(message.MessageId, 7), reply.message.id);
    try std.testing.expectEqualStrings("user-42", reply.message.body);

    var request = runtime.runtime.recvReliable() orelse return error.RequestMissing;
    defer request.deinit();
    try std.testing.expectEqual(@as(u64, 1), request.stream_id);
    try std.testing.expectEqualStrings("time.now", request.message.subject);
}

// ---- inbound embed seam (foreign-driver attach, hermetic) --------------------

const quic_zig = @import("quic");

/// A stand-in for mruby-quic's embedder: it owns the listener, the
/// Driver, and the loop; qmsg only rides the connections it routes
/// in by ALPN. Per-connection state is one embedded seat.
const ForeignEmbedder = struct {
    allocator: std.mem.Allocator,
    node: *Node,
    dispatch: transport.quic_embedded.EmbeddedDispatch(Node),
    driver: D,

    pub const D = quic_zig.app.Driver(@This());

    /// Per-connection state, exactly as a real embedder keeps it: the
    /// qmsg seat rides alongside the embedder's own connection state.
    pub const ConnState = struct {
        qmsg: ?transport.quic_embedded.EmbeddedDispatch(Node).Seat = null,
    };

    pub const StreamState = struct {};

    fn create(
        allocator: std.mem.Allocator,
        node: *Node,
        transport_options: transport.quic.QuicOptions,
    ) !*ForeignEmbedder {
        const self = try allocator.create(ForeignEmbedder);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .node = node,
            .dispatch = transport.quic_embedded.EmbeddedDispatch(Node).init(
                allocator,
                node,
                transport_options,
                .events,
            ),
            .driver = undefined,
        };
        self.driver = try D.init(.{
            .allocator = allocator,
            .app = self,
            .hooks = .{
                .on_handshake = onHandshake,
                .on_stream_open = onStreamOpen,
                .on_stream_data = onStreamData,
                .on_stream_end = onStreamEnd,
                .on_datagram = onDatagram,
                .on_disconnect = onDisconnect,
            },
            .max_tracked_streams = transport.quic_embedded.driverSizing(transport_options).max_tracked_streams,
            .datagram_buf_bytes = transport.quic_embedded.driverSizing(transport_options).datagram_buf_bytes,
        });
        return self;
    }

    fn destroy(self: *ForeignEmbedder) void {
        self.driver.deinit();
        self.allocator.destroy(self);
    }

    fn onHandshake(app: *@This(), s: *D.Session) anyerror!void {
        if (!transport.quic_embedded.isQmsgAlpn(s.conn)) return;
        if (s.app.qmsg != null) return;
        var seat = transport.quic_embedded.EmbeddedDispatch(Node).Seat.init(app.allocator);
        try app.dispatch.onHandshake(&seat, s.conn);
        s.app.qmsg = seat;
    }

    fn onStreamOpen(app: *@This(), s: *D.Session, e: *D.StreamEntry, bidi: bool) anyerror!void {
        if (s.app.qmsg == null) return;
        try app.dispatch.onStreamOpen(&s.app.qmsg.?, e.id, bidi);
    }

    fn onStreamData(app: *@This(), s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
        if (s.app.qmsg == null) return;
        try app.dispatch.onStreamData(&s.app.qmsg.?, s.conn, e.id, chunk);
    }

    fn onStreamEnd(app: *@This(), s: *D.Session, e: *D.StreamEntry, end: quic_zig.app.StreamEnd) anyerror!void {
        if (s.app.qmsg == null) return;
        try app.dispatch.onStreamEnd(&s.app.qmsg.?, s.conn, e.id, end);
    }

    fn onDatagram(app: *@This(), s: *D.Session, datagram: D.Datagram) anyerror!void {
        if (s.app.qmsg == null) return;
        try app.dispatch.onDatagram(&s.app.qmsg.?, datagram.bytes, datagram.arrived_in_early_data);
    }

    fn onDisconnect(app: *@This(), s: *D.Session) void {
        if (s.app.qmsg == null) return;
        app.dispatch.onDisconnect(&s.app.qmsg.?);
        s.app.qmsg = null;
    }
};

const EmbedTestPeers = struct {
    listener: transport.quic_runtime.ListenerRuntime,
    embedder: *ForeignEmbedder,
    client: transport.quic_runtime.ClientRuntime,
    rx: [8192]u8 = undefined,
    now_us: u64 = 1_000,

    fn drive(self: *EmbedTestPeers) !void {
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
        try self.embedder.driver.service(&self.listener.server);
        for (self.listener.server.iterator()) |slot| {
            const ds = self.embedder.driver.sessionOn(slot) orelse continue;
            if (ds.app.qmsg == null) continue;
            try self.embedder.dispatch.serviceSeat(&ds.app.qmsg.?, slot.conn);
        }
        while (try self.listener.drainOutbound(&self.rx, self.now_us)) |out| {
            try self.client.feedInbound(.{ .bytes = self.rx[0..out.len] }, self.now_us);
        }
        try self.listener.tick(self.now_us);
        try self.client.tick(self.now_us);
        self.now_us += 1_000;
    }
};

/// Builds the hermetic peers (embedder-owned listener + dial client)
/// around `node`. The caller owns teardown; LIFO defers must run
/// `p.listener.deinit()` before `p.embedder.destroy()` (the will-close
/// ride-along), then `p.client.deinit()`.
fn embedPeersInit(
    p: *EmbedTestPeers,
    allocator: std.mem.Allocator,
    node: *Node,
    server_opts: transport.quic.QuicOptions,
    client_opts: transport.quic.QuicOptions,
) !void {
    p.* = .{ .listener = undefined, .embedder = undefined, .client = undefined, .now_us = 1_000 };
    p.listener = try transport.quic_runtime.ListenerRuntime.init(allocator, "127.0.0.1:4433", .{
        .tls_cert_pem = dispatch_test_cert_pem,
        .tls_key_pem = dispatch_test_key_pem,
        .transport = server_opts,
    });
    p.embedder = try ForeignEmbedder.create(allocator, node, server_opts);
    p.embedder.driver.attach(&p.listener.server);
    p.client = try transport.quic_runtime.ClientRuntime.init(allocator, "127.0.0.1:4433", .{
        .server_name = "localhost",
        .insecure_skip_verify = true, // self-signed test fixture
        .transport = client_opts,
    });
}

/// Drives the peers through the TLS handshake and the qmsg HELLO
/// exchange until both runtimes are ready; returns the embedded
/// server-side session.
fn embedPeersUntilReady(
    p: *EmbedTestPeers,
    node: *Node,
    client_sess: *QuicSessionRuntime,
) !*QuicSessionRuntime {
    var step: u32 = 0;
    while (step < 4_000) : (step += 1) {
        try p.drive();
        if (p.client.connection().handshakeDone() and
            p.listener.connectionCount() > 0 and
            p.listener.connection(0).?.handshakeDone()) break;
    }
    client_sess.transport_ready = true;
    try client_sess.runtime.onQuicReady();

    var embedded_sess: ?*QuicSessionRuntime = null;
    step = 0;
    while (step < 4_000) : (step += 1) {
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        try p.drive();
        if (embedded_sess == null) {
            for (node.quic_sessions.items) |candidate| {
                if (candidate != client_sess) embedded_sess = candidate;
            }
        }
        const embedded_ready = if (embedded_sess) |sess| sess.state() == .ready else false;
        if (client_sess.state() == .ready and embedded_ready) break;
    }
    return embedded_sess orelse error.ServerSessionMissing;
}

test "foreign embedder drives qmsg sessions through its own Driver end to end" {
    const allocator = std.testing.allocator;
    const control = @import("control.zig");

    const server_opts: transport.quic.QuicOptions = .{
        .peer_id = "embed-server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        .datagram_enabled = true,
    };
    const client_opts: transport.quic.QuicOptions = .{
        .peer_id = "embed-client",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        .datagram_enabled = true,
    };

    var node = try Node.init(allocator, .{});
    defer node.deinit();

    var p: EmbedTestPeers = undefined;
    try embedPeersInit(&p, allocator, &node, server_opts, client_opts);
    // Defer order (LIFO): listener FIRST (its Server.deinit fires the
    // will-close hook, whose on_disconnect destroys the embedded
    // session through the owner while the node is still alive), then
    // the embedder's driver, then the client — the teardown
    // ride-along under test.
    defer p.embedder.destroy();
    defer p.listener.deinit();
    defer p.client.deinit();

    const client_sess = try node.openQuicSession(.{
        .role = .client,
        .transport = client_opts,
    });

    // Handshake + HELLO exchange: the server side is driven entirely
    // by the embedder's Driver hooks.
    const srv_sess = try embedPeersUntilReady(&p, &node, client_sess);
    try std.testing.expectEqual(transport.quic.State.ready, client_sess.state());
    try std.testing.expectEqual(transport.quic.State.ready, srv_sess.state());
    try std.testing.expect(srv_sess.runtime.event_delivery);

    // Request: client -> embedded server through the foreign driver.
    const stream_id = try client_sess.queueReliable(.{
        .subject = "user.get",
        .id = 4242,
        .deadline_ms = 1_000,
        .body = "ada",
    });
    var got_request = false;
    var step: u32 = 0;
    while (step < 4_000 and !got_request) : (step += 1) {
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        try p.drive();
        var events: [4]Event = undefined;
        const count = try node.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .quic_request => |*ev| {
                    try std.testing.expectEqual(srv_sess.id(), ev.session_id);
                    try std.testing.expectEqual(stream_id, ev.stream_id);
                    try std.testing.expectEqual(@as(message.MessageId, 4242), ev.msg.id);
                    try std.testing.expectEqualStrings("user.get", ev.msg.subject);
                    try std.testing.expectEqualStrings("ada", ev.msg.body);
                    try node.replyQuic(ev, .{ .subject = "", .body = "Ada Lovelace" });
                    got_request = true;
                },
                else => {},
            }
        }
    }
    try std.testing.expect(got_request);

    // Reply: embedded server -> client on the request's own stream
    // (the receiver queueReliable armed).
    var reply: ?transport.quic_session_runtime.ReceivedReliable = null;
    step = 0;
    while (step < 4_000 and reply == null) : (step += 1) {
        try p.drive();
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        reply = client_sess.runtime.recvReliable();
    }
    var got_reply = reply orelse return error.ReplyMissing;
    defer got_reply.deinit();
    try std.testing.expectEqual(stream_id, got_reply.stream_id);
    try std.testing.expectEqual(@as(message.MessageId, 4242), got_reply.message.id);
    try std.testing.expectEqualStrings("Ada Lovelace", got_reply.message.body);

    // Datagram delivery: client publishes, the embedded session's
    // poll events surface it as quic_delivery.
    _ = try transport.quic_datagram.send(
        p.client.connection(),
        allocator,
        .{ .subject = "presence.ada", .flags = .{ .unreliable = true }, .body = "online" },
        .{ .fallback = .datagram_only },
    );
    var got_delivery = false;
    step = 0;
    while (step < 4_000 and !got_delivery) : (step += 1) {
        try p.drive();
        var events: [4]Event = undefined;
        const count = try node.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .quic_delivery => |*ev| {
                    try std.testing.expectEqual(srv_sess.id(), ev.session_id);
                    try std.testing.expectEqualStrings("presence.ada", ev.msg.subject);
                    try std.testing.expectEqualStrings("online", ev.msg.body);
                    got_delivery = true;
                },
                else => {},
            }
        }
    }
    try std.testing.expect(got_delivery);

    // The session's lifecycle rides the embedder's will-close path:
    // fall off the end with the connection live; the defers tear the
    // listener down first (hook -> onDisconnect -> session destroyed
    // exactly once), then the driver, then the node's leftovers.
}

test "foreign embedder: reply deferred past the poll loop still reaches the requester" {
    const allocator = std.testing.allocator;
    const control = @import("control.zig");

    const server_opts: transport.quic.QuicOptions = .{
        .peer_id = "embed-server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };
    const client_opts: transport.quic.QuicOptions = .{
        .peer_id = "embed-client",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };

    var node = try Node.init(allocator, .{});
    defer node.deinit();

    var p: EmbedTestPeers = undefined;
    try embedPeersInit(&p, allocator, &node, server_opts, client_opts);
    defer p.embedder.destroy();
    defer p.listener.deinit();
    defer p.client.deinit();

    const client_sess = try node.openQuicSession(.{
        .role = .client,
        .transport = client_opts,
    });
    const srv_sess = try embedPeersUntilReady(&p, &node, client_sess);

    // One request. The embedder's actor does NOT answer inline: the
    // quic_request event is merely held, and the reply is queued from
    // a deferred delivery pass several drive iterations later.
    const req_stream = try client_sess.queueReliable(.{
        .subject = "user.get",
        .id = 77,
        .deadline_ms = 500,
        .body = "ada",
    });

    var got_request = false;
    var subject_buf: [64]u8 = undefined;
    var subject_len: usize = 0;
    var req_id: message.MessageId = 0;
    var req_deadline: ?u64 = null;
    var step: u32 = 0;
    while (step < 4_000 and !got_request) : (step += 1) {
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        try p.drive();
        var events: [4]Event = undefined;
        const count = try node.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .quic_request => |*ev| {
                    try std.testing.expectEqual(req_stream, ev.stream_id);
                    subject_len = @min(ev.msg.subject.len, subject_buf.len);
                    @memcpy(subject_buf[0..subject_len], ev.msg.subject[0..subject_len]);
                    req_id = ev.msg.id;
                    req_deadline = ev.msg.deadline_ms;
                    got_request = true;
                },
                else => {},
            }
        }
    }
    try std.testing.expect(got_request);

    // The deferred pass: iterations keep flowing while the request is
    // merely held. Whatever the seat does during this window must not
    // make the later reply unwritable.
    var idle: u32 = 0;
    while (idle < 50) : (idle += 1) {
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        try p.drive();
    }

    var held: QuicRequestEvent = .{
        .session_id = srv_sess.id(),
        .stream_id = req_stream,
        .msg = .{
            .allocator = allocator,
            .subject = subject_buf[0..subject_len],
            .id = req_id,
            .deadline_ms = req_deadline,
        },
    };
    try node.replyQuic(&held, .{ .subject = "", .body = "Ada Lovelace (deferred)" });

    var reply: ?transport.quic_session_runtime.ReceivedReliable = null;
    step = 0;
    while (step < 4_000 and reply == null) : (step += 1) {
        try p.drive();
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        reply = client_sess.runtime.recvReliable();
    }
    var got_reply = reply orelse return error.ReplyMissing;
    defer got_reply.deinit();
    try std.testing.expectEqual(req_stream, got_reply.stream_id);
    try std.testing.expectEqual(req_id, got_reply.message.id);
    try std.testing.expectEqualStrings("Ada Lovelace (deferred)", got_reply.message.body);
    try std.testing.expectEqual(transport.quic.State.ready, srv_sess.state());
}

test "foreign embedder: two requests on one session, one unanswered, keep the connection" {
    const allocator = std.testing.allocator;
    const control = @import("control.zig");

    const server_opts: transport.quic.QuicOptions = .{
        .peer_id = "embed-server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };
    const client_opts: transport.quic.QuicOptions = .{
        .peer_id = "embed-client",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };

    var node = try Node.init(allocator, .{});
    defer node.deinit();

    var p: EmbedTestPeers = undefined;
    try embedPeersInit(&p, allocator, &node, server_opts, client_opts);
    defer p.embedder.destroy();
    defer p.listener.deinit();
    defer p.client.deinit();

    const client_sess = try node.openQuicSession(.{
        .role = .client,
        .transport = client_opts,
    });
    const srv_sess = try embedPeersUntilReady(&p, &node, client_sess);

    // Two requests in one flight, mirroring the consumer's actor: one
    // answered, one deliberately never answered (its deadline is the
    // requester's business, not the server's).
    const echo_stream = try client_sess.queueReliable(.{
        .subject = "remote.echo",
        .id = 1,
        .deadline_ms = 2_000,
        .body = "payload",
    });
    const silent_stream = try client_sess.queueReliable(.{
        .subject = "remote.silent",
        .id = 2,
        .deadline_ms = 60,
        .body = "x",
    });
    try std.testing.expectEqual(@as(u64, 0), echo_stream);
    try std.testing.expectEqual(@as(u64, 4), silent_stream);

    var echoed = false;
    var silent_seen = false;
    var step: u32 = 0;
    while (step < 4_000 and (!echoed or !silent_seen)) : (step += 1) {
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        try p.drive();
        var events: [4]Event = undefined;
        const count = try node.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .quic_request => |*ev| {
                    if (ev.stream_id == echo_stream) {
                        try node.replyQuic(ev, .{ .subject = "", .body = "pong" });
                        echoed = true;
                    } else if (ev.stream_id == silent_stream) {
                        silent_seen = true; // held; no reply, ever
                    }
                },
                else => {},
            }
        }
    }
    try std.testing.expect(echoed);
    try std.testing.expect(silent_seen);

    // The answered request's reply must arrive...
    var reply: ?transport.quic_session_runtime.ReceivedReliable = null;
    step = 0;
    while (step < 4_000 and reply == null) : (step += 1) {
        try p.drive();
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        reply = client_sess.runtime.recvReliable();
    }
    var got_reply = reply orelse return error.ReplyMissing;
    defer got_reply.deinit();
    try std.testing.expectEqual(echo_stream, got_reply.stream_id);
    try std.testing.expectEqual(@as(message.MessageId, 1), got_reply.message.id);
    try std.testing.expectEqualStrings("pong", got_reply.message.body);

    // ...and the connection must survive both requests plus the never
    // answered one: a third request still round-trips.
    try std.testing.expectEqual(transport.quic.State.ready, srv_sess.state());
    try std.testing.expectEqual(transport.quic.State.ready, client_sess.state());
    const third_stream = try client_sess.queueReliable(.{
        .subject = "remote.echo",
        .id = 3,
        .deadline_ms = 2_000,
        .body = "again",
    });
    var third_replied = false;
    step = 0;
    while (step < 4_000 and !third_replied) : (step += 1) {
        _ = try client_sess.runtime.pumpConnection(p.client.connection());
        try p.drive();
        var events: [4]Event = undefined;
        const count = try node.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .quic_request => |*ev| {
                    if (ev.stream_id == third_stream) {
                        try node.replyQuic(ev, .{ .subject = "", .body = "pong-3" });
                    }
                },
                else => {},
            }
        }
        if (client_sess.runtime.recvReliable()) |late| {
            var owned_late = late;
            defer owned_late.deinit();
            if (owned_late.stream_id == third_stream) third_replied = true;
        }
    }
    try std.testing.expect(third_replied);
    try std.testing.expectEqual(transport.quic.State.ready, srv_sess.state());
}

// ---- outbound QUIC request outcomes (docs/QUIC_REQUEST_OUTCOMES.md) --------

fn outcomeTestSession(n: *Node) !*QuicSessionRuntime {
    const sess = try n.openQuicSession(.{
        .role = .client,
        .transport = .{ .peer_id = "outcome-client" },
    });
    sess.transport_ready = true;
    try sess.runtime.onQuicReady();

    const allocator = sess.runtime.allocator;
    const peer_hello = try transport.quic.encodeHelloControlStream(allocator, .{
        .peer_id = "outcome-server",
    });
    defer allocator.free(peer_hello);
    try sess.runtime.session.acceptPeerControl(peer_hello);
    return sess;
}

fn injectReplyForTest(
    sess: *QuicSessionRuntime,
    stream_id: u64,
    id: message.MessageId,
) !void {
    const allocator = sess.runtime.allocator;
    var incoming = try message.Message.init(allocator, .{
        .subject = "user.get",
        .id = id,
        .flags = .{ .final = true },
        .body = "reply",
    });
    errdefer incoming.deinit();
    try sess.runtime.inbox.append(allocator, .{
        .stream_id = stream_id,
        .message = incoming,
    });
}

fn pollForQuicRequestFailed(
    n: *Node,
    events: []Event,
) !?QuicRequestFailedEvent {
    const count = try n.poll(events);
    var found: ?QuicRequestFailedEvent = null;
    for (events[0..count]) |*event| {
        defer event.deinit();
        switch (event.*) {
            .quic_request_failed => |ev| found = ev,
            else => {},
        }
    }
    return found;
}

test "quic request outcomes: deadline, reply-wins, cancel, close, first-wins" {
    const allocator = std.testing.allocator;
    var n = try Node.init(allocator, .{});
    defer n.deinit();

    // Deadline expiry classifies once, keyed (session, stream), and
    // never re-classifies.
    {
        const sess = try outcomeTestSession(&n);
        const stream_id = try n.requestQuic(sess.id(), .{
            .subject = "remote.slow",
            .id = 1,
            .deadline_ms = 100,
            .body = "x",
        });
        try n.tick(1_000);
        var events: [4]Event = undefined;
        try std.testing.expectEqual(
            @as(?QuicRequestFailedEvent, null),
            try pollForQuicRequestFailed(&n, &events),
        );

        try n.tick(150_000); // deadline (sent_at 1ms + 100ms) passed
        const failed = (try pollForQuicRequestFailed(&n, &events)).?;
        try std.testing.expectEqual(sess.id(), failed.session_id);
        try std.testing.expectEqual(stream_id, failed.stream_id);
        try std.testing.expectEqual(@as(message.MessageId, 1), failed.id);
        try std.testing.expectEqual(RequestFailure.deadline_exceeded, failed.failure);

        try n.tick(500_000);
        try std.testing.expectEqual(
            @as(?QuicRequestFailedEvent, null),
            try pollForQuicRequestFailed(&n, &events),
        );
    }

    // A reply already in the inbox settles the request silently — the
    // reply IS the outcome — and popping it through the wrapper
    // settles too; no deadline fires afterwards either way.
    {
        const sess = try outcomeTestSession(&n);
        const stream_id = try n.requestQuic(sess.id(), .{
            .subject = "remote.echo",
            .id = 2,
            .deadline_ms = 100,
            .body = "y",
        });
        try injectReplyForTest(sess, stream_id, 2);
        try n.tick(150_000); // deadline passed, but the reply won
        var events: [4]Event = undefined;
        try std.testing.expectEqual(
            @as(?QuicRequestFailedEvent, null),
            try pollForQuicRequestFailed(&n, &events),
        );
        try std.testing.expectEqual(@as(usize, 0), n.quic_pending.items.len);

        // Wrapper pop settles requests whose reply was injected.
        const stream_id_b = try n.requestQuic(sess.id(), .{
            .subject = "remote.echo",
            .id = 3,
            .deadline_ms = 100,
            .body = "z",
        });
        try injectReplyForTest(sess, stream_id_b, 3);
        var popped = sess.recvReliable() orelse return error.ReplyMissing;
        popped.deinit();
        try n.tick(150_000);
        try std.testing.expectEqual(
            @as(?QuicRequestFailedEvent, null),
            try pollForQuicRequestFailed(&n, &events),
        );
    }

    // Explicit cancel classifies .canceled exactly once; a second
    // cancel is a no-op.
    {
        const sess = try outcomeTestSession(&n);
        const stream_id = try n.requestQuic(sess.id(), .{
            .subject = "remote.echo",
            .id = 4,
            .body = "w",
        });
        try std.testing.expect(try n.cancelQuicRequest(sess.id(), stream_id));
        var events: [4]Event = undefined;
        const failed = (try pollForQuicRequestFailed(&n, &events)).?;
        try std.testing.expectEqual(RequestFailure.canceled, failed.failure);
        try std.testing.expectEqual(@as(message.MessageId, 4), failed.id);

        try std.testing.expect(!(try n.cancelQuicRequest(sess.id(), stream_id)));
        try n.tick(1_000);
        try std.testing.expectEqual(
            @as(?QuicRequestFailedEvent, null),
            try pollForQuicRequestFailed(&n, &events),
        );
    }

    // A dying session classifies every still-pending request as
    // .peer_closed.
    {
        const sess = try outcomeTestSession(&n);
        _ = try n.requestQuic(sess.id(), .{ .subject = "remote.a", .id = 5, .body = "a" });
        _ = try n.requestQuic(sess.id(), .{ .subject = "remote.b", .id = 6, .body = "b" });
        sess.runtime.beginClosing();

        try n.tick(1_000);
        var events: [4]Event = undefined;
        const count = try n.poll(&events);
        var failures: usize = 0;
        try std.testing.expect(count >= 2);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .quic_request_failed => |ev| {
                    failures += 1;
                    try std.testing.expectEqual(sess.id(), ev.session_id);
                    try std.testing.expectEqual(RequestFailure.peer_closed, ev.failure);
                },
                .connected => {}, // session-creation event still queued
                else => return error.UnexpectedEvent,
            }
        }
        try std.testing.expectEqual(@as(usize, 2), failures);
        try std.testing.expectEqual(@as(usize, 0), n.quic_pending.items.len);
    }

    // Raw queueReliable stays untracked: no deadline classification
    // for plain reliable sends.
    {
        const sess = try outcomeTestSession(&n);
        _ = try sess.queueReliable(.{
            .subject = "plain.send",
            .id = 7,
            .deadline_ms = 10,
            .body = "untracked",
        });
        try n.tick(100_000);
        var events: [4]Event = undefined;
        try std.testing.expectEqual(
            @as(?QuicRequestFailedEvent, null),
            try pollForQuicRequestFailed(&n, &events),
        );
        try std.testing.expectEqual(@as(usize, 0), n.quic_pending.items.len);
    }
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
        // runOnce runs BEFORE the reply check on purpose: a reply on
        // the client's own request stream must survive runOnce
        // undispatched (a rep-dispatcher would otherwise answer it,
        // and that echo sender fails on the reaped request stream).
        // It stays queued for this recvReliable.
        _ = try n.runOnce(&dispatcher);
        reply = client.runtime.recvReliable();
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

const LivePhaseBDispatcher = struct {
    allocator: std.mem.Allocator,

    const Result = struct {
        allocator: std.mem.Allocator,
        replies: std.ArrayList(message.Message) = .empty,

        fn deinit(self: *Result) void {
            for (self.replies.items) |*msg| msg.deinit();
            self.replies.deinit(self.allocator);
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
        // The consumer's phase-B shape: one subject answered, one
        // deliberately never answered (its deadline is the
        // requester's business, not this server's).
        if (std.mem.eql(u8, owned.subject, "remote.silent")) return result;

        const reply = try message.Message.init(self.allocator, .{
            .subject = owned.subject,
            .id = owned.id,
            .flags = .{ .final = true },
            .deadline_ms = owned.deadline_ms,
            .body = "pong",
        });
        errdefer {
            var cleanup = reply;
            cleanup.deinit();
        }
        try result.replies.append(self.allocator, reply);
        return result;
    }
};

// The consumer's phase-B regression shape, verbatim structure: a
// qmsg-owned listener on an ephemeral port, one dial session issuing
// an answered and a never-answered request in the same flight, driven
// `tick; runOnce` — with tick errors SURFACED (their loop swallows
// them with `catch {}`, which is how the v0.1.4 failure hid).
test "live UDP: answered and unanswered requests on one dial session (phase B mirror)" {
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

    const echo_stream = try n.requestQuic(client_session_id, .{
        .subject = "remote.echo",
        .id = 11,
        .deadline_ms = 2_000,
        .body = "payload",
    });
    const silent_stream = try n.requestQuic(client_session_id, .{
        .subject = "remote.silent",
        .id = 12,
        .deadline_ms = 60,
        .body = "x",
    });

    var dispatcher = LivePhaseBDispatcher{ .allocator = allocator };
    var got_reply: ?transport.quic_session_runtime.ReceivedReliable = null;
    step = 0;
    while (step < 20_000 and got_reply == null) : (step += 1) {
        now_us += 1_000;
        try n.tick(now_us);
        _ = try n.runOnce(&dispatcher);
        // Wrapper pop: settles the request the reply completes, so a
        // later sweep cannot misclassify it.
        got_reply = client.recvReliable();
    }
    var reply = got_reply orelse return error.ReplyMissing;
    defer reply.deinit();
    try std.testing.expectEqual(echo_stream, reply.stream_id);
    try std.testing.expectEqual(@as(message.MessageId, 11), reply.message.id);
    try std.testing.expectEqualStrings("pong", reply.message.body);

    // The never-answered sibling must not take the connection down:
    // both sessions stay ready and a third request round-trips.
    try std.testing.expectEqual(transport.quic.State.ready, client.state());
    try std.testing.expect(liveServerSessionReady(&n, client_session_id));

    const third_stream = try n.requestQuic(client_session_id, .{
        .subject = "remote.echo",
        .id = 13,
        .deadline_ms = 2_000,
        .body = "again",
    });
    var third: ?transport.quic_session_runtime.ReceivedReliable = null;
    step = 0;
    while (step < 20_000 and third == null) : (step += 1) {
        now_us += 1_000;
        try n.tick(now_us);
        _ = try n.runOnce(&dispatcher);
        if (client.recvReliable()) |late| {
            if (late.stream_id == third_stream) {
                third = late;
            } else {
                var stray = late;
                stray.deinit();
            }
        }
    }
    var got_third = third orelse return error.ThirdReplyMissing;
    defer got_third.deinit();
    try std.testing.expectEqual(@as(message.MessageId, 13), got_third.message.id);
    try std.testing.expectEqual(transport.quic.State.ready, client.state());

    // Dial-side outcome classification, live: the silent request —
    // dispatched by the server, never answered — ends as exactly one
    // `quic_request_failed{.deadline_exceeded}` keyed by its (session,
    // stream); the answered and third requests never classify.
    var silent_failure: ?QuicRequestFailedEvent = null;
    var stray_failures: usize = 0;
    step = 0;
    while (step < 20_000 and silent_failure == null) : (step += 1) {
        now_us += 1_000;
        try n.tick(now_us);
        _ = try n.runOnce(&dispatcher);
        var events: [4]Event = undefined;
        const count = try n.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .quic_request_failed => |ev| {
                    if (ev.stream_id == silent_stream) {
                        silent_failure = ev;
                    } else {
                        stray_failures += 1;
                    }
                },
                else => {},
            }
        }
    }
    const failed = silent_failure orelse return error.SilentFailureMissing;
    try std.testing.expectEqual(client_session_id, failed.session_id);
    try std.testing.expectEqual(@as(message.MessageId, 12), failed.id);
    try std.testing.expectEqual(RequestFailure.deadline_exceeded, failed.failure);
    try std.testing.expectEqual(@as(usize, 0), stray_failures);
    try std.testing.expectEqual(@as(usize, 0), n.quic_pending.items.len);
    try std.testing.expectEqual(transport.quic.State.ready, client.state());
}

// The consumer's swarm visibility seam: a dial session must OBSERVE
// its connection dying. The remote closes (CONNECTION_CLOSE on the
// wire), the dial passes through closing/draining, and once the
// connection is terminally closed the node tears the session down
// through closeQuicSession's path: `.closed` emitted, session gone,
// and in-flight requestQuic pendings classify `.peer_closed` in the
// same tick's sweep. Detection lags the wire event by the draining
// window — late and certain.
test "live UDP: dial session observes remote death, closes, and classifies pendings" {
    const allocator = std.testing.allocator;
    const control = @import("control.zig");

    const server_opts: transport.quic.QuicOptions = .{
        .peer_id = "doomed-server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };
    const client_opts: transport.quic.QuicOptions = .{
        .peer_id = "death-watcher",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };

    var server = try Node.init(allocator, .{});
    const server_listener_id = server.listenQuic("127.0.0.1:0", .{
        .tls_cert_pem = dispatch_test_cert_pem,
        .tls_key_pem = dispatch_test_key_pem,
        .transport = server_opts,
    }) catch |err| switch (err) {
        error.AccessDenied,
        error.AddressInUse,
        error.AddressUnavailable,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    const server_listener = server.quic_listeners.items[server_listener_id];
    const target = try localhostEndpoint(allocator, server_listener.localAddress());
    defer allocator.free(target);

    var n = try Node.init(allocator, .{});
    defer n.deinit();
    const client_session_id = try n.dialQuic(target, .{
        .server_name = "localhost",
        .ca_pem = dispatch_test_cert_pem,
        .transport = client_opts,
    });
    const client = n.quicSession(client_session_id) orelse return error.EndpointNotFound;

    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < 20_000) : (step += 1) {
        now_us += 1_000;
        try server.tick(now_us);
        try n.tick(now_us);
        if (client.state() == .ready and liveServerSessionReady(&n, client_session_id)) break;
    }
    try std.testing.expectEqual(transport.quic.State.ready, client.state());

    // Healthy ticks emit no `.closed` — terminal-only detection must
    // not fire on a live connection.
    {
        var healthy_steps: u32 = 0;
        while (healthy_steps < 50) : (healthy_steps += 1) {
            now_us += 1_000;
            try server.tick(now_us);
            try n.tick(now_us);
        }
        var events: [4]Event = undefined;
        const count = try n.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .closed => return error.UnexpectedClosed,
                else => {},
            }
        }
    }

    // One request in flight when the remote dies (deadline far out,
    // so only the death — not the deadline — can classify it).
    const stream_id = try n.requestQuic(client_session_id, .{
        .subject = "remote.slow",
        .id = 99,
        .deadline_ms = 60_000,
        .body = "in flight",
    });

    // Kill the remote: close the SERVER-side connection so a
    // CONNECTION_CLOSE goes out on the wire, then keep both loops
    // driving while the client drains to terminal.
    const server_conn = server_listener.listener.runtime.connection(0) orelse
        return error.ServerConnectionMissing;
    server_conn.close(false, transport.quic_cancel.AppErrorCode.graceful_shutdown, "remote died");

    var saw_closed = false;
    var saw_peer_closed = false;
    var closed_count: usize = 0;
    step = 0;
    while (step < 20_000 and !(saw_closed and saw_peer_closed)) : (step += 1) {
        now_us += 1_000;
        server.tick(now_us) catch {};
        try n.tick(now_us);
        var events: [4]Event = undefined;
        const count = try n.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .closed => |id| {
                    closed_count += 1;
                    try std.testing.expectEqual(client_session_id, id);
                    saw_closed = true;
                },
                .quic_request_failed => |ev| {
                    try std.testing.expectEqual(client_session_id, ev.session_id);
                    try std.testing.expectEqual(stream_id, ev.stream_id);
                    try std.testing.expectEqual(@as(message.MessageId, 99), ev.id);
                    try std.testing.expectEqual(RequestFailure.peer_closed, ev.failure);
                    saw_peer_closed = true;
                },
                else => {},
            }
        }
    }
    try std.testing.expect(saw_closed);
    try std.testing.expect(saw_peer_closed);
    try std.testing.expectEqual(@as(usize, 1), closed_count);
    try std.testing.expectEqual(@as(?*QuicSessionRuntime, null), n.quicSession(client_session_id));
    try std.testing.expectEqual(@as(usize, 0), n.quic_pending.items.len);
}

// The never-landing dial (consumer hazard 4): nothing listens at the
// target, quic-zig's handshake timeout eventually flips the
// connection terminally closed, and the death observation closes the
// session through the same path — `.closed` exactly once. Consumer
// connect-timeout recycling may race this; whichever side closes
// first, the routing is idempotent per session.
test "live UDP: never-landing dial closes when the handshake times out" {
    const allocator = std.testing.allocator;
    const control = @import("control.zig");

    var n = try Node.init(allocator, .{});
    defer n.deinit();
    const client_session_id = n.dialQuic("127.0.0.1:1", .{
        .server_name = "localhost",
        .ca_pem = dispatch_test_cert_pem,
        .transport = .{
            .peer_id = "dead-port-dialer",
            .role_flags = control.RoleFlags.client,
            .supported_patterns = control.PatternBits.req,
        },
    }) catch |err| switch (err) {
        // Environments that deny UDP binds skip rather than fail.
        error.AccessDenied,
        error.AddressInUse,
        error.AddressUnavailable,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        => return error.SkipZigTest,
        else => return err,
    };

    // The default handshake timeout is 30s; the virtual clock
    // advances 1ms per tick, so terminal close lands near 30_000
    // iterations. Dead-port sends may also surface transient socket
    // errors (ICMP-driven refusals) — they are not the death signal
    // and must not stall the drive.
    var now_us: u64 = 1_000;
    var closed_count: usize = 0;
    var step: u32 = 0;
    while (step < 60_000 and closed_count == 0) : (step += 1) {
        now_us += 1_000;
        n.tick(now_us) catch {};
        var events: [4]Event = undefined;
        const count = try n.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .closed => |id| {
                    try std.testing.expectEqual(client_session_id, id);
                    closed_count += 1;
                },
                else => {},
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 1), closed_count);
    try std.testing.expectEqual(@as(?*QuicSessionRuntime, null), n.quicSession(client_session_id));
}

// Hermetic fan-out mechanics (docs/QUIC_PUBSUB.md ask 2): registry
// matching, the datagram_enabled gate, and the slow-consumer
// shed-and-count contract at the outbox bound — drop-newest sheds the
// publication, drop-oldest sheds the oldest queued datagram — with
// `message_dropped` surfacing every skip.
test "quic publish fan-out matches registry entries and sheds slow consumers" {
    const allocator = std.testing.allocator;
    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const fast = try outcomeTestSession(&n);
    const slow = try outcomeTestSession(&n);
    const quiet = try outcomeTestSession(&n); // no datagram support

    // fast/slow carry datagram support; quiet opts out. Opposite
    // slow-consumer policies on the two subscribers.
    fast.runtime.appSession().datagram_enabled = true;
    slow.runtime.appSession().datagram_enabled = true;
    quiet.runtime.appSession().datagram_enabled = false;
    _ = try n.quic_registry.subscribe(quicRegistryPeer(fast.id()), "swarm.events", .{ .on_full = .drop_newest });
    _ = try n.quic_registry.subscribe(quicRegistryPeer(slow.id()), "swarm.events", .{ .on_full = .drop_oldest });
    _ = try n.quic_registry.subscribe(quicRegistryPeer(quiet.id()), "swarm.other", .{});

    // Matching: only the swarm.events subscribers receive it.
    try std.testing.expectEqual(@as(usize, 2), try n.publishQuicSubscribed(.{
        .subject = "swarm.events",
        .flags = .{ .unreliable = true },
        .body = "one",
    }));
    try std.testing.expectEqual(@as(usize, 1), fast.datagram_outbox.items.len);
    try std.testing.expectEqual(@as(usize, 1), slow.datagram_outbox.items.len);
    try std.testing.expectEqual(@as(usize, 0), quiet.datagram_outbox.items.len);

    // Fill both outboxes to the bound (default 64), then publish
    // past it.
    while (fast.datagram_outbox.items.len < n.options.quic_datagram_outbox_max) {
        try fast.queueDatagram(.{ .subject = "swarm.events", .flags = .{ .unreliable = true }, .body = "fill" });
    }
    while (slow.datagram_outbox.items.len < n.options.quic_datagram_outbox_max) {
        try slow.queueDatagram(.{ .subject = "swarm.events", .flags = .{ .unreliable = true }, .body = "fill" });
    }

    try std.testing.expectEqual(@as(usize, 1), try n.publishQuicSubscribed(.{
        .subject = "swarm.events",
        .flags = .{ .unreliable = true },
        .body = "two",
    }));
    // drop-newest shed the publication ("two" never queued); the
    // outbox stays at the bound with "one" still first.
    try std.testing.expectEqual(n.options.quic_datagram_outbox_max, fast.datagram_outbox.items.len);
    try std.testing.expectEqualStrings("one", fast.datagram_outbox.items[0].body);
    // drop-oldest shed "one" to make room for "two".
    try std.testing.expectEqual(n.options.quic_datagram_outbox_max, slow.datagram_outbox.items.len);
    try std.testing.expectEqualStrings("fill", slow.datagram_outbox.items[0].body);
    try std.testing.expectEqualStrings("two", slow.datagram_outbox.items[slow.datagram_outbox.items.len - 1].body);

    // The skip surfaced as message_dropped events, counted in Stats.
    try std.testing.expect(n.stats().dropped >= 1);
    var events: [8]Event = undefined;
    var saw_drop = false;
    const count = try n.poll(&events);
    for (events[0..count]) |*event| {
        defer event.deinit();
        switch (event.*) {
            .message_dropped => saw_drop = true,
            else => {},
        }
    }
    try std.testing.expect(saw_drop);

    // A subscriber without datagram support is skipped-and-counted
    // even on a matching subject.
    try std.testing.expectEqual(@as(usize, 0), try n.publishQuicSubscribed(.{
        .subject = "swarm.other",
        .flags = .{ .unreliable = true },
        .body = "quiet-only",
    }));
    try std.testing.expectEqual(@as(usize, 0), quiet.datagram_outbox.items.len);
    quiet.runtime.appSession().datagram_enabled = true;
    try std.testing.expectEqual(@as(usize, 1), try n.publishQuicSubscribed(.{
        .subject = "swarm.other",
        .flags = .{ .unreliable = true },
        .body = "quiet-only",
    }));
    try std.testing.expectEqual(@as(usize, 1), quiet.datagram_outbox.items.len);

    // A dying subscriber leaves the fan-out set whole.
    quiet.runtime.beginClosing();
    try n.tick(1_000);
    try std.testing.expectEqual(@as(usize, 0), try n.publishQuicSubscribed(.{
        .subject = "swarm.other",
        .flags = .{ .unreliable = true },
        .body = "nobody",
    }));
}

// Hermetic emission mechanics (ask 1): the node set queues on ready
// sessions, duplicates no-op, unsubscribe queues the delta, and a
// session that dies drops its queued frames with the wrapper.
test "quic node subscription set queues full set and deltas per session" {
    const allocator = std.testing.allocator;
    var n = try Node.init(allocator, .{});
    defer n.deinit();

    try n.subscribeQuic("swarm.events", .{});
    try n.subscribeQuic("swarm.events", .{}); // duplicate: no-op
    try std.testing.expectEqual(@as(usize, 1), n.quic_subscriptions.len());

    const sess = try outcomeTestSession(&n);
    try n.tick(1_000);
    // The full set is queued for the session. Hermetically nothing
    // pumps the session's pending HELLO sender, so the flush (which
    // requires an idle control sender) waits — on a live session the
    // HELLO lands first and the subscription flush follows.
    try std.testing.expect(sess.subscriptions_synced);
    try std.testing.expect(!sess.runtime.hasControlFlushSender());
    try std.testing.expectEqual(@as(usize, 1), sess.control_state.?.queuedFrameCount());

    // Delta on a synced session queues an UNSUBSCRIBE.
    n.unsubscribeQuic("swarm.events");
    try std.testing.expectEqual(@as(usize, 0), n.quic_subscriptions.len());
    try std.testing.expectEqual(@as(usize, 2), sess.control_state.?.queuedFrameCount());

    // subscribeQuic before any session exists is not an error; the
    // set is the source of truth for later sessions.
    var n2 = try Node.init(allocator, .{});
    defer n2.deinit();
    try n2.subscribeQuic("swarm.early", .{});
    try std.testing.expectEqual(@as(usize, 1), n2.quic_subscriptions.len());
}

// The consumer's swarm item 2, verbatim contract: subscriptions are
// NODE state that outlives sessions. A dial-side subscribeQuic lands
// in the LISTENER's registry (follow-up uni control stream, embedded
// apply); a registry-aware publish crosses the wall back as a
// datagram; and after the remote dies silently and is reborn on the
// same port, the redial's NEW session re-emits the FULL subscription
// set with no new subscribe call — the mesh either heals here or
// quietly loses subscriptions.
test "live UDP: node subscriptions survive kill, reborn, and redial" {
    const allocator = std.testing.allocator;
    const control_mod = @import("control.zig");

    var reset_key: [32]u8 = undefined;
    for (&reset_key, 0..) |*byte, index| byte.* = @intCast(index *% 5 +% 11);

    const listen_opts: transport.quic.QuicOptions = .{
        .peer_id = "swarm-hub",
        .role_flags = control_mod.RoleFlags.server,
        .supported_patterns = control_mod.PatternBits.pub_ | control_mod.PatternBits.sub,
        .datagram_enabled = true,
    };
    const dial_opts: transport.quic.QuicOptions = .{
        .peer_id = "swarm-member",
        .role_flags = control_mod.RoleFlags.client,
        .supported_patterns = control_mod.PatternBits.pub_ | control_mod.PatternBits.sub,
        .datagram_enabled = true,
    };

    var hub = try Node.init(allocator, .{});
    const hub_listener_id = hub.listenQuic("127.0.0.1:0", .{
        .tls_cert_pem = dispatch_test_cert_pem,
        .tls_key_pem = dispatch_test_key_pem,
        .transport = listen_opts,
        .stateless_reset_key = reset_key,
    }) catch |err| switch (err) {
        error.AccessDenied,
        error.AddressInUse,
        error.AddressUnavailable,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        => return error.SkipZigTest,
        else => return err,
    };
    const target = try localhostEndpoint(allocator, hub.quic_listeners.items[hub_listener_id].localAddress());
    defer allocator.free(target);

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    var now_us: u64 = 1_000;

    // Generation 1: dial, subscribe ONCE, and cross the wall.
    const session_a = try n.dialQuic(target, .{
        .server_name = "localhost",
        .ca_pem = dispatch_test_cert_pem,
        .transport = dial_opts,
    });
    var step: u32 = 0;
    while (step < 20_000) : (step += 1) {
        now_us += 1_000;
        try hub.tick(now_us);
        try n.tick(now_us);
        if (n.quicSession(session_a).?.state() == .ready) break;
    }
    try std.testing.expectEqual(
        transport.quic.State.ready,
        n.quicSession(session_a).?.state(),
    );

    try n.subscribeQuic("swarm.events", .{});

    step = 0;
    while (step < 20_000 and hub.quic_registry.peerCount() == 0) : (step += 1) {
        now_us += 1_000;
        try hub.tick(now_us);
        try n.tick(now_us);
    }
    try std.testing.expectEqual(@as(usize, 1), hub.quic_registry.peerCount());
    // Registry peers key by the HUB's own session id (each node keys
    // its registry by the sessions IT owns).
    try std.testing.expectEqual(@as(usize, 1), hub.quic_registry.subscriptionCount(
        @intCast(soleQuicSessionId(&hub).?),
    ));

    const delivered = try hub.publishQuicSubscribed(.{
        .subject = "swarm.events",
        .flags = .{ .unreliable = true },
        .body = "hello-wall",
    });
    try std.testing.expectEqual(@as(usize, 1), delivered);

    var got: ?transport.quic_datagram.ReceivedDatagram = null;
    step = 0;
    while (step < 20_000 and got == null) : (step += 1) {
        now_us += 1_000;
        try hub.tick(now_us);
        try n.tick(now_us);
        got = n.quicSession(session_a).?.recvDatagram();
    }
    var received = got orelse return error.WallCrossingMissing;
    defer received.deinit();
    try std.testing.expectEqualStrings("swarm.events", received.message.subject);
    try std.testing.expectEqualStrings("hello-wall", received.message.body);

    // Silent death (plain deinit ships nothing) + same-key reborn.
    hub.deinit();
    var reborn = try Node.init(allocator, .{});
    defer reborn.deinit();
    _ = reborn.listenQuic(target, .{
        .tls_cert_pem = dispatch_test_cert_pem,
        .tls_key_pem = dispatch_test_key_pem,
        .transport = listen_opts,
        .stateless_reset_key = reset_key,
    }) catch |err| switch (err) {
        error.AddressInUse, error.AddressUnavailable => return error.SkipZigTest,
        else => return err,
    };

    // The old session observes death at the idle window (its
    // subscription is long acked; nothing probes), the consumer's
    // redial loop replaces it, and the replacement gets the FULL
    // subscription set on its first ready tick — no new subscribe
    // call anywhere below.
    var saw_closed = false;
    step = 0;
    while (step < 60_000 and !saw_closed) : (step += 1) {
        now_us += 1_000;
        reborn.tick(now_us) catch {};
        try n.tick(now_us);
        var events: [4]Event = undefined;
        const count = try n.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .closed => saw_closed = true,
                else => {},
            }
        }
    }
    try std.testing.expect(saw_closed);

    const session_b = try n.dialQuic(target, .{
        .server_name = "localhost",
        .ca_pem = dispatch_test_cert_pem,
        .transport = dial_opts,
    });
    try std.testing.expect(session_b != session_a);

    step = 0;
    while (step < 20_000 and reborn.quic_registry.peerCount() == 0) : (step += 1) {
        now_us += 1_000;
        try reborn.tick(now_us);
        try n.tick(now_us);
    }
    // The re-emission contract: the reborn hub knows the NEW
    // session's subscription with no subscribe call from the test.
    try std.testing.expectEqual(@as(usize, 1), reborn.quic_registry.peerCount());
    try std.testing.expectEqual(@as(usize, 1), reborn.quic_registry.subscriptionCount(
        @intCast(soleQuicSessionId(&reborn).?),
    ));

    try std.testing.expectEqual(@as(usize, 1), try reborn.publishQuicSubscribed(.{
        .subject = "swarm.events",
        .flags = .{ .unreliable = true },
        .body = "hello-again",
    }));

    var got2: ?transport.quic_datagram.ReceivedDatagram = null;
    step = 0;
    while (step < 20_000 and got2 == null) : (step += 1) {
        now_us += 1_000;
        try reborn.tick(now_us);
        try n.tick(now_us);
        got2 = n.quicSession(session_b).?.recvDatagram();
    }
    var received2 = got2 orelse return error.RebornDeliveryMissing;
    defer received2.deinit();
    try std.testing.expectEqualStrings("hello-again", received2.message.body);
}

// The under-load starvation the consumer hit: a connection with
// unacked data in flight never idles (quic-zig bumps the activity
// clock on SEND, so every PTO probe resets the idle timer), so a
// silently-dead remote with a deadline-less request pending leaves
// the session visibly ready forever. A KEYED listener closes that
// hole: the reborn listener on the same port (same pinned reset key)
// answers the orphan's probes with a Stateless Reset, the client
// verifies it through the per-CID token it was advertised at
// handshake, and the v0.1.7 death observation closes the session —
// at the first PTO after rebirth, not after the idle window.
test "live UDP: keyed reborn listener resets an orphan under load, fast" {
    const allocator = std.testing.allocator;
    const control = @import("control.zig");

    // One pinned key across death and rebirth — the multi-instance /
    // replacement posture. A fresh random key on the reborn listener
    // would emit resets the orphan cannot verify.
    var reset_key: [32]u8 = undefined;
    for (&reset_key, 0..) |*byte, index| byte.* = @intCast(index *% 7 +% 3);

    const listen_opts: transport.quic.QuicOptions = .{
        .peer_id = "reborn-server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };
    const client_opts: transport.quic.QuicOptions = .{
        .peer_id = "orphan-prober",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
    };

    var server = try Node.init(allocator, .{});
    const server_listener_id = server.listenQuic("127.0.0.1:0", .{
        .tls_cert_pem = dispatch_test_cert_pem,
        .tls_key_pem = dispatch_test_key_pem,
        .transport = listen_opts,
        .stateless_reset_key = reset_key,
    }) catch |err| switch (err) {
        error.AccessDenied,
        error.AddressInUse,
        error.AddressUnavailable,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        => return error.SkipZigTest,
        else => return err,
    };
    const server_listener = server.quic_listeners.items[server_listener_id];
    const target = try localhostEndpoint(allocator, server_listener.localAddress());
    defer allocator.free(target);

    var n = try Node.init(allocator, .{});
    defer n.deinit();
    const client_session_id = try n.dialQuic(target, .{
        .server_name = "localhost",
        .ca_pem = dispatch_test_cert_pem,
        .transport = client_opts,
    });
    const client = n.quicSession(client_session_id) orelse return error.EndpointNotFound;

    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < 20_000) : (step += 1) {
        now_us += 1_000;
        try server.tick(now_us);
        try n.tick(now_us);
        if (client.state() == .ready and liveServerSessionReady(&n, client_session_id)) break;
    }
    try std.testing.expectEqual(transport.quic.State.ready, client.state());

    // The starving shape: a DEADLINE-LESS request in flight when the
    // remote dies silently. Nothing but the reset can classify it.
    const stream_id = try n.requestQuic(client_session_id, .{
        .subject = "remote.slow",
        .id = 100,
        .body = "never answered",
    });

    // Silent kill: plain deinit — quic-zig's Server.deinit is local
    // teardown only, no CONNECTION_CLOSE ships — then the reborn
    // listener takes the same port with the SAME key.
    server.deinit();
    var reborn = try Node.init(allocator, .{});
    defer reborn.deinit();
    _ = reborn.listenQuic(target, .{
        .tls_cert_pem = dispatch_test_cert_pem,
        .tls_key_pem = dispatch_test_key_pem,
        .transport = listen_opts,
        .stateless_reset_key = reset_key,
    }) catch |err| switch (err) {
        // The old socket may still hold the port briefly in some
        // environments; that is an environment limit, not a failure
        // of the behavior under test.
        error.AddressInUse, error.AddressUnavailable => return error.SkipZigTest,
        else => return err,
    };

    const death_us = now_us;
    var saw_closed = false;
    var saw_peer_closed = false;
    var closed_count: usize = 0;
    step = 0;
    while (step < 20_000 and !(saw_closed and saw_peer_closed)) : (step += 1) {
        now_us += 1_000;
        try reborn.tick(now_us);
        try n.tick(now_us);
        var events: [4]Event = undefined;
        const count = try n.poll(&events);
        for (events[0..count]) |*event| {
            defer event.deinit();
            switch (event.*) {
                .closed => |id| {
                    closed_count += 1;
                    try std.testing.expectEqual(client_session_id, id);
                    saw_closed = true;
                },
                .quic_request_failed => |ev| {
                    try std.testing.expectEqual(client_session_id, ev.session_id);
                    try std.testing.expectEqual(stream_id, ev.stream_id);
                    try std.testing.expectEqual(@as(message.MessageId, 100), ev.id);
                    try std.testing.expectEqual(RequestFailure.peer_closed, ev.failure);
                    saw_peer_closed = true;
                },
                else => {},
            }
        }
    }
    try std.testing.expect(saw_closed);
    try std.testing.expect(saw_peer_closed);
    try std.testing.expectEqual(@as(usize, 1), closed_count);
    try std.testing.expectEqual(@as(?*QuicSessionRuntime, null), n.quicSession(client_session_id));

    // Fast, not the idle window: the reset lands at the first PTO
    // after rebirth (sub-second probes), while idle death needs the
    // full quiet window. 10s of virtual time is generous for one and
    // impossible for the other.
    try std.testing.expect(now_us - death_us < 10_000_000);
}

fn soleQuicSessionId(n: *const Node) ?QuicSessionId {
    if (n.quic_sessions.items.len != 1) return null;
    return n.quic_sessions.items[0].id();
}

// Channel-binding dial side: signs a fresh PASETO per session, bound
// to the challenge the listener advertised in its HELLO. Records what
// it saw and minted so tests can assert freshness and replay tokens.
const BoundDialProvider = struct {
    const auth_paseto = @import("auth_paseto.zig");

    key: auth_paseto.V4Public,
    kid: []const u8,
    claims: []const u8,
    seen_challenges: std.ArrayListUnmanaged([]const u8) = .empty,
    minted_tokens: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *BoundDialProvider, allocator: std.mem.Allocator) void {
        for (self.seen_challenges.items) |challenge| allocator.free(challenge);
        self.seen_challenges.deinit(allocator);
        for (self.minted_tokens.items) |token| allocator.free(token);
        self.minted_tokens.deinit(allocator);
    }

    fn provider(self: *BoundDialProvider) auth.CredentialProvider {
        return .{ .ptr = self, .provide_fn = provide };
    }

    fn provide(
        ptr: ?*anyopaque,
        allocator: std.mem.Allocator,
        context: auth.PeerHelloContext,
    ) anyerror!auth.ProvidedCredential {
        const self: *BoundDialProvider = @ptrCast(@alignCast(ptr.?));
        // The returned credential is freed by the runtime that asked
        // for it, so both records take their own copies.
        try self.seen_challenges.append(allocator, try allocator.dupe(u8, context.challenge));

        const assertion = try auth.allocHelloImplicitAssertion(allocator, .{
            .challenge = context.challenge,
        });
        defer allocator.free(assertion);
        const token = try self.key.sign(allocator, self.claims, .{
            .implicit_assertion = assertion,
        });
        errdefer allocator.free(token);
        try self.minted_tokens.append(allocator, try allocator.dupe(u8, token));

        return .{
            .credential = token,
            .key_id_hint = try allocator.dupe(u8, self.kid),
        };
    }
};

// The channel-binding acceptance test: a listener armed with the
// challenge template mints a fresh challenge per accepted session, a
// provider-credentialed dial binds its token to the advertised
// challenge and authenticates, the next dial earns a DIFFERENT
// challenge, and the first dial's captured token replayed
// statically never authenticates -- the whole point of the binding.
test "live UDP: per-connection HELLO challenge binds credentials and kills replays" {
    const allocator = std.testing.allocator;
    const auth_paseto = @import("auth_paseto.zig");
    const control = @import("control.zig");

    const key = try auth_paseto.V4Public.fromSeed(&@as([32]u8, @splat(15)));
    const key_id = try auth_paseto.v4PublicKeyId(key);
    const kid = try key_id.toString(allocator);
    defer allocator.free(kid);

    const entries = [_]auth_paseto.PublicKeyEntry{.{ .key_id = key_id, .key = key }};
    const store = auth_paseto.StaticKeyStore{ .v4_public_keys = &entries };
    var authenticator = auth_paseto.V4PublicAuthenticator{
        .keys = store.keyStore(),
        .options = .{ .verify = .{ .require_footer_key_id = false } },
    };

    var dialer = BoundDialProvider{
        .key = key,
        .kid = kid,
        .claims =
        \\{"sub":"bound-client","iss":"node-test","qmsg":{"patterns":["req","rep"]}}
        ,
    };
    defer dialer.deinit(allocator);

    const server_opts: transport.quic.QuicOptions = .{
        .peer_id = "bound-server",
        .role_flags = control.RoleFlags.server,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        .auth_config = .{
            .required = true,
            .authenticator = authenticator.authenticator(),
        },
        .hello_challenge = .{},
    };
    const client_opts: transport.quic.QuicOptions = .{
        .peer_id = "bound-client",
        .role_flags = control.RoleFlags.client,
        .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
        .credential_provider = dialer.provider(),
    };

    var n = try Node.init(allocator, .{});
    defer n.deinit();

    const listener_id = n.listenQuic("127.0.0.1:0", .{
        .tls_cert_pem = dispatch_test_cert_pem,
        .tls_key_pem = dispatch_test_key_pem,
        .transport = server_opts,
    }) catch |err| switch (err) {
        // Environments that deny UDP binds skip this test rather
        // than fail it.
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

    // Dial 1: the deferred-HELLO exchange -- server advertises its
    // challenge, the provider mints against it, the session lands.
    const first_id = try n.dialQuic(target, .{
        .server_name = "localhost",
        // The fixture cert is a self-signed CA with a localhost SAN,
        // so it verifies against itself.
        .ca_pem = dispatch_test_cert_pem,
        .transport = client_opts,
    });
    const first = n.quicSession(first_id) orelse return error.EndpointNotFound;

    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < 20_000) : (step += 1) {
        now_us += 1_000;
        try n.tick(now_us);
        if (first.state() == .ready and liveServerSessionReady(&n, first_id)) break;
    }
    try std.testing.expectEqual(transport.quic.State.ready, first.state());
    try std.testing.expectEqual(@as(usize, 1), dialer.seen_challenges.items.len);
    const first_challenge = dialer.seen_challenges.items[0];
    try std.testing.expectEqual(auth.default_hello_challenge_bytes, first_challenge.len);

    // The challenge the provider bound to is THIS session's mint, not
    // a static listener value.
    var server_challenge: ?[]const u8 = null;
    for (n.quic_sessions.items) |runtime| {
        if (runtime.id() == first_id) continue;
        if (runtime.state() != .ready) continue;
        const binding = runtime.runtime.session.hello_challenge_binding orelse continue;
        server_challenge = binding.challenge();
        break;
    }
    try std.testing.expectEqualSlices(
        u8,
        first_challenge,
        server_challenge orelse return error.ServerSessionMissing,
    );

    // Dial 2: a fresh dial earns a FRESH challenge -- dial 1's token
    // could not verify here.
    const second_id = try n.dialQuic(target, .{
        .server_name = "localhost",
        .ca_pem = dispatch_test_cert_pem,
        .transport = client_opts,
    });
    const second = n.quicSession(second_id) orelse return error.EndpointNotFound;
    step = 0;
    while (step < 20_000) : (step += 1) {
        now_us += 1_000;
        try n.tick(now_us);
        if (second.state() == .ready) break;
    }
    try std.testing.expectEqual(transport.quic.State.ready, second.state());
    try std.testing.expectEqual(@as(usize, 2), dialer.seen_challenges.items.len);
    try std.testing.expect(!std.mem.eql(u8, first_challenge, dialer.seen_challenges.items[1]));

    // Dial 3, the replay: dial 1's captured token presented
    // statically. The listener mints a new challenge, the signature
    // no longer matches, and the session never authenticates.
    const replay_id = try n.dialQuic(target, .{
        .server_name = "localhost",
        .ca_pem = dispatch_test_cert_pem,
        .transport = .{
            .peer_id = "replay-client",
            .role_flags = control.RoleFlags.client,
            .supported_patterns = control.PatternBits.req | control.PatternBits.rep,
            .auth = .{
                .scheme = auth.hello_auth_scheme_paseto,
                .credential = dialer.minted_tokens.items[0],
                .key_id_hint = kid,
            },
        },
    });
    step = 0;
    while (step < 20_000) : (step += 1) {
        now_us += 1_000;
        try n.tick(now_us);
        // A rejected session is destroyed by the node -- re-fetch per
        // step; the session vanishing IS the rejection signal.
        const replay_session = n.quicSession(replay_id) orelse break;
        if (replay_session.state() == .ready) break;
    }
    const replay_final = n.quicSession(replay_id);
    try std.testing.expect(replay_final == null or replay_final.?.state() != .ready);
}

fn localhostEndpoint(allocator: std.mem.Allocator, address: std.Io.net.IpAddress) ![]u8 {
    return switch (address) {
        .ip4 => |ip4| try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{ip4.port}),
        .ip6 => |ip6| try std.fmt.allocPrint(allocator, "[::1]:{d}", .{ip6.port}),
    };
}
