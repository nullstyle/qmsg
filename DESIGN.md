# qmsg Design

## Purpose

`qmsg` is a Zig-native messaging framework for building applications around
messages, subjects, and communication patterns rather than HTTP resources.

It combines:

- nng-like socket patterns.
- A small handler facade for application ergonomics.
- QUIC streams and datagrams as the primary transport substrate.

The goal is to make networked Zig services feel small and direct while keeping
transport realities visible: deadlines, cancellation, flow control, queue
limits, connection migration, stream resets, and lossy datagrams.

## Non-Goals

- No HTTP/3 API.
- No HTTP routing model.
- No hidden global runtime.
- No unbounded queues by default.
- No implicit allocation in hot paths when a caller-provided buffer/lifetime
  model is viable.
- No broker requirement. Brokered topologies can be built later as ordinary
  `qmsg` applications.

## Mental Model

HTTP frameworks route `method + path`.

`qmsg` routes:

- pattern: `req`, `rep`, `pub`, `sub`, `push`, `pull`, etc.
- subject: `user.get`, `jobs.image.resize`, `metrics.cpu`.
- transport capability: reliable stream or unreliable datagram.
- peer/session state: authenticated identity, connection metadata, negotiated
  options.

QUIC gives connections, streams, datagrams, encryption, ALPN, migration, and
flow control. `qmsg` turns those into application messages and nng-style
interaction patterns.

## Main Layers

```text
App
  High-level handler registration and lifecycle hooks.

Node
  Runtime owner for listeners, dialers, sessions, timers, and dispatch.

Socket(pattern)
  Pattern-specific low-level API.

Protocol(pattern)
  State machine for req/rep, pub/sub, push/pull, etc.

Transport
  QUIC first. Future inproc/ipc/tcp transports can satisfy the same boundary.

Message
  Subject, id, flags, deadline, headers/properties, body.
```

## Core Types

### App

Convenience facade for applications.

Responsibilities:

- register handlers by pattern and subject;
- own app-level config;
- install lifecycle hooks;
- expose simple `listenQuic`, `dialQuic`, and `run` helpers;
- delegate actual messaging behavior to `Node` and `Socket`.

Sketch:

```zig
pub const App = struct {
    pub fn init(allocator: Allocator, options: AppOptions) !App;
    pub fn deinit(self: *App) void;

    pub fn onConnect(self: *App, handler: ConnectHandler) void;
    pub fn onClose(self: *App, handler: CloseHandler) void;

    pub fn rep(self: *App, subject: []const u8, handler: RepHandler) void;
    pub fn pull(self: *App, subject: []const u8, handler: PullHandler) void;
    pub fn sub(self: *App, subject: []const u8, handler: SubHandler) void;
    pub fn datagram(self: *App, subject: []const u8, handler: DatagramHandler) void;

    pub fn listenQuic(self: *App, addr: []const u8, tls: TlsConfig) !void;
    pub fn run(self: *App) !void;
};
```

### Node

Embeddable runtime object. `App` wraps it, but advanced users can drive it
directly.

Responsibilities:

- own listeners and outbound dialers;
- own active sessions;
- drive transport polling and timers;
- dispatch inbound frames/messages to pattern state machines;
- surface events to embedders.

Sketch:

```zig
pub const Node = struct {
    pub fn init(allocator: Allocator, options: NodeOptions) !Node;
    pub fn deinit(self: *Node) void;

    pub fn listen(self: *Node, transport: TransportKind, endpoint: Endpoint) !void;
    pub fn dial(self: *Node, transport: TransportKind, endpoint: Endpoint) !SessionId;

    pub fn tick(self: *Node, now_us: u64) !void;
    pub fn poll(self: *Node, out: []Event) !usize;
    pub fn nextTimer(self: *const Node) ?u64;
};
```

### Socket

Pattern-specific API. This is the nng-like core.

```zig
pub fn Socket(comptime pattern: Pattern) type {
    return struct {
        pub fn init(allocator: Allocator, options: SocketOptions(pattern)) !Self;
        pub fn deinit(self: *Self) void;

        pub fn listen(self: *Self, transport: TransportKind, endpoint: Endpoint) !void;
        pub fn dial(self: *Self, transport: TransportKind, endpoint: Endpoint) !void;

        // Shape depends on pattern.
    };
}
```

Example pattern-specific operations:

```zig
// req
pub fn request(self: *ReqSocket, msg: OutgoingMessage) !Message;

// rep
pub fn recv(self: *RepSocket) !Request;
pub fn reply(self: *RepSocket, req: Request, msg: OutgoingMessage) !void;

// pub
pub fn publish(self: *PubSocket, msg: OutgoingMessage) !void;

// sub
pub fn subscribe(self: *SubSocket, subject_filter: []const u8) !void;
pub fn recv(self: *SubSocket) !Message;
```

### Session

One connected peer.

Responsibilities:

- track peer identity and negotiated capabilities;
- own transport connection handle;
- track active streams and in-flight operations;
- provide app-visible metadata;
- surface migration and close events.

Sketch:

```zig
pub const Session = struct {
    id: SessionId,
    peer_id: PeerId,
    transport: TransportKind,
    remote_addr: Address,
    alpn: []const u8,
    datagram_enabled: bool,
    max_message_size: usize,
    user_data: ?*anyopaque,
};
```

### Message

The common unit across patterns.

```zig
pub const Message = struct {
    subject: []const u8,
    id: MessageId,
    flags: Flags = .{},
    deadline_ms: ?u64 = null,
    headers: []const Header = &.{},
    body: []const u8 = &.{},
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};
```

Important fields:

- `subject`: route key and pub/sub topic.
- `id`: correlation id for request/reply and multi-part messages.
- `flags`: final, no_reply, unreliable, more, error, etc.
- `deadline_ms`: sender's requested deadline, interpreted relative to receive
  time unless the wire protocol later adds synchronized absolute deadlines.
- `headers`: small metadata; body remains bytes.

## Subject Matching

Subjects are dot-separated byte strings:

```text
user.get
jobs.image.resize
metrics.cpu
presence.user.123
```

Initial filters:

- exact: `user.get`
- star segment: `metrics.*`
- trailing glob: `presence.>`

Keep the first implementation simple:

- no regex;
- no allocation during match after registration;
- deterministic priority: exact first, then longest specific filter, then
  registration order as tie-breaker.

## Patterns

### Pair

One-to-one bidirectional messaging.

Use cases:

- control sessions;
- test harnesses;
- direct peer protocols.

QUIC mapping:

- one control stream for protocol management;
- reliable messages may use one bidi stream per message or a framed shared
  stream depending on message size and ordering requirements.

### Req/Rep

Request/reply with correlation, deadline, and cancellation.

QUIC mapping:

- one bidirectional stream per request;
- request body flows client to server;
- reply body flows server to client on the same stream;
- reset maps to request cancellation or failure.

Properties:

- multiple outstanding requests per session;
- replies correlate by stream and message id;
- deadlines cancel in-flight streams;
- responder can return typed application errors.

### Pub/Sub

Subject fanout.

QUIC mapping:

- control stream carries subscriptions;
- reliable publications use streams or framed shared streams;
- unreliable publications may use QUIC DATAGRAM when the publisher marks the
  message as lossy and the peer negotiated datagrams.

Properties:

- bounded per-subscriber queues;
- configurable slow-consumer policy;
- subject filters live on the subscriber side but are sent to publishers for
  filtering at source.

### Push/Pull

Work distribution.

QUIC mapping:

- reliable streams with explicit credit;
- pull side advertises capacity;
- push side sends only when credit exists unless configured to queue.

Properties:

- fair distribution across pullers;
- no duplicate delivery guarantee in MVP after transport failure;
- at-least-once can be a later protocol kit with ack/retry.

### Bus

Peer mesh broadcast.

QUIC mapping:

- one session per peer;
- messages fan out across sessions;
- loop prevention uses peer id and message id.

Properties:

- useful for small clusters and discovery;
- not a replacement for large-scale brokered pub/sub.

### Survey/Respondent

Request-many-responses with deadline.

QUIC mapping:

- survey request fanout across sessions;
- each response arrives on its own stream or response frame;
- deadline closes the survey and ignores late responses.

Use cases:

- health checks;
- cluster query;
- local discovery.

## Backpressure and Queue Policy

Backpressure is part of the API.

Every socket and session has bounded queues:

```zig
pub const QueueOptions = struct {
    max_messages: usize = 1024,
    max_bytes: usize = 16 * 1024 * 1024,
    on_full: OnFull = .block,
};

pub const OnFull = enum {
    block,
    fail,
    drop_oldest,
    drop_newest,
};
```

Pattern defaults:

- `req`: fail or block when request concurrency is exhausted.
- `rep`: bounded inbound queue; backpressure new streams.
- `pub`: configurable; telemetry often wants `drop_oldest`.
- `sub`: bounded receive queue; slow consumers visible to app.
- `push`: credit-based.
- `pull`: explicit capacity advertisement.

QUIC flow control should not be hidden. Operations may return:

- `error.FlowControlled`
- `error.QueueFull`
- `error.DeadlineExceeded`
- `error.PeerClosed`
- `error.StreamReset`
- `error.MessageTooLarge`

The handler facade can provide defaults, but the lower-level socket API should
make the pressure visible.

## Allocation and Lifetimes

Zig users should be able to reason about memory.

Receive options:

- borrowed message valid until handler returns;
- owned message copied into caller allocator;
- streaming body reader for large messages.

Send options:

- copy body into qmsg-owned queue;
- borrow body until send completion;
- streaming body writer for large messages.

MVP can start with owned/copying messages plus clear size caps. Zero-copy and
streaming bodies should be designed early but implemented after the pattern
state machines are stable.

## Handler API

Handlers receive context plus message.

```zig
pub const Context = struct {
    app: *App,
    node: *Node,
    session: SessionRef,
    deadline: ?Deadline,

    pub fn reply(self: *Context, msg: OutgoingMessage) !void;
    pub fn publish(self: *Context, msg: OutgoingMessage) !void;
    pub fn close(self: *Context, code: CloseCode, reason: []const u8) void;
    pub fn reset(self: *Context, code: StreamError) void;
};
```

Example:

```zig
fn getUser(ctx: *qmsg.Context, msg: qmsg.Message) !void {
    const id = try decodeUserId(msg.body);
    const user = try loadUser(ctx.allocator(), id);
    try ctx.reply(.{
        .subject = "user.get.ok",
        .body = try encodeUser(ctx.scratch(), user),
    });
}
```

## Transports

### QUIC

The reference transport.

Required capabilities:

- encrypted sessions via TLS;
- ALPN `qmsg/1`;
- bidirectional streams;
- unidirectional control stream;
- optional QUIC DATAGRAM;
- connection migration events;
- stream reset and stop-sending propagation.

### Inproc

Useful early for tests and local composition.

Required capabilities:

- same message semantics;
- deterministic scheduling;
- no network/TLS dependency.

### IPC/TCP

Potential later transports. They should be added only after QUIC and inproc
prove the transport boundary.

## Security and Identity

QUIC provides transport encryption and peer authentication hooks. `qmsg` should
add application identity, not replace TLS.

Initial model:

- TLS config supplied by embedder;
- peer id advertised in HELLO;
- optional auth headers in HELLO or first control message;
- app hook validates session before pattern traffic is accepted.

```zig
app.onAuthenticate(authenticatePeer);
```

Security-sensitive defaults:

- cap max message size;
- cap header count and header bytes;
- cap outstanding streams/messages;
- reject unknown protocol versions unless configured otherwise;
- avoid reflecting detailed internal resource failures to peers.

## Error Model

Separate these error classes:

- local resource errors: `OutOfMemory`, `QueueFull`, `MessageTooLarge`;
- transport errors: `PeerClosed`, `ConnectionLost`, `StreamReset`;
- protocol errors: `MalformedFrame`, `UnexpectedFrame`, `VersionMismatch`;
- app errors: encoded as qmsg error replies where the pattern supports them;
- deadline/cancel errors: `DeadlineExceeded`, `Canceled`.

Application error replies should be messages, not Zig errors. Zig errors should
describe local failure to complete an operation.

## Observability

Minimum useful hooks:

- session connected/closed;
- stream opened/closed/reset;
- message received/sent/dropped;
- queue high-water marks;
- deadline exceeded;
- protocol violation;
- QUIC migration event.

Expose counters without requiring a metrics dependency:

```zig
pub const Stats = struct {
    messages_sent: u64,
    messages_recv: u64,
    messages_dropped: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    active_sessions: usize,
    active_streams: usize,
};
```

