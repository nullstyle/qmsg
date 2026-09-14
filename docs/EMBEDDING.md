# Embedding a qmsg Node

This is the contract for embedding a qmsg `Node` in a host runtime
that owns its own loop — a scripting engine bridge, an actor
framework, a game tick, an embedded supervisor. The executable form
of everything here is
[examples/embedded_inproc_node.zig](../examples/embedded_inproc_node.zig);
when this document and the example disagree, the example is the
contract and this file is the explanation.

The inproc surface is socketless from the embedder's point of view:
the Node owns every qmsg socket, and the only I/O is message queues
inside one process. QUIC transports (outbound `dialQuic`) coexist on
the same Node; inbound QUIC attach on a foreign embedder's listener is
built — see "Inbound QUIC attach" below and
[QUIC_EMBED_SEAM.md](QUIC_EMBED_SEAM.md).

`Node` now defaults to canonical events for both transports. The migration
from transport-specific events and direct inbox consumption is documented in
[MIGRATION.md](MIGRATION.md), including request budgets and retained replies.

## The loop

```zig
var node = try qmsg.node.Node.init(allocator, .{});
defer node.deinit();

while (running) {
    try node.tick(now_us);               // 1. advance the clock
    do_embedder_work();                  // 2. your actors, your I/O
    var events: [16]qmsg.node.Event = undefined;
    const count = try node.poll(&events); // 3. pump + drain events
    defer for (events[0..count]) |*event| event.deinit();
    for (events[0..count]) |*event| {
        switch (event.*) { ... }          // 4. route by pattern
    }
}
```

- **The clock is yours.** `tick(now_us)` records the node's notion of
  now; request deadlines are evaluated against it (microseconds,
  converted to milliseconds internally). Nothing in qmsg reads a wall
  clock on the inproc surface, so runs are deterministic under a
  virtual clock. A request sent before the first tick measures its
  deadline from 0.
- **`poll` is the pump.** It first drains node-owned state — expired
  request deadlines, then served requests, request replies, and
  subscription deliveries — into the event queue, then moves up to
  `events.len` events out. Reserved request outcomes drain before ordinary
  events; there is no global FIFO order between those queues. Deadlines use
  the time most recently passed to `tick`.
- **Event memory is owned.** `request`, `reply`, and `delivery`
  events carry an owned `Message` plus (for deliveries) a borrowed
  filter slice. `deinit()` each event after handling it; payloads
  return to the allocator the Node was built with. `Node.deinit`
  frees anything never drained.
- **One allocator.** The Node's allocator owns every socket, queue,
  event payload, and pending-request entry on the embedded surface.
  Pass an allocator whose lifetime encloses the Node's.

### Why batch `poll` and not one event per call

The embedding ask sketched `while (try node.poll(&events)) |ev|`.
qmsg ships the batch form (`poll(&events) !usize` with a count loop)
instead: the embedder picks the buffer size once, the drain is
allocation-free per iteration, and per-event iteration is still a
`for (events[0..count])` away. The consumer-side bridge wraps this in
whatever per-actor queue fan-out it wants; the load-bearing property
— poll drains and returns everything ready, embedder controls
buffering — is preserved.

## Wiring

All wiring is explicit and order-tolerant where possible:

| Operation | Bind/dial side | Call |
| --- | --- | --- |
| Serve requests | Node binds | `listenInprocRep(&network, "svc", .{})` |
| Reply to a served request | — | `reply(request_event.msg.reply_handle.?, .{ .subject = "", .body })` |
| Reply with an error | — | `replyErrorInproc(&request_event, .{ .code, .message })` |
| Send requests | Node dials | `dialInprocReq(&network, "peers", .{})` → `request(.{ .inproc = dial_id }, .{...})` |
| Cancel a request | — | `cancelRequest(request_id)` |
| Receive deliveries | Node dials | `dialInprocSub(&network, "events")` + `subscribeInproc("metrics.*")` |
| Stop receiving | — | `unsubscribeInproc("metrics.*")` |
| Publish | Node binds | `listenInprocPub(&network, "feed", .{})` → `publishInproc(pub_id, .{...})` |

Inproc dials require the peer's pattern binding to exist (inproc has
no listening backlog), so bind before dial — or accept
`error.EndpointNotFound` and retry on a later tick. Subscription
filters may be added before or after the dial; they replay at connect
time.

Subject-to-address routing is the embedder's concern: qmsg requests
are addressed to an inproc endpoint (nng-style), and the subject
travels inside the message for the serving side to route. A bridge
that offers script-level `serve("user.get")` keeps the mapping and
binds/dials accordingly.

## Rendering outcomes from events alone

Every request/reply outcome is a poll event or a synchronous error:

- `request` — inbound request: `msg.id` is the correlation id,
  `msg.deadline_ms` the deadline, `msg.subject`/`msg.body` the ask.
  Reply through `msg.reply_handle` while the event is alive, or retain the
  handle for later work. `Node.reply` echoes an empty reply subject.
- `reply` — the peer answered: `request_id` matches the local ID returned by
  `Node.request`; `msg.flags.err`
  plus the `qmsg-error-code` / `qmsg-error-message` headers carry the
  peer's error when it answered with one.
- `request_failed` — terminal, classified:

  | `RequestFailure` | Meaning |
  | --- | --- |
  | `deadline_exceeded` | `deadline_ms` elapsed per the node clock |
  | `canceled` | `cancelRequest` was called |
  | `queue_full` | The reply exceeded available completion bytes; also a synchronous send error |
  | `peer_closed` | A pending QUIC session closed; also a synchronous closed-endpoint error |
  | `no_route` | sync-only: no peer / unknown dial |

- `delivery` — a publication matched one of the node's filters:
  `msg` is the delivery, `filter` is the subscription that claimed it
  (first match in subscription order; borrowed — copy to retain).
- `message_dropped` — a message that will never deliver: late reply
  after cancel/deadline, queue-policy drop on a node-owned queue, or
  (QUIC) a malformed/oversized datagram.
- `connected` / `closed` — endpoint/session lifecycle bookkeeping. Use
  `sessionStatus(id).state == .ready` to check QUIC usability after TLS and
  HELLO, or `findReadySessionSupporting` to find a verified peer session.

## Backpressure and observability

Backpressure is observable, never hidden:

- **Send-time pressure is synchronous.** `requestInproc`,
  `replyInproc`, and `publishInproc` return `error.QueueFull` /
  `error.FlowControlled` (peer queue full, `.fail`/`.block`
  policies), `error.EndpointClosed`, or `error.NoPeer` immediately.
  Map them through `qmsg.classifyRequestError` to fold them into the
  same `RequestFailure` vocabulary the events use — one error space
  for both paths.
- **Slow consumers are configured, not guessed.**
  `NodeOptions.inproc_sub` is the node-owned subscription socket's
  queue options; its `on_full` policy is the delivery slow-consumer
  policy. Drop policies lose messages visibly (counted), not
  silently.
- **`stats()` is plain fields** — `sent`, `recv`, `dropped`,
  `queue_high_water`, `events_dropped` — computed live from node
  counters plus node-owned queue stats. No metrics dependency; fold
  them into whatever exporter the host already runs.
- **Ordinary events and request outcomes have separate bounds.**
  `max_events` (default 1024) and `max_event_bytes` (default 16 MiB) bound
  ordinary events. Lossy events count drops; inbound request draining
  backpressures when space runs out. `max_requests` (default 1024) bounds
  pending requests plus unread terminal outcomes. Admission reserves outcome
  capacity, so ordinary event pressure cannot erase a reply or failure.
  `max_request_bytes` and `max_completion_bytes` default to 16 MiB each.
  A reply exceeding available completion bytes becomes `.queue_full`.
  Consume outcomes with `poll` or `takeOutcome` to release reservations.

## Fault containment

A handler fault must not propagate out of the embedder's loop — that
containment is the embedder's `catch` around its own dispatch, and
qmsg's contract makes it possible: event delivery never re-enters
qmsg. Handling an event is side-effect-free from the queue's
perspective; the only re-entry is through the explicit calls above
(`replyInproc`, `requestInproc`, ...), each of which returns errors
rather than unwinding through callbacks. qmsg calls no embedder code
from `tick` or `poll`.

## Inbound QUIC attach (embedder-owned listener)

A `Node` can also serve qmsg sessions over connections on a FOREIGN
embedder's QUIC listener — the embedder owns the listener, the UDP
socket, and the single `quic.app.Driver`; qmsg rides the connections
the embedder routes to it by negotiated ALPN (`qmsg/1`). The embedder
keeps one `EmbeddedDispatch(Node).Seat` per connection in its own
connection state and delegates its Driver hooks:

```zig
fn onHandshake(app: *App, s: *Driver(App).Session) anyerror!void {
    if (qmsg.isQmsgAlpn(s.conn)) {
        var seat = qmsg.EmbeddedDispatch(Node).Seat.init(app.allocator);
        try app.qmsg_dispatch.onHandshake(&seat, s.conn);
        s.app.qmsg_seat = seat;
    }
}
// likewise on_stream_open/data/end + on_datagram (+ the seat check),
// on_disconnect frees the seat through the dispatch, and once per
// tick per connection: try app.qmsg_dispatch.serviceSeat(&seat, conn);
```

Embedded sessions are pull-consumed like everything else: inbound
requests arrive as `request` events, replies to the node's outbound requests
as `reply` events keyed by local `request_id`, and datagrams as `delivery`
events. QUIC events also carry `session_id` and optional `stream_id` metadata.
Answer with `Node.reply(request.msg.reply_handle.?, outgoing)` while the
event is alive, or retain the handle for asynchronous work; publish with
`Node.publishQuic`. Credentials verify once at HELLO from the
`auth_config` carried on the transport options passed to
`EmbeddedDispatch.init`. Sizing for the embedder's Driver comes from
`qmsg.embeddedDriverSizing`.

The full contract — including the one-Driver constraint that forces
this shape, and the teardown ride-along through the embedder's
will-close path — is
[QUIC_EMBED_SEAM.md](QUIC_EMBED_SEAM.md), and
[examples/embedded_quic_attach.zig](../examples/embedded_quic_attach.zig)
is the executable form.

### Outbound requests over QUIC: outcomes, not just replies

`Node.request(.{ .quic = session_id }, outgoing)` sends and tracks a request.
It returns a local `RequestId`; `reply` and `request_failed` carry that ID.
An accepted request reserves a terminal outcome until it is consumed. Failures
include:

- `.deadline_exceeded` — the deadline passed against the node clock
  (`tick`'s `now_us`),
- `.canceled` — you called `Node.cancelRequest` (which also
  RESET/STOP_SENDINGs the stream when the node owns the connection),
- `.peer_closed` — the session closed or was torn down,
- `.queue_full` — an arriving reply could not fit the completion byte budget.

Classification is first-wins — see
[QUIC_REQUEST_OUTCOMES.md](QUIC_REQUEST_OUTCOMES.md). Raw `queueReliable`
sends remain untracked. `requestQuic` still returns a stream ID for compatibility;
new code uses `Node.request` and its transport-independent local ID. Send-path
errors remain synchronous. Direct inbox consumption requires explicit legacy
delivery; it must not compete with the default Node event consumer.

**QUIC pub/sub crosses the process wall.** `Node.subscribeQuic(filter,
options)` subscribes the NODE on every QUIC session, current and
future: the full set re-emits on each new session's first ready
tick, so a redial's replacement inherits the mesh's subscriptions
with no re-subscribe call — state outlives sessions by construction.
`Node.publishQuicSubscribed(outgoing)` fans a datagram out to every
session whose registry entry matches (dial peers and embedded qmsg/1
clients, one registry): sessions without datagram support and
over-budget outboxes are skipped-and-counted (`message_dropped`), a
subscriber's `on_full` policy sheds drop-newest or drop-oldest at
its `NodeOptions.quic_datagram_outbox_max` bound, and slow consumers
never block the loop. Inbound SUBSCRIBE/UNSUBSCRIBE from peers apply
into the same registry on the listener/embedded seam (control frames
beyond HELLO ride follow-up uni streams), and a dying session leaves
the fan-out set whole on every death path. Full contract in
[QUIC_PUBSUB.md](QUIC_PUBSUB.md); replay and reliable-stream
publication are future work.

Three operational notes, each learned the hard way downstream:

- **Both ends must announce `pub_ | sub` (and
  `datagram_enabled = true`) in their transport options.** A session
  negotiated without the pattern bits silently carries no pub/sub:
  the handshake completes, requests flow, and subscriptions simply
  do not register — no error, no drop counter. Pattern announcement
  is a contract, not a formality.
- **Both dialed and embedded sessions use canonical events by default.**
  Poll `delivery` for datagrams and `reply` for responses. Do not also drain
  their session inboxes. Older inbox consumers must select `.delivery =
  .legacy`; select `.event_format = .legacy_transport` separately if they
  still expect `quic_*` event names. See [MIGRATION.md](MIGRATION.md).
- **A publication racing a reborn subscriber's re-sync loses, by
  design.** After a redial heals the mesh, the subscriber's set
  re-emits on its first ready tick; a publication sent before that
  tick lands is a lost datagram — correct lossy pub/sub behavior,
  but it will surprise someone. Settle the subscription before
  publishing when certainty matters.

**Auth tokens are fail-closed on the `qmsg` claim.** A PASETO token
without a `qmsg` claim is rejected outright under the default
`require_qmsg_claim = true` (and with the claim, `patterns` is
required and must be non-empty — a token that parses but carries no
patterns would deny every pattern a real HELLO announces). There is
no unset-means-allow-all path: every usable token carries
`{"sub":…, "iss":…, "qmsg":{"patterns":[…], "datagram":true?}}`.
Claim pattern spellings differ from the identifiers you will meet in
source: claims use `"pub"`/`"sub"`, while the enum tags are
`.@"pub"`/`.sub` and the `PatternBits` fields are `pub_`/`sub`. A
working example token's claims:

```json
{"sub":"actor-7","iss":"swarm-ca","qmsg":{"patterns":["req","rep","sub"],"datagram":true}}
```

**Dial sessions observe connection death.** A node-owned dial whose
connection reaches QUIC's terminal closed state — a peer
CONNECTION_CLOSE observed through the draining deadline, a stateless
reset, an idle or handshake timeout — is closed through the same
path an explicit `closeQuicSession` takes: one `.closed` event, the
session gone from `quicSession`, and every still-pending request
classified `.peer_closed` in the same tick. Detection is
terminal-only on purpose (`closeState()`'s closing/draining are an
in-progress close, not death) and lags the wire event by the
draining window — on real clocks that is seconds; on a
virtual-clock embedder, whenever `now_us` crosses the deadline.
Late-and-certain is the contract; peers that need earlier signal can
close on their own deadlines. Driver-owned (listener-side) sessions
are untouched — they already die through the will-close teardown.

One QUIC caveat survives this: a connection with UNACKED data in
flight never idles — every PTO probe resets the idle timer — so a
silently-dead remote plus a deadline-less pending request would
probe forever. qmsg listeners therefore answer stateless resets by
default: every `listenQuic` arms a fresh random RFC 9000 §10.3
stateless-reset key (overridable via `QuicListenOptions
.stateless_reset_key`), and a keyed listener responds to unroutable
orphan probes with a Stateless Reset the probing peer verifies
through the per-CID token it was advertised at handshake — the
orphan dies at its first PTO. Pin ONE key across instances and
restarts in multi-instance or replacement deployments: a reborn
listener can only kill a dead instance's orphans when its reset
verifies against the tokens the dead instance minted, which requires
the same key. What resets cannot fix: a port where NOTHING listens
is silent, so detection there still waits for quiet-plus-idle (or a
request deadline) — that residual is QUIC, and the consumer-side
answer is deadlines on cross-peer requests.

## Relation to the App facade

`App` (the handler-registration facade over the same Node) consumes
inbound messages through `runOnce(dispatcher)` — a pull-dispatch
model. The embedded event model consumes through `tick`/`poll`. Both
work on the same Node, but they compete for the same rep inboxes:
pick one consumption model per endpoint, not both.
