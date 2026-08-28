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
the same Node; inbound QUIC attach is a designed-but-unbuilt seam —
see [QUIC_EMBED_SEAM.md](QUIC_EMBED_SEAM.md).

## The loop

```zig
var node = try qmsg.node.Node.init(allocator, .{});
defer node.deinit();

while (running) {
    node.tick(now_us) catch {};          // 1. advance the clock
    do_embedder_work();                  // 2. your actors, your I/O
    var events: [16]qmsg.node.Event = undefined;
    const count = try node.poll(&events); // 3. pump + drain events
    for (events[0..count]) |*event| {
        defer event.deinit();
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
  `events.len` events out. Ordering is FIFO; deadlines are evaluated
  before replies, so a reply that lands after its deadline classifies
  as a late drop, not a correlation surprise.
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
| Reply to a served request | — | `replyInproc(&request_event, .{ .subject = "", .body })` |
| Reply with an error | — | `replyErrorInproc(&request_event, .{ .code, .message })` |
| Send requests | Node dials | `dialInprocReq(&network, "peers", .{})` → `requestInproc(dial_id, .{...})` |
| Cancel a request | — | `cancelInprocRequest(dial_id, id)` |
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
  Reply while the event is alive (`replyInproc` echoes the subject
  when the reply's subject is empty).
- `reply` — the peer answered: `msg.id` correlates, `msg.flags.err`
  plus the `qmsg-error-code` / `qmsg-error-message` headers carry the
  peer's error when it answered with one.
- `request_failed` — terminal, classified:

  | `RequestFailure` | Meaning |
  | --- | --- |
  | `deadline_exceeded` | `deadline_ms` elapsed per the node clock |
  | `canceled` | `cancelInprocRequest` was called |
  | `queue_full` | sync-only: peer queue full (see below) |
  | `peer_closed` | sync-only: peer endpoint closed |
  | `no_route` | sync-only: no peer / unknown dial |

- `delivery` — a publication matched one of the node's filters:
  `msg` is the delivery, `filter` is the subscription that claimed it
  (first match in subscription order; borrowed — copy to retain).
- `message_dropped` — a message that will never deliver: late reply
  after cancel/deadline, queue-policy drop on a node-owned queue, or
  (QUIC) a malformed/oversized datagram.
- `connected` / `closed` — endpoint/session lifecycle bookkeeping.

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
- **The event queue is bounded.** `NodeOptions.max_events` (default
  1024) caps queued events; overflow drops the event (freeing its
  payload), counts `events_dropped`, and counts message-carrying
  drops in `dropped`. A stopped embedder loses events loudly in the
  counters rather than growing memory.

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
requests arrive as `quic_request` events (correlation id + the
request's stream), replies to the node's own outbound requests as
`quic_reply` events keyed by (session, stream), and datagrams as
`quic_delivery` events. Answer with `Node.replyQuic` (or
`replyErrorQuic`) while the request event is alive; publish with
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

`Node.requestQuic(session_id, outgoing)` sends a request on a QUIC
session AND records it for terminal-outcome classification — the
QUIC twin of `requestInproc`. It returns the stream the request
rides; the `(session_id, stream_id)` pair keys every later surface: a
`quic_reply` event (or a `recvReliable` pop — the session wrapper
settles the pending entry for you), or exactly one
`quic_request_failed` event when the request dies without one:

- `.deadline_exceeded` — the deadline passed against the node clock
  (`tick`'s `now_us`),
- `.canceled` — you called `Node.cancelQuicRequest` (which also
  RESET/STOP_SENDINGs the stream when the node owns the connection),
- `.peer_closed` — the session closed or was torn down.

Classification is first-wins and idempotent with a consumer's own
pending table: whichever side observes an outcome first, the other
ignores — see
[QUIC_REQUEST_OUTCOMES.md](QUIC_REQUEST_OUTCOMES.md). Raw
`queueReliable` sends remain untracked (a plain reliable send is not
a request); send-path errors from `requestQuic` stay synchronous and
map through `classifyRequestError` like the inproc ones.

## Relation to the App facade

`App` (the handler-registration facade over the same Node) consumes
inbound messages through `runOnce(dispatcher)` — a pull-dispatch
model. The embedded event model consumes through `tick`/`poll`. Both
work on the same Node, but they compete for the same rep inboxes:
pick one consumption model per endpoint, not both.
