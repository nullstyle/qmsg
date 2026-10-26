# Migrating to canonical Node messaging

The default `Node` uses `.delivery = .events` and
`.event_format = .canonical`. Both inproc and QUIC application traffic flow
through `poll`: `request`, `reply`, `request_failed`, and `delivery`.
The qmsg wire protocol remains `qmsg/1`; this is a library interface change.

**Breaking (behavior), since 0.8.0, and the compiler does not report it.** A
`Node.init` call written for 0.7.0 compiles unchanged and gets these
defaults. `poll` then drains every QUIC session's inboxes, so code that also
reads a session itself (`recvReliable` / `recvDatagram`) finds nothing, and
its replies disappear with no error. A Debug build panics on that second
reader. To keep the 0.7.0 behavior, set both fields of
[Explicit compatibility mode](#explicit-compatibility-mode).

## Requests, replies, and ownership

Use `Node.request` for either transport. Its return value is an opaque local
`RequestId`, distinct from the wire message ID and QUIC stream ID. Match
`reply.request_id` or `request_failed.request_id` against that value.

```zig
const request_id = try node.request(.{ .quic = session_id }, .{
    .subject = "user.get",
    .body = "42",
    .deadline_ms = 250,
});
// For inproc, use .{ .inproc = dial_id } with the same outgoing message.
```

Drive `tick(now_us)` with monotonic microseconds and drain `poll`. Each event
owns its message. Free the whole returned batch even when a handler returns
early; a defer inside each iteration alone leaves later events unfreed.
The example's `consumeReply` and `consumePublication` functions borrow their
message argument; ownership stays with the event until the batch is freed.

```zig
try node.tick(now_us);
var events: [16]qmsg.node.Event = undefined;
const count = try node.poll(&events);
defer for (events[0..count]) |*event| event.deinit();
for (events[0..count]) |*event| {
    switch (event.*) {
        .request => |ev| try node.reply(ev.msg.reply_handle.?, .{
            .subject = "",
            .body = "ok",
        }),
        .reply => |ev| {
            if (ev.request_id == request_id) consumeReply(ev.msg);
        },
        .request_failed => |ev| {
            if (ev.request_id == request_id) handleFailure(ev.failure);
        },
        .delivery => |ev| consumePublication(ev.msg),
        else => {},
    }
}
```

`Node.reply(handle, outgoing)` works on either transport. The request message
owns its reply handle; retain a copy before releasing the event if work is
asynchronous, then deinit the retained handle when finished. `Message.clone`
also retains the handle. A retained handle keeps routing metadata alive without
keeping the request body. It reports `EndpointClosed` after its target is
destroyed; it does not keep a connection alive. A final reply completes the
handle, so another reply returns `InvalidState`.

`replyInproc` and `replyErrorInproc` reply through the same handle. If you
keep a copy of a request event, retain the handle in the copy
(`msg.reply_handle.?.retain()`, or `msg.clone`). A copy without it returns
`error.ReplyHandleMissing`. Before 0.8.0 such a reply went by message id
alone, and a requesting `Node` dropped it with no error at the replier.

Use `Node.cancelRequest(request_id)` for cancellation. A terminal outcome stays
available until consumed by `poll` or `takeOutcome(request_id)`. `takeOutcome`
removes one already-completed result; it does not pump network I/O or advance
the clock. Deinit the returned event just as with `poll`.

## Bounded requests and outcomes

Node options separate request and completion capacity from ordinary events:

| Option | Default | Meaning |
| --- | --- | --- |
| `max_requests` | 1024 | Pending requests plus terminal outcomes waiting to be consumed |
| `max_request_bytes` | 16 MiB | Aggregate subject, header, and body bytes of pending requests |
| `max_completion_bytes` | 16 MiB | Retained reply payload bytes across terminal outcomes |
| `max_events` | 1024 | Ordinary queued events, separate from terminal outcomes |
| `max_event_bytes` | 16 MiB | Retained message bytes in the ordinary event queue |

Request admission reserves terminal-outcome capacity before sending. A full
ordinary event queue cannot discard an accepted request's terminal result.
If a reply cannot fit the completion byte budget, its outcome becomes
`request_failed` with `.queue_full`; the payload is freed. New requests fail
with `TooManyInflightRequests` when pending requests plus unread outcomes reach
the count bound, or `QueueFull` at the request byte bound. Drain outcomes to
release reservations. Set request deadlines so unreachable peers eventually
release pending work into terminal outcomes.

`poll` drains terminal outcomes before ordinary events; there is no global FIFO
ordering between those two queues. Datagram deliveries and lifecycle events
remain subject to the ordinary event bounds and drop counters. Inbound request
draining applies backpressure when that queue is full. None of these byte
budgets is a total-process memory ceiling: transport buffers and application
copies have their own ownership and limits.

## Authorization and peer readiness

Credential verification happens at HELLO. Configured session policy is checked
automatically before a message reaches Node event consumers, socket consumers,
or App handlers. App dispatch also checks decoded messages supplied by an
external driver. Handlers do not need `Context.requireRouteAccess` to enforce
the configured policy; that helper remains an explicit authenticated-only
check. Anonymous sessions remain allowed when configuration permits them.

`dialQuic` returns an allocated session ID while connection establishment is
pending. `connected` is lifecycle bookkeeping, not a readiness signal. Use
`sessionStatus(id)` for `.connecting`, `.ready`, or `.closing`, the observed
certificate SPKI, and the peer's announced pattern bits. A missing result means
the session no longer exists. Ready means TLS and qmsg HELLO have completed.

When dialing a specific certificate identity, set
`QuicDialOptions.expected_peer_spki` to its 32-byte digest. This is checked
against the authenticated certificate before qmsg exposes a usable session.
It is independent of the peer's HELLO text ID. Configure CA trust and name
verification for the deployment as well. To require protocol capabilities, set
`transport.required_peer_patterns`; HELLO rejects a peer missing any required
bit. `findReadySessionSupporting(peer_spki, required_patterns)` reuses only an
authenticated ready session satisfying those requirements.

## QUIC heartbeat and graceful shutdown

Heartbeats are enabled only when both HELLOs offer a nonzero
`heartbeat_interval_ms`; the effective interval is the smaller offer. The
runtime answers PING with PONG and tracks idle probes on the caller's clock.
Lifecycle response state is bounded, including when flow control prevents a
response from being written.

`closeQuicSession(id)` retains its immediate-abort behavior. To drain a ready
session, call:

```zig
try node.goawayQuicSession(session_id, 0, "shutdown", now_us, 5_000_000);
```

The session stops accepting new work and `sessionStatus(id)` reports
`.closing`. Existing streams and retained reply handles continue to run for
the explicit drain interval; keep ticking and polling. The connection closes
at the deadline even if application work remains. Empty transport queues do
not shorten this interval, since asynchronous application work may still own a
reply handle. Receiving GOAWAY starts the configured
`QuicOptions.drain_timeout_ms` interval (default 5000 ms).

The additive `session_goaway` event carries `session_id`, `code`, and an owned
`reason`. Update exhaustive event switches and call `Event.deinit` as for
message events. Like other ordinary lifecycle events, this notification is
subject to event queue bounds; `sessionStatus` remains available independently.
Accepted requests still retain one terminal outcome if the session closes.

`Node.nextTimer()` includes heartbeat and drain deadlines. Foreign owners must
set `EmbeddedDispatch.setHeartbeatClock(now_us)` before servicing seats and
combine each runtime's `nextLifecycleTimer()` with their own QUIC deadlines.
Use a monotonic microsecond clock and continue servicing inbound data before
evaluating timeout expiration.

Unknown control tags with bit 61 set are optional extensions and can be
skipped on bounded follow-up control streams. Unknown required tags,
malformed frames, and invalid startup HELLOs remain errors. The standalone
control decoder remains strict. ALPN and the HELLO wire version remain
`qmsg/1` and `1`.

## Owned QUIC facade and peer-role grants

`QuicSocket(.pair/.req/.rep)` provides owned listen/dial with explicit
`pump(now_us)` and canonical poll events. It owns one heap-stable Node; configure
limits through its `node` options and use its `nextTimer` / `readableSockets`
methods in the owner loop. Its selected inbound profile and canonical delivery
are fixed by the socket type. See [the Sprint 2 guide](SPRINT_2_QUIC_SOCKETS.md).

Automatic authorization now consistently checks the peer action accepted at
HELLO: REP handlers admit REQ peers, PULL handlers admit PUSH peers, SUB handlers
admit PUB peers, and PAIR remains PAIR. Previously request admission checked the
local REP role after authenticating a REQ peer, making minimal REQ grants
unusable. Change local-receiver-only grants to peer-action grants when migrating.
Explicit `requirePattern` checks remain literal; `requireRouteAccess` maps the
local handler to its peer action. Subject restrictions and anonymous policy
are unchanged.
If an explicit handler check used `requirePattern(.rep)` to mean "may issue
requests", change that check to `.req` or use `requireRouteAccess`.

## Explicit compatibility mode

Older direct-inbox integrations can opt into:

```zig
var node = try qmsg.Node.init(allocator, .{
    .delivery = .legacy,
    .event_format = .legacy_transport,
});
```

`delivery` controls whether Node drains session inboxes; `event_format` controls
the names of returned events. In legacy mode, sessions explicitly attached
with event delivery still produce poll events, while ordinary dial sessions
retain the direct `recvReliable` / `recvDatagram` path. Legacy QUIC event names
are `quic_request`, `quic_reply`, `quic_request_failed`, and `quic_delivery`.
Transport-specific request/reply helpers remain compatibility adapters.

Choose one receive consumer per session. Under the default event mode, do not
also drain raw session inboxes. A Debug build panics when one session has
both readers. `App.init` deliberately selects legacy inbox
delivery for its `runOnce` dispatcher; low-level App examples retain that
pattern. Standalone Node examples use the canonical interface:
[embedded_inproc_node.zig](../examples/embedded_inproc_node.zig) and
[embedded_quic_attach.zig](../examples/embedded_quic_attach.zig).
