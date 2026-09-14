# Migrating to canonical Node messaging

The default `Node` uses `.delivery = .events` and
`.event_format = .canonical`. Both inproc and QUIC application traffic flow
through `poll`: `request`, `reply`, `request_failed`, and `delivery`.
The qmsg wire protocol remains `qmsg/1`; this is a library interface change.

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
also drain raw session inboxes. `App.init` deliberately selects legacy inbox
delivery for its `runOnce` dispatcher; low-level App examples retain that
pattern. Standalone Node examples use the canonical interface:
[embedded_inproc_node.zig](../examples/embedded_inproc_node.zig) and
[embedded_quic_attach.zig](../examples/embedded_quic_attach.zig).
