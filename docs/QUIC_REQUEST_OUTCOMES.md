# QUIC dial-side request outcomes — design note

Status: BUILT as of qmsg 0.1.6 (`Node.requestQuic` /
`cancelQuicRequest` / `settleQuicRequest`, the `quic_request_failed`
event, and the session wrapper's settling `recvReliable`). The
contract below is the implemented behavior. This note was recorded
before implementation (the item the roadmap carried since the
embed-seam review as "QUIC dial-side deadline outcomes"); the
consumer (mruby-quic) enforces deadlines on its own clock today and
asked only that qmsg's classification be *idempotent with theirs* —
their words: "pending keyed by session+stream, first classification
wins."

## Problem

An outbound QUIC request (`queueReliable` on a dial session) has no
node-level terminal outcome. The reply surfaces through `recvReliable`
or a `quic_reply` event, but a request that dies silently — deadline
passes, the peer never answers, the connection closes — is never
classified by qmsg. Every consumer builds its own deadline table on
top. The inproc surface already has the answer shape: a node-owned
pending table, `RequestFailure` vocabulary, and `request_failed`
events (`requestInproc` / `cancelInprocRequest` / `expireInprocPending`).

## Contract

**One pending table, node-owned, keyed `(session_id, stream_id)`.**
The key is the same pair the reply event carries (`QuicReplyEvent`),
so a consumer's correlation table joins on either side.

**Registration is explicit.** `Node.requestQuic(session_id, outgoing)
!u64` wraps the session's `queueReliable` and records the pending
entry (message id carried for correlation). Raw `queueReliable` stays
untracked: a plain reliable send is not a request, and silently
classifying every stream send would emit phantom failures.

**First classification wins — on both sides of the seam.** A pending
entry settles exactly once, on whichever outcome is observed first:

| Outcome | Classification | Wire action |
| --- | --- | --- |
| reply surfaces (event session: `quic_reply` emitted; recvReliable session: reply present in inbox, or consumer calls `settleQuicRequest` after popping) | none — the reply IS the outcome | — |
| deadline passes at `tick` | `quic_request_failed{.deadline_exceeded}` | none (matches consumer behavior; a STOP_SENDING-on-expiry option can come later) |
| `cancelQuicRequest` | `quic_request_failed{.canceled}` | cancel plan applied when the node owns the connection (dial clients): RESET our half + STOP_SENDING the reply half, `0x51_01` |
| session closing/closed/destroyed | `quic_request_failed{.peer_closed}` | none |

Event shape mirrors `RequestFailedEvent` with the QUIC key:

```zig
QuicRequestFailedEvent { session_id, stream_id, id, failure: RequestFailure }
```

**Idempotency with consumer tables.** qmsg's events are advisory and
first-wins symmetric: a consumer that already classified a request
(for example, it popped the reply through `recvReliable` before qmsg's
sweep ran, or its own deadline fired first) ignores qmsg's event for
that `(session, stream)`; qmsg likewise never re-emits after it has
settled an entry. Neither side needs to know about the other. The
false-positive window — reply popped by the consumer, qmsg's sweep
has not seen it — is closed by the consumer calling
`Node.settleQuicRequest(session_id, stream_id)` when it pops a reply
it registered through `requestQuic` (the node-level session wrapper's
`recvReliable` does this automatically).

**Synchronous send errors stay synchronous.** `requestQuic` returns
`error.QueueFull`/`FlowControlled`/`EndpointClosed`/`InvalidState`
from `queueReliable` directly; consumers map them through the existing
`classifyRequestError` — no events for failures that happen before
the request is in flight.

## Scope and non-goals

- Per-stream RESET on a live dial connection is covered by the
  connection-level `.peer_closed` path for now; observing individual
  inbound stream resets on the dial side would need recv-state
  surfacing nobody has asked for yet.
- `no_route` / `queue_full` never appear as events — they are
  send-path errors by nature.
- No new wire frames: cancellation reuses `quic_cancel` plans and
  app error codes that already exist and are vector-tested.
- `queueReliable` semantics are unchanged.

## Acceptance

- Hermetic: deadline expiry classifies once; a reply that raced the
  deadline settles silently; cancel classifies and does not
  double-classify; session close classifies all its pending; a second
  classification attempt for the same `(session, stream)` is a no-op.
- Live UDP: the phase-B mirror shape — answered and never-answered
  requests — now ends with `quic_request_failed{.deadline_exceeded}`
  for the silent one and a reply for the answered one.
- Consumer: mruby-quic's deadline classification and qmsg's coexist
  (their table ignores ours after their first classification, and
  vice versa) — their two live tests stay green on this release.
