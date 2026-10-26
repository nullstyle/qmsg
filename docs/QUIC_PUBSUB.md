# QUIC pub/sub across sessions

Node owns the desired subscription set and the source-side registry. Wire
subscriptions belong to individual sessions; their desired filters survive
reconnect. The current default is canonical `delivery` events. Direct inbox
consumption requires explicit legacy delivery and must have a single owner.

## Subscription lifecycle and source filtering

`Node.subscribeQuic(filter, QueueOptions)` and `unsubscribeQuic(filter)` update
the node-level desired set. Every ready session reconciles its queued snapshot:
new sessions receive the complete set, existing sessions receive deltas, and
bounded control-queue pressure defers reconciliation until a later tick. One
session's failure does not unwind the set. A busy control flush preserves its
queued prefix and subsequent updates.

SUBSCRIBE/UNSUBSCRIBE frames ride bounded follow-up unidirectional control
streams. Both dialed and accepted sessions use the shared EmbeddedDispatch
reader and `Node.driverControlFramesReceived`; the older dial-side inbound
limitation no longer applies. Source matching yields each subscribed peer once,
even if several filters match. Closing a session removes its registry entries. `NodeOptions.max_quic_subscriptions`
bounds both the local desired set and remote filter count per peer. At capacity,
updates to an existing filter and unsubscribe still work; a new remote filter
fails through the existing per-peer protocol error path, containing the offending
connection while preserving healthy peers.

## Choose datagrams or reliable streams

`publishQuicSubscribed(outgoing)!usize` retains its datagram behavior and returns
the number of queued recipients. It requires DATAGRAM negotiation. Slow
subscribers shed according to their policy and the local byte/count bounds.

`publishQuicReliable(outgoing)!ReliablePublishResult` uses the same source
registry and requires PUB/SUB roles without DATAGRAM. Its result has:

- `matched`: registry peers matching the subject;
- `queued`: new publications retained in per-peer pre-admission FIFOs;
- `backpressured`: peers whose block/fail policy refused this publication;
- `dropped`: publications shed by policy or refused by role, authorization,
  size, readiness, or closing state. Drop-oldest may shed an earlier publication
  while queuing this one, so these fields are not a partition of `matched`.

Fanout visits healthy peers even when another peer is full. This call never
waits. Invalid envelope input is checked before fanout. Allocation or other
fallible per-peer work can fail after earlier peers accepted the publication;
retrying an entire failed fanout may therefore duplicate those deliveries.

The publisher's `NodeOptions.quic_reliable_publications` bounds each unsent FIFO
by count and message bytes. Limits are also capped by the local session's
transport queue bounds. SUBSCRIBE transmits the `on_full` policy only; a remote
subscriber cannot enlarge publisher limits. Block/fail reports pressure,
drop-newest sheds the incoming publication, and drop-oldest evicts only
publications still in that FIFO. Already admitted transport streams are never
evicted by a later publication's queue policy. The existing transport sender
queue has its own count/byte bounds, in addition to the unsent FIFO.

`Node.publicationStats()` exposes pending FIFO count/bytes, aggregate FIFO high
water marks, stream-admitted publications, policy/teardown drops, and pressure.
High water marks aggregate all current peers, rather than describing one peer.

## Receive and authorize

A reliable subscriber selects `NodeOptions.quic_inbound = .publications`,
announces SUB and requires PUB in its QUIC options, and calls `subscribeQuic`.
The publisher announces PUB and requires SUB. Reliable publications force
`no_reply` and clear `unreliable`; the receiver emits owned canonical `delivery`
events without reply handles or request tracker reservations. The explicit
profile rejects request-shaped traffic. App's same profile dispatches `.sub`
handlers through the additive optional `dispatchQuicPublication` dispatcher
hook. Existing REP dispatcher signatures and request/pair profiles retain their
contracts.

The source checks each authenticated peer's SUB grant and subject permission.
The receiver checks the publisher's PUB grant and subject scope, plus its own
current desired filters. Unsubscribing therefore rejects already-in-flight
messages that arrive after local interest was removed. Literal pattern checks
use peer roles, as described in [AUTH.md](../AUTH.md).

## Pump, pressure and closure

Continue pumping after queuing publications. `nextTimer()` exposes immediate
work when the FIFO or newly admitted transport senders need another owner
pass. A full transport queue disarms that local wake; transport readiness and
transport/lifecycle deadlines drive later retry. Foreign owners continue to
call their driver's service and qmsg service hooks. No qmsg thread or hidden
loop is created.

GOAWAY stops new admission and discards/counts the pre-admission FIFO when
local drain begins or remote GOAWAY is observed. It does not open new streams
to flush that FIFO during drain. Already admitted streams retain the bounded
Sprint 1 lifecycle contract. Immediate session close discards/counts remaining
FIFO entries and frees all owned messages.

Each publication uses its own stream. Bytes within a stream retain transport
ordering; deliveries across publication streams may arrive out of order.
Transport reliability applies after stream admission while the connection
remains usable. Queuing is not a delivery acknowledgment. There is no durable
storage, application acknowledgment, exactly-once guarantee, retained replay,
or automatic replay across reconnect. A reconnect restores subscription
interest; publications racing that synchronization may find no subscriber.

See [Sprint 3 qualification](SPRINT_3_RELIABLE_PUBSUB.md) and the reusable
[public workload](../examples/reliable_pubsub_workload.zig).
