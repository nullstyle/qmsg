# QUIC pub/sub across the process wall — design note

Status: design recorded before implementation, at the mruby-quic
consumer's request (swarm item 2: "make the process wall transparent
to SUBSCRIBE and publish"). This is ROADMAP phase 5's "automatic
live-session emission," plus its two companions.

## What exists (surveyed, not rebuilt)

- `protocol/pubsub.Registry` — peer-keyed subscription registry;
  `subscribe` auto-adds peers, `applyControlFrame` maps inbound
  SUBSCRIBE/UNSUBSCRIBE frames onto it, `collectMatches(subject)`
  enumerates matching peers in subscription order, `removePeer`
  drops a dead subscriber whole.
- `transport/quic_control.State` — per-session control-frame queue +
  apply state. Queue side: `queueSubscribe`/`queueUnsubscribe` then
  `flushQueuedControl` (a follow-up uni control stream via
  `FlushSender`, pumped by the existing session pump). Apply side:
  `applyReceivedFrames` into the registry.
- `QuicSessionRuntime.queueDatagram` / `datagram_outbox` — pumped
  for dial clients in `tick` and for embedded sessions through
  `driverSessionPass`.
- Inbound datagrams already surface as `quic_delivery` events.

What was missing: nothing wires these to session lifecycle.

## Contract

**One registry per node; peer id = session id.** Subscriptions are
SESSION-scoped on the wire but NODE-owned on both sides: the node's
outbound set (what WE want from peers) and the registry (what PEERS
want from us).

**Ask 1 — node-level subscriptions that survive sessions.**
`Node.subscribeQuic(filter, options)` / `unsubscribeQuic(filter)`
mutate a node-level `SubscriptionSet`. Emission is tick-driven state
sync, not edge hooks: each tick, for every QUIC session —
`state == .ready` and not yet synced — queues the FULL node set
(one follow-up control stream) and marks it; sessions already synced
get only deltas; a busy flush sender leaves frames queued for the
next tick. A redial's NEW session starts unsynced, so the full set
re-emits on its first ready tick — subscriptions outlive sessions by
construction. Per-session queueing failures are contained: one
session's failure never unwinds the loop or the node set.

**Ask 2 — registry-aware fan-out.** `Node.publishQuicSubscribed(
outgoing) !usize` sends the datagram to every session whose registry
entry matches the subject — dial peers and embedded qmsg/1 clients
alike, one registry. Sessions without `datagram_enabled` and
over-budget outboxes are skipped-and-counted (`message_dropped`,
`Stats.dropped`); a subscriber's `on_full` queue policy decides
drop-newest vs drop-oldest at its outbox bound. Slow consumers shed;
the fan-out loop never blocks.

**Ask 3 — inbound SUBSCRIBE on the listener/embedded seam.**
Control frames beyond HELLO ride FOLLOW-UP uni streams (the HELLO
stream is HELLO-only by the session state machine's contract). The
embedded seat now tracks peer-initiated uni streams as control
receivers, decodes frames incrementally against its buffered bytes,
and hands complete frames to the owner, which applies them through
the session's control state into the node registry. Because
`ServerDispatch` delegates to `EmbeddedDispatch`, the qmsg-owned
listener gets this for free: an external qmsg client's SUBSCRIBE
registers. On ANY session death — reaper close, explicit
`closeQuicSession`, embedded will-close teardown —
`Registry.removePeer` runs: dying subscribers do not linger in the
fan-out set.

## Scope decisions

- Both ends announce `pub_ | sub` and `datagram_enabled` in their
  transport options; a session negotiated without the bits silently
  carries no pub/sub (no error, no drop).
- Dial-side deliveries are inbox-only (`recvDatagram`), mirroring
  dial-side replies (`recvReliable`); `quic_delivery` events are the
  embedded-session surface. A publication racing a reborn
  subscriber's re-sync is a lost datagram by design.
- Datagram-first; reliable-stream publication is future work.
- Replay/update machinery stays unwired (live-only subscriptions).
- No subscription-changed event; the registry stays invisible to
  embedders.
- Dial-side INBOUND control frames (a remote subscribing TO the
  dialer) are not wired this release: nothing in the consumer's
  model subscribes server-side. The seat-side machinery is where it
  would attach.
- `PeerId` (usize) vs `SessionId` (u64): cast at the registry
  boundary; ids are small and both are 64-bit on target platforms.

## Acceptance

- Live two-node: dial-side `subscribeQuic`, listener-side
  `publishQuicSubscribed`, delivery as `quic_delivery`; kill /
  same-key reborn / redial; delivery resumes with NO new subscribe
  call (the redial re-emission contract — tested hardest).
- Slow subscriber: bounded outbox sheds and counts instead of
  blocking.
- Hermetic: registry apply/removePeer lifecycle, node-set emission
  batching, fan-out matching and policy.
