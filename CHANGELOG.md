# Changelog

All notable changes to qmsg are documented in this file.

The project is pre-1.0. Any 0.x release may include breaking API
changes.

## [Unreleased]

## [0.4.0] - 2026-09-03

### Added

- **Optional Cap'n Proto body codec** (`-Dcapnp=true`, module
  `qmsg-codec-capnp`, `src/codec_capnp.zig`): the phase-9 typed-codec
  slot's first resident. `encode` packs a capnp `MessageBuilder` into a
  qmsg body, `decode` parses one back with bounded validation — the
  standard packed encoding, interoperable with any Cap'n Proto
  implementation. The capnp-zig dependency is LAZY: default builds and
  non-opting consumers never fetch it. Run its tests with
  `zig build -Dcapnp=true capnp-test`.

### Changed

- The `quic` dependency is now configured with `.optimize` forwarded and
  `.@"sanitize-c" = "trap"` (previously only `.target`). Two reasons,
  one behavioral and one structural. Behaviorally, `trap` keeps C/UB
  checks in BoringSSL's statically linked objects without needing a
  UBSan runtime, which Linux/lld ReleaseSafe links otherwise fail to
  resolve — the same rationale capnp-zig documents for its identical
  quic pin. Structurally, the build system only deduplicates a shared
  dependency module when every parent configures it with an identical
  option set; aligning with capnp-zig's map is what lets one binary link
  qmsg and capnp-zig against a single quic (see
  `capnp-qmsg-demo/` in the workspace). The historical note that quic's
  build rejects an `optimize` option applied to an older quic build;
  v0.19.0 declares it.

## [0.3.0] - 2026-08-28

Channel binding end to end: the QUIC adapter now wires the HELLO
challenge hooks (minted per accepted session, verified per credential)
that 0.2.1 shipped as library primitives without transport support.
Found and specified by the mruby-quic consumer against the v0.2.1
tarball; implemented, tested live over UDP here.

### Added

- **`QuicOptions.hello_challenge` — per-connection challenge minting
  in the QUIC listener loop.** A listener armed with an
  `auth.HelloChallengeConfig` template mints a fresh challenge for
  every accepted session at `Node.driverServerSessionCreate` (the
  seam both listener dispatches converge on): bytes from the node's
  io, binding installed into that session's `AuthConfig`
  (`hello_binding` required), challenge advertised in the outgoing
  HELLO. The session owns the binding, so a challenge dies with its
  connection — a token verified here is bound to THIS connection's
  implicit assertion and replays nowhere else (proven live: a
  captured token re-presented statically on a second connection is
  rejected and the session torn down). Static-credential listeners
  are untouched; the template is strictly opt-in.
- **`QuicOptions.credential_provider` + `auth.CredentialProvider` —
  dial-side bound minting.** Fn-pointer shape mirrors
  `Authenticator` (`ptr` + `provide_fn`, root-re-exported). A dial
  with a provider defers its local HELLO until the peer's arrives,
  then calls the provider with an `auth.PeerHelloContext`
  (peer id + advertised challenge); the returned
  `auth.ProvidedCredential` (token, optional hint, allocator-owned)
  rides the HELLO, the session owning its copies. A provider error
  closes the session, exactly like a rejected static credential.
  Mutual deferral (providers on both ends) is unsupported and
  documented: one side must send eagerly, and listeners always do.
- **`auth.HelloChallengeState.fromOwnedChallenge`** — build a binding
  state around caller-filled bytes, for seams that draw randomness
  from `std.Io` rather than a `std.Random` (the node's own path).
- **The peer's advertised challenge is retained and honored**: the
  session stores `peer_hello_challenge`, and what
  `Session.authenticateHello` validates is now the real advertised
  bytes (previously decoded-then-dropped, and the policy check saw
  empty). A binding policy tighter than the codec's 128-byte wire
  bound now rejects over-long challenges — the challenge is policy
  input, not decoration.

### Documentation

- AUTH.md's replay-defense section now documents the adapter wiring
  (both hooks, ownership lifetimes, the mutual-deferral limitation)
  in place of the "still needs to wire" note. ROADMAP item 10
  reflects the shipped minting; the remaining gap is replay-cache
  wiring at the listener seam.

## [0.2.1] - 2026-08-28

Fixes the published-tarball auth-path breakage (found by the
mruby-quic consumer, reproduced cold on our side), plus the v0.2.0
adoption-review documentation.

### Fixed

- **The v0.1.9 and v0.2.0 tarballs do not compile their auth path
  against their own paseto pin.** paseto 0.3.0 changed
  `verifyToken` to take the token by reference; the v0.1.9 pin bump
  (and everything tagged through v0.2.0) still passed it by value —
  warm-cache suite runs from the checkout never surfaced it, and the
  published artifact failed with
  `auth_paseto.zig:246: error: expected type '*const token.Token'`.
  This release rides the repair (adapted call, paseto pinned to
  0.4.0, `paseto-0.4.0-EBI95RcXCADs0jz3tebS1xMaAiT2r3Tpx8HsF5LfpqOS`)
  and is itself verified the way the broken tags were not: cold
  build + full suite from the packed archive (335/335). Treat
  v0.1.9 and v0.2.0 tarballs as broken for auth; v0.1.8 is the last
  sound earlier pin.
- **Release process:** `tools/tarball-smoke.sh` is now the release
  gate — `git archive` of the tag, cold caches, full build + tests.
  A checkout-built CI cannot catch a tree that is internally
  incoherent; the packed artifact can, and now does before tagging.

### Documentation

- **Pattern-bit gate is silent**: a session negotiated without
  `pub_ | sub` (and `datagram_enabled`) carries no pub/sub —
  handshake completes, requests flow, subscriptions never register,
  no error or drop. Both operational notes now live in
  EMBEDDING.md's pub/sub section and QUIC_PUBSUB.md's scope: both
  ends announce the bits.
- **Dial-side deliveries are inbox-only by design** — recorded as
  the direct-consumption twin of dial-side replies through
  `recvReliable` (embedded sessions get `quic_delivery` events;
  dial sessions surface through `recvDatagram`). Consumers draining
  dial inboxes by hand keep their drain; if qmsg ever emits
  dial-side delivery events, first-wins makes deleting it a
  one-liner downstream.
- **A publication racing a reborn subscriber's re-sync is a lost
  datagram by design** — noted so the first person it surprises has
  a doc to find.
- **Auth claims from the consumer's mapping** (EMBEDDING.md): the
  `qmsg` claim is fail-closed by default (missing claim rejected,
  `patterns` required and non-empty — no unset-means-allow-all), with
  a working example token; and the claim-vs-identifier pattern
  spelling table (`"pub"`/`"sub"` in claims vs `.@"pub"`/`.sub` enum
  tags vs `pub_`/`sub` PatternBits fields).

## [0.2.0] - 2026-08-28

QUIC pub/sub across the process wall (swarm item 2, per the
mruby-quic consumer request; ROADMAP phase 5's "automatic
live-session emission" plus its two companions). Design recorded
before code in docs/QUIC_PUBSUB.md.

### Added

- **`Node.subscribeQuic` / `Node.unsubscribeQuic`** — node-level
  subscriptions that emit on every session and RE-EMIT the full set
  on each NEW session's first ready tick: a redial's replacement
  session inherits the mesh's subscriptions with no re-subscribe
  call. Tick-driven sync (not edge hooks) over the existing
  control-frame queue/flush machinery; per-session failures never
  unwind the set. Bounded by `NodeOptions.max_quic_subscriptions`.
- **`Node.publishQuicSubscribed`** — registry-aware datagram
  fan-out to every session whose registry entry matches the subject
  (dial peers and embedded qmsg/1 clients, one registry keyed by
  session id). Sessions without datagram support and over-budget
  outboxes are skipped-and-counted (`message_dropped`,
  `Stats.dropped`); a subscriber's `on_full` queue policy sheds
  drop-newest or drop-oldest at the new
  `NodeOptions.quic_datagram_outbox_max` bound. Slow consumers
  shed; the fan-out never blocks.
- **Inbound SUBSCRIBE/UNSUBSCRIBE on the listener/embedded seam** —
  control frames beyond HELLO ride follow-up uni streams; the
  embedded seat arms incremental control readers for them (deferred
  until the session reaches ready — a first-ready-tick flush can
  ride the same flight as the HELLO tail) and applies decoded frames
  into the node registry. Because `ServerDispatch` delegates to
  `EmbeddedDispatch`, external qmsg clients subscribing to a qmsg
  App node work unchanged. `Registry.removePeer` runs in
  `destroyQuicSession`, so dying subscribers leave the fan-out set
  on every death path (reaper, explicit close, embedded teardown).

### Scope

Datagram-first (reliable-stream publication later); replay stays
unwired (live-only subscriptions); no subscription-changed event;
dial-side inbound control frames unwired (nothing in the consumer
model subscribes server-side — the seat machinery is where it would
attach).

### Testing

- Live, the consumer's hardest contract: dial, subscribe ONCE,
  delivery crosses the wall both directions; silent kill, same-key
  reborn, idle-window death observed, redial — the reborn hub knows
  the NEW session's subscription with no subscribe call. Verified
  red on: no full-set emission, no control-read arming, and no
  outbox bound (each neuter breaks exactly the matching test).
- Hermetic: fan-out matching, the datagram gate both ways,
  drop-newest vs drop-oldest shedding with `message_dropped`, and
  emission mechanics (full set on first ready tick, duplicate
  no-op, unsubscribe delta, set-before-sessions).
- Full suite 335 tests (252 root + 83 transport) in debug AND
  `--release=safe`.

## [0.1.9] - 2026-08-28

Dependency integration: `paseto-zig` 0.2.0 → 0.3.0.

### Changed

- **Pinned `paseto-zig` `0.3.0`** (tag tarball,
  `paseto-0.3.0-EBI95S2uBwBha2qo-qgtyvS3BJVrGAf7HDhlrsCmCrQL`). The
  0.3.0 release is audit-hardened on the untrusted-input path qmsg
  feeds it (token parse, PASERK id/PEM validation), adds
  cross-implementation interop fixtures, and verifies both the
  stable and dev Zig toolchains in CI. qmsg's consumption surface
  (`PaserkId`, `v4.Public`/`v4.Local`, `paserk.id` parse,
  `token.parse`/`serialize`, `Validator`) is unchanged by the bump —
  no source changes were needed. The pin id itself is the release-
  hygiene acceptance check: it reads `paseto-0.3.0-…` where the old
  0.2.0 tag's id read `paseto-0.1.0-…` (that tag shipped with a
  stale zon version; 0.3.0 declares correctly).

### Testing

- Full suite 332/332 in debug AND `--release=safe`; consumer
  dependency-instantiation check (path dependency, `.{ .target,
  .optimize }` forwarded) green in both modes; examples run
  (localhost live, auth-paseto).

## [0.1.8] - 2026-08-28

qmsg listeners answer stateless resets (the under-load death-detection
hole, per the mruby-quic adoption follow-up).

### Added

- **`QuicListenOptions.stateless_reset_key`** — RFC 9000 §10.3
  stateless-reset HMAC key, threaded through the listener runtime to
  quic-zig's `Server.Config`. Null (the default) generates a fresh
  random key per listener, so every qmsg listener answers unroutable
  orphan probes with a Stateless Reset instead of silently dropping
  them — quic-zig's documented production posture, which qmsg's
  `listenQuic` wiring had simply never turned on.

### Fixed

- **Silent death under load had no detection path.** quic-zig bumps
  the connection's activity clock on SEND, so a connection with
  unacked data in flight PTO-probes forever and never idles — with a
  deadline-less request pending, a silently-dead remote left the
  session visibly `.ready` indefinitely (the consumer reproduced
  this: 45s of virtual time, no transition). With a keyed listener
  on the peer's port, the orphan's first probe after the remote dies
  earns a Stateless Reset; the client verifies it through the
  per-CID token it was advertised at handshake (no shared secret on
  the peer side), the connection reaches terminal closed, and the
  v0.1.7 death observation closes the session — `.closed` plus
  `.peer_closed` for the pending, at PTO latency rather than the
  idle window. Pin one key across instances/restarts so a replacement
  listener's resets verify against tokens minted by the dead
  instance; documented in EMBEDDING.md, including the fundamental
  residual: a port where nothing listens is still silent, and the
  consumer-side answer there is request deadlines.

### Testing

- Live starvation mirror (the consumer's shape, red on keyless
  wiring — verified by neutering the key pass-through, 331/332): a
  deadline-less `requestQuic` in flight when the remote dies
  SILENTLY (plain deinit — quic-zig's `Server.deinit` is local
  teardown, nothing ships), a reborn keyed listener takes the same
  port, and the orphan receives the reset: one `.closed`, the
  pending classified `.peer_closed`, in under 10s of virtual time
  where idle death needs the full quiet window and a deadline-less
  pending would never classify at all.
- Full suite 332 tests (249 root + 83 transport), green in debug;
  examples run (localhost live).

## [0.1.7] - 2026-08-28

Dial sessions now observe connection death (the swarm peer-visibility
seam, per the mruby-quic consumer report).

### Fixed

- **A client dial session whose connection died emitted nothing,
  forever.** `tickQuicClients` never inspected the connection's
  close state, quic-zig's `Connection.tick` early-returns once
  closed, and the connection was unreachable from the embedder side —
  so a silently dead remote (process kill, partition) left the peer
  visibly up with no event, and consumer redial machinery keyed on
  `.closed` never fired. The client tick now stops pumping a
  terminally-dead connection and tears its session down through the
  existing `closeQuicSession` path: exactly one `.closed` event, the
  session gone from `quicSession`, and every still-pending
  `requestQuic` classified `.peer_closed` in the same tick's outcome
  sweep. Detection is terminal-only by design (`Connection.isClosed`;
  `closeState()`'s closing/draining are an in-progress close, not
  death) and lags the wire event by the draining window — documented
  in EMBEDDING.md as late-and-certain. Driver-owned (listener-side)
  sessions are untouched (will-close teardown already handles them),
  and a never-landing dial whose handshake times out closes through
  the same path — intentional, and safe to race consumer-side
  connect-timeout recycling (`closeQuicSession` is idempotent per
  session on the consumer's event routing).

### Testing

- Live kill-remote acceptance: dial to a live listener, drive to
  ready, fifty healthy ticks emit no `.closed`, then the server-side
  connection closes (CONNECTION_CLOSE on the wire) with a request
  in flight — the dial emits `.closed` exactly once, the session is
  gone, and the pending classifies `.peer_closed` with the right
  (session, stream, id).
- Live never-landing dial: a dial to a dead port closes through the
  handshake-timeout path with exactly one `.closed`. Both tests fail
  on v0.1.6 (verified by neutering the reaper: 246/248).
- Full suite 331 tests (248 root + 83 transport), all green in
  debug; examples run (localhost live).

## [0.1.6] - 2026-08-28

Dial-side QUIC request outcomes (the Phase B item deferred since the
embed-seam review), plus the ReleaseSafe resolution the changelog has
carried as a known issue since 0.1.0.

### Added

- **`Node.requestQuic` / `cancelQuicRequest` / `settleQuicRequest`
  and the `quic_request_failed` event** — terminal-outcome
  classification for outbound QUIC requests, the twin of the inproc
  surface's pending table. A node-owned table keyed
  `(session_id, stream_id)` — the same key the `quic_reply` event
  carries — settles first-classification-wins on whichever outcome is
  observed first: the reply surfacing (settled silently; the session
  wrapper's `recvReliable` settles on pop, the `quic_reply` drain
  settles inline, and a reply already sitting in the inbox settles at
  sweep time), a passed deadline at `tick`
  (`quic_request_failed{.deadline_exceeded}`), an explicit cancel
  (`.canceled`, plus a RESET/STOP_SENDING cancel plan on the wire
  when the node owns the connection), or the session dying
  (`.peer_closed` for every still-pending request). The contract —
  including idempotency with a consumer's own pending table, exactly
  as the mruby-quic review requested ("pending keyed by
  session+stream, first classification wins") — is recorded in
  docs/QUIC_REQUEST_OUTCOMES.md, written before the code. Raw
  `queueReliable` sends stay untracked; send-path errors remain
  synchronous through `classifyRequestError`.
- `QuicSessionRuntime.recvReliable` on the node-level session wrapper
  (the inner runtime's pop, plus pending settlement), and
  `QuicSessionRuntime.inboxHasStream` on the transport runtime for
  the sweep's reply-already-landed check.

### Fixed

- **ReleaseSafe no longer fails to link** — the `___ubsan_handle_*`
  undefined-symbol failure (known issue since 0.1.0, tracked as
  upstream boringssl-zig/quic-zig) is resolved through the current
  pins: qmsg's own full suite passes 329/329 at `--release=safe`,
  and the consumer dependency-instantiation check (qmsg as a path
  dependency with `.{ .target, .optimize }` forwarded) builds and
  runs green in safe mode. The 0.1.1 note stands as history; this
  entry supersedes it.

### Testing

- Hermetic outcome suite: deadline classifies once and never
  re-classifies; a reply already in the inbox settles silently and
  beats a passed deadline; wrapper pops settle; cancel classifies
  `.canceled` exactly once (second cancel is a no-op); a dying
  session classifies every pending request `.peer_closed`; raw
  `queueReliable` sends never classify.
- Live-UDP acceptance (phase-B mirror upgraded): the silent request
  ends as exactly one `quic_request_failed{.deadline_exceeded}`
  keyed to its (session, stream) while the answered requests never
  classify and the connection stays ready.
- Full suite 329 tests (246 root + 83 transport) in debug AND
  `--release=safe`; all nine examples run (localhost live).

## [0.1.5] - 2026-08-28

Fixes for three consumer-reported defects in the v0.1.4 embed seam
(mruby-quic's Phase C integration report). Two of the three share one
root cause; all three carry regression tests that fail on v0.1.4.

### Fixed

- **Embedded sessions died on streams that were open but had not yet
  delivered data** — the seam's adapter answered "no such stream"
  (`StreamNotFound`) for any stream without a seat buffer, but
  receivers are armed at `onStreamOpen` (and the control receiver at
  HELLO) while the buffer first exists at `onStreamData`. Any pump in
  that window — a `serviceSeat` pass, or another stream's data/end
  hook in the same driver pass — killed the whole session
  (`pumpSeat`'s protocol-error path: `beginClosing` + connection
  close). Hermetic packet timing coalesces the flight so qmsg's own
  tests never opened the window; real UDP timing does. This is the
  v0.1.2→v0.1.4 reply regression on the qmsg-owned listener (the
  ServerDispatch rewrite moved reads from the connection's stream
  table — where an opened-but-dataless stream exists — to the seat
  map) AND the second-request connection close on the embedded seam.
  The adapter now reports "open, no bytes observed" (not reset, no
  final size, nothing read) for unbuffered streams — the answer the
  connection's own table would have given.
- **A pump error stranded receivers/senders that completed earlier in
  the same pass** — the removal loop never ran, so the next pump
  failed with `InvalidState` from a stale decoded receiver (or re-FINs
  a finished sender's stream) instead of the real cause. Both pump
  loops now finish their removal pass before propagating an error.
- **examples/quic_node_localhost.zig live mode failed at the TLS
  handshake** (`InvalidState` via `mapSslError`): the dial passed no
  `ca_pem`, and the dial path has no skip-verify escape hatch — the
  self-signed fixture now verifies against itself, as the live-UDP
  acceptance test already did. (The v0.1.4 cert repair was correct;
  this was the remaining blocker.)

### Testing

- Hermetic foreign-driver e2e: a reply deferred past the poll loop
  still reaches the requester; two requests on one session — one
  answered, one deliberately never answered — keep the connection
  alive (a third request round-trips afterwards). The latter fails on
  v0.1.4 with `EndpointClosed`.
- Live-UDP acceptance mirror of the consumer's phase-B shape (qmsg
  App server on an ephemeral port, answered + never-answered requests
  on one dial session, `tick; runOnce` driving with errors
  surfaced — their loop swallows them with `catch {}`, which is how
  the regression hid): fails on v0.1.4, passes now.
- Unit: a pump error mid-pass no longer strands completed receivers
  (the completed one is removed and its message delivered; the next
  pump reports the real error again).
- `runOnce`'s QUIC dispatch now tolerates dispatchers whose result
  carries replies only (no `publications` field) — the shape of the
  consumer's minimal dispatchers.
- Full suite 328 tests (245 root + 83 transport); all nine examples
  run, including the localhost example's live-UDP mode; the consumer
  dependency-instantiation check (qmsg as a tarball-path dependency
  with `.target` + `.optimize` forwarded) is green.

## [0.1.4] - 2026-08-28

The inbound QUIC embed seam, built per the consumer-reviewed design
(docs/QUIC_EMBED_SEAM.md, approved with decisions: shared listener +
ALPN routing; pull-model events; AuthConfig once at init;
drop-and-count datagrams).

### Added

- **`EmbeddedDispatch(Owner)` + `EmbeddedSeat(Owner)`** — inbound
  qmsg attach on a FOREIGN embedder's listener: the embedder owns
  the listener, UDP, and the one `quic.app.Driver` (quic-zig allows
  a single will-close hook per Server); qmsg owns only the sessions
  riding ALPN-`qmsg/1` connections. The embedder keeps one seat per
  connection in its own connection state, delegates its Driver hooks
  (`onHandshake`/`onStreamOpen`/`onStreamData`/`onStreamEnd`/
  `onDatagram`/`onDisconnect`), and calls `serviceSeat` once per
  connection per tick. `isQmsgAlpn` routes; `driverSizing` derives
  the Driver's table/buffer sizing from transport options. The
  dispatch is stateless (state lives in seats and the owner), so the
  qmsg-owned listener's `ServerDispatch` now delegates to the same
  bodies — one copy of the teardown mechanics, not two.
- **Pull-model QUIC events** — embedded sessions are
  `event_delivery`: inbound requests arrive as `quic_request` poll
  events (correlation id + the request's stream + deadline), replies
  to the node's own outbound QUIC requests as `quic_reply` events
  keyed by (session, stream), and datagrams as `quic_delivery`
  events — the same registry as the inproc embedded surface.
  `Node.replyQuic`/`replyErrorQuic` answer request events (subject
  echo and deadline carry-back mirror the inproc rules);
  `Node.publishQuic` sends datagrams on an embedded session.
  `runOnce` never touches event-delivery sessions.
- **Credentials verify once at HELLO** on the embedded path via the
  transport options' `auth_config` handed to `EmbeddedDispatch.init`
  (Q3: once at init; there is no per-message credential check).
- **examples/embedded_quic_attach.zig** — the executable contract:
  a hermetic foreign-embedder loop (embedder-owned Driver, seat in
  its own ConnState, ALPN routing) completing request/reply plus
  datagram delivery through poll events, then teardown with the
  connection live.
- `QuicSessionRuntime.peekReliableStreamId` consumers get
  `isPeerBidiStreamId`-based request/reply classification in
  `Node.poll`; `quic_datagram.codecFromTransport` is the shared
  datagram codec derivation.

### Fixed

- examples/quic_node_localhost.zig carried a truncated inline test
  certificate (its live-UDP mode is env-gated, so nothing failed
  loudly); both examples now inline the known-good testdata certs.

### Testing

- Hermetic foreign-driver end-to-end test: embedder-owned Driver
  drives handshake → HELLO → embedded session; client request →
  `quic_request` event → `replyQuic` → reply received on the
  requester's own stream; client datagram → `quic_delivery` event;
  teardown ride-along (listener will-close → onDisconnect → session
  destroyed exactly once) with the connection live. 324/324 tests,
  27/27 example steps, and a consumer-side dependency instantiation
  check with `.{ .target, .optimize }` forwarded all green.

### Known gaps (unchanged, documented)

- QUIC dial-side request deadline/cancellation outcomes (Phase B);
  the consumer's pending table and qmsg's planned classification
  are idempotent together by construction.

## [0.1.3] - 2026-08-27

`Node.runOnce` no longer dispatches replies as requests. A reliable
message on a session's OWN bidi stream is a reply to an outbound
request (client-side correlation is the embedder's, via
`recvReliable`); only messages on peer-initiated streams are inbound
requests. Previously every received reliable message went through
the `.rep` dispatch path, so an answering dispatcher replied to
replies — an echo whose sender then failed on the already-reaped
request stream. Replies now stay queued for the embedder; socket
attachments are unchanged (they route raw messages and let the
socket's own state machine classify). Note the FIFO consequence: a
reply at the head of a session's inbox gates dispatch of later
messages on that same session until the embedder drains it — mixed
request/reply sessions should drain replies each loop iteration
(dial and listener sessions do not mix in practice).

- New `QuicSessionRuntime.peekReliableStreamId` (stream id of the
  next queued reliable message, without dequeuing) supports the
  distinction.
- Regression coverage: a hermetic test asserts a reply and a
  peer-initiated request both survive `runOnce` undispatched in
  order, and the live-UDP acceptance test now runs `runOnce` BEFORE
  checking the client reply — both fail against the old behavior.

## [0.1.2] - 2026-08-27

Two consumer-reported fixes from mruby-quic's live QUIC round-trip
testing (a real listener on an ephemeral localhost port, client
embedded in their single-threaded tick loop), plus the requested
dial documentation.

### Fixed

- **`queueReliable` now arms the reply receiver on the request's own
  stream.** A reply to `queueReliable` arrives on the requester's OWN
  bidi stream, which `acceptPeerBidiStreamsConnection` never covers
  (it auto-accepts only peer-initiated streams) — so the reply's
  bytes landed on the connection while `recvReliable()` returned null
  forever and every outbound request expired. Consumers no longer
  need the explicit `acceptReliableStream` workaround; a stream a
  request is sent on is a stream a reply is expected on. A stream
  that never receives its reply keeps an idle receiver until session
  deinit.
- **`Node.deinit` no longer use-after-frees live sessions.** It freed
  `quic_sessions` before `quic_listeners`; a live listener's
  `Server.deinit` then fired the will-close hook per connection,
  whose user_data pointed at session runtimes already freed —
  SIGBUS at 0xaaaaaaaaaaaaaaaa on teardown with any connected
  session (a graceful client-side close did not help; the
  server-side session never retires through `runOnce` alone).
  Teardown order is now listeners (whose hook destroys each
  driver-owned session exactly once) → clients → remaining
  sessions, and `QuicListenerRuntime.deinit` tears the listener's
  Server down before the dispatch that owns the hook state.

### Added

- Live-UDP acceptance test (skipped when the sandbox denies binds):
  request/reply over real QUIC with no explicit accept anywhere, then
  plain `Node.deinit` with both sessions still live. Verified it
  reproduces the consumer's exact crash signature under the old
  teardown order.
- `QuicDialOptions` now documents that `supported_patterns` is
  announced in the HELLO and is meaningful on dials (announce
  `req | rep` for a req/rep dial; req-only is the plausible-looking
  mistake).

## [0.1.1] - 2026-08-27

The dependency-build fix: qmsg could not be instantiated as a
dependency. Consumers that forward `optimize` into
`b.dependency("qmsg", …)` (the normal shape) made qmsg's own
`b.dependency("quic"/"paseto", …)` calls fail with
`invalid option: optimize` before any module was even requested —
dependency builds on this toolchain reject an `optimize` option for
these packages. qmsg now forwards only `.target` to its dependencies;
consumers forward `.optimize` to qmsg and it stops there. Verified by
building a scratch consumer that instantiates qmsg as a path
dependency with `.{ .target, .optimize }` forwarded (debug mode, full
transitive graph). No source-level API changes.

Known issue (pre-existing at 0.1.0, upstream of qmsg): ReleaseSafe
links that actually pull boringssl's C objects in fail with
undefined `___ubsan_handle_*` symbols on this toolchain. Debug-mode
dependency builds are unaffected. This needs a boringssl-zig/quic-zig
-side resolution; not caused or changed by this release.

## [0.1.0] - 2026-08-27

The first pinnable release, cut for the mruby-quic actor-messaging
integration: a publishable package (no escaping path dependencies),
a socketless embedded-Node contract over inproc with every outcome
renderable from poll events, and a reviewed-but-unbuilt seam design
for inbound QUIC attach.

Verified toolchain: zig 0.17.0-dev.1786+75044cb04 (the consumer's
pin; clean-room re-resolution of the dependency graph from the
network). Dependencies: quic-zig v0.19.0 (URL+hash tarball pin),
paseto-zig 0.2.0.

### Added

- **Socketless embedded Node contract** — a `Node` whose loop is
  entirely the embedder's: `tick(now_us)` advances the node clock
  (request deadlines evaluate against it), `poll` pumps node-owned
  inproc state into the event queue and hands events out, and
  nothing in qmsg sleeps, spawns threads, or opens sockets on the
  inproc surface. The Node owns one of each client-side socket:
  `dialInprocReq`/`requestInproc`/`cancelInprocRequest` for outbound
  requests, `replyInproc`/`replyErrorInproc` answering `request`
  events by correlation key, `dialInprocSub`/`subscribeInproc` for
  matched-filter deliveries, `listenInprocPub`/`publishInproc` for
  fanout. Documented in docs/EMBEDDING.md;
  examples/embedded_inproc_node.zig is the executable contract.
- **Event completeness for embedders** — new `Event` variants
  carrying owned payloads (`deinit` required): `request`
  (correlation id + deadline), `reply` (peer reply incl. the stable
  error-reply shape), `request_failed` with `RequestFailure`
  classification (deadline_exceeded / canceled / queue_full /
  peer_closed / no_route), and `delivery` with the matched filter.
  Sync send-path errors classify into the same vocabulary via
  `classifyRequestError`. Late replies after cancel/deadline are
  dropped, counted, and surfaced as `message_dropped`.
- **`Stats`** — `sent`, `recv`, `dropped`, `queue_high_water`,
  `events_dropped` as plain fields computed live from node counters
  plus node-owned queue stats; no metrics dependency.
- **Bounded event queue** — `NodeOptions.max_events` (default 1024)
  drops and counts overflow instead of growing without limit;
  message-carrying drops free their payloads.
- **Inbound QUIC embed seam design** — docs/QUIC_EMBED_SEAM.md:
  the embedder's `quic.app.Driver` owns the connection (one
  will-close hook slot per Server forces one Driver), qmsg delegated
  per-hook over ALPN; the pinned `dispatchQuic` contract; the
  three-layer auth placement; open questions for consumer review.
  Design only — deliberately not built this release.
- Core (from earlier tranches, first appearing in a release):
  `Message`/`OutgoingMessage`/`Header`/`Flags`, subject filters and
  routers, bounded queues with backpressure policy, inproc
  transport, `Socket(.pair/.req/.rep/.@"pub"/.sub/.push/.pull)`,
  request ids/deadlines/cancellation and stable error replies,
  pub/sub and push/pull helpers, `Session`/`Node`/`App`/`Context`
  facade, auth kit (PASETO v4.public, PASERK lookup, replay hooks,
  HELLO challenge binding, `SubjectPolicy`), QUIC transport surfaces
  (runtime wrappers, UDP listener/client owners, HELLO over control
  streams, reliable req/rep over streams, DATAGRAM envelopes,
  cancellation mapping, `quic.app.Driver`-based listener dispatch),
  and hermetic end-to-end tests plus live localhost and embedded
  examples.

### Changed

- **quic-zig is a URL+hash tarball pin (v0.19.0), not a path
  dependency.** Published packages cannot carry escaping path deps,
  so consumers could not pin qmsg at all; the local checkout also
  drifted under the build (the `on_datagram` Driver hook now passes
  a `Datagram` payload with `arrived_in_early_data`, which qmsg now
  threads through instead of hardcoding `false`).
- Zig floor is 0.17.0-dev.1786+75044cb04 — the consumer's toolchain
  is the one that compiles qmsg, so qmsg verifies and declares it.
- `Node.poll` pumps node-owned inproc state before handing events
  out (it was a pure queue drain); `Event` gained owned-memory
  variants and a `deinit`. The `message_dropped` payload was named
  (`MessageDropped`) — field-compatible with the previous anonymous
  struct.

### Known gaps (deliberate, documented)

- No QUIC dial-side request deadline/cancellation outcomes yet —
  inproc-only this release; the state machine is the first Phase B
  work item (docs/QUIC_EMBED_SEAM.md).
- Inbound QUIC attach (embedder-owned listener) is design-only.
- Public `Socket.listen(.quic)`/`dial(.quic)` conveniences remain
  future work; QUIC is driven through Node/App surfaces.
