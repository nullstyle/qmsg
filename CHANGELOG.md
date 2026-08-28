# Changelog

All notable changes to qmsg are documented in this file.

The project is pre-1.0. Any 0.x release may include breaking API
changes.

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
