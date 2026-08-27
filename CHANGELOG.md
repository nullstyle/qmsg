# Changelog

All notable changes to qmsg are documented in this file.

The project is pre-1.0. Any 0.x release may include breaking API
changes.

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
