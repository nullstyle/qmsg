# Sprint: deployable qmsg/1 (started 2026-09-04)

Theme: make a real deployment possible — the API users are promised, the
liveness operators need, and the CI that protects both. Assessment and plan
recorded here; progress tracked per item.

## S1 — CI + stability floor: DONE

- `.github/workflows/ci.yml`: four lanes on the mise-pinned toolchain
  (unit+QUIC on Linux/macOS, examples, `-Dcapnp=true` capnp-test), with
  capnp-zig's setup-zig composite action (mise.toml is the single Zig
  specifier; PATH-vs-pin assertion).
- The four deterministic test failures on the private ziglang fork's
  dev.2001+ builds are a FORK COMPILER regression (`@hasDecl` answers
  false even for locally-declared fns; `Node.runOnce`'s dispatcher probes
  use it). Documented in ROADMAP's validation section and the workspace
  HANDOFF §1c with a reproduce script. Not a qmsg bug; do not work around.
- ROADMAP status table refreshed (phase 9 = Partial: capnp codec shipped).

## S2 — Liveness and graceful shutdown: IN PROGRESS

Landed so far (additive, 344/344 green): `PING` (tag 6) / `PONG` (tag 7)
control-frame codec — token round-trip tested, validation arms added,
`Tag.fromInt` mapped. Not yet emitted or consumed by any runtime.

### Remaining wiring (design settled; anchors verified 2026-09-04)

1. **Negotiation**: heartbeat interval = `min(local, peer)` of the two
   HELLOs' `heartbeat_interval_ms` fields, zero if either is zero
   (none negotiated). Hook: `QuicSession.acceptHello`
   (`src/transport/quic.zig`, `session.peer_hello_received` flip) — store
   the peer's interval on `session.Session`, compute the effective value
   in `QuicSessionRuntime` when the session turns ready.
2. **State**: on `QuicSessionRuntime` —
   `last_activity_us: u64`, `outstanding_ping: ?struct { token: u64,
   deadline_us: u64 }`. Update `last_activity_us` in `pump()` whenever
   inbound progress occurs (control frames, reliable bytes, datagrams).
3. **Sweep**: `pub fn tickHeartbeat(self, now_us) !HeartbeatOutcome`
   on `QuicSessionRuntime` — `.none` (no interval / not ready),
   `.ping_sent` (idle >= interval and no outstanding: enqueue PING on a
   one-shot uni stream via `stream_ids.nextUni()` + a
   `quic_streams.ControlStreamSender`, mirroring `flushQueuedControl`
   at `src/transport/quic_session_runtime.zig:277`), `.timed_out`
   (outstanding past deadline = 2x interval, floor 1s → `beginClosing`
   with a classified timeout outcome). Call sites: `Node.tickQuicClients`
   / `tickQuicListeners` (both have `now_us`); for embedded seats, record
   `last_now_us` on `Node.tick` and sweep in `pumpEmbeddedQuic`.
4. **Inbound PING → PONG**: intercept in the two control-frame
   application points BEFORE registry apply — the embedded path
   `pumpControlReads` (`src/transport/quic_embedded.zig`) and the
   node-owned path that feeds `driverControlFramesReceived`
   (`src/node.zig:1908` → `quic_control.State.applyReceivedFrames`).
   Reply with a one-shot uni PONG stream (same sender shape as the PING).
   Inbound PONG: match `outstanding_ping.token`, clear it, bump activity.
5. **GOAWAY wiring**: outbound — `Node.closeQuicSession(id, code, reason)`
   queues a GOAWAY frame via the `control_flush_sender` path
   (`flushQueuedControl`), marks the session draining, closes the
   connection after the flush completes. Inbound — handle `goaway` at the
   same two application points as ping/pong: set a
   `session.goaway_received {code, reason}`, transition to draining, and
   surface a `.session_goaway` poll event (new `Event` variant — note for
   downstream exhaustive switches, same as past additions).
6. **Tests**: control codec (done); runtime-level with the existing fake
   transport pumps (idle → ping_sent; pong withheld → timed_out;
   ping→pong echo); one live-UDP integration with a short negotiated
   interval. WIRE.md: move PING/PONG and GOAWAY sections from "sketch" to
   documented behavior; keep `wire_version = 1` (additive frames).

### Forward-compat note

`Tag.fromInt` errors `UnknownControlFrame` on unknown tags — check whether
the follow-up-stream application paths SKIP unknown frames or kill the
session before shipping any peer that might send newer frames; if they
kill, add skip-with-counter before freezing qmsg/1.

## S3 — Public QUIC socket surface: NOT STARTED

Design risk is the driving model (tenet: no hidden runtime). Proposal:
`Socket(.req).listen(.quic, addr, .{tls})` owns a private `Node` and
exposes an explicit `pump(now_us)` / documented opt-in run thread; the
socket-level `UnsupportedTransport` arms at `src/socket.zig:883,890` are
the entry points. Settle the ownership contract in the first hour; crib
the Node/App machinery that already works (see
capnp-qmsg-demo/src/full_stack_l3_test.zig for the complete driving loop).

## Stretch

- S4: CREDIT live-session re-emission (mirror 0.2.0's SUBSCRIBE re-emit);
  reliable-stream publication option.
- S5: survey pattern (phase 8 start).
