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

## S2 — Liveness and graceful shutdown: Sprint 1 qualification

The 2026-10-26 cross-project sprint completes the runtime wiring that was
previously left open here. The additive interface is:

- negotiated PING/PONG handling in the shared session runtime;
- bounded pending lifecycle responses under flow control;
- `Node.goawayQuicSession(id, code, reason, now_us, timeout_us)`;
- received `session_goaway` events with owned reason bytes;
- explicit drain intervals that preserve existing streams and deferred replies;
- owner-visible heartbeat and drain deadlines;
- optional unknown follow-up tags (bit 61), with strict startup and required tags.

`closeQuicSession(id)` retains immediate-abort behavior. Public dependencies
remain QUIC v0.37.2 and Zig 0.17.0. The coordinated QUIC candidate is tested
separately; no dependency upgrade or publication is implied by source changes.

See [MIGRATION.md](MIGRATION.md#quic-heartbeat-and-graceful-shutdown) for
ownership and clocks, and [WIRE.md](../WIRE.md#control-frames) for wire behavior.
See [Sprint 1 lifecycle qualification](SPRINT_1_LIFECYCLE.md) for regression
coverage, toolchain identity, and retained gate evidence. Earlier 410-test
counts described an intermediate September tree, not this sprint.

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
