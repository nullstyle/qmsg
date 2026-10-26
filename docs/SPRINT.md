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

## S3 — Public QUIC socket surface: Sprint 2

`QuicSocket(.pair/.req/.rep)` owns one heap-stable Node and exposes explicit
`pump(now_us)`, canonical `poll` events, TLS-configured listen/dial, borrowed
readable socket handles, and absolute deadlines. Request correlation and
terminal outcomes use the existing Node engine. The typed facade announces
its selected role and requires its counterpart at HELLO.

The existing address-only `Socket(.quic)` endpoint remains the low-level
unsupported convenience spelling; it does not carry TLS or runtime options.
Inproc sockets and foreign-driver attachments retain their contracts.

See [the Sprint 2 socket guide](SPRINT_2_QUIC_SOCKETS.md) for the interface,
ownership, and local qualification records. Public Node/App examples use the
same request/outcome methods. Reliable pub/sub is covered by Sprint 3 below.

## S4 — Reliable QUIC pub/sub: Sprint 3

Source-filtered reliable publications use bounded per-peer pre-admission FIFOs
and canonical delivery ownership. A slow peer reports pressure or sheds by
policy without stopping healthy fanout. Existing node-level subscriptions
reconcile on replacement sessions, including both listen/dial topologies.
Datagram publication remains the default existing API. See
[the Sprint 3 contract and qualification](SPRINT_3_RELIABLE_PUBSUB.md).

## Deferred

Live CREDIT/push-pull, new typed patterns, survey/bus, retained replay, extra
codecs, dynamic endpoint advertisements, and evented backend adoption remain
outside this sprint. Application-state snapshot reconciliation across gossip
retention boundaries belongs to the optional qmesh composition layer.
