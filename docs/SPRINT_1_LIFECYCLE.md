# Sprint 1: QUIC lifecycle qualification

Date: 2026-10-26. Source starts at `1e6960465c1af8f2cfdb8675b01fb00fbea38326`
(qmsg 0.8.5) plus the reviewed, uncommitted Sprint 1 changes. No release,
dependency promotion, or publication is part of this qualification.

## Implementation

The shared session runtime handles negotiated PING/PONG and fixed-interval
GOAWAY draining. Owned clients, accepted sessions, and foreign-driver seats
use the same lifecycle handlers. Both QUIC v0.37.2 and v0.42.2 expose and use
ConnectionDriver. The raw-connection compatibility helper also reads follow-up
control streams and is exercised by the hermetic foreign-embed fixture.

`Node.goawayQuicSession(id, code, reason, now_us, timeout_us)` stops new work
while existing streams and retained ReplyHandles continue until the drain
deadline. `closeQuicSession(id)` still aborts immediately. A received GOAWAY
emits `Event.session_goaway`, whose reason bytes are owned and included in the
ordinary event byte budget. Request terminal outcomes retain their separate
reserved capacity.

Lifecycle response state is bounded: eight pending PONG tokens and one encoded
PONG sender. Overflow closes only the offending peer. Reserved unidirectional
control senders pump in stream-ID order. `nextLifecycleTimer()` exposes absolute
owner-clock deadlines, including a blocked PONG send; `Node.nextTimer()` includes
these deadlines. Runtime counters are `pings_received`, `pongs_received`,
`mismatched_pongs`, and `unknown_optional_frames`; Node Stats has no new fields.

Only unknown optional tags (bit 61) on bounded follow-up control streams are
skipped. Required tags, startup HELLO, malformed frames, and standalone decode
remain strict. See [MIGRATION.md](MIGRATION.md#quic-heartbeat-and-graceful-shutdown)
and [WIRE.md](../WIRE.md#control-frames).

## Reproductions and regression coverage

- Healthy real-UDP peers with a negotiated 20 ms heartbeat failed with
  `HealthyPeerLost` before runtime interception; the regression passes after it.
- A reverse-direction GOAWAY at 20 seconds of uptime reproduced premature
  accepted-session closing. Server callbacks constructed a dispatch with clock
  zero. Carrying the owner clock into those callbacks fixes the regression.
- Deferred replies complete during a bounded drain, new requests/publications
  are refused, the owned GOAWAY event is observed once, and retained reply
  handles fail after teardown.
- An unanswered real-UDP probe produces one terminal request failure even with
  `max_events=0`. Foreign-driver sessions answer probes and expose GOAWAY using
  the explicitly supplied clock.
- Focused tests cover mismatched PONGs, ingress at the timeout boundary,
  flow-controlled response deadlines, bounded queues, ordered senders, optional
  frame skipping, and GOAWAY reason cleanup under event pressure.
- A blocked PING whose outstanding probe had been satisfied by other inbound
  traffic returned `InvalidState` and left the owner timer in the past. Its
  regression now requires retaining the sender, reusing its token for a bounded
  renewed probe, and scheduling a future timer without allocating another ID.
- An exhaustive Event switch in the existing inproc example needed the new
  variant; the first failed example build is retained as qualification evidence.
- A reset pending PONG sender reproduced `StreamClosed` escaping from
  `EmbeddedDispatch.serviceSeat` through `Node.tick` after that peer was
  already marked closing. The lifecycle sweep now skips closing peers and
  contains other non-OOM sender errors on the affected connection. The
  regression uses reset send halves on real accepted and owned connections;
  another real-UDP peer on the same Node still completes a request/reply.

## Toolchain and gates

Use the mise-pinned stock Zig 0.17.0. The macOS arm64 compiler binary SHA-256 is
`1c5f706db0ed6d55451940f31dc05a6177d05696bc1fa5d853696d04c718b523`.
Public dependencies remain QUIC v0.37.2 and PASETO 0.4.0. The QUIC option map
remains `{ target, release = optimize != .debug, sanitize-c = "trap" }`.

The focused real-UDP reproduction command is:

```sh
mise exec -- zig build node-pair-test -Dtest-filter=lifecycle: -j2 --summary all
```

Full gates include unit tests, QUIC runtime tests, Node pair tests, all examples,
and the optional Cap'n Proto codec, in Debug and ReleaseSafe:

```sh
mise exec -- zig build test quic-test node-pair-test examples -Dcapnp=true capnp-test -j2 --summary all
mise exec -- zig build test quic-test node-pair-test examples -Dcapnp=true capnp-test -Doptimize=ReleaseSafe -j2 --summary all
```

Read the retained mode logs for final executed-versus-cached counts. An
intermediate Debug gate completed 39/39 build steps and executed 664 tests,
with QUIC runtime and codec tests reused from the preceding run. Subsequent
source changes and their reruns are captured in the final mode logs and summary;
the intermediate count is not presented as the final suite total. A successful
filtered run alone is not the full gate.

Local raw evidence is ignored, outside the shipped docs:

- `../.zig-cache/sprint-1-evidence/debug-first-example-failure.log`
- `../.zig-cache/sprint-1-evidence/debug.log`
- `../.zig-cache/sprint-1-evidence/release-safe.log`

From the repository root, the actual paths begin `.zig-cache/`; these filenames
are evidence pointers, not files included in package archives. Final gate
outcomes and source/config identities are retained in the local JSON evidence
and the qmesh composition reports. This document is frozen before that matrix
so the wrapper can verify source inputs remain unchanged during execution.

qmesh's composition checker runs both consumer-native pins and an injected,
content-verified QUIC candidate. Its `test-qmsg` target includes the root,
QUIC runtime, and real-UDP Node pair suites, exercising the shared ConnectionDriver
on both releases and the hermetic raw-connection helper. Hosted CI is authored separately;
local execution does not establish a hosted result.
