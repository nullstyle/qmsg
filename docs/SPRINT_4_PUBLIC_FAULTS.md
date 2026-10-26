# Sprint 4: public application fault acceptance

This sprint qualifies the existing public messaging surface under overload,
authorization failure, deadlines, cancellation, peer loss, reconnect and
bounded graceful shutdown. It adds no patterns, CREDIT, codecs, wire changes,
public dependency promotions or production runtime features. The base is
committed Sprint 3 `8510c90c6aad9dd0b22ca1ace953fc545e044491`.

The reusable [workload](../examples/public_fault_workload.zig) exports
`run(allocator, std.Io, Options)!Report`. It uses only public
`QuicSocket(.req/.rep)`, `ReplyHandle`, status, event, clock and borrowed socket
interfaces. Each owner loop pumps, consumes complete event batches, and waits
only after a quiet iteration using readiness and absolute deadlines. There
are no fixed sleeps or background qmsg loops. The seed controls actor/wire-ID
payload bytes, not delay injection. TLS verifies the localhost server against
the existing fixture certificate. The report identifies its exact PEM SHA-256,
payload pattern, seed, capacities, deadlines and GOAWAY code/reason.

## Default acceptance sequence

Two requesters share one reply listener. The victim has zero ordinary event
capacity and two request slots; both transports have two-message send bounds
and an eight-stream window. The independent healthy requester has ordinary
event capacity. All phase assertions are inside `run`, so the CLI and parent
composition tests enforce the same behavior.

| Phase | Required observation |
| --- | --- |
| Admission and cancellation | A third request is refused at the two-slot bound. Cancellation produces a reserved terminal outcome; leaving it unread still refuses admission. Consuming it frees the reservation. Transport queue pressure refuses an attempted request without delivering it. |
| Deadline and sibling progress | A received request is retained for a deferred reply, expires by its public request deadline, and produces one terminal outcome despite ordinary event capacity being zero. The other requester completes its own request. |
| Authorization | A subject outside `svc.*` returns an owned Unauthorized error reply and never reaches the application. A valid extra requester reaches ready on both public sides at the same two-client load; after fully closing that control connection, the otherwise matched wrong-role credential is rejected. |
| Late application attempts | Retained handles are used after cancellation and expiry. Immediate API rejection or later suppression is allowed; no second terminal outcome may appear. This does not claim that a delayed wire frame was observed. |
| Remote loss and reconnect | Only the server initiates close while a request is pending. The client learns closure through real UDP pumping, receives `peer_closed` before its five-second deadline and observes the old session disappear. A sibling request completes during closure. Redial reuses the wire ID with a distinct local request ID. The old handle fails safely. |
| Graceful shutdown | GOAWAY owns the expected reason bytes, refuses new work, and still permits an already retained deferred reply. Another session completes requests during and after the bounded drain; both sides of the drained session disappear. |

A successful default run has 15 admitted requests and 15 terminal outcomes:
10 successful replies, one authorization error reply, two cancellations, one
deadline and one remote `peer_closed`. The healthy requester supplies six of
the successful replies. There are two inflight refusals and at least one
queue refusal, one wrong-role rejection, one GOAWAY refusal, four retained and
released handles, two late handle attempts, and one stale-handle rejection.
The final ledger has no pending or duplicate terminal outcomes; every returned
event is deinited.

The ledger is bounded to 32 entries and retained handles to eight. Configured
Node session capacity is four per actor. `peak_server_sessions` measures only
observed public connected-session IDs; it does not measure all transport
handshakes or half-open states. Similarly, the outstanding count is the
application's admitted-but-unconsumed ledger, not a private runtime counter.
The capability authenticator is a deterministic fixture granting minimal
REQ/REP peer actions. PASETO cryptography and mutual-TLS/SPKI coverage remain
in their existing suites; this workload adds no authentication framework.

## Run and interpret

The CLI is opt-in and emits one `PUBLIC_FAULTS` JSON record on successful
execution. Without `QMSG_RUN_LIVE_UDP=1`, it opens no sockets.

```sh
mise exec -- zig build examples -j2
QMSG_RUN_LIVE_UDP=1 ./zig-out/bin/quic-public-faults
QMSG_RUN_LIVE_UDP=1 ./zig-out/bin/quic-public-faults --seed 0x42 --payload-bytes 256 --stream-window 2
```

Options are bounded: payload 1–512 bytes, stream window 2–16, short request
deadline 20–500 ms and overall timeout 3–30 seconds. Normal request deadlines
are two seconds, the remote-loss request gets five seconds, and GOAWAY's drain
interval is 200 ms. The default seed is `0x71534d3400000001`.

`public-fault-test` is a dedicated qmsg test target. It is intentionally outside
the ordinary root `test` step: the unchanged public QUIC v0.37.2 pin retains
the known idle-cache assertion reproduced in Sprint 3. A timing-dependent
native application pass does not clear that retained negative. Do not add
sleeps, swallow assertions or alter the public pin to make it appear fixed.
Positive fault qualification uses the fixed selected candidate through the
parent composition graph, sharing one QUIC module with qmesh and qmsg:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B qmesh-zig/tools/check-composition.py \
  --qmsg-path qmsg --quic-archive quic-zig/benchmark-reports/sprint-4-2026-10-26/quic-sprint4-final-candidate.tar.gz \
  --quic-sha256 0cb202a6a4efae6f2e28354ce90bb0869397069521c64c8503c4b26d611d2bcb \
  --mode selected --sprint4 --optimize Debug --jobs 2 \
  --output-dir qmesh-zig/.zig-cache/sprint-4-public-debug
```

The command assumes the common parent directory and a mise-pinned Zig 0.17.0
on PATH. Repeat with `--optimize ReleaseSafe` and a fresh output directory.
The parent also qualifies its seeded application-chaos workload separately.

Exact commands, compiler/source identities, executed/cached counts, CLI records
and the retained native-pin limitation are indexed in ignored
`.zig-cache/sprint-4-evidence/summary.json`. Parent matrix artifacts identify
their own complete frozen inputs. Local tests establish no hosted-CI,
physical-network, durability or delivery-order guarantee beyond the documented
messaging contracts.
