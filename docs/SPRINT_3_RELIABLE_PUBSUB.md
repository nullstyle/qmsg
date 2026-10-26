# Sprint 3: bounded reliable QUIC pub/sub

The agreed qmsg scope is reliable QUIC pub/sub with source filtering,
reconnect/resubscription, and isolation of slow subscribers. Live CREDIT,
push/pull, new typed patterns, survey/bus, replay, extra codecs and evented
backends remain deferred. QUIC v0.37.2, PASETO 0.4.0, ALPN `qmsg/1`, and wire
version 1 stay unchanged. Sprint 2 base is
`941eef6b65deb250d2e5ee56637523be9eec5527`; Sprint 3 stays uncommitted.

The additive Node interface is `publishQuicReliable(outgoing)`, returning
`ReliablePublishResult { matched, queued, backpressured, dropped }`, and
`publicationStats()`. Reliable subscribers select
`NodeOptions.quic_inbound = .publications` and use the existing
`subscribeQuic`/`unsubscribeQuic` methods. Publisher-local
`quic_reliable_publications` options bound each pending FIFO. The datagram
publication default is unchanged. See [the complete contract](QUIC_PUBSUB.md)
for partial fanout, role/subject authorization, delivery ownership, pressure,
and GOAWAY's discard-and-count boundary.

## Repeatable public workload

The [scenario module](../examples/reliable_pubsub_workload.zig) exports
`run(allocator, io, Options)!Report`. It uses public Node APIs and an explicit
monotonic clock/readiness loop. Defaults are 24 publications of 128 bytes,
three subscribers, a two-stream window, a four-message/16-KiB unsent FIFO per
peer, and a ten-second overall deadline. One subscriber stops pumping while
the other two receive all 48 matching publications. It rejects nonmatching
source publications, checks payloads and duplicate IDs, requires observable
slow-peer pressure and bounded queue high water marks, then reconnects a
healthy peer without calling subscribe again and requires resumed delivery.
Cold handshake and warm publication times are separate host measurements.

Build and run the opt-in localhost CLI:

```sh
mise exec -- zig build examples -j2
QMSG_RUN_LIVE_UDP=1 ./zig-out/bin/quic-pubsub-localhost
QMSG_RUN_LIVE_UDP=1 ./zig-out/bin/quic-pubsub-localhost --publications 5000 --payload-bytes 128 --timeout-ms 120000
```

Without the environment variable this program prints the opt-in instruction
and performs no workload. A successful execution emits one `PUBSUB_WORKLOAD`
JSON record. Counts, payload and timeout are bounded; invalid options fail.
The same module is imported by the parent qmesh composition matrix with its
selected single QUIC module, and can be profiled without changing options or
adding library instrumentation.

## Verification evidence

Raw local logs and the final command/compiler/source/count index live under
ignored `.zig-cache/sprint-3-evidence/summary.json`. They distinguish fresh
executions from unchanged cached artifacts. The initial source-filter test
failed before implementation (`source-red.log`); focused hermetic cases cover
source filtering, all queue policies, sibling admission, role/subject/size
refusal, canonical receiver ownership, App SUB dispatch, GOAWAY discard,
transport-pressure wake disarming and retry. Public real-UDP tests exercise
minimal PUB/SUB grants in both accepted and dialed publisher topologies.

The final handoff reports full Debug and ReleaseSafe unit/QUIC/Node-pair,
optional codec and example gates plus real UDP smoke results. Parent matrix
reports establish their own exact native/candidate/archive inputs. Local
macOS arm64 checks do not establish hosted CI or physical-network results.
Cross-project application snapshot reconciliation is owned by qmesh's optional
composition layer; reliable live publication does not replace it.
