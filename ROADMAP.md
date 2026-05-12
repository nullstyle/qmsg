# qmsg Roadmap

This roadmap assumes `quic-zig` is the underlying QUIC implementation and that
HTTP/3 remains outside this project.

## Implementation Status

This table tracks the current implementation, not the final ambition of each
phase.

| Phase | Status | Notes |
| --- | --- | --- |
| 0 Decisions and spikes | Partial | Package, ALPN, envelope, inproc, auth boundary, local `quic-zig` dependency, transport-parameter mapping, and QUIC HELLO skeleton exist. A real QUIC stream/datagram spike is next. |
| 1 Core package skeleton | Complete | Core message, envelope, subject, queue, transport boundary, and inproc transport are implemented and tested. |
| 2 Pair and req/rep over inproc | Complete for inproc MVP | Pair and req/rep work over inproc with ids, deadlines, cancellation, queue pressure tests, and error replies. |
| 3 QUIC transport MVP | Started | `quic-zig` is wired locally and `transport.quic` owns qmsg options/session/control-HELLO state with skeleton tests. Hermetic quic-zig handshake coverage is being wired. Real QUIC I/O, stream mapping, and smoke binaries remain. |
| 4 App facade | Partial | Route registration, `Context`, in-memory dispatch, inproc REP `runOnce`, auth checks, default REP error replies, and QUIC listener/session lifecycle placeholders exist. QUIC message dispatch remains. |
| 5 Pub/sub reliable | Partial | Inproc pub/sub, source-side subscription registry, replay/update, and slow-consumer behavior are implemented. QUIC subscription propagation remains. |
| 6 QUIC datagrams | Not started | HELLO carries datagram capability, but no datagram envelope or transport path exists yet. |
| 7 Push/pull | Partial | Inproc push/pull has fair selection, puller credit, queue policy handling, and at-most-once semantics. QUIC `CREDIT` integration remains. |
| 8 Survey/respondent and bus | Not started | No public API or state machines yet. |
| 9 Typed codecs and ergonomics | Not started | Raw bytes remain first-class; typed helpers are future work. |
| 10 PASETO/PASERK auth kit | Partial | `paseto-zig` 0.2.0 is wired, v4.public verification, PASERK id lookup, qmsg claim parsing, replay hook, and key rotation example exist. Runtime HELLO integration and more purposes remain. |

## Phase 0: Decisions and Spikes

Goal: reduce unknowns before writing much framework code.

Tasks:

- Decide repository layout: standalone `qmsg` package with `quic-zig` as a
  dependency.
- Define initial ALPN: `qmsg/1`.
- Choose initial message envelope fields.
- Spike envelope encode/decode with size caps.
- Spike a minimal inproc transport to test pattern state machines without QUIC.
- Spike a `quic-zig` transport adapter:
  - listen/dial;
  - session lifecycle;
  - open bidi stream;
  - receive stream payload;
  - optional datagram send/receive probe.
- Wire the local `quic-zig` package into qmsg builds and keep the public qmsg
  API behind qmsg-owned wrapper types.
- Track `paseto-zig` `0.2.0` as the PASETO/PASERK dependency target and keep
  qmsg's auth boundary aligned with its release API.

Exit criteria:

- A test can encode/decode `Message`.
- A fake transport can deliver messages between two sockets.
- A QUIC spike can complete HELLO over a control stream.
- QUIC option wrappers map to `quic_zig.tls.TransportParams` without exposing
  `quic_zig.Connection` from the public qmsg root.
- The authentication boundary is sketched with key lookup and fail-closed
  behavior.

## Phase 1: Core Package Skeleton

Goal: establish the public shape and internal boundaries.

Files/modules:

```text
src/root.zig
src/message.zig
src/envelope.zig
src/subject.zig
src/socket.zig
src/node.zig
src/session.zig
src/transport/root.zig
src/transport/inproc.zig
src/protocol/root.zig
```

Tasks:

- Implement `Message`, `Header`, `Flags`, and `OutgoingMessage`.
- Implement subject matcher:
  - exact;
  - `*` one-segment wildcard;
  - `>` trailing wildcard.
- Implement bounded queue primitive with byte accounting.
- Define common error set.
- Define `Transport` boundary.
- Add inproc transport.

Exit criteria:

- Unit tests for subject matching and queues.
- Inproc pair socket can send one message.

## Phase 2: Pair and Req/Rep over Inproc

Goal: prove pattern state machines before QUIC complexity.

Tasks:

- Implement `Socket(.pair)`.
- Implement `Socket(.req)` and `Socket(.rep)`.
- Add request correlation ids.
- Add request deadline handling.
- Add cancellation path.
- Add app-level error reply message.
- Add blocking/simple API plus nonblocking pollable operation shape.

Exit criteria:

- Pair round trip test.
- Multiple concurrent req/rep calls over inproc.
- Deadline test cancels request and frees resources.
- Queue cap tests for send/receive.

## Phase 3: QUIC Transport MVP

Goal: run pair and req/rep over real QUIC.

Tasks:

- Implement `transport/quic.zig` adapter over `quic-zig`.
- Negotiate ALPN `qmsg/1`.
- Open and validate control stream.
- Encode/decode HELLO.
- Map one reliable message to one QUIC bidi stream.
- Map stream reset to qmsg cancellation/failure.
- Surface session close.
- Surface basic migration event if `quic-zig` exposes it.
- Document that internet-facing QUIC builds must use `ReleaseSafe`.

Exit criteria:

- Pair over QUIC on localhost.
- Req/rep over QUIC on localhost.
- Peer close and request cancel tests.
- Interop-style smoke binary: `qmsg-server` and `qmsg-client`.
- Release guidance carries the `quic-zig` `ReleaseSafe` requirement for
  production QUIC use.

## Phase 4: App Facade

Goal: provide the small Sinatra-like surface without hiding the core.

Tasks:

- Implement `App`.
- Add handler registration:
  - `rep(subject, handler)`;
  - `pair(subject, handler)`;
  - `onConnect`;
  - `onClose`.
- Implement `Context`.
- Add QUIC listener/session lifecycle placeholders without promising UDP I/O.
- Add app-owned scratch allocator or per-handler temporary arena option.
- Add default error handling policy.
- Add auth hooks and session authorization plumbing, initially independent of
  any concrete token format.

Exit criteria:

- Example service fits in one small Zig file.
- Handler can reply, close session, and inspect peer metadata.
- Errors are observable and not swallowed silently.
- Handlers can require authenticated subjects/patterns.

## Phase 5: Pub/Sub Reliable

Goal: support subject fanout without datagrams first.

Tasks:

- Implement `Socket(.pub)` and `Socket(.sub)`.
- Add control frames:
  - `SUBSCRIBE`;
  - `UNSUBSCRIBE`.
- Implement subscription filter storage per session.
- Implement slow-consumer policy:
  - block;
  - fail;
  - drop_oldest;
  - drop_newest.
- Add app facade:
  - `sub(filter, handler)`;
  - `publish(message)`.

Exit criteria:

- Multiple subscribers receive matching subjects.
- Non-matching subjects are filtered at source.
- Slow consumer behavior is deterministic and tested.

## Phase 6: QUIC Datagrams

Goal: add unreliable low-latency subjects.

Tasks:

- Negotiate datagram support in HELLO.
- Encode compact datagram envelope.
- Add datagram send API:
  - fail if too large;
  - optional fallback to reliable send.
- Add app facade:
  - `datagram(filter, handler)`.
- Add counters for dropped/oversized datagrams.

Exit criteria:

- Presence/telemetry example.
- Datagram size cap tests.
- Datagrams never fragment at qmsg layer.

## Phase 7: Push/Pull

Goal: add work distribution with explicit credit.

Tasks:

- Implement `Socket(.push)` and `Socket(.pull)`.
- Add `CREDIT` control frame.
- Add fair distribution policy.
- Add retry/ack discussion but keep MVP at-most-once after transport failure.

Exit criteria:

- Work is distributed across pullers.
- Puller credit limits inflight work.
- Queue and flow-control interactions are tested.

## Phase 8: Survey/Respondent and Bus

Goal: complete the first nng-like pattern set.

Tasks:

- Implement `survey/respondent` with deadlines.
- Implement `bus` with peer id based loop prevention.
- Add examples:
  - cluster health survey;
  - small peer mesh.

Exit criteria:

- Late survey responses are ignored and counted.
- Bus message fanout avoids immediate echo loops.

## Phase 9: Typed Codecs and Ergonomics

Goal: make applications pleasant without hard-coding a serialization stack.

Tasks:

- Add codec interface:
  - raw bytes default;
  - JSON helper;
  - optional protobuf/msgpack adapters later.
- Add typed handler helpers:

```zig
app.rpcTyped("user.get", UserGetRequest, UserGetReply, getUser);
```

- Add better examples and docs.

Exit criteria:

- Typed API is purely optional.
- Raw message API remains first-class.

## Phase 10: PASETO/PASERK Auth Kit

Goal: provide a batteries-included auth option without making cryptography the
core of qmsg.

Tasks:

- Add `paseto-zig` `0.2.0` as the optional auth-kit dependency.
- Support PASETO v4.public verification for HELLO credentials via
  `paseto.v4.Public.verifyToken`.
- Support typed PASERK `pid` key-id lookup using keys generated or parsed by
  `paseto-zig`.
- Add claim validation policy:
  - issuer;
  - audience;
  - subject;
  - expiry;
  - not-before;
  - issued-at;
  - token id.
- Parse qmsg-specific authorization claims after `paseto.Validator` accepts the
  registered claims.
- Cache validated authorization on `Session`.
- Add optional replay cache interface.
- Add key rotation example using PASERK IDs.

Exit criteria:

- Authenticated req/rep example.
- Unknown key id fails closed.
- Expired/not-yet-valid tokens are rejected.
- Session handlers can inspect authorization without reparsing tokens.
- Tests cover footer/HELLO key-id tampering and wrong-key verification failure.

## Validation Strategy

Unit tests:

- envelope encode/decode;
- subject matching;
- queue accounting;
- pattern state machines;
- deadline/cancel behavior.

Integration tests:

- inproc pair/req/rep/pub/sub;
- QUIC skeleton control-HELLO/session tests via `zig build quic-test`;
- future QUIC localhost pair/req/rep once real UDP or hermetic stream I/O
  lands;
- future QUIC close/reset/cancel;
- future datagram delivery/drop behavior.

Fuzz/property tests:

- envelope decoder rejects malformed frames;
- subject matcher does not panic on arbitrary bytes;
- pattern state machines preserve invariants under random event order.

Interop tests:

- future `qmsg-client` and `qmsg-server` binaries once real QUIC transport
  surfaces land;
- scripted smoke tests for each pattern;
- packet loss/reorder tests once transport hooks support them.

## MVP Definition

The smallest useful public MVP:

- `Message` envelope;
- subject matcher;
- bounded queues;
- inproc transport;
- QUIC transport;
- `pair`;
- `req/rep`;
- handler facade for `rep`;
- deadlines and cancellation;
- basic examples;
- no datagrams yet.

This MVP is enough to prove the core idea: nng-style messaging patterns with
Zig ergonomics over QUIC, without HTTP/3 in the design.
