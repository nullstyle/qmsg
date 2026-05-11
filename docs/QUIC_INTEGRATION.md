# qmsg QUIC Integration Plan

This plan maps qmsg's transport boundary onto the current `quic-zig`
checkout at `/Users/nullstyle/prj/ai-workspace/quic-zig`. It intentionally
ignores HTTP/3. qmsg owns the application protocol: ALPN `qmsg/1`, qmsg
control frames, qmsg message envelopes, pattern state, auth policy, and
backpressure semantics.

## Current quic-zig Surface

Use the public module name `quic_zig`.

Relevant entry points:

- `quic_zig.Server`: server-side connection table, CID routing, Retry,
  Version Negotiation, TLS context setup, and per-connection slots.
- `quic_zig.Client`: client-side TLS setup and first `Connection`.
- `quic_zig.Connection`: I/O-agnostic QUIC state machine.
- `quic_zig.tls.TransportParams`: transport parameter config, including
  stream limits and `max_datagram_frame_size`.
- `quic_zig.transport`: UDP helpers and optional `runUdpServer` /
  `runUdpClient` loops.

qmsg should prefer the raw `Server` / `Client` / `Connection` surfaces rather
than `runUdpServer` / `runUdpClient` for the real library runtime. The helper
loops are useful examples, but qmsg needs to interleave application dispatch,
bounded queues, deadlines, auth hooks, and transport polling in one `Node`
loop without requiring an extra app thread.

## Build Integration

`quic-zig` package metadata:

- package name: `quic_zig`
- module name: `quic_zig`
- current version: `0.2.0`
- minimum Zig version: `0.16.0`
- transitive dependency: `boringssl_zig`

qmsg currently declares `minimum_zig_version = "0.17.0"` and has no
dependencies. Before adding the dependency, verify that the local qmsg
toolchain can build the quic-zig checkout. If not, either align qmsg's
toolchain target with quic-zig or pin a quic-zig branch known to build on
the qmsg compiler.

Keep quic support behind a clearly named module such as
`src/transport/quic.zig`. Do not expose `quic_zig.Connection` directly in the
main qmsg API; wrap it in qmsg session and transport types so quic-zig can
evolve without breaking qmsg applications.

## Mapping

### listenQuic

qmsg `listenQuic(addr, tls_config)` maps to:

1. Build `quic_zig.Server` with:
   - `.allocator = allocator`
   - `.tls_cert_pem`
   - `.tls_key_pem`
   - `.alpn_protocols = &.{ "qmsg/1" }`
   - `.transport_params = qmsgQuicTransportParams(options)`
   - production gates when configured: Retry key, NEW_TOKEN key,
     stateless reset key, listener/source rate limits, qlog/log callbacks.
2. Own the UDP socket in qmsg's `Node` event loop.
3. For each inbound datagram:
   - convert `std.Io.net.IpAddress` to `quic_zig.conn.path.Address`
     using the same layout as `quic_zig.transport.udp_server`.
   - call `server.feedWithEcn(bytes, from, ecn, now_us)` or
     `server.feed(bytes, from, now_us)`.
   - drain `server.drainStatelessResponse()` and send those bytes back
     on the receiving socket.
4. For each live `Server.Slot` from `server.iterator()`:
   - drive qmsg session state from `slot.conn`.
   - drain outbound UDP with `slot.conn.pollDatagram(tx, now_us)`.
   - send `out.to` when present, otherwise `slot.peer_addr`.
5. Call `server.tick(now_us)` and periodically `server.reap()`.

Use `quic_zig.transport.runUdpServer` only for examples or smoke binaries that
do not need qmsg's own cooperative app loop.

### dialQuic

qmsg `dialQuic(endpoint, options)` maps to:

1. Parse the target literal separately from TLS SNI.
2. Build `quic_zig.Client.connect` with:
   - `.allocator = allocator`
   - `.server_name = options.server_name`
   - `.alpn_protocols = &.{ "qmsg/1" }`
   - `.transport_params = qmsgQuicTransportParams(options)`
   - optional `tls_context_override` for custom verification/key logging.
   - optional `session_ticket`, `new_token`, and callbacks later.
3. Call `client.conn.advance()` to emit the first Initial unless qmsg is
   intentionally staging 0-RTT data first. MVP should not use qmsg app data
   in 0-RTT.
4. Own the UDP socket and feed inbound datagrams to
   `client.conn.handleWithEcn` / `handle`.
5. Drain outbound datagrams with `client.conn.pollDatagram(tx, now_us)`.
6. Call `client.conn.tick(now_us)` and consume `client.conn.pollEvent()`.

### Session Lifecycle

qmsg `Session` should become application-ready only after both layers are
ready:

- QUIC ready: `conn.handshakeDone()` is true.
- ALPN selected: selected protocol is `qmsg/1`.
- qmsg ready: both endpoints exchanged and accepted qmsg `HELLO`.
- auth ready: `HELLO` auth policy succeeded, or anonymous sessions are
  explicitly allowed.

Server-side storage maps naturally to `quic_zig.Server.Slot`; client-side
storage maps to the single `quic_zig.Client.conn`. qmsg should assign its own
stable `SessionId` and store a pointer/index from the qmsg session table to
the underlying slot/client connection.

Connection close maps through:

- `conn.pollEvent()` -> `.close`
- `conn.close(is_transport, error_code, reason)`
- `server.shutdown(error_code, reason)` for listener shutdown
- `conn.closeEvent()` for sticky post-close details

qmsg protocol violations should close with transport-level/application-level
QUIC close depending on severity:

- malformed qmsg control/envelope that means the peer violated qmsg/1:
  application close with a qmsg error code.
- QUIC parser/flow violations are already handled inside quic-zig.

### Control Streams

qmsg requires one unidirectional control stream per endpoint.

`quic-zig` maps this to:

- `conn.openUni(stream_id)`
- `conn.streamWrite(stream_id, bytes)`
- no `streamFinish` while the control stream is live
- `conn.streamIterator()` plus `conn.streamRead(stream_id, dst)` to read the
  peer's unidirectional control stream

Stream IDs are caller-supplied. qmsg must track the next local IDs:

- client bidi: `0, 4, 8, ...`
- server bidi: `1, 5, 9, ...`
- client uni: `2, 6, 10, ...`
- server uni: `3, 7, 11, ...`

`quic-zig` provides `nextServerUniId(start)` and `nextServerBidiId(start)`,
but qmsg still needs a role-aware allocator for client-side IDs and for
consistent bookkeeping.

Control stream boot sequence:

1. After QUIC handshake, open local uni control stream.
2. Write a qmsg stream-type marker, then qmsg `HELLO`.
3. Keep stream state in a qmsg `ControlStream` object.
4. Parse peer control frames from the first peer-opened uni stream with the
   qmsg control marker.
5. Process `HELLO`, `GOAWAY`, `SUBSCRIBE`, `UNSUBSCRIBE`, and later `CREDIT`.

Risk: quic-zig currently exposes streams by iterating all streams rather than
by a dedicated "new stream" event. qmsg should keep a per-session stream table
with parse state for each stream ID and scan `conn.streamIterator()` on each
tick/poll cycle.

### Reliable Message Streams

MVP reliable qmsg messages should use one bidirectional QUIC stream per
logical message or request.

Send path:

1. Allocate the next local bidi stream ID.
2. `conn.openBidi(stream_id)`.
3. Encode one qmsg reliable envelope.
4. Repeatedly call `conn.streamWrite(stream_id, remaining)` until all bytes
   are accepted, respecting short writes as backpressure.
5. Call `conn.streamFinish(stream_id)` after the envelope/body is complete.

Receive path:

1. Iterate streams with `conn.streamIterator()`.
2. For each peer-opened bidi stream, read available bytes with
   `conn.streamRead(stream_id, scratch)`.
3. Feed bytes into qmsg's envelope decoder.
4. Dispatch only after a complete qmsg frame is decoded.
5. Treat peer FIN as the end of the reliable message stream.

Pattern mapping:

- pair: either endpoint opens one bidi stream per reliable message.
- req/rep: requester opens one bidi stream, sends `MESSAGE(pattern=req)`,
  responder writes `MESSAGE(pattern=rep, same message_id)` on the same stream
  and finishes.
- pub/sub reliable: publisher opens one stream per matched subscriber/session.
- push/pull: pusher opens one stream when qmsg credit exists.

qmsg must not assume a single `streamWrite` accepts a full message. quic-zig's
send stream has a bounded buffer and may short-write.

### Datagrams

Enable QUIC DATAGRAM by setting nonzero `TransportParams.max_datagram_frame_size`
on both endpoints. A conservative value near 1200 is enough for the MVP.

Send:

- `conn.sendDatagram(payload)` for fire-and-forget.
- `conn.sendDatagramTracked(payload)` when qmsg wants ack/loss telemetry.

Receive:

- `conn.pendingDatagrams()`
- `conn.receiveDatagramInfo(dst)`

Events:

- `conn.pollEvent()` -> `.datagram_acked`
- `conn.pollEvent()` -> `.datagram_lost`

Map quic-zig errors to qmsg errors:

- `error.DatagramUnavailable` -> `error.UnsupportedTransport` or reliable
  fallback, depending on qmsg send options.
- `error.DatagramTooLarge` -> `error.MessageTooLarge`.
- `error.DatagramQueueFull` -> `error.FlowControlled` or `error.QueueFull`.

qmsg must never fragment datagram messages. If the encoded compact qmsg
datagram envelope plus body does not fit, fail or fall back to reliable
delivery only when the caller opted into fallback.

### Resets And Cancellation

quic-zig exposes both halves of QUIC stream cancellation:

- `conn.streamReset(stream_id, app_error_code)` sends RESET_STREAM for the
  local send half.
- `conn.streamStopSending(stream_id, app_error_code)` asks the peer to stop
  sending on the receive half.
- inbound RESET_STREAM is visible on the stream receive state
  (`stream.recv.reset` / reset states).
- inbound STOP_SENDING causes quic-zig to reset the local sender.

qmsg cancellation rules should use both directions:

- If a request deadline fires while qmsg is still sending the request body,
  call `streamReset`.
- If the requester is waiting for a reply and wants to abandon it, call
  `streamStopSending`.
- For a full bidirectional cancellation, call both when legal and ignore
  `StreamNotFound` if the stream was already reclaimed.
- Map inbound peer reset to `error.Canceled` when it matches a local
  cancellation path, otherwise `error.StreamReset`.

Control stream reset or STOP_SENDING should be a qmsg protocol/session failure,
not a normal application cancellation.

### Timers

qmsg `Node.nextTimer()` should take the minimum of:

- each `conn.nextTimerDeadline(now_us)`
- qmsg request deadlines
- qmsg heartbeat/PING deadlines
- auth token expiry/replay-cache deadlines when present
- bounded queue retry/backpressure wakeups

qmsg `Node.tick(now_us)` should:

1. Feed ready socket datagrams into `Server.feed` / `Connection.handle`.
2. Pump qmsg control and stream parse state.
3. Expire qmsg deadlines and issue stream cancellation.
4. Call `conn.tick(now_us)` or `server.tick(now_us)`.
5. Drain `conn.pollDatagram`.
6. Poll `conn.pollEvent`.
7. Reap closed streams/sessions.

`conn.requestPing()` can back qmsg heartbeat frames or idle liveness probes,
but qmsg `PING` / `PONG` control frames are still useful because they measure
application protocol liveness and can carry qmsg-level metadata.

## qmsg Transport Params

Initial defaults for qmsg over QUIC:

```zig
quic_zig.tls.TransportParams{
    .max_idle_timeout_ms = options.max_idle_timeout_ms,
    .initial_max_data = options.connection_window_bytes,
    .initial_max_stream_data_bidi_local = options.stream_window_bytes,
    .initial_max_stream_data_bidi_remote = options.stream_window_bytes,
    .initial_max_stream_data_uni = options.control_stream_window_bytes,
    .initial_max_streams_bidi = options.max_concurrent_message_streams,
    .initial_max_streams_uni = 4,
    .active_connection_id_limit = 4,
    .max_datagram_frame_size = if (options.datagrams) 1200 else 0,
}
```

Tie these to qmsg limits:

- `max_message_size` must not exceed the qmsg decoder cap even when QUIC flow
  control allows more.
- stream and connection flow-control windows are transport flow control, not
  qmsg queue sizes. qmsg still needs bounded message queues above QUIC.
- `initial_max_streams_bidi` is the peer-visible cap for concurrent reliable
  message streams. It should line up with qmsg's bounded in-flight operation
  limit.

## Auth And HELLO

PASETO/PASERK is a qmsg `HELLO` concern, not a QUIC replacement. QUIC TLS
establishes encrypted transport; qmsg `HELLO` establishes application identity,
authorization, pattern/subject permissions, and qmsg feature negotiation.

The qmsg QUIC adapter should treat auth bytes as opaque control-frame payloads:

- encode token and key-id hint in qmsg `HELLO`;
- block application dispatch until qmsg auth accepts the session;
- use `qmsg.Authorization` as session state;
- do not expose PASETO dependency details from the transport adapter.

If qmsg later uses typed `paseto.paserk.Id`, keep that type at the auth
boundary and serialize it into qmsg `HELLO` as bytes/strings before it reaches
the QUIC adapter.

## MVP Implementation Sequence

1. Add the `quic_zig` dependency and a private `transport/quic.zig` module.
   Verify Zig version compatibility before wiring it into the default build.
2. Implement `QuicOptions`, `QuicListener`, `QuicDialer`, and
   `QuicSession` wrappers. No socket patterns yet; just handshake and qmsg
   session creation.
3. Add a hermetic test using `quic_zig.Server` and `quic_zig.Client` with no
   OS sockets, following quic-zig's `tests/e2e/server_client_handshake.zig`.
   Assert ALPN `qmsg/1`.
4. Implement qmsg control stream open/read/write and exchange `HELLO`.
   Session becomes app-ready only after both HELLOs are accepted.
5. Implement one reliable qmsg message over one bidi stream. Test pair-style
   echo over the hermetic transport.
6. Implement req/rep over one bidi stream, including deadline cancellation via
   reset/stop-sending and stable qmsg error mapping.
7. Add real UDP listen/dial loops inside qmsg `Node`, borrowing the shape of
   `quic_zig.transport.udp_server` / `udp_client` but keeping qmsg dispatch in
   the same loop.
8. Add optional DATAGRAM support for `Flags.unreliable`; test too-large,
   disabled, queue-full, and ack/loss event paths.
9. Add production hardening knobs: Retry, NEW_TOKEN, stateless reset,
   listener/source rate limits, qlog callback, keylog callback, and migration
   callback.

## Risks And Open Questions

- API stability: quic-zig is pre-1.0. qmsg should hide quic-zig types behind
  qmsg transport wrappers.
- Toolchain skew: qmsg currently targets Zig 0.17.0 while quic-zig currently
  advertises Zig 0.16.0+. Verify before committing the dependency.
- Stream ID allocation: quic-zig requires caller-supplied IDs. qmsg must own
  role-aware stream ID allocation and stream state.
- Stream discovery: no dedicated public "new stream" event exists today.
  qmsg must scan `streamIterator()` and maintain per-stream parser state.
- ALPN accessor stability: quic-zig tests inspect `conn.inner.alpnSelected()`.
  If this is not intended as public API, qmsg should request or add a stable
  accessor upstream.
- TLS verification: `Client.Config.ca_pem` exists, but production verification
  may require a caller-built `tls_context_override` depending on the exact
  boringssl-zig surface. Treat certificate verification as a required design
  item before internet-facing use.
- Backpressure layering: quic-zig has bounded stream/datagram buffers and flow
  control, but qmsg still needs its own bounded operation queues and user-facing
  `QueueFull` / `FlowControlled` behavior.
- Cancellation semantics: qmsg's "reset the stream" wording should become
  explicit: RESET_STREAM for our send half, STOP_SENDING for the peer's send
  half, both for full request cancellation.
- 0-RTT: leave off for MVP. If enabled later, qmsg must reject non-idempotent
  operations in early data and use quic-zig's anti-replay surfaces.
- Datagram payload limit: quic-zig caps outbound datagram payloads near the
  QUIC minimum MTU and peer transport params may lower it. qmsg's datagram
  send path must encode into a caller-provided/scratch buffer and fail before
  allocation-heavy work when possible.
- Migration/multipath: quic-zig has migration callbacks, path stats, and
  multipath plumbing. qmsg MVP should surface session migration as an event
  later, but should not couple pattern semantics to multipath in the first
  adapter.
- Production posture: quic-zig README requires ReleaseSafe for
  internet-facing builds. qmsg should carry that requirement in its own QUIC
  docs and CI/release guidance.

