# qmsg Wire Protocol Sketch

This file describes the initial `qmsg/1` protocol shape. It is a sketch, not a
frozen specification.

## Transport Assumptions

The primary transport is QUIC.

Required QUIC features:

- TLS handshake with ALPN `qmsg/1`;
- bidirectional streams;
- at least one unidirectional control stream per endpoint;
- optional QUIC DATAGRAM extension.

HTTP/3 is not used.

## Connection Startup

After QUIC handshake, each endpoint opens a unidirectional control stream and
sends `HELLO`.

```text
CONTROL_STREAM:
  stream_type = qmsg_control
  HELLO
  zero or more CONTROL frames
```

HELLO fields:

```text
version
peer_id
role_flags
supported_patterns
max_message_size
max_header_bytes
max_header_count
datagram_enabled
heartbeat_interval_ms
auth_properties
  scheme
  credential
  key_id_hint: optional PASERK ID string
```

The intended first auth scheme is PASETO, using `paseto-zig` once it has a
release. PASERK key identifiers are strings such as `k4.pid...` and are used
only as lookup hints into a trusted local key store. See [AUTH.md](AUTH.md).

The session becomes application-ready after both sides validate peer HELLO and
the application authentication hook accepts the session.

## Encoding

Use QUIC varints for field lengths and numeric ids where possible.

Strings and byte arrays:

```text
varint length
length bytes
```

Maps/headers:

```text
varint count
repeated:
  name bytes
  value bytes
```

MVP can use a simple hand-rolled binary codec. A later version can add optional
schema-aware codecs above the message body without changing the transport
envelope.

## Message Envelope

Reliable message frame:

```text
MESSAGE {
  message_id: varint
  pattern: varint
  flags: varint
  subject: bytes
  deadline_ms: varint-or-zero
  headers: header-list
  body_len: varint
  body: bytes
}
```

Datagram message frame:

```text
DATAGRAM_MESSAGE {
  message_id: truncated-varint-or-zero
  flags: varint
  subject: bytes
  headers: compact-header-list
  body: remaining bytes
}
```

Datagrams must fit inside the peer's datagram payload limit. They are never
fragmented by `qmsg`. If a datagram message is too large, send returns
`error.MessageTooLarge` or, if configured, falls back to reliable delivery.

## Flags

Candidate flags:

```text
final
more
no_reply
error
unreliable
compressed
borrowed_deadline
```

MVP should implement only:

- `final`
- `no_reply`
- `error`
- `unreliable`

## Pattern Mapping

### Req/Rep

Client opens one bidirectional stream per request:

```text
client -> server: MESSAGE(pattern=req, subject=...)
server -> client: MESSAGE(pattern=rep, same message_id, final)
```

Cancellation:

- requester resets the stream when local deadline/cancel fires;
- responder maps reset to `error.Canceled` if it is still processing.

### Pair

Either side may open a message stream. Small ordered pair messages may later use
a shared framed stream, but MVP can use one stream per reliable message.

### Pub/Sub

Subscriptions travel on the control stream:

```text
SUBSCRIBE {
  filter
  options
}

UNSUBSCRIBE {
  filter
}
```

Publications use reliable message streams unless marked `unreliable`, the peer
negotiated datagrams, and the encoded message fits.

### Push/Pull

Pullers advertise credit:

```text
CREDIT {
  subject_filter
  messages
  bytes
}
```

Pushers spend credit when sending work. If no credit exists, the configured
queue policy decides whether to block, fail, or drop.

### Survey/Respondent

Survey opens a logical survey id and broadcasts to sessions:

```text
SURVEY {
  survey_id
  subject
  deadline_ms
  body
}
```

Responses include `survey_id`. Late responses after deadline are ignored and
may be counted.

## Control Frames

Candidate control frames:

```text
HELLO
PING
PONG
GOAWAY
SUBSCRIBE
UNSUBSCRIBE
CREDIT
RESET_PATTERN
SESSION_ERROR
```

MVP needs:

- `HELLO`
- `GOAWAY`
- `SUBSCRIBE`
- `UNSUBSCRIBE`
- `CREDIT` if push/pull is in MVP, otherwise later

## Close Semantics

Connection close:

- transport-level close for protocol violations and hard session failures;
- application-level close for graceful node shutdown.

Stream reset:

- request canceled;
- message body abandoned;
- responder failed before producing a reply.

Application errors:

- encoded as `MESSAGE(flags.error)` when the pattern supports replies;
- not represented as QUIC transport errors unless the peer violated protocol.

## Versioning

ALPN starts as `qmsg/1`.

Within HELLO:

```text
wire_version = 1
min_supported_version
feature_bits
```

Rules:

- incompatible major wire version fails handshake after HELLO;
- unknown feature bits are ignored unless marked required;
- pattern-specific extensions must be negotiated.
