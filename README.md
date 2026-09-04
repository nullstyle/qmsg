# qmsg

`qmsg` is a Zig-native messaging and application framework inspired by nng's
brokerless communication patterns and Sinatra's low ceremony application style.
QUIC is the primary network transport direction, while in-process transport is
the first testable transport for pattern development.

`qmsg` is not an HTTP/3 framework. It does not expose HTTP routing, request
objects, status codes, or header semantics. `qmsg` defines its own small
message protocol over QUIC streams and datagrams.

## Status

This repository is now a real Zig package skeleton, not only a design folder.
The public root module exports the core names that the first implementation
tranches are building around:

- `Message`, `OutgoingMessage`, `Header`, `Flags`, and `MessageId`;
- `SubjectFilter` and `SubjectRouter`;
- `Socket(.pair/.req/.rep/.@"pub"/.sub/.push/.pull)` and `SocketOptions`;
- `ErrorReply` plus deadline/cancellation helpers for req/rep;
- `QueueOptions` and `OnFull` for bounded queues and backpressure policy;
- `InprocNetwork` and `Endpoint`;
- `AuthConfig`, `Authorization`, and `SubjectPolicy`;
- `PasetoAuth` for concrete PASETO/PASERK v4.public verification;
- `control` for qmsg `HELLO`, `GOAWAY`, `SUBSCRIBE`, `UNSUBSCRIBE`, and
  `CREDIT` control-frame encoding;
- `protocol.pubsub` and `protocol.pushpull` helpers for subscription and
  credit accounting;
- `transport.quic`, `transport.quic_runtime`, `transport.quic_udp`,
  `transport.quic_session_runtime`, `transport.quic_streams`,
  `transport.quic_cancel`, `transport.quic_datagram`, and
  `transport.quic_control` for qmsg-owned QUIC options, UDP ownership,
  session driving, stream, cancellation, datagram, and live control-frame
  surfaces over `quic-zig`;
- `App`, `Context`, and `Session`;
- an embeddable socketless `Node` surface: the embedder owns the
  loop and clock (`tick`/`poll`), the Node owns every inproc socket,
  and all outcomes render from poll events — requests with
  correlation ids and deadlines, replies, classified request
  failures (`RequestFailure`), pub/sub deliveries with the matched
  filter, drop accounting, and plain `Stats` counters. See
  [docs/EMBEDDING.md](docs/EMBEDDING.md) and
  [examples/embedded_inproc_node.zig](examples/embedded_inproc_node.zig);
- inbound QUIC attach for foreign embedders (`EmbeddedDispatch`):
  qmsg sessions ride connections on the embedder's own listener and
  `quic.app.Driver`, routed by ALPN, with inbound requests/replies/
  deliveries flowing through the same `poll` events and replies via
  `replyQuic`.

The inproc socket examples build and run against the current public API. The
App facade can now serve inproc REP routes through `runOnce`, and can prepare
QUIC listener/session runtime plumbing. QUIC has a pinned released
`quic-zig` dependency (URL+hash tarball, v0.19.0), option wrappers, transport-parameter
mapping, socket-free runtime wrappers around `quic_zig.Server`/`Client`,
Node-embeddable UDP socket owners, per-session QUIC drivers, socket QUIC
attachment callbacks, App dispatch for already-decoded QUIC messages,
incremental control/reliable stream pumps, cancellation/error mapping,
compact DATAGRAM envelope helpers, and hermetic tests that drive quic-zig
handshake, qmsg HELLO, and reliable req/rep over QUIC streams. Wiring these
pieces into `Node.listenQuic`/`dialQuic` runtime loops has started: `Node`
owns UDP listener/client sockets, per-session drivers, socket attachment
helpers, tick-driven reliable stream pumping, and decoded datagram dispatch
queues. An opt-in Node/App localhost example exercises the live UDP loop by
queuing a reliable message directly on the current session runtime. Public
`Socket.listen(.quic)`/`dial(.quic)` convenience APIs remain future work.

## Package Use

From another Zig package, import the module as `qmsg` and start with plain byte
messages:

```zig
const qmsg = @import("qmsg");

const msg = qmsg.OutgoingMessage{
    .subject = "user.get",
    .headers = &.{
        .{ .name = "accept", .value = "application/json" },
    },
    .body = "user-42",
    .deadline_ms = 250,
};
```

Messages are owned explicitly. `OutgoingMessage` is a borrowed send view.
Received `Message` values own their duplicated subject, headers, and body and
must be `deinit`ed by the receiver.

Subject filters are dot-separated byte strings:

```text
user.get
metrics.*
presence.>
```

Initial matching priority is exact match, then the most specific wildcard, then
registration order.

## Inproc Socket Style

The low-level API is nng-like: choose the pattern at compile time, bind or dial
an endpoint, and exchange byte messages. Inproc comes first so behavior can be
tested without QUIC.

```zig
const queue = qmsg.QueueOptions{
    .max_messages = 16,
    .max_bytes = 128 * 1024,
    .on_full = .fail,
};

var rep = try qmsg.Socket(.rep).init(allocator, .{ .recv_queue = queue });
defer rep.deinit();

var req = try qmsg.Socket(.req).init(allocator, .{ .recv_queue = queue });
defer req.deinit();

var network = qmsg.InprocNetwork.init(allocator);
defer network.deinit();

try rep.listenInproc(&network, "users");
try req.dialInproc(&network, "users");

const id = try req.sendRequest(.{
    .subject = "user.get",
    .body = "user-42",
    .deadline_ms = 250,
});

var request = try rep.recv();
defer request.deinit();

try rep.reply(request, .{
    .subject = "user.get.ok",
    .body = "{\"id\":\"user-42\",\"name\":\"Ada\"}",
});

var reply = try req.recv();
defer reply.deinit();
std.debug.assert(reply.id == id);
```

See [examples/inproc_reqrep.zig](examples/inproc_reqrep.zig) for the pair and
req/rep example shape.

## App Facade Style

The high-level facade is route-like, but the routes are qmsg patterns and
subjects, not HTTP methods and paths. The current runnable facade path is
inproc REP through `listenInprocRep` and `runOnce`; QUIC message dispatch is
available for session drivers that deliver decoded messages into
`dispatchQuic`, and `listenQuic`/`dialQuic` expose Node-owned listener/client
tick plumbing for embedders.

```zig
const qmsg = @import("qmsg");

pub fn main() !void {
    var app = try qmsg.App.init(allocator, .{});
    defer app.deinit();

    try app.rep("user.get", getUser);
    try app.pull("jobs.image.resize", resizeJob);
    try app.sub("metrics.*", observeMetric);
    try app.datagram("presence.*", updatePresence);

    _ = try app.listenInprocRep(&network, "users", .{});
    _ = try app.runOnce();
}
```

See [examples/app_ergonomics.zig](examples/app_ergonomics.zig) for the current
facade handler shape over inproc req/rep.

## Embedding a Node (socketless inproc)

For host runtimes that own their own loop — scripting bridges, actor
frameworks, supervisors — a `Node` embeds without sockets, threads,
or a hidden runtime. The embedder drives `tick(now_us)` and
`poll(&events)`; the Node owns every inproc socket and renders every
outcome from events alone:

```zig
node.tick(now_us) catch {};
var events: [16]qmsg.node.Event = undefined;
const count = try node.poll(&events);
for (events[0..count]) |*event| {
    defer event.deinit();
    switch (event.*) {
        .request => |*ev| try node.replyInproc(ev, .{ .subject = "", .body = "ok" }),
        .reply, .request_failed, .delivery, .message_dropped, .connected, .closed => {},
    }
}
```

Backpressure is observable (synchronous send errors plus a bounded
event queue with drop counters) and `node.stats()` returns plain
fields. The full contract — wiring, event semantics, error
classification, ownership — is
[docs/EMBEDDING.md](docs/EMBEDDING.md), and
[examples/embedded_inproc_node.zig](examples/embedded_inproc_node.zig)
is the executable form of it (run it with
`zig build examples && ./zig-out/bin/embedded-inproc-node` — deterministic,
virtual clock, no sockets). Inbound QUIC attach — qmsg sessions riding
a foreign embedder's listener and `quic.app.Driver`, routed by ALPN,
consumed through the same poll events — is built:
[docs/QUIC_EMBED_SEAM.md](docs/QUIC_EMBED_SEAM.md) and
[examples/embedded_quic_attach.zig](examples/embedded_quic_attach.zig).

## Embeddable QUIC Hooks

The current public QUIC hooks are deliberately library-level. A runtime driver
owns UDP, stream ids, stream encoding, and flow control. Sockets own pattern
state, request ids, deadlines, and receive queues.

For socket embedding, attach a session callback and let the driver consume
owned messages:

```zig
try req.attachQuicSession(.{
    .context = driver,
    .send = sendThroughDriver,
});

const id = try req.sendRequest(.{
    .subject = "user.get",
    .deadline_ms = 250,
    .body = "user-42",
});
```

When the driver decodes an inbound qmsg message from QUIC, hand ownership back
to the socket:

```zig
try req.receiveQuicMessage(decoded_reply);
var reply = try req.recv();
```

For App embedding, a session driver that has already decoded a reliable stream
or datagram can call `dispatchQuic`, `dispatchQuicReliable`, or
`dispatchQuicDatagram` and encode any returned replies/publications.

See [examples/quic_socket_hooks.zig](examples/quic_socket_hooks.zig) for a
buildable fake-driver req/rep flow using the current socket hooks, and
[examples/quic_app_dispatch.zig](examples/quic_app_dispatch.zig) for the
decoded App reliable/datagram dispatch surface.

## QUIC Runtime Smoke

The current QUIC examples are library examples, not `qmsg-server` or
`qmsg-client` binaries.

The hermetic runtime smoke is intentionally one process: it drives
`quic_zig.Client` and `quic_zig.Server` through qmsg's runtime wrappers, then
exchanges qmsg HELLO and one reliable req/rep stream.

```sh
zig build examples
./zig-out/bin/quic-runtime-reqrep
```

That path proves the qmsg protocol mapping without requiring live UDP sockets.

The decoded App dispatch smoke stays hermetic as well:

```sh
./zig-out/bin/quic-app-dispatch
```

The live localhost smoke uses `App.listenQuic`, `Node.dialQuic`, and the
Node-owned UDP tick loop. It is opt-in because some CI/sandboxed environments
do not permit UDP binds. When enabled, it queues one reliable message directly
on the session runtime and lets `App.runOnce` dispatch the server-side request.

```sh
QMSG_RUN_LIVE_UDP=1 ./zig-out/bin/quic-node-localhost
```

Without the environment variable, the example exits cleanly without opening a
socket:

```sh
./zig-out/bin/quic-node-localhost
```

The public socket convenience APIs still stay explicit about unsupported
direct `.quic` endpoints.

## Design Tenets

- QUIC-native, not HTTP-shaped.
- Brokerless by default.
- Explicit allocators and bounded queues.
- Backpressure is part of the API, not an implementation leak.
- Raw bytes are always supported; typed codecs are optional helpers.
- Patterns are compile-time selected where practical, e.g. `Socket(.req)`.
- Blocking/simple loop first, embeddable poll/tick API underneath.
- Pluggable transports, but QUIC is the reference transport.
- PASETO/PASERK auth targets `paseto-zig` release `0.3.0`; qmsg owns only
  session policy, key lookup, replay hooks, and subject/pattern authorization.

## Authentication Surface

The current package keeps authentication optional and transport-independent:

```zig
const auth = qmsg.AuthConfig{
    .required = true,
    .max_token_bytes = 4096,
    .max_clock_skew_ms = 30_000,
};
```

`Authorization` is session state exposed to handlers after credentials have
been validated. `qmsg.PasetoAuth` uses
[`paseto-zig` `0.3.0`](https://github.com/nullstyle/paseto-zig/releases/tag/0.3.0)
for typed PASERK IDs and bounded fail-closed v4.public token verification,
while the rest of core keeps auth interfaces transport-independent.
See [examples/auth_paseto.zig](examples/auth_paseto.zig) for the current
PASERK key-rotation and v4.public verification shape.

## Optional Cap'n Proto Body Codec

Message bodies are raw bytes by design; the typed-codec slot (ROADMAP
phase 9) has a Cap'n Proto implementation behind an opt-in build flag.
It adds a LAZY dependency on
[capnp-zig](https://github.com/nullstyle/capnp-zig) — builds without the
flag never compile or link it into qmsg's module graph (note: on current
0.17-dev toolchains, dependency resolution still downloads and
hash-validates every manifest entry, lazy or not):

```sh
zig build -Dcapnp=true capnp-test
```

Consumers opt in by passing `-Dcapnp=true` when depending on qmsg and
importing the extra module:

```zig
const qmsg = @import("qmsg");
const capnp_codec = @import("qmsg-codec-capnp");

// Encode a capnp MessageBuilder as a message body:
const body = try capnp_codec.encode(allocator, &builder);

// Decode a received body (zero-copy reads; malformed input is an error,
// never a crash):
var msg = try capnp_codec.decode(allocator, received.body);
defer msg.deinit();
```

The codec uses the standard packed encoding, so bodies interoperate with
any Cap'n Proto implementation. One constraint: the codec resolves the
`capnpc-zig` module at its default root — a binary linking capnp-zig
directly alongside this codec must resolve the same module (same
version, default root, no extra options) or the build duplicates
capnp-zig's shared source files.

## Development

Run the unit tests:

```sh
zig build test
```

Run only the QUIC transport skeleton tests:

```sh
zig build quic-test
```

Build the examples:

```sh
zig build examples
```

For internet-facing QUIC builds, follow `quic-zig`'s production posture and
use `ReleaseSafe`; the current qmsg QUIC surface has embeddable runtime pieces
but is not yet a production listener/dialer with public socket APIs.

### Package resolution note (macOS)

If a tarball pin fails with `hash mismatch: manifest declares
<name>-<version>-… but the fetched package has N-V-__8AA…`, the
global package cache is stale, not the pin: clear the global cache
(default `~/.cache/zig`, or your `ZIG_GLOBAL_CACHE_DIR`) — and the
project's `zig-pkg` if an `N-V-__8AA…` entry appeared in it — and
re-resolve. Interrupted fetches leave temp dirs that make subsequent
resolution hash the unstripped package (unnamed id) even though the
same URL hashes correctly on a clean cache. Fetching with
`COPYFILE_DISABLE=1` avoids the AppleDouble variant of the same
poisoning.

## Repository Notes

The design files remain the source of intent while implementation lands:

- [DESIGN.md](DESIGN.md): architecture, primitives, APIs, pattern semantics.
- [WIRE.md](WIRE.md): initial QUIC wire protocol sketch.
- [AUTH.md](AUTH.md): PASETO/PASERK authentication and key-management plan.
- [ROADMAP.md](ROADMAP.md): implementation milestones and validation plan.
- [docs/EMBEDDING.md](docs/EMBEDDING.md): the socketless embedded Node contract.
- [docs/QUIC_EMBED_SEAM.md](docs/QUIC_EMBED_SEAM.md): the inbound QUIC
  embed seam design (embedder-owned listener and Driver).
