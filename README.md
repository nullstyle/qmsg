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
- `QueueOptions` and `OnFull` for bounded queues and backpressure policy;
- `InprocNetwork` and `Endpoint`;
- `AuthConfig`, `Authorization`, and `SubjectPolicy`;
- `PasetoAuth` for concrete PASETO/PASERK v4.public verification;
- `control` for qmsg `HELLO`, `GOAWAY`, `SUBSCRIBE`, `UNSUBSCRIBE`, and
  `CREDIT` control-frame encoding;
- `App`, `Context`, and `Session`.

The inproc socket examples build and run against the current public API. The
App facade can register and dispatch route handlers in memory. Network
listeners and the QUIC transport adapter are still future work.

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

The high-level facade should feel small and route-like, but the routes are qmsg
patterns and subjects, not HTTP methods and paths.

```zig
const qmsg = @import("qmsg");

pub fn main() !void {
    var app = try qmsg.App.init(allocator, .{});
    defer app.deinit();

    try app.rep("user.get", getUser);
    try app.pull("jobs.image.resize", resizeJob);
    try app.sub("metrics.*", observeMetric);
    try app.datagram("presence.*", updatePresence);

    try app.listenQuic("0.0.0.0:4433", tls_config);
    try app.run();
}
```

See [examples/app_ergonomics.zig](examples/app_ergonomics.zig) for the current
facade route plan and handler shape.

## Design Tenets

- QUIC-native, not HTTP-shaped.
- Brokerless by default.
- Explicit allocators and bounded queues.
- Backpressure is part of the API, not an implementation leak.
- Raw bytes are always supported; typed codecs are optional helpers.
- Patterns are compile-time selected where practical, e.g. `Socket(.req)`.
- Blocking/simple loop first, embeddable poll/tick API underneath.
- Pluggable transports, but QUIC is the reference transport.
- PASETO/PASERK auth targets `paseto-zig` release `0.2.0`; qmsg owns only
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
[`paseto-zig` `0.2.0`](https://github.com/nullstyle/paseto-zig/releases/tag/0.2.0)
for typed PASERK IDs and bounded fail-closed v4.public token verification,
while the rest of core keeps auth interfaces transport-independent.

## Development

Run the unit tests:

```sh
zig build test
```

Build the examples:

```sh
zig build examples
```

## Repository Notes

The design files remain the source of intent while implementation lands:

- [DESIGN.md](DESIGN.md): architecture, primitives, APIs, pattern semantics.
- [WIRE.md](WIRE.md): initial QUIC wire protocol sketch.
- [AUTH.md](AUTH.md): PASETO/PASERK authentication and key-management plan.
- [ROADMAP.md](ROADMAP.md): implementation milestones and validation plan.
