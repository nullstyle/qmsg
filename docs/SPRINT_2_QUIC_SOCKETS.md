# Owned QUIC sockets and explicit application loops

`QuicSocket(.pair/.req/.rep)` owns UDP sockets and session state behind one
heap-stable Node. The outer handle may move; copying it does not create a
second owner. Call `deinit` exactly once. Retained request reply handles remain
valid during the socket's lifetime and fail after its target session is gone.

The facade uses canonical Node events and the existing request tracker. Its
only receive interface is `poll`; it creates no application drive loop. Call
`pump(now_us)` with monotonic microseconds, then handle owned poll events. Node
limits can be configured through `QuicSocketOptions.node`; canonical delivery
and the selected inbound pattern are managed by the facade.

The runnable [owned req/rep example](../examples/quic_owned_reqrep.zig) shows
the full loop and a retained reply handle. The
[Node/App localhost example](../examples/quic_node_localhost.zig) uses the
public Node request/outcome and App dispatch interfaces.

## Pattern and TLS configuration

| Owned socket | HELLO offer | Required peer | Application interface |
| --- | --- | --- | --- |
| `QuicSocket(.pair)` | PAIR | PAIR | `send` and delivery events |
| `QuicSocket(.req)` | REQ | REP | `request` and terminal outcomes |
| `QuicSocket(.rep)` | REP | REQ | Request events and `reply` |

The facade sets the selected pattern capability and validates counterpart
requirements. Two REQ sockets or two REP sockets cannot negotiate a useful
session. General Nodes may still advertise multiple roles. HELLO compatibility
now checks counterpart roles rather than requiring identical role bits.

`listen(address, QuicListenOptions)` takes certificate/key and transport
options. `localAddress(listener_id)` returns the actual bound address, including
an ephemeral port requested with `:0`. The default listener limit is one.
`dial(address, QuicDialOptions)` returns a session ID before readiness; keep
pumping and inspect `sessionStatus(id).state`. Ready means TLS and HELLO have
completed according to the supplied verification policy. Use
`expected_peer_spki` when a particular authenticated peer identity is required.

The facade uses nonblocking receive options. Reliable pair/req/rep are its
scope; configure DATAGRAM or other patterns through the existing Node interface.
The lower-level `Socket` keeps inproc and foreign-driver attachment behavior.
Its address-only `.quic` endpoint does not configure an owned TLS runtime.

## Drive and consume

This is a single serving iteration using only public interfaces:

```zig
fn serveOnce(server: *qmsg.QuicSocket(.rep), now_us: u64) !bool {
    try server.pump(now_us);
    var events: [16]qmsg.NodeEvent = undefined;
    const count = try server.poll(&events);
    defer for (events[0..count]) |*event| event.deinit();
    for (events[0..count]) |event| switch (event) {
        .request => |request| try server.reply(request.msg.reply_handle.?, .{
            .subject = "",
            .body = request.msg.body,
        }),
        else => {},
    };
    if (count != 0) try server.pump(now_us);
    return count != 0; // Continue the owner loop before waiting when true.
}
```

A requesting socket calls `request(session_id, outgoing)` once per application
operation. The returned local `RequestId` matches `reply.request_id` or
`request_failed.request_id`. It is distinct from the wire message ID. Use
`cancelRequest` for cancellation and `takeOutcome` to retrieve an already
completed result. Accepted requests reserve terminal outcome capacity just as
on Node, including under ordinary event pressure.

`request`, `reply`, `send`, and `goaway` queue work. Pump after those mutations
before sleeping. Continue processing if handling events queued more work, then
poll again after pumping. `nextTimer` describes deadlines; it is not a local
work-queue readiness signal. Park only after a quiet iteration so a pump does
not consume a ready datagram into an event queue immediately before sleeping.

Each returned event owns its payload. Free the whole batch even if a handler
returns early. For asynchronous work, retain `request.msg.reply_handle` before
releasing the request event; release that retained handle after the reply.

`nextTimer()` returns an absolute deadline on the owner clock. Combine it with
other application deadlines and UDP readability before calling `pump` again.
`readableSockets(out)` copies the complete borrowed handle inventory, returning
`BufferTooSmall` without a partial result if the buffer cannot hold it. Refresh
the inventory after pumping or changing sessions; the socket owns the handles,
and the application must not close them. Native owner loops can wait through
their platform's readiness mechanism. The public examples demonstrate POSIX
polling on the locally qualified platforms.

`closeSession(id)` aborts a session. `goaway(id, code, reason, now_us, timeout_us)`
uses the bounded drain contract from [Sprint 1](SPRINT_1_LIFECYCLE.md): new work
is refused, existing requests and deferred replies may finish, and the owner
continues pumping until the deadline. `session_goaway` owns its reason bytes.

## Authorization compatibility correction

Pattern grants describe what the peer may do. A client issuing requests needs
REQ permission; a replying peer needs REP permission. Automatic admission now
uses that same meaning as HELLO across Node, sockets, inproc and App handlers:

| Local receiver | Required peer action |
| --- | --- |
| REP | REQ |
| PULL | PUSH |
| SUB | PUB |
| PAIR | PAIR |

Earlier request admission checked the local REP role after HELLO had accepted
a peer's REQ role. Minimal REQ grants could therefore authenticate and then
fail every request. Existing policies/tests that granted only the local
receiver role must change to the peer action. Subject restrictions and literal
`Session.requirePattern` / `Context.requirePattern` retain their meaning.
`Context.requireRouteAccess` applies the route-to-peer mapping automatically.
See [AUTH.md](../AUTH.md) for the grant contract.

## Qualification and scope

Sprint 2 starts from committed Sprint 1 `6bdcf69732d1101b9c91c9271674b0416772a6ff`
on stock mise-pinned Zig 0.17.0. Public QUIC v0.37.2/PASETO 0.4.0 pins, ALPN
`qmsg/1`, and wire version 1 stay unchanged. New work remains uncommitted.

The local report under `.zig-cache/sprint-2-evidence/` records exact source,
compiler, commands, executed/cached tests, negative reproductions and live
examples. It covers role negotiation, authenticated minimal grants, canonical
ownership, concurrent/deferred requests, cancellation/deadlines, queue and stream
pressure, teardown, and public Node/App/owned-socket usage. The qmesh composition
checker additionally drives public sockets alongside real deadline-driven mesh
runners with one shared QUIC module in Debug and ReleaseSafe. Those reports
identify their exact inputs and establish no hosted CI or physical-network claim.
