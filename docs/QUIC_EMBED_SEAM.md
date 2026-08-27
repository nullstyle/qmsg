# QUIC inbound embed seam (Phase C design)

**Status: design only — not built.** This is the seam for qmsg
sessions riding connections on a FOREIGN embedder's QUIC listener
(mruby-quic phase C): the embedder owns the listener, the UDP
socket, and the `quic.app.Driver`; qmsg owns session state and the
qmsg protocol. mruby-quic reviews this before it is built.

Companion reading: [EMBEDDING.md](EMBEDDING.md) (the inproc
embedder contract this extends), `src/transport/quic_app_server.zig`
(the qmsg-owned-listener Dispatch this inverts), quic-zig's
`docs/EMBEDDING.md` and `src/app/root.zig` (the Driver contract).

## What exists today

Two QUIC shapes are built and tested:

1. **qmsg-owned listener** — `Node.listenQuic` owns a UDP listener
   and a `ServerDispatch(Owner)` that instantiates
   `quic.app.Driver(App)` itself, attaches the will-close hook, and
   is serviced from the node tick. The Driver, the listener, and the
   session store are all inside qmsg.
2. **Outbound dial** — `Node.dialQuic` owns a UDP client socket; the
   embedder ticks it (`Node.tick`). Reply correlation on the dial
   side is app-driven today; see "Deadline/cancellation" below.

The missing shape is the inverse of (1): the Driver belongs to the
embedder, and qmsg hangs sessions off it.

## The seam: invert ownership of the Driver

The hard constraint comes from quic-zig: a `Server` has exactly ONE
connection-will-close hook (`setConnectionWillCloseHook`), and the
Driver is the thing that registers `D.willCloseHook` there. Two
independent Drivers over one Server would double-consume stream data
and fight over the single teardown slot. Therefore:

> **There is one `quic.app.Driver` per Server — the embedder's. qmsg
> never instantiates a Driver on the inbound seam. The embedder's App
> hooks delegate qmsg connections into qmsg.**

Concretely, qmsg ships an `EmbeddedDispatch` (name tentative) that is
`ServerDispatch` with the Driver ownership removed and the hook
bodies made public, embedder-callable:

```zig
// embedder's App — per-connection state gains a qmsg seat:
const App = struct {
    conn_state: struct {
        qmsg_sess: ?*qmsg.node.QuicSessionRuntime = null,
        qmsg_pending_accepts: std.ArrayListUnmanaged(u64) = .empty,
        // ...the embedder's own actor state...
    },

    // embedder's hooks delegate for qmsg-ALPN connections:
    fn onHandshake(app: *App, s: *Driver(App).Session) anyerror!void {
        if (isQmsgConnection(s)) {
            try app.qmsg_dispatch.onHandshake(s);   // creates the session
        } else {
            // embedder's own actor handshake
        }
    }
    // likewise on_stream_open / on_stream_data / on_stream_end /
    // on_datagram / on_disconnect
};
```

`EmbeddedDispatch` owns per-connection stream buffering exactly as
`ServerDispatch.App.StreamState` does today (the pull-based qmsg
receivers read through the same `Adapter` shape:
`streamRead`/`streamReceiveStatus` over Driver-owned buffers). The
embedder calls one pass hook per listener tick, before its
`Server.tick` (the same service-before-tick ordering
`ServerDispatch.service` documents — the stream GC must never reap a
stream whose arrived bytes qmsg has not read).

**Ownership statements:**
- qmsg owns: session runtimes, control/reliable/datagram codecs,
  per-stream receive buffers it attached to the embedder's stream
  entries, and the event/dispatch surface.
- The embedder owns: UDP, the listener/Server, the Driver, reaping,
  and the clock. qmsg sessions are created on handshake and destroyed
  from the embedder's `on_disconnect` (delivered by the will-close
  hook's synthesized stream ends) — exactly once, same as the
  driver-owned lifecycle in `Node` today (`QuicSessionRuntime.driver_owned`
  refuses manual close; teardown belongs to the hook).

## Connection discrimination

On a shared listener the embedder routes by ALPN: `qmsg/1`
connections go to the qmsg dispatch, everything else to the
embedder's own handlers. Alternatives (separate listener port, or a
first-byte discriminator) exist but ALPN is the negotiated,
standard place — `Connection.alpnSelected()` after handshake.
Open question Q1 below: shared listener + ALPN, or a dedicated
qmsg listener the embedder still owns.

## The stabilized `dispatchQuic` contract

`App.dispatchQuic*` is already public and shape-stable; the seam
doc pins it:

```zig
pub fn dispatchQuic(
    app: *App,
    kind: RouteKind,                 // .rep | .pull | .sub | .datagram
    incoming: message.Message,       // owned; consumed on ALL paths
    sess: *session.Session,          // the qmsg session's appSession()
    options: QuicDispatchOptions,    // reply/publish hooks (optional)
) !DispatchResult
```

- `incoming` ownership transfers on success AND on error (the facade
  deinits or converts it to an error reply per `ErrorPolicy`).
- `sess` must have `transport == .quic` — the session the runtime
  created for that connection, not a synthetic one.
- Returns a `DispatchResult` (replies/publications lists) unless
  hooks intercept; the EMBEDDER's transport encodes replies back onto
  the right stream (`replyReliableOnStream`) or as datagrams. This is
  how reply routing stays in the hands of the Driver owner.
- Error replies: default `reply_error` policy converts handler
  failures into `flags.err` messages carrying `qmsg-error-code` /
  `qmsg-error-message` headers — the same stable error shape the
  inproc embedded surface emits.

## Where SubjectPolicy / PASETO checks belong

Three layers, in order, fail-closed:

1. **Transport admission** — the embedder's listener policy (ALPN,
   TLS client auth) happens before qmsg sees anything. Not qmsg's.
2. **Session establishment (HELLO)** — the ONLY place credentials
   verify. When the qmsg control stream's HELLO is accepted
   (`QuicSessionRuntime` → `session.acceptPeerControl`), the
   embedder-configured `AuthConfig` runs
   `Session.authenticateHello` (PASETO v4.public via the PASERK key
   registry, challenge binding, replay hooks). A rejected credential
   closes the qmsg session (`beginClosing`) — it must never reach
   dispatch. The resulting `Authorization` caches on the Session.
3. **Per-message authorization** — dispatch-time enforcement via
   `Context.requireRouteAccess()`: pattern, subject (`SubjectPolicy`
   filters), datagram permission, message size, against the cached
   `Authorization`. This is the embedder's handler-side gate and it
   is already the enforcement point on every dispatch path.

Rule of thumb: credentials verify once at HELLO; policy checks run
per message; nothing authorizes at the socket layer.

## Coexistence of the two hook sets

Because there is one Driver and it is the embedder's:

- The embedder's hooks branch FIRST on connection kind (ALPN), then
  delegate qmsg connections wholly to `EmbeddedDispatch` — including
  stream events, datagrams, and disconnect. Splitting one qmsg
  connection's streams between qmsg and the embedder is not
  supported (qmsg's control stream is uni stream 2/3 by id; request
  streams are peer-opened bidi streams the session must accept).
- The embedder's Driver sizing must satisfy qmsg's transport
  parameters for those connections: `max_tracked_streams` at least
  the advertised bidi+uni stream limits, and
  `datagram_buf_bytes` at least qmsg's `max_datagram_frame_size`
  (the same sizing `ServerDispatch.init` derives from
  `QuicOptions` — the seam will expose a helper so embedders do not
  re-derive it).
- The will-close teardown path stays single-owner: the embedder's
  Driver synthesizes `on_stream_end(.reaped)` for live streams and
  fires `on_disconnect` while the qmsg session is valid — the qmsg
  seat frees there, once, exactly like `ServerDispatch`'s
  `onDisconnect` does for `Node` today.

## Deadline/cancellation over QUIC dials (Phase B note)

The inproc embedded surface classifies outcomes
(`RequestFailure`: deadline/canceled/queue-full/peer-closed/no-route)
from the node's pending table (`Node.requestInproc`). Over QUIC
dials, the same table extends naturally: `queueReliable` returns the
stream id to key on, deadline expiry is evaluated in `tick` against
the node clock, and wire-level cancellation maps onto the existing
CANCEL control-frame helpers (`transport/quic_cancel.zig`) plus
stream reset. What is NOT built today: no QUIC-side request timeout
fires in `Node.tick` — the hermetic end-to-end dispatch test
completes req/rep with deadlines carried on the wire, but an
unserved request does not yet surface a deadline outcome. That state
machine (pending table + `request_failed` events over QUIC) is the
first Phase B work item after this sprint, and it reuses the
embedded event vocabulary unchanged.

## Open questions for mruby-quic review

- **Q1 — listener shape:** shared listener with ALPN routing, or a
  dedicated qmsg listener owned by the embedder? Affects hook
  branching and TLS cert sharing; ALPN routing is the current
  recommendation.
- **Q2 — dispatch consumption:** does the bridge consume inbound
  QUIC messages through `App` handlers (`dispatchQuic`, push model)
  or should the QUIC path also feed `poll` events like the inproc
  embedded surface (pull model)? The latter unifies the bridge's
  event loop across phases A–C and is the leaning, but it means the
  event queue becomes the single consumption path for QUIC sessions
  too.
- **Q3 — HELLO auth config surface:** who constructs the
  `AuthConfig`/key registry for embedded qmsg sessions — the
  embedder at `EmbeddedDispatch.init`, or per-listener? Inproc has
  no HELLO, so this is the first place it binds.
- **Q4 — datagram fallback policy:** on the qmsg-owned listener,
  datagrams that cannot decode are dropped and counted; confirm the
  embedded seam should keep drop-and-count (no reliable fallback for
  unreliable sends).
