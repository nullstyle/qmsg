# QUIC inbound embed seam (Phase C)

**Status: BUILT as of v0.1.4** — `transport.quic_embedded.EmbeddedDispatch`,
with [examples/embedded_quic_attach.zig](../examples/embedded_quic_attach.zig)
as the executable contract and a hermetic foreign-driver end-to-end
test (request event → `replyQuic` → reply received; datagram
delivery event; will-close teardown ride-along). The design below is
the record of what was built and why; the consumer (mruby-quic)
reviewed and approved it with these decisions:

- **Q1 — shared listener + ALPN routing** (confirmed): the embedder
  routes by negotiated ALPN (`isQmsgAlpn`); qmsg connections
  delegate wholly to the dispatch, everything else is the embedder's.
- **Q2 — PULL model** (emphatic): embedded sessions are
  `event_delivery` — inbound messages surface through `Node.poll`
  events (`quic_request`, `quic_reply`, `quic_delivery`), the same
  registry as the inproc embedded surface; `runOnce` never touches
  them. Replies correlate by (session, stream).
- **Q3 — AuthConfig once at init**: credentials ride the transport
  options' `auth_config` into `EmbeddedDispatch.init` and verify once
  at HELLO acceptance.
- **Q4 — drop-and-count confirmed** for undecodable datagrams.

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
and fight over the single teardown slot. Therefore (as built):

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

As built, `EmbeddedDispatch(Owner)` is the hook-body library and
`EmbeddedSeat(Owner)` is the per-connection state (session handle,
pre-HELLO stream accepts, per-stream inbound buffers). The dispatch
is stateless — all state lives in seats and the owner — so the
qmsg-owned listener's `ServerDispatch` delegates to the same bodies
and there is exactly one copy of the teardown mechanics. The embedder
calls `serviceSeat` once per connection per tick, after its
`driver.service` and before its `Server.tick` (the stream GC must
never reap a stream whose arrived bytes qmsg has not read).
`driverSizing` derives the Driver's `max_tracked_streams` and
`datagram_buf_bytes` from the transport options so embedders do not
re-derive them.

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
from the node's pending table (`Node.requestInproc`). Over QUIC dials
the same table now exists: `Node.requestQuic` records the
`(session, stream)` pair, deadline expiry is evaluated in `tick`
against the node clock, `Node.cancelQuicRequest` maps onto the
existing cancel plans (`transport/quic_cancel.zig`, app code
`0x51_01`, applied where the node owns the connection), and a dying
session classifies its pending as `.peer_closed`. The full contract —
including the first-classification-wins idempotency with a consumer's
own pending table — is recorded in docs/QUIC_REQUEST_OUTCOMES.md.

## Deferred (recorded, not built)

- Per-stream inbound RESET observation on the dial side: individual
  stream resets are covered by the connection-level `.peer_closed`
  path; surfacing recv-state per stream would need a consumer ask.
- A wire action on deadline expiry (STOP_SENDING for the expired
  request's reply half): deliberately not sent today, matching
  consumer-side deadline enforcement behavior.
