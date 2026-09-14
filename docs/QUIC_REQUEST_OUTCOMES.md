# Request outcomes over QUIC

`Node.request(.{ .quic = session_id }, outgoing)` uses the same request owner
as the inproc transport. It returns a local `RequestId`. Both transports emit
canonical `reply` or `request_failed` events carrying that ID; QUIC outcomes
also include session and stream metadata. For migration from the older
transport-specific interface, see [MIGRATION.md](MIGRATION.md).

## Admission and completion

A request is registered only after synchronous admission and send checks
succeed. Admission reserves one terminal-outcome slot before sending. The
`max_requests` bound includes pending requests and outcomes waiting for the
caller to consume them. Request byte usage is bounded separately by
`max_request_bytes`.

Each accepted request settles once. Continue driving `tick` and `poll`, and
give requests a deadline when peer silence must eventually finish the work.

| Outcome | Canonical result |
| --- | --- |
| A reply arrives | `reply`, keyed by `request_id` |
| The request deadline expires | `request_failed` with `.deadline_exceeded` |
| `cancelRequest(request_id)` wins the race | `request_failed` with `.canceled` |
| The session closes or is destroyed | `request_failed` with `.peer_closed` |
| The reply cannot fit `max_completion_bytes` | `request_failed` with `.queue_full`; reply payload freed |

The first observed outcome wins. A late reply after completion does not create
a second terminal result. Cancellation applies the QUIC reset/stop-sending
plan when Node owns the connection.

Terminal outcomes use reserved storage, so ordinary event pressure cannot
discard them. `poll` returns terminal outcomes before ordinary events; there
is no global FIFO order between the two queues. `takeOutcome(request_id)` can
remove one already-completed outcome without consuming unrelated events. Both
transfer ownership to the caller, who must deinit the returned event. Neither
an unread outcome nor a pending request releases its count reservation until
the caller consumes or explicitly settles it.

`TooManyInflightRequests` means the combined request/outcome count is full;
`QueueFull` can indicate the request byte limit or a transport queue. These
are synchronous errors when admission/send fails. An accepted reply that
exceeds the completion byte budget instead produces the terminal `.queue_full`
failure listed above.

## Reply capability

An inbound `request` owns a message with `reply_handle`. Reply with
`Node.reply(handle, outgoing)`. Retain the handle before freeing the message
if a worker will answer asynchronously; deinit that retained copy afterward.
This keeps the necessary correlation and routing metadata without retaining
the request body. Endpoint destruction invalidates the target safely. A final
reply completes the handle and further replies fail.

## Compatibility with direct-inbox integrations

`requestQuic(session_id, outgoing)` remains a compatibility adapter returning
the QUIC stream ID. `cancelQuicRequest` and `settleQuicRequest` address its
session/stream pair. Raw `queueReliable` sends remain untracked.

Direct inbox consumers must select `NodeOptions.delivery = .legacy`.
The node-level session wrapper's `recvReliable` settles a registered request
when it returns the reply. Consumers that bypass that wrapper must call
`settleQuicRequest` themselves. Do not drain the inbox in parallel with the
default canonical event consumer. The separate
`event_format = .legacy_transport` option restores `quic_reply` and
`quic_request_failed` names for consumers still using that event schema.
