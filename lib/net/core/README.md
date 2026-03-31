# `lib/net/core`

`core` is the routing and connection-management layer that sits on top of
`noise`.

It turns authenticated Noise packets into a stable boundary for the rest of the
network stack: connection lifecycle, dial/listen orchestration, peer tables,
session indexing, and per-service routing all live here.

## Scope

`core` owns:

- protocol constants and protocol-kind classification
- single-peer connection state and session rotation
- outbound dial retry and handshake timeout policy
- inbound listener acceptance and accepted-connection admission
- multi-peer host routing and peer lookup
- session lookup by receiver index and remote public key
- service routing for direct packets and stream protocols

`core` does not own:

- Noise handshake or cipher primitives
- KCP internals
- peer-level RPC or service naming policy
- HTTP adapters
- OS-specific transport code

## Public Entry Points

The public package root is `lib/net.zig`:

```zig
const net = @import("giztoy").make(lib);

const Core = net.core;
```

`lib/net/core.zig` is the lower-level package entry for code that already works
with a crypto-shaped dependency:

```zig
const core = @import("net/core.zig");
const Core = core.make(Crypto);
```

Package and test entry files:

- package entry: `lib/net/core.zig`
- package test entry: `lib/net/core_test.zig`
- suite runner: `lib/net/test_runner/core.zig`
- per-file runners: `lib/net/test_runner/core/`

## Public Surface

`lib/net/core.zig` exports:

- `Error`
- protocol constants: `ProtocolHTTP`, `ProtocolRPC`, `ProtocolEVENT`,
  `ProtocolOPUS`
- protocol helpers: `isFoundationProtocol()`, `isStreamProtocol()`,
  `isDirectProtocol()`
- timing and queue constants used by the package
- runtime types produced by `make(comptime Crypto: type)`:
  `Conn`, `Dial`, `Listener`, `SessionManager`, `ServiceMux`, and `Host`

## Foundation Protocols

| Name | Byte | Kind |
| --- | --- | --- |
| `ProtocolHTTP` | `0x80` | stream |
| `ProtocolRPC` | `0x81` | stream |
| `ProtocolEVENT` | `0x03` | direct packet |
| `ProtocolOPUS` | `0x10` | direct packet |

Important routing rules:

- HTTP and RPC are stream-only.
- EVENT and OPUS stay on the direct packet lane.
- Stream payloads are routed by `(service, protocol)` after a varint service
  prefix is decoded from the authenticated plaintext.
- Direct payloads stay on the default direct lane.

## Main Types

### `Conn`

Owns one peer's handshake integration, active session state, send/receive
lifecycle, keepalive, and rekey timing.

Use `Conn` when you already know which peer you are talking to and want the
lowest-level `core` state machine above `noise`.

### `Dial`

Wraps an initiator-side `Conn` and owns retry / timeout behavior for outbound
handshakes.

### `Listener`

Owns responder-side handshake acceptance and admission of accepted connections.

`Listener.receive()` only surfaces direct-packet payloads through
`ReceiveResult.payload`. Stream-class protocols are not returned through that
surface.

### `SessionManager`

Maintains O(1)-average lookup by local receiver index and by remote public key.
It is responsible for reserved-index handling, replacement, and expiry
bookkeeping.

### `ServiceMux`

Routes authenticated payloads by `(peer, service, protocol)`.

- Direct protocols use queue-based read surfaces.
- Stream protocols cross the stream-adapter boundary.
- Unknown or stopped stream services reject explicitly.

### `Host`

Owns multi-peer routing on top of `Conn` and `ServiceMux`.

- handshake packets are matched against known or allowed peers
- stream packets are routed into `ServiceMux`
- direct packets surface as `HostRoute.direct`

## Ownership And Concurrency

All main `core` runtime types are single-threaded today:

- `Conn`
- `Dial`
- `Listener`
- `SessionManager`
- `ServiceMux`
- `Host`

Callers must serialize access to each instance.

Buffer ownership is explicit:

- `HostRoute.direct.payload` aliases the caller-provided plaintext buffer
- `Listener.ReceiveResult.payload.payload` also aliases the caller-provided
  plaintext buffer
- do not retain those slices after the next receive/decrypt that reuses the
  same buffer

`Listener.sessionManager()` exposes session pointers that alias storage owned by
live accepted connections. Do not retain those session pointers after
`removeConn()` or `close()`.

## Choosing A Surface

Use `Conn` when:

- you manage one peer directly
- you want explicit send/recv/tick control

Use `Dial` and `Listener` when:

- you want separate initiator and responder orchestration
- you do not need a host-wide peer table

Use `Host` when:

- you want handshake routing, peer lookup, and direct-vs-stream dispatch in one
  place
- you want `ServiceMux` integrated per peer

## Testing

`core` is tested independently from higher peer layers.

Current tests cover:

- protocol classification and rejection behavior
- handshake integration and state transitions
- keepalive, rekey, and timeout behavior
- listener acceptance and queue saturation
- session replacement, collision, and expiry behavior
- host routing for handshake, direct packets, and stream packets
- service admission, bounded queues, and stopped-service control frames

Run the focused package suite with:

```sh
zig build test-core
```
