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
with the same `lib` dependency bundle used by the public package root:

```zig
const core = @import("net/core.zig");
const Core = core.make(lib);
```

Package and test entry files:

- package entry: `lib/net/core.zig`
- package test entry: `lib/net/core.zig`
- suite runner: `lib/net/test_runner/unit/core.zig`
- per-file runners: `lib/net/test_runner/unit/core/`

## Public Surface

`lib/net/core.zig` exports:

- `Error`
- the `protocol` namespace, including `protocol.http`, `protocol.rpc`,
  `protocol.event`, `protocol.opus`, and `protocol.Kind`
- protocol helpers: `isFoundationProtocol()`, `isStreamProtocol()`,
  `isDirectProtocol()`
- timing and queue constants used by the package
- runtime types produced by `make(comptime lib: type)`:
  `Conn`, `Dialer`, `Listener`, `SessionManager`, `ServiceMux`, `Host`, and `UDP`
- `UDP` also exposes nested runtime helper types for observability and hooks:
  `UDP.HostInfo`, `UDP.PeerInfo`, `UDP.PeerEvent`, and `UDP.PeerEventHook`
- `UDP` exposes `serviceMux(remote_pk)` and an explicit `tick()` path for
  KCP-backed stream maintenance under the transport owner

## Foundation Protocols

| Name | Byte | Kind |
| --- | --- | --- |
| `protocol.http` | `0x80` | stream |
| `protocol.rpc` | `0x81` | stream |
| `protocol.event` | `0x03` | direct packet |
| `protocol.opus` | `0x10` | direct packet |

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

`Conn` is intentionally not the transport owner. It remains the immediate-wire
per-peer helper underneath `UDP`, not the place where pre-session runtime
buffering lives.

### `UDP`

Owns the real upstream `PacketConn` runtime boundary in Zig.

- stores peer endpoints
- drives packet intake from the owned `PacketConn`
- routes handshake / transport packets into `Host`, `Conn`, and `ServiceMux`
- provides the primary `connect()` / `accept()` story for real datagram use
- owns bounded pre-session pending-send queues per peer
- exposes explicit queued-vs-sent results for runtime write paths
- learns and overwrites peer endpoints only after handshake completion or
  authenticated transport decrypt, including stream-only roaming traffic
- exposes minimal runtime observability through `hostInfo()` / `peerInfo()`
- can emit synchronous peer-state callbacks for `connecting`, `established`, and
  `failed` through `Config.on_peer_event`
- finalizes each peer's `ServiceMux` output hook back into the encrypted send
  path, so KCP-backed stream adapters do not bypass `Host` / `Conn`
- exposes `serviceMux(remote_pk)` for peer-scoped stream access and `tick()` for
  explicit KCP time progression

`UDP` is the intended upper-layer entry point when you want a real datagram
runtime instead of caller-fed packet plumbing.

When a peer is not established yet, `UDP.writeDirect()` and
`UDP.writeStream()` may queue payloads inside the runtime and return
`UDP.SendResult.queued`. Once the peer becomes established through
`UDP.connect()` or the inbound accept path, `UDP` flushes those pending payloads
using the normal `Host.sendDirect()` / `Host.sendStream()` wire-build path.

`UDP.setPeerEndpoint()` remains the explicit seed/update API for caller-provided
endpoints, but runtime roaming can later overwrite that stored address when a
packet is authenticated from a new source.

Runtime-facing error notes:

- `UDP` now uses Go-like transport-owner sentinels for the main runtime paths:
  `Error.Closed`, `Error.NoEndpoint`, and `Error.HandshakeFailed`
- `Error.NoEndpoint` covers the transport-owner cases where a peer has no usable
  endpoint yet, including missing stored endpoint state or an explicit empty
  endpoint passed into `setPeerEndpoint()`
- object-local surfaces still keep narrower names such as `ConnClosed`,
  `ListenerClosed`, or service / queue-specific errors where those distinctions
  remain useful
- `UDP` still propagates other runtime-relevant outcomes where the boundary is
  genuinely broader than those three sentinels, such as `AcceptQueueEmpty`,
  `PeerNotFound`, `HandshakeIncomplete`, `error.TimedOut`, context
  deadline/cancel causes, selected `PacketConn` errors, and packet/decrypt
  failures surfaced from `Host`
- specifically, `UDP.connect()` normalizes a failed outbound handshake response
  into `Error.HandshakeFailed`, while handshake timeout remains the separate
  `Error.HandshakeTimeout`; lower-level packet-pump paths such as `pumpContext()`
  still surface the concrete packet/decrypt, I/O, or context error observed on
  that path instead of collapsing them into one transport-owner sentinel
- the older compatibility helper `Dialer.dialContext()` intentionally keeps the
  narrower `Error.MissingRemoteAddress` wording, while the real transport-owner
  `UDP` path uses `Error.NoEndpoint`
- Go's `ErrNoData` is intentionally not mirrored on a public `UDP` read API yet,
  because Zig does not currently expose a `ReadPacket()`-style output queue

### `Dialer`

Wraps an initiator-side `Conn` and owns retry / timeout behavior for outbound
handshakes.

`Dialer.dialContext()` can also drive a caller-owned upstream `PacketConn`
directly for the initial Noise IK exchange. That compatibility path now keeps
its handshake scratch buffers internal, but it still borrows the transport and
remote address bytes instead of becoming the long-lived socket owner for the
whole runtime. The preferred product path for real transport ownership is now
`UDP.connect()`.

### `Listener`

Owns responder-side handshake acceptance and admission of accepted connections.

`Listener.receive()` only surfaces direct-packet payloads through
`ReceiveResult.payload`. Stream-class protocols are not returned through that
surface.

`Listener` remains useful as a compatibility / injected-packet helper, but the
main transport-owning accept path now lives on `UDP`.

### `SessionManager`

Maintains O(1)-average lookup by local receiver index and by remote public key.
It is responsible for reserved-index handling, strict registration collision
checks, atomic replacement by remote public key, and expiry bookkeeping.

`SessionManager` now synchronizes its own index tables internally. Use
`withSessionBy*Locked()` / `forEachLocked()` or index/key snapshots when you
need concurrent-safe inspection. Those locked callbacks run under the manager's
shared lock and must not call back into write APIs such as `createSession()`,
`registerSession()`, `remove*()`, `clear()`, or `expire()`. The legacy
`getByIndex()` / `getByPublicKey()` lookups still return borrowed `*Session`
pointers for compatibility, but those pointers are not lifetime-pinning
handles.

### `ServiceMux`

Routes authenticated payloads by `(peer, service, protocol)`.

- Direct protocols use queue-based read surfaces.
- Stream protocols cross a per-peer stream-adapter boundary.
- The real KCP path now comes from `Config.stream_adapter_factory`, which builds
  one adapter per peer after `Host` fixes the peer-specific role and `UDP`
  fixes the output bridge back to encrypted transport writes.
- Stream traffic keeps separate open / accept / send / recv / close / tick
  surfaces instead of collapsing into the direct-packet queues.
- Unknown or stopped stream services reject explicitly.

### `Host`

Owns multi-peer routing on top of `Conn` and `ServiceMux`.

- handshake packets are matched against known or allowed peers
- stream packets are routed into `ServiceMux`
- direct packets surface as `Host.Route.direct`
- `handlePacketResult()` also reports the authenticated peer identity and any
  peer-state transition so `UDP` can update endpoint/runtime state without
  guessing from `Route.none`

`Host` is now the reusable routing core underneath `UDP`, not the recommended
top-level `PacketConn` owner for upper layers.

## Ownership And Concurrency

Most main `core` runtime types are still single-threaded today:

- `Conn`
- `Dialer`
- `Listener`
- `ServiceMux`
- `Host`
- `UDP`

Callers must serialize access to those instances.

`SessionManager` is the exception:

- its index tables are internally synchronized
- `count()`, snapshots, and `withSessionBy*Locked()` / `forEachLocked()` are
  safe under concurrent access when those callbacks stay short and non-reentrant
- `startExpiryWorker()` / `stopExpiryWorker()` provide an explicit background
  expiry path
- `get*()` still returns borrowed session pointers, so concurrent table safety
  does not make those pointers GC-like or safe to retain after removal

Buffer ownership is explicit:

- `Host.Route.direct.payload` aliases the caller-provided plaintext buffer
- `Listener.ReceiveResult.payload.payload` also aliases the caller-provided
  plaintext buffer
- `Dialer.dialContext()` borrows the caller-owned `PacketConn` and remote address
  bytes only for the duration of the dial attempt
- `UDP` owns reusable read / plaintext / ciphertext / wire buffers allocated at
  initialization time
- `UDP` also owns any queued pre-session payload bytes until they are flushed,
  dropped on failure, or released during close/deinit
- `UDP.peerInfo()` returns copied endpoint bytes and counters, not aliases into
  mutable runtime storage
- do not retain those slices after the next receive/decrypt that reuses the
  same buffer

`Listener.sessionManager()` exposes a read-mostly synchronized manager, but any
`Session` pointers you fetch from it still alias storage owned by live accepted
connections. Do not retain those session pointers after `removeConn()` or
`close()`.

## Choosing A Surface

Use `Conn` when:

- you manage one peer directly
- you want explicit send/recv/tick control

Use `UDP` when:

- you want the primary transport-owning `PacketConn` runtime
- you do not want to manually feed packet bytes into `core`
- you want one coherent `connect()` / `accept()` boundary
- you want Go-like pre-session buffering at the runtime layer instead of in bare
  `Conn`

Use `Dialer` and `Listener` when:

- you want compatibility helpers around a caller-owned or injected transport
- you do not want `UDP` to own the packet loop

Use `Host` when:

- you are building lower-level routing glue under `UDP`
- you want the reusable peer/session/service routing logic without making `Host`
  itself the transport owner

## Testing

`core` is tested independently from higher peer layers.

Current tests cover:

- protocol classification and rejection behavior
- handshake integration and state transitions
- keepalive, rekey, and timeout behavior
- listener acceptance and queue saturation
- session replacement, strict collision, concurrent read access, and expiry
  worker behavior
- host routing for handshake, direct packets, and stream packets
- UDP-owned dial / accept / retry behavior over fake `PacketConn` links
- authenticated handshake-response and stream-only roaming updates on `UDP`
- `UDP` runtime snapshots and synchronous peer-state events
- service admission, bounded queues, and stopped-service control frames

Run the focused package suite with:

```sh
zig build test-net
```
