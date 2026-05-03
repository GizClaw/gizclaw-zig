# giznet

`giznet` is the current transport foundation of `giztoy-zig`. It provides a
Zig/embed-zig implementation of the encrypted peer connectivity layer that the
broader GizClaw platform can build on.

The package is intentionally split into small layers. Each layer owns a specific
part of the data flow so the transport can be tested in isolation and later
adapted to embedded runtimes.

## Public Shape

The public entry points are exposed from `lib/giznet.zig`:

- `GizNet`: erased root handle for a running backend.
- `Conn`: erased peer connection handle.
- `DialOptions`: peer dial options.
- `Key` and `KeyPair`: Noise static identity types.
- `AddrPort`: endpoint type from `glib`.

The erased handles are used so callers can depend on a stable surface while the
runtime implementation remains generic over `embed-zig` runtime capabilities.

## Layers

### `noise`

The `noise` layer handles peer identity, handshakes, transport sessions, packet
encryption/decryption, timers, and peer session state.

It is a single-threaded state machine driven by the runtime. It emits events
such as outbound packets, established peers, and decrypted inbound transport
payloads.

### `packet`

The `packet` layer owns inbound and outbound packet wrappers, packet pools, and
packet state transitions.

Packet pools are owned by the runtime layer. Lower layers receive borrowed pool
access where needed, but the runtime is responsible for global packet lifecycle.
The ownership contract is:

- On success, a callee consumes or transfers packet ownership.
- On error, the caller retains ownership and may clean up with `errdefer`.

This rule keeps error paths predictable and avoids double-returning pooled
packets.

### `service`

The `service` layer routes plaintext transport payloads above Noise. It parses
service framing, creates peer ports, and delivers direct packets to per-peer
channels.

Current service support is focused on direct packet delivery and connection
control. KCP stream support is still a planned area.

### `runtime`

The `runtime` layer wires everything together:

- UDP `PacketConn` read/write loops.
- Noise engine drive calls.
- Service engine drive calls.
- Accept and input channels.
- Error reporting.
- Packet pool ownership.
- Runtime close and join lifecycle.

`GizNet.up()` starts the drive, read, and timer workers. `close()` signals
shutdown, and `join()` waits for worker exit.

## Connection Flow

At a high level:

1. A caller creates a concrete `GizNet` backend with a UDP `PacketConn`.
2. `up()` starts runtime workers.
3. `dial()` sends an initiate-handshake command to the runtime.
4. The runtime drives Noise handshake state.
5. Once a peer is established, service state creates an accepted `Conn`.
6. `Conn.write(protocol, payload)` sends plaintext service payloads through the
   runtime and Noise transport.
7. `Conn.read()` returns the service protocol byte and payload length.

## Testing

Run all `giznet` unit tests:

```sh
zig build test-unit-giznet
```

Run `giznet` integration tests:

```sh
zig build test-integration-giznet
```

Run local benchmarks:

```sh
zig build -Doptimize=ReleaseSafe test-benchmark-giznet
```

CI currently runs unit tests and then integration tests for platforms whose unit
tests passed. Benchmarks are intentionally kept out of CI because UDP loopback
throughput and packet loss on hosted runners are noisy and not representative of
local or target-device behavior.

## Current Limits

- The integration tests use real UDP and strict data integrity checks; they are
  meant to validate correctness, not benchmark throughput.
- KCP stream service paths are not yet implemented in the new `giznet` stack.
- Runtime APIs and packet ownership internals are still being refined.
- Embedded target integration is a goal, but the current tests primarily run on
  host platforms.
