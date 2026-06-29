# giznet

`giznet` is the transport-independent VTable/API boundary for GizClaw
connectivity.

It defines the stable handles that higher-level packages use:

- `GizNet`: erased root backend instance.
- `Conn`: erased peer connection.
- `Stream`: erased service stream.
- `DialOptions`: transport-independent peer dial options.
- `Key` and `KeyPair`: static identity types.
- `StreamConn`: adapter from `Stream` to `grt.net.Conn`.
- `HttpTransport`: HTTP-over-`Conn` utility.
- `NetPerfClient` and `NetPerfServer`: packet and stream perf helpers built
  only on `Conn` and `Stream`.

Concrete transports are implemented outside this package. The current
Noise/UDP/KCP backend lives in `giznoise`.

## Runtime Namespace

Use the runtime-bound namespace for public APIs that need runtime-shaped
adapters:

```zig
const giznet = @import("giznet").make(grt);
```

The namespace exposes the same transport-independent types plus generic
adapters such as `giznet.StreamConn` and `giznet.HttpTransport`.

## Dependency Boundary

`giznet` must not depend on concrete transport implementations.

Allowed here:

- erased VTable handles
- transport-independent public types
- generic adapters and utilities built only on the VTables

Not allowed here:

- Noise handshake/session implementation
- UDP runtime worker implementation
- service mux implementation
- KCP stream implementation
- concrete backend construction

## Testing

Run `giznet` API tests:

```sh
zig build test-unit-giznet
zig build test-integration-giznet
```

Concrete Noise backend tests live under `giznoise`:

```sh
zig build test-unit-giznoise
zig build test-integration-giznoise
```
