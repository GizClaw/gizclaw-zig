# giznoise

`giznoise` is the current concrete Noise/UDP/KCP backend for the `giznet`
VTable/API surface.

It owns the implementation that used to live under `lib/giznet`:

- Noise handshake and transport sessions
- packet pools and packet ownership
- UDP runtime workers
- service mux
- KCP stream service

`giznoise` depends on `giznet` and implements `giznet.GizNet`,
`giznet.Conn`, and `giznet.Stream`. `giznet` does not depend on `giznoise`.

## Wiring

Application or context/config wiring constructs this backend and passes the
resulting `giznet.GizNet` handle to higher-level clients:

```text
Context -> Config -> GizNoise -> giznet.GizNet -> Client
```

The GizClaw client core operates on `giznet` VTables after construction.

## Testing

Run the backend unit and integration tests:

```sh
zig build test-unit-giznoise
zig build test-integration-giznoise
```

Run backend benchmarks when throughput data is needed:

```sh
zig build -Doptimize=ReleaseSafe test-benchmark-giznoise
```
