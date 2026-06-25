# giztoy-zig

`AGENTS.md` is a local work prompt file, not product documentation.
In this repository, only `README.md` files count as user-facing docs.

## Core Rules

- `lib/giznet` is the main product area in this repository.
- Non-test implementation code under `lib/giznet` must not import `std` directly.
- Prefer `embed` for runtime, memory, crypto, time, threading, formatting, and testing support.
- Use file-as-struct style for primary objects: prefer `const Conn = @import("Conn.zig");` over wrapper shapes such as `ConnFile.Conn`.
- Only `lib/giznet.zig` should aggregate package entry files such as `giznet/noise.zig`, `giznet/packet.zig`, `giznet/runtime.zig`, and `giznet/service.zig`.
- For comptime factories that return a type, do not use vague names such as `Package`.
- Allowed forms for type factories are:
  `TypeName(comptime ...) type`
  `TypeName.make(comptime ...) type`
  `namespace.make(comptime ...) type`
- For the public package root `lib/giznet.zig`, prefer `make(comptime grt: type) type`.
- Lower-level package entry files that only need runtime-shaped capabilities, such as `lib/giznet/noise.zig` or `lib/giznet/service.zig`, may use `make(comptime grt: type) type` or the narrower factory shape already used by the package.
- Future `giznet2/core` or transport-core work must be reconciled with the current `giznet` package layout before implementation; old issue text that mentions `lib/net` or `lib/giznet2` is not authoritative for paths.

## Testing Rules

- `lib`-side named test blocks are centralized in `lib/test.zig`.
- The current `lib/giznet` test entry names are `giznet/unit`, `giznet/integration`, `giznet/benchmark`, and `giznet/cork`.
- Put per-file unit runners under `lib/giznet/test_runner/unit/<package>/`.
- Put integration scenario runners under `lib/giznet/test_runner/integration/`, split by layer such as `integration/noise/`, `integration/service/`, `integration/http/`, or `integration/giz_net.zig`.
- Put benchmark runners under `lib/giznet/test_runner/benchmark/<package>/`.
- Keep the aggregate runner entry files at `lib/giznet/test_runner/unit.zig`, `lib/giznet/test_runner/integration.zig`, `lib/giznet/test_runner/benchmark.zig`, and `lib/giznet/test_runner/cork.zig`.
- Build wiring relies on the named-test filters `giznet/unit`, `giznet/integration`, `giznet/benchmark`, and `giznet/cork`.
- Focused build steps are type-qualified, for example `zig build test-unit-giznet`, `zig build test-integration-giznet`, `zig build test-benchmark-giznet`, and `zig build test-cork-giznet`.
- Keep tests deterministic and small; host-only behavior should stay in explicit test entry files instead of leaking into library code.

## Read Before Editing

- Read [`lib/giznet/noise/README.md`](lib/giznet/noise/README.md) before editing the `noise` package.
- Use the nearest local `AGENTS.md` as an implementation prompt for constraints, layering, and sequencing.

## Package Docs

- [`lib/giznet/README.md`](lib/giznet/README.md)
- [`lib/giznet/noise/README.md`](lib/giznet/noise/README.md)
