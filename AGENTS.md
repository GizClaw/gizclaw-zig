# giztoy-zig

`AGENTS.md` is a local work prompt file, not product documentation.
In this repository, only `README.md` files count as user-facing docs.

## Core Rules

- `lib/net` is the main product area in this repository.
- Non-test implementation code under `lib/net` must not import `std` directly.
- Prefer `embed` for runtime, memory, crypto, time, threading, formatting, and testing support.
- Use file-as-struct style for primary objects: prefer `const Conn = @import("Conn.zig");` over wrapper shapes such as `ConnFile.Conn`.
- Only `lib/net.zig` should aggregate package entry files such as `net/noise.zig` or future `net/core.zig`.
- For comptime factories that return a type, do not use vague names such as `Package`.
- Allowed forms for type factories are:
  `TypeName(comptime ...) type`
  `TypeName.make(comptime ...) type`
  `namespace.make(comptime ...) type`
- For the public package root `lib/net.zig`, prefer `net.make(comptime lib: type) type`.
- Lower-level package entry files that only need crypto-shaped capabilities, such as `lib/net/noise.zig` or `lib/net/core.zig`, may use `make(comptime Crypto: type) type`.

## Testing Rules

- Unit package test entries currently live in `lib/net/noise.zig`, `lib/net/core.zig`, and `lib/net/kcp.zig`.
- The integration package test entry lives at `lib/integration.zig`.
- Put per-file unit runners under `lib/net/test_runner/unit/<package>/`.
- Put integration scenario runners under `lib/net/test_runner/integration/`.
- Keep the aggregate runner entry files at `lib/net/test_runner/unit.zig` and `lib/net/test_runner/integration.zig`.
- Keep tests deterministic and small; host-only behavior should stay in explicit test entry files instead of leaking into library code.

## Read Before Editing

- Read [`lib/net/noise/README.md`](lib/net/noise/README.md) before editing the `noise` package.
- Use the nearest local `AGENTS.md` as an implementation prompt for constraints, layering, and sequencing.

## Package Docs

- [`lib/net/noise/README.md`](lib/net/noise/README.md)
