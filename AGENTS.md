# giztoy-zig

`AGENTS.md` is a local work prompt file, not product documentation.
In this repository, only `README.md` files count as user-facing docs.

## Core Rules

- `lib/net` is the main product area in this repository.
- Non-test implementation code under `lib/net` must not import `std` directly.
- Prefer `embed` for runtime, memory, crypto, time, threading, formatting, and testing support.
- Use file-as-struct style for primary objects: prefer `const Conn = @import("conn.zig");` over wrapper shapes such as `ConnFile.Conn`.
- Only `lib/net.zig` should aggregate package entry files such as `net/noise.zig` or future `net/core.zig`.

## Testing Rules

- Put package test entry files at `lib/net/<package>_test.zig`.
- Put per-file runners under `lib/net/test_runner/<package>/`.
- Prefer one runner per implementation file, for example `lib/net/test_runner/noise/address.zig`.
- Keep tests deterministic and small; host-only behavior should stay in explicit test entry files instead of leaking into library code.

## Read Before Editing

- Read [`lib/net/noise/README.md`](lib/net/noise/README.md) before editing the `noise` package.
- Use the nearest local `AGENTS.md` as an implementation prompt for constraints, layering, and sequencing.

## Package Docs

- [`lib/net/noise/README.md`](lib/net/noise/README.md)
