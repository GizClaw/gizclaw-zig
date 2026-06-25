# GizClaw RPC E2E

`client/rpc` contains reusable RPC TestRunner entrypoints plus thin host CLI
wrappers. The default runner is intentionally a small smoke check; heavier API
domains are separate build steps so generated API instantiation does not make
the default e2e command slow.

## Steps

```sh
zig build run-gizclaw-e2e-rpc -- --connect-timeout-ms 5000
zig build run-gizclaw-e2e-rpc-server-run -- --connect-timeout-ms 5000
zig build run-gizclaw-e2e-rpc-resources -- --connect-timeout-ms 5000
```

All steps use the shared context and remote override flags from
`test/gizclaw-e2e/common.zig`.

## Coverage

- `run-gizclaw-e2e-rpc`
  - connect
  - ping
  - server info
  - server runtime
  - server status
- `run-gizclaw-e2e-rpc-server-run`
  - connect / ping
  - server run agent/status/workspace
  - workspace memory stats and recall
  - workspace select/reload
  - history list/play when fixtures exist
  - reload/stop gated by `--allow-mutations`
- `run-gizclaw-e2e-rpc-resources`
  - connect / ping
  - workspace list/get/history
  - workflow list/get
  - model list/get
  - credential list/get
  - voice list/get
  - firmware list/get

## Rules

- CLI files parse args and print reports only.
- TestRunner/domain files do not import `std` directly.
- Fixture-dependent paths must fail with a concrete missing-fixture error
  instead of silently disappearing or reporting a structured skip.
- Social/multi-peer checks remain out of the default RPC runner.
