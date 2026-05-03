# giztoy-zig

[![CI](https://github.com/GizClaw/gizclaw-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/GizClaw/gizclaw-zig/actions/workflows/ci.yml)

[中文](README.zh-CN.md)

`giztoy-zig` provides Zig components for GizClaw, built on top of `embed-zig`
for MCU-class and other embedded environments.

The repository currently includes `giznet`, the embedded transport foundation
used by GizClaw components.

## Table Of Contents

- [Requirements](#requirements)
- [Build And Test](#build-and-test)
- [Layout](#layout)

## Requirements

- Zig `0.15.2` or newer

Dependencies are managed through `build.zig.zon`.

## Build And Test

Run all configured tests:

```sh
zig build test
```

Run focused test groups:

```sh
zig build test-unit
zig build test-integration
zig build test-benchmark
```

Run only `giznet` tests:

```sh
zig build test-unit-giznet
zig build test-integration-giznet
zig build -Doptimize=ReleaseSafe test-benchmark-giznet
```

## Layout

- `lib/giznet/README.md`: `giznet` architecture and test notes
