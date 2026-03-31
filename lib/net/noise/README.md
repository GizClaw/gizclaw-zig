# `lib/net/noise`

`noise` is the lowest networking layer in `giztoy-zig`.

It owns transport-facing primitives and the cryptographic/session machinery that
higher layers build on top of.

## Scope

- address and transport abstractions
- handshake state
- session state
- cipher state and replay protection
- packet framing helpers such as message, varint, and address codecs

## Rules

- Implementation files in `lib/net/noise/` must not import `std`.
- External dependencies should come from `embed`.
- `noise` must not depend on `core`, `kcp`, `peer`, or `httptransport`.
- Keep file-as-struct style for main objects such as `Handshake`, `Session`, and `ReplayFilter`.

## Entry Points

- package entry: `lib/net/noise.zig`
- package test entry: `lib/net/noise_test.zig`
- test runners: `lib/net/test_runner/noise/`
- suite runner: `lib/net/test_runner/noise.zig`

## Testing

- Prefer one runner per implementation file.
- Keep runner names aligned with implementation names, such as `address.zig`, `cipher.zig`, and `handshake.zig`.
- Let `lib/net/noise_test.zig` assemble the suite instead of duplicating assertions inline.
- A package-level runner may exist to validate the public `lib/net/noise.zig`
  surface as a whole.

