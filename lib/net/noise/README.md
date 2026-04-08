# `lib/net/noise`

`noise` is the lowest networking layer in `giztoy-zig`.

It owns datagram-boundary message, handshake, and cryptographic/session
machinery that higher layers build on top of.

## Scope

- message framing and packet-boundary validation
- handshake state
- session state
- cipher state and replay protection
- packet framing helpers such as `message`, `varint`, and `TransportMessage`
- integration against the upstream `embed` `lib.net` / `PacketConn` datagram
  contract, not a local `Addr` / `Transport` abstraction

## Rules

- Implementation files in `lib/net/noise/` must not import `std`.
- External dependencies should come from `embed`.
- `noise` must not depend on `core`, `kcp`, `peer`, or `http_transport`.
- Keep file-as-struct style for main objects such as `Handshake`, `Session`, and `ReplayFilter`.

## Entry Points

- package entry: `lib/net/noise.zig`
- package tests: `lib/net/noise.zig`
- test runners: `lib/net/test_runner/unit/noise/`
- suite runner: `lib/net/test_runner/unit/noise.zig`

## Testing

- Prefer one runner per implementation file.
- Keep runner names aligned with implementation names, such as `Blake2s.zig`,
  `Handshake.zig`, and `Session.zig`.
- Let `lib/net/noise.zig` assemble the suite instead of duplicating assertions inline.
- A package-level runner may exist to validate the public `lib/net/noise.zig`
  surface as a whole.

