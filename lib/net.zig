//! Package root for the `giztoy-zig` v2 networking rewrite.
//!
//! The implementation contract and package design live in `lib/net/AGENTS.md`.

pub const noise = @import("net/noise.zig");

test {
    _ = @This();
    _ = noise;
}
