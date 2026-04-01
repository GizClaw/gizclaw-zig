//! Package root for the `giztoy-zig` v2 networking rewrite.
//!
//! The implementation contract and package design live in `lib/net/AGENTS.md`.

const noise_ns = @import("noise");
const core_ns = @import("net/core.zig");
const kcp_ns = @import("net/kcp.zig");

pub const noise = noise_ns;
pub const core = core_ns;
pub const kcp = kcp_ns;

pub fn make(comptime lib: type) type {
    const Crypto = noise_ns.LibAdapter.make(lib);

    return struct {
        pub const noise = noise_ns.make(Crypto);
        pub const core = core_ns.make(Crypto);
        // KCP stays as the raw package until the core-facing adapter boundary exists.
        pub const kcp = kcp_ns;
    };
}

test {
    _ = @This();
    _ = noise;
    _ = core;
    _ = kcp;
}
