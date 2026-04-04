//! Package root for the `giztoy-zig` v2 networking rewrite.
//!
//! The implementation contract and package design live in `lib/net/AGENTS.md`.

const noise_ns = @import("net/noise.zig");
const core_ns = @import("net/core.zig");
const kcp_ns = @import("net/kcp.zig");
const peer_ns = @import("net/peer.zig");

pub const noise = noise_ns;
pub const core = core_ns;
pub const kcp = kcp_ns;
pub const peer = peer_ns;

pub fn make(comptime lib: type) type {
    const Core = core_ns.make(lib);
    return struct {
        pub const noise = noise_ns.make(lib);
        pub const core = Core;
        pub const kcp = kcp_ns.make(core_ns);
        pub const peer = peer_ns.make(Core);
    };
}

test {
    _ = @This();
    _ = noise;
    _ = core;
    _ = kcp;
    _ = peer;
    _ = @import("net/test_runner/unit.zig");
}
