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
pub const test_runner = struct {
    pub const unit = @import("net/test_runner/unit.zig");
    pub const integration = @import("net/test_runner/integration.zig");
    pub const benchmark = @import("net/test_runner/benchmark.zig");
    pub const cork = @import("net/test_runner/cork.zig");
};

pub fn make(comptime lib: type) type {
    const Core = core_ns.make(lib);
    return struct {
        pub const noise = noise_ns.make(lib);
        pub const core = Core;
        pub const kcp = kcp_ns.make(core_ns);
        pub const peer = peer_ns.make(Core);
    };
}
