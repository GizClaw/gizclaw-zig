//! Package root for the `giznet` rewrite.

const embed = @import("embed");
const noise_ns = @import("giznet/noise.zig");

pub const noise = noise_ns;
pub const AddrPort = embed.net.netip.AddrPort;
pub fn eqlAddrPort(lhs: AddrPort, rhs: AddrPort) bool {
    return @import("embed").std.meta.eql(lhs, rhs);
}
pub const test_runner = struct {
    pub const unit = @import("giznet/test_runner/unit.zig");
    pub const integration = struct {
        pub fn make(comptime lib: type) embed.testing.TestRunner {
            return @import("giznet/test_runner/integration.zig").make(lib);
        }
    };
    pub const benchmark = struct {
        pub fn make(comptime lib: type) embed.testing.TestRunner {
            return @import("giznet/test_runner/benchmark.zig").make(lib);
        }
    };
    pub const cork = @import("giznet/test_runner/cork.zig");
};

pub fn make(comptime lib: type) type {
    return struct {
        pub const noise = noise_ns.make(lib, noise_ns.default_cipher_kind);
    };
}
