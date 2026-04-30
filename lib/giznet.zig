//! Package root for the `giznet` rewrite.

const glib = @import("glib");
const ConnFile = @import("giznet/Conn.zig");
const DialOptionsFile = @import("giznet/DialOptions.zig");
const GizNetFile = @import("giznet/GizNet.zig");
const noise_ns = @import("giznet/noise.zig");

pub const noise = noise_ns;
pub const GizNet = GizNetFile;
pub const Conn = ConnFile;
pub const DialOptions = DialOptionsFile;
pub const Key = noise_ns.Key;
pub const KeyPair = noise_ns.KeyPair;
pub const AddrPort = glib.net.netip.AddrPort;
pub fn eqlAddrPort(lhs: AddrPort, rhs: AddrPort) bool {
    return glib.std.meta.eql(lhs, rhs);
}
pub const test_runner = struct {
    pub const unit = @import("giznet/test_runner/unit.zig");
    pub const integration = struct {
        pub fn make(comptime grt: type) glib.testing.TestRunner {
            return @import("giznet/test_runner/integration.zig").make(grt);
        }
    };
    pub const benchmark = struct {
        pub fn make(comptime grt: type) glib.testing.TestRunner {
            return @import("giznet/test_runner/benchmark.zig").make(grt);
        }
    };
    pub const cork = @import("giznet/test_runner/cork.zig");
};

pub fn make(comptime grt: type) type {
    return struct {
        pub const GizNet = @import("giznet/GizNet.zig");
        pub const Conn = @import("giznet/Conn.zig");
        pub const DialOptions = @import("giznet/DialOptions.zig");
        pub const Key = noise_ns.Key;
        pub const KeyPair = noise_ns.KeyPair;
        pub const noise = noise_ns.make(grt, noise_ns.default_cipher_kind);
    };
}
