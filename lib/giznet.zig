//! Package root for the `giznet` rewrite.

const glib = @import("glib");
const noise_ns = @import("giznet/noise.zig");
const packet_ns = @import("giznet/packet.zig");
const runtime_ns = @import("giznet/runtime.zig");
const service_ns = @import("giznet/service.zig");

pub const noise = noise_ns;
pub const packet = packet_ns;
pub const runtime = runtime_ns;
pub const service = service_ns;
pub const GizNet = @import("giznet/GizNet.zig");
pub const Conn = @import("giznet/Conn.zig");
pub const Stream = @import("giznet/Stream.zig");
pub const DialOptions = @import("giznet/DialOptions.zig");
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
        pub const Stream = @import("giznet/Stream.zig");
        pub const DialOptions = @import("giznet/DialOptions.zig");
        pub const Key = noise_ns.Key;
        pub const KeyPair = noise_ns.KeyPair;
        pub const noise = noise_ns.make(grt, noise_ns.default_cipher_kind);
        pub const packet = packet_ns;
        pub const runtime = runtime_ns;
        pub const service = service_ns.make(grt);
    };
}
