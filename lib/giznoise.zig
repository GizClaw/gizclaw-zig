//! Concrete Noise/UDP/KCP backend for the giznet VTable/API.

const glib = @import("glib");

const noise_ns = @import("giznoise/noise.zig");
const packet_ns = @import("giznoise/packet.zig");
const runtime_ns = @import("giznoise/runtime.zig");
const service_ns = @import("giznoise/service.zig");

pub const noise = noise_ns;
pub const packet = packet_ns;
pub const runtime = runtime_ns;
pub const service = service_ns;
pub const GizNoise = @import("giznoise/GizNoise.zig");
pub const Key = @import("giznet").Key;
pub const KeyPair = @import("giznet").KeyPair;
pub const Cipher = noise_ns.Cipher;
pub const default_cipher_kind: Cipher.Kind = noise_ns.default_cipher_kind;
pub const min_packet_size_capacity: usize = noise_ns.min_packet_size_capacity;

pub const test_runner = struct {
    pub const unit = @import("giznoise/test_runner/unit.zig");
    pub const integration = struct {
        pub fn make(comptime grt: type) glib.testing.TestRunner {
            return @import("giznoise/test_runner/integration.zig").make(grt);
        }
    };
    pub const benchmark = struct {
        pub const service = @import("giznoise/test_runner/benchmark/service.zig");
        pub const kcp_stream = @import("giznoise/test_runner/benchmark/service/kcp_stream.zig");
        pub const kcp_stream_real_udp = @import("giznoise/test_runner/benchmark/service/kcp_stream_real_udp.zig");
        pub const noise = @import("giznoise/test_runner/benchmark/noise.zig");
        pub const giz_net = @import("giznoise/test_runner/benchmark/giz_net.zig");

        pub fn make(comptime grt: type) glib.testing.TestRunner {
            return @import("giznoise/test_runner/benchmark.zig").make(grt);
        }
    };
    pub const cork = @import("giznoise/test_runner/cork.zig");
};

pub fn make(comptime grt: type) type {
    return struct {
        pub const Key = @import("giznet").Key;
        pub const KeyPair = @import("giznet").KeyPair;
        pub const noise = noise_ns.make(grt, noise_ns.default_cipher_kind);
        pub const packet = packet_ns;
        pub const runtime = runtime_ns;
        pub const service = service_ns.make(grt);
        pub const GizNoise = @import("giznoise/GizNoise.zig");
    };
}
