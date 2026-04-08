const dep = @import("dep");
const testing_api = dep.testing;

const RoutingLookupBaselineRunner = @import("core/routing_lookup_baseline.zig");
const DirectRealUdpBaselineRunner = @import("core/direct_real_udp_baseline.zig");
const RawPacketRealUdpBaselineRunner = @import("core/raw_packet_real_udp_baseline.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("routing_lookup_baseline", RoutingLookupBaselineRunner.make(lib));
            t.run("raw_packet_real_udp_baseline", RawPacketRealUdpBaselineRunner.make(lib));
            t.run("direct_real_udp_baseline", DirectRealUdpBaselineRunner.make(lib));
            return true;
        }

        pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
