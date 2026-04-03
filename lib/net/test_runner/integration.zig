const dep = @import("dep");
const testing_api = dep.testing;

const UdpHandshakeAndDirectRunner = @import("integration/udp_handshake_and_direct.zig");
const UdpRetryAfterDroppedInitRunner = @import("integration/udp_retry_after_dropped_init.zig");
const UdpKcpStreamOpenDataCloseRunner = @import("integration/udp_kcp_stream_open_data_close.zig");
const UdpRoamingUpdatesEndpointRunner = @import("integration/udp_roaming_updates_endpoint.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("udp_handshake_and_direct", UdpHandshakeAndDirectRunner.make(lib));
            t.run("udp_retry_after_dropped_init", UdpRetryAfterDroppedInitRunner.make(lib));
            t.run("udp_kcp_stream_open_data_close", UdpKcpStreamOpenDataCloseRunner.make(lib));
            t.run("udp_roaming_updates_endpoint", UdpRoamingUpdatesEndpointRunner.make(lib));
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
