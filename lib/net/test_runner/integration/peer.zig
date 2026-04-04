const dep = @import("dep");
const testing_api = dep.testing;

const PeerListenerEventOpusRealUdpRunner = @import("peer/peer_listener_event_opus_real_udp.zig");
const PeerRpcRoundTripRealUdpRunner = @import("peer/peer_rpc_round_trip_real_udp.zig");
const PeerServiceRealUdpRunner = @import("peer/peer_service_real_udp.zig");
const PeerConnCloseHandleLocalRealUdpRunner = @import("peer/peer_conn_close_handle_local_real_udp.zig");
const PeerUnderlyingClosePropagationRealUdpRunner = @import("peer/peer_underlying_close_propagation_real_udp.zig");
const PeerReconnectDedupeRealUdpRunner = @import("peer/peer_reconnect_dedupe_real_udp.zig");
const PeerMultipleConcurrentConnectionsRealUdpRunner = @import("peer/peer_multiple_concurrent_connections_real_udp.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("listener_event_opus_real_udp", PeerListenerEventOpusRealUdpRunner.make(lib));
            t.run("rpc_round_trip_real_udp", PeerRpcRoundTripRealUdpRunner.make(lib));
            t.run("service_real_udp", PeerServiceRealUdpRunner.make(lib));
            t.run("conn_close_handle_local_real_udp", PeerConnCloseHandleLocalRealUdpRunner.make(lib));
            t.run("underlying_close_propagation_real_udp", PeerUnderlyingClosePropagationRealUdpRunner.make(lib));
            t.run("reconnect_dedupe_real_udp", PeerReconnectDedupeRealUdpRunner.make(lib));
            t.run("multiple_concurrent_connections_real_udp", PeerMultipleConcurrentConnectionsRealUdpRunner.make(lib));
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
