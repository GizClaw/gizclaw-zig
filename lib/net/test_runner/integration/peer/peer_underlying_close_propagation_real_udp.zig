const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");
const testing_api = dep.testing;

const core = net_pkg.core;
const peer = net_pkg.peer;
const PeerRealUdpFixtureFile = @import("../test_utils/peer_real_udp_fixture.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const testing = lib.testing;
    const Fixture = PeerRealUdpFixtureFile.make(lib);

    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            var fixture = Fixture.init(allocator, .{
                .enable_kcp = true,
            }) catch |err| {
                t.logErrorf("integration/net/peer_underlying_close_propagation_real_udp setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(&fixture, testing, allocator) catch |err| {
                t.logErrorf("integration/net/peer_underlying_close_propagation_real_udp failed: {}", .{err});
                return false;
            };
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

fn runCase(fixture: anytype, testing: anytype, allocator: dep.embed.mem.Allocator) !void {
    try fixture.dialAndAccept();

    var second_client = try fixture.secondClientHandle();
    defer second_client.deinit();

    try fixture.closeClientUDP();

    try testing.expectError(core.Error.Closed, (try fixture.clientConn()).openRPC());
    try testing.expectError(core.Error.Closed, second_client.sendEvent(allocator, .{
        .name = "after-close",
    }));
    try (try fixture.clientConn()).close();
    try testing.expectError(peer.Error.ConnClosed, (try fixture.clientConn()).openRPC());
}
