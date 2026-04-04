const dep = @import("dep");
const testing_api = dep.testing;
const net_pkg = @import("net");

const RealUdpFixtureFile = @import("real_udp_fixture.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const testing = lib.testing;
    const Fixture = RealUdpFixtureFile.make(lib);

    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            var fixture = Fixture.init(allocator, .{
                .drop_first_client_write = true,
            }) catch |err| {
                t.logErrorf("integration/net/udp_retry_after_dropped_init setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(&fixture, testing) catch |err| {
                t.logErrorf("integration/net/udp_retry_after_dropped_init failed: {}", .{err});
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

fn runCase(fixture: anytype, testing: anytype) !void {
    try fixture.establish();

    const client_info = fixture.client_udp.peerInfo(fixture.server_static.public) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(net_pkg.core.Host.PeerState.established, client_info.state);
    try testing.expect(fixture.client_wrapper.write_count >= 2);
}
