const dep = @import("dep");
const testing_api = dep.testing;
const net_pkg = @import("../../../../net.zig");

const RealUdpFixtureFile = @import("../test_utils/real_udp_fixture.zig");

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

            var fixture = Fixture.init(allocator, .{}) catch |err| {
                t.logErrorf("integration/net/udp_roaming_updates_endpoint setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(&fixture, lib, testing) catch |err| {
                t.logErrorf("integration/net/udp_roaming_updates_endpoint failed: {}", .{err});
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

fn runCase(fixture: anytype, comptime lib: type, testing: anytype) !void {
    try fixture.establish();
    const roamed_addr = try fixture.switchClientSocket();

    const sent = try fixture.client_udp.writeDirect(fixture.server_static.public, net_pkg.core.protocol.event, "roam");
    try testing.expect(sent == .sent);

    var buf: [32]u8 = undefined;
    const read = try fixture.waitForServerDirect(&buf, 32);
    try testing.expectEqual(net_pkg.core.protocol.event, read.protocol_byte);
    try testing.expectEqualStrings("roam", buf[0..read.n]);

    const updated = try fixture.waitForServerEndpoint(roamed_addr, 32);
    try testing.expectEqual(roamed_addr.len, updated.len);
    try testing.expect(lib.mem.eql(
        u8,
        roamed_addr.storage[0..@intCast(roamed_addr.len)],
        updated.storage[0..@intCast(updated.len)],
    ));
}
