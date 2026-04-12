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
                t.logErrorf("integration/net/udp_handshake_and_direct setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(&fixture, testing) catch |err| {
                t.logErrorf("integration/net/udp_handshake_and_direct failed: {}", .{err});
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
    const direct_protocol: u8 = 0x03;

    try fixture.establish();

    const client_info = fixture.client_udp.peerInfo(fixture.server_static.public) orelse return error.TestUnexpectedResult;
    const server_info = fixture.server_udp.peerInfo(fixture.client_static.public) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(net_pkg.core.Host.PeerState.established, client_info.state);
    try testing.expectEqual(net_pkg.core.Host.PeerState.established, server_info.state);

    const sent = try fixture.client_udp.writeDirect(fixture.server_static.public, direct_protocol, "ping");
    try testing.expect(sent == .sent);

    var buf: [32]u8 = undefined;
    const read = try fixture.waitForServerDirect(&buf, 32);
    try testing.expectEqual(direct_protocol, read.protocol_byte);
    try testing.expectEqualStrings("ping", buf[0..read.n]);
}
