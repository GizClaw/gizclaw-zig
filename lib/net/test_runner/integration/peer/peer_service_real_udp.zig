const dep = @import("dep");
const testing_api = dep.testing;

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
                .allow_all_services = true,
            }) catch |err| {
                t.logErrorf("integration/net/peer_service_real_udp setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(&fixture, testing) catch |err| {
                t.logErrorf("integration/net/peer_service_real_udp failed: {}", .{err});
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
    const service_id: u64 = 23;

    try fixture.dialAndAccept();

    var client_stream = try (try fixture.clientConn()).openService(service_id);
    defer client_stream.deinit();
    var server_stream = try fixture.waitForAcceptedServerService(service_id, 256);
    defer server_stream.deinit();

    try testing.expectEqual(service_id, client_stream.service());
    try testing.expectEqual(service_id, server_stream.service());

    _ = try client_stream.write("hello");
    var buf: [64]u8 = undefined;
    const hello_n = try fixture.waitForStreamRead(server_stream, &buf, 256);
    try testing.expectEqualStrings("hello", buf[0..hello_n]);

    _ = try server_stream.write("world");
    const world_n = try fixture.waitForStreamRead(client_stream, &buf, 256);
    try testing.expectEqualStrings("world", buf[0..world_n]);
}
