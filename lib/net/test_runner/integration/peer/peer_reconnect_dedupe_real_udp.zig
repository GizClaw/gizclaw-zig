const dep = @import("dep");
const net_pkg = @import("net");
const testing_api = dep.testing;

const core = net_pkg.core;
const PeerRealUdpFixtureFile = @import("peer_real_udp_fixture.zig");

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

            var fixture = Fixture.init(allocator, .{}) catch |err| {
                t.logErrorf("integration/net/peer_reconnect_dedupe_real_udp setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(&fixture, testing) catch |err| {
                t.logErrorf("integration/net/peer_reconnect_dedupe_real_udp failed: {}", .{err});
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
    try fixture.dialAndAccept();

    var retained_server_handle = try fixture.secondServerHandle();
    defer retained_server_handle.deinit();

    try (try fixture.serverConn()).close();

    var reconnect_handle = try fixture.reconnectClient();
    defer reconnect_handle.deinit();
    try testing.expect(reconnect_handle.publicKey().eql(fixture.base.server_static.public));

    try expectNoAccept(fixture, 64);
}

fn expectNoAccept(fixture: anytype, max_rounds: usize) !void {
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        _ = fixture.server_listener.accept() catch |err| {
            if (err == core.Error.QueueEmpty) {
                try fixture.drive(1);
                continue;
            }
            return err;
        };
        return error.TestUnexpectedResult;
    }
}
