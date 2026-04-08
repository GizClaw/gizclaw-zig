const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");
const testing_api = dep.testing;

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
                t.logErrorf("integration/net/peer_conn_close_handle_local_real_udp setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(&fixture, testing, allocator) catch |err| {
                t.logErrorf("integration/net/peer_conn_close_handle_local_real_udp failed: {}", .{err});
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

    var client_stream = try (try fixture.clientConn()).openRPC();
    defer client_stream.deinit();
    var server_stream = try fixture.waitForAcceptedServerRPC(256);
    defer server_stream.deinit();

    _ = try client_stream.write("before-close");
    var buf: [128]u8 = undefined;
    const before_n = try fixture.waitForStreamRead(server_stream, &buf, 256);
    try testing.expectEqualStrings("before-close", buf[0..before_n]);

    try (try fixture.clientConn()).close();
    try testing.expectError(peer.Error.ConnClosed, (try fixture.clientConn()).openRPC());

    try second_client.sendEvent(allocator, .{
        .name = "still-alive",
        .data = "{\"after\":\"conn-close\"}",
    });

    var received_event = try fixture.waitForServerEvent(allocator, 256);
    defer received_event.deinit(allocator);
    try testing.expectEqualStrings("still-alive", received_event.name);
    try testing.expectEqualStrings("{\"after\":\"conn-close\"}", received_event.data.?);

    _ = try server_stream.write("stream-still-open");
    const after_n = try fixture.waitForStreamRead(client_stream, &buf, 256);
    try testing.expectEqualStrings("stream-still-open", buf[0..after_n]);
}
