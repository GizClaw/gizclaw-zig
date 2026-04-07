const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");
const testing_api = dep.testing;

const peer = net_pkg.peer;
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
                t.logErrorf("integration/net/peer_listener_event_opus_real_udp setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(&fixture, testing, allocator) catch |err| {
                t.logErrorf("integration/net/peer_listener_event_opus_real_udp failed: {}", .{err});
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

    try testing.expect((try fixture.clientConn()).publicKey().eql(fixture.base.server_static.public));
    try testing.expect((try fixture.serverConn()).publicKey().eql(fixture.base.client_static.public));

    const sent_event = peer.Event{
        .name = "ready",
        .data = "{\"role\":\"client\"}",
    };
    try (try fixture.clientConn()).sendEvent(allocator, sent_event);

    var received_event = try fixture.waitForServerEvent(allocator, 256);
    defer received_event.deinit(allocator);
    try testing.expectEqualStrings("ready", received_event.name);
    try testing.expectEqualStrings("{\"role\":\"client\"}", received_event.data.?);

    var sent_frame = try peer.stampOpusFrame(allocator, "pcm", 42);
    defer sent_frame.deinit(allocator);
    try (try fixture.clientConn()).sendOpusFrame(sent_frame);

    var received_frame = try fixture.waitForServerOpusFrame(allocator, 256);
    defer received_frame.deinit(allocator);
    try testing.expectEqual(@as(peer.EpochMillis, 42), received_frame.stamp());
    try testing.expectEqualStrings("pcm", received_frame.frame());
}
