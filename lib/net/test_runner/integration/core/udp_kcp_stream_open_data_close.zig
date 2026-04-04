const dep = @import("dep");
const testing_api = dep.testing;

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
                .enable_kcp = true,
            }) catch |err| {
                t.logErrorf("integration/net/udp_kcp_stream_open_data_close setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(Fixture, &fixture, testing) catch |err| {
                t.logErrorf("integration/net/udp_kcp_stream_open_data_close failed: {}", .{err});
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

fn runCase(comptime Fixture: type, fixture: anytype, testing: anytype) !void {
    try fixture.establish();

    const client_mux = fixture.client_udp.serviceMux(fixture.server_static.public) orelse return error.TestUnexpectedResult;
    const server_mux = fixture.server_udp.serviceMux(fixture.client_static.public) orelse return error.TestUnexpectedResult;

    // Accept the remote stream before driving KCP ticks. A queued inbound stream
    // is aborted if data arrives before the accept path drains it.
    const opened = try client_mux.openStream(Fixture.service_id);
    const accepted = fixture.waitForAcceptedServerStream(256) catch |err| switch (err) {
        error.TimedOut => return error.AcceptTimedOut,
        else => return err,
    };
    try testing.expectEqual(opened, accepted);

    _ = try fixture.client_udp.sendStreamData(fixture.server_static.public, Fixture.service_id, opened, "ping");
    var buf: [32]u8 = undefined;
    const ping_n = fixture.waitForServerStreamData(accepted, &buf, 256) catch |err| switch (err) {
        error.TimedOut => return error.ServerReadTimedOut,
        else => return err,
    };
    try testing.expectEqualStrings("ping", buf[0..ping_n]);

    _ = try fixture.server_udp.sendStreamData(fixture.client_static.public, Fixture.service_id, accepted, "pong");
    const pong_n = fixture.waitForClientStreamData(opened, &buf, 256) catch |err| switch (err) {
        error.TimedOut => return error.ClientReadTimedOut,
        else => return err,
    };
    try testing.expectEqualStrings("pong", buf[0..pong_n]);

    try fixture.client_udp.closeStream(fixture.server_static.public, Fixture.service_id, opened);
    try fixture.drive(24);
    try testing.expectEqual(@as(usize, 0), client_mux.numStreams());
    try testing.expectEqual(@as(usize, 0), server_mux.numStreams());
}
