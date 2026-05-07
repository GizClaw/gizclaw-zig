const testing_api = @import("glib").testing;

const giznet = @import("../../../../giznet.zig");
const test_utils = @import("../../test_utils/giz_net.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const PairFixture = test_utils.DefaultFixture(grt, &[_]u32{ 3351, 3352 });

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            runRejectsUnsupportedScheme(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/unsupported_scheme rejects_https failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runRejectsUnsupportedScheme(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();
    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    var transport = giznet.HttpTransport.make(grt).init(allocator, pair.a, 26);
    defer transport.deinit();
    var client = try grt.net.http.Client.init(allocator, .{ .round_tripper = transport.roundTripper() });
    defer client.deinit();

    var resp = client.get("https://giznet.local/unsupported") catch |err| {
        try grt.std.testing.expectEqual(error.UnsupportedScheme, err);
        return;
    };
    defer resp.deinit();
    return error.TestUnexpectedResult;
}
