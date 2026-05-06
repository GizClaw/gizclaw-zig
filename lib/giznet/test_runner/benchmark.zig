const glib = @import("glib");
const testing_api = glib.testing;

const GizNetRunner = @import("benchmark/giz_net.zig");
const NoiseRunner = @import("benchmark/noise.zig");
const ServiceRunner = @import("benchmark/service.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("giz_net", GizNetRunner.make(grt));
            t.run("noise", NoiseRunner.make(grt));
            t.run("service", ServiceRunner.make(grt));
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
