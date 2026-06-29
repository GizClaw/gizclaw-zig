const glib = @import("glib");
const testing_api = glib.testing;

const NoiseRunner = @import("integration/noise.zig");
const ServiceRunner = @import("integration/service.zig");
const GizNetRunner = @import("integration/giz_net.zig");
const HttpRunner = @import("integration/http.zig");
const ListenerRunner = @import("integration/listener.zig");
const PerfRunner = @import("integration/perf.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("noise", NoiseRunner.make(grt));
            t.run("service", ServiceRunner.make(grt));
            t.run("giz_net", GizNetRunner.make(grt));
            t.run("listener", ListenerRunner.make(grt));
            t.run("http", HttpRunner.make(grt));
            t.run("perf", PerfRunner.make(grt));
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
