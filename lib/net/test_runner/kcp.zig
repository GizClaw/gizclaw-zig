const embed = @import("embed");
const testing_api = @import("testing");

const frame_runner = @import("kcp/frame.zig");
const map_runner = @import("kcp/map.zig");
const conn_runner = @import("kcp/conn.zig");
const mux_runner = @import("kcp/mux.zig");
const package_runner = @import("kcp/package.zig");

pub fn runner(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("map", map_runner.make(lib));
            t.run("frame", frame_runner.make(lib));
            t.run("conn", conn_runner.make(lib));
            t.run("mux", mux_runner.make(lib));
            t.run("package", package_runner.make(lib));
            return true;
        }

        pub fn deinit(self: *@This(), allocator: embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
