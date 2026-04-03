const dep = @import("dep");
const testing_api = @import("dep").testing;

const frame_runner = @import("kcp/frame.zig");
const UIntMap_runner = @import("kcp/UIntMap.zig");
const Conn_runner = @import("kcp/Conn.zig");
const Mux_runner = @import("kcp/Mux.zig");
const Adapter_runner = @import("kcp/Adapter.zig");
const package_runner = @import("kcp/package.zig");

pub fn runner(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("UIntMap", UIntMap_runner.make(lib));
            t.run("frame", frame_runner.make(lib));
            t.run("Conn", Conn_runner.make(lib));
            t.run("Mux", Mux_runner.make(lib));
            t.run("Adapter", Adapter_runner.make(lib));
            t.run("package", package_runner.make(lib));
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
