const dep = @import("dep");
const testing_api = dep.testing;

const ConnRunner = @import("peer/Conn.zig");
const ListenerRunner = @import("peer/Listener.zig");
const package_runner = @import("peer/package.zig");
const opus_frame_runner = @import("peer/opus_frame.zig");
const prologue_runner = @import("peer/prologue.zig");

pub fn runner(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("prologue", prologue_runner.make(lib));
            t.run("opus_frame", opus_frame_runner.make(lib));
            t.run("Conn", ConnRunner.make(lib));
            t.run("Listener", ListenerRunner.make(lib));
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
