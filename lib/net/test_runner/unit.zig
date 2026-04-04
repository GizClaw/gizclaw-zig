const dep = @import("dep");
const testing_api = dep.testing;

const NoiseRunner = @import("unit/noise.zig");
const CoreRunner = @import("unit/core.zig");
const KcpRunner = @import("unit/kcp.zig");
const PeerRunner = @import("unit/peer.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("noise", NoiseRunner.runner(lib));
            t.run("core", CoreRunner.runner(lib));
            t.run("kcp", KcpRunner.runner(lib));
            t.run("peer", PeerRunner.runner(lib));
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
