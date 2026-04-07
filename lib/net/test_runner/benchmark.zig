const dep = @import("dep");
const testing_api = dep.testing;

const NoiseRunner = @import("benchmark/noise.zig");
const CoreRunner = @import("benchmark/core.zig");
const KcpRunner = @import("benchmark/kcp.zig");
const PeerRunner = @import("benchmark/peer.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("noise", NoiseRunner.make(lib));
            t.run("core", CoreRunner.make(lib));
            t.run("kcp", KcpRunner.make(lib));
            t.run("peer", PeerRunner.make(lib));
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
