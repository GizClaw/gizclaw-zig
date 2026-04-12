const dep = @import("dep");
const testing_api = dep.testing;

const core = @import("../../../core.zig");
const peer = @import("../../../peer.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;
            runCases(lib, t) catch |err| {
                t.logErrorf("peer/package failed: {}", .{err});
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

fn runCases(comptime lib: type, t: *testing_api.T) !void {
    const Core = core.make(lib);
    const Peer = peer.make(Core);

    _ = t;
    _ = Peer.Conn;
    _ = Peer.Listener;
    _ = Peer.Stream;
}
