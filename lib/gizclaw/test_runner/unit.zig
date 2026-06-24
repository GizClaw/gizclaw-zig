const glib = @import("glib");
const testing_api = glib.testing;

const ClientRunner = @import("unit/Client.zig");
const ContextRunner = @import("unit/Context.zig");
const KeyRunner = @import("unit/key.zig");
const RpcRunner = @import("unit/rpc.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("Client", ClientRunner.make(grt));
            t.run("Context", ContextRunner.make(grt));
            t.run("key", KeyRunner.make(grt));
            t.run("rpc", RpcRunner.make(grt));
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
