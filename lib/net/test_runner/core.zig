const embed = @import("embed");
const testing_api = @import("testing");

const map_runner = @import("core/map.zig");
const protocol_runner = @import("core/protocol.zig");
const session_manager_runner = @import("core/session_manager.zig");
const service_mux_runner = @import("core/service_mux.zig");
const conn_runner = @import("core/conn.zig");
const dial_runner = @import("core/dial.zig");
const listener_runner = @import("core/listener.zig");
const host_runner = @import("core/host.zig");
const package_runner = @import("core/package.zig");

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
            t.run("protocol", protocol_runner.make(lib));
            t.run("session_manager", session_manager_runner.make(lib));
            t.run("service_mux", service_mux_runner.make(lib));
            t.run("conn", conn_runner.make(lib));
            t.run("dial", dial_runner.make(lib));
            t.run("listener", listener_runner.make(lib));
            t.run("host", host_runner.make(lib));
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
