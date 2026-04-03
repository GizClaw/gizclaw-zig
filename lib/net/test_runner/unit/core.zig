const dep = @import("dep");
const testing_api = @import("dep").testing;

const UIntMapRunner = @import("core/UIntMap.zig");
const KeyMapRunner = @import("core/KeyMap.zig");
const protocol_runner = @import("core/protocol.zig");
const SessionManagerRunner = @import("core/SessionManager.zig");
const ServiceMuxRunner = @import("core/ServiceMux.zig");
const ConnRunner = @import("core/Conn.zig");
const DialerRunner = @import("core/Dialer.zig");
const ListenerRunner = @import("core/Listener.zig");
const HostRunner = @import("core/Host.zig");
const UDPRunner = @import("core/UDP.zig");
const package_runner = @import("core/package.zig");

pub fn runner(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("uint_map", UIntMapRunner.make(lib));
            t.run("key_map", KeyMapRunner.make(lib));
            t.run("protocol", protocol_runner.make(lib));
            t.run("session_manager", SessionManagerRunner.make(lib));
            t.run("service_mux", ServiceMuxRunner.make(lib));
            t.run("conn", ConnRunner.make(lib));
            t.run("dialer", DialerRunner.make(lib));
            t.run("listener", ListenerRunner.make(lib));
            t.run("host", HostRunner.make(lib));
            t.run("udp", UDPRunner.make(lib));
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
