const glib = @import("glib");
const testing_api = glib.testing;

const NoiseHandshake = @import("../noise/Handshake.zig");
const NoiseSession = @import("../noise/Session.zig");
const NoiseTimerState = @import("../noise/TimerState.zig");
const NoisePeer = @import("../noise/Peer.zig");
const NoisePeerTable = @import("../noise/PeerTable.zig");
const NoiseEngine = @import("../noise/Engine.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("noise/handshake", NoiseHandshake.TestRunner(grt));
            t.run("noise/session", NoiseSession.TestRunner(grt));
            t.run("noise/timer_state", NoiseTimerState.TestRunner(grt));
            t.run("noise/peer", NoisePeer.TestRunner(grt));
            t.run("noise/peer_table", NoisePeerTable.TestRunner(grt));
            t.run("noise/engine", NoiseEngine.TestRunner(grt));
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
