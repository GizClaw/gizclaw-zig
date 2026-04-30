const embed = @import("embed");
const testing_api = embed.testing;

const NoiseHandshake = @import("../noise/Handshake.zig");
const NoiseSession = @import("../noise/Session.zig");
const NoiseTimerState = @import("../noise/TimerState.zig");
const NoisePeer = @import("../noise/Peer.zig");
const NoisePeerTable = @import("../noise/PeerTable.zig");
const NoiseEngine = @import("../noise/Engine.zig");

pub fn make(comptime std: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("noise/handshake", NoiseHandshake.testRunner(std));
            t.run("noise/session", NoiseSession.testRunner(std));
            t.run("noise/timer_state", NoiseTimerState.testRunner(std));
            t.run("noise/peer", NoisePeer.testRunner(std));
            t.run("noise/peer_table", NoisePeerTable.testRunner(std));
            t.run("noise/engine", NoiseEngine.TestRunner(std));
            return true;
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            std.testing.allocator.destroy(self);
        }
    };

    const value = std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
