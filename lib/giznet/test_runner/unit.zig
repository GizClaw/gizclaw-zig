const embed = @import("embed");
const std = embed.std;
const testing_api = embed.testing;

const NoiseHandshake = @import("../noise/Handshake.zig");
const NoiseSession = @import("../noise/Session.zig");
const NoiseTimerState = @import("../noise/TimerState.zig");
const NoisePeer = @import("../noise/Peer.zig");
const NoisePeerTable = @import("../noise/PeerTable.zig");
const NoiseEngine = @import("../noise/Engine.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("noise/handshake", NoiseHandshake.testRunner(lib));
            t.run("noise/session", NoiseSession.testRunner(lib));
            t.run("noise/timer_state", NoiseTimerState.testRunner(lib));
            t.run("noise/peer", NoisePeer.testRunner(lib));
            t.run("noise/peer_table", NoisePeerTable.testRunner(lib));
            t.run("noise/engine", NoiseEngine.TestRunner(lib));
            return true;
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
