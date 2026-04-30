const embed = @import("embed");
const testing_api = embed.testing;

const HandshakeTransfer1MiBRunner = @import("noise/handshake_transfer_1MiB.zig");
const HandshakeTransfer20MiBRunner = @import("noise/handshake_transfer_20MiB.zig");
const HandshakeTransfer50KiBMultiplePeersRunner = @import("noise/handshake_transfer_50KiB_multiple_peers.zig");

pub fn make(comptime std: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("handshake_transfer_1MiB", HandshakeTransfer1MiBRunner.make(std));
            t.run("handshake_transfer_20MiB", HandshakeTransfer20MiBRunner.make(std));
            t.run("handshake_transfer_50KiB_multiple_peers", HandshakeTransfer50KiBMultiplePeersRunner.make(std));
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
