const glib = @import("glib");
const testing_api = glib.testing;

const HandshakeTransfer1MiBRunner = @import("noise/handshake_transfer_1MiB.zig");
const HandshakeTransfer20MiBRunner = @import("noise/handshake_transfer_20MiB.zig");
const HandshakeTransfer50KiBMultiplePeersRunner = @import("noise/handshake_transfer_50KiB_multiple_peers.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("handshake_transfer_1MiB", HandshakeTransfer1MiBRunner.make(grt));
            t.run("handshake_transfer_20MiB", HandshakeTransfer20MiBRunner.make(grt));
            t.run("handshake_transfer_50KiB_multiple_peers", HandshakeTransfer50KiBMultiplePeersRunner.make(grt));
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
