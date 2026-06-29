const glib = @import("glib");
const testing_api = glib.testing;
const noise_test_utils = @import("../../test_utils/noise.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Cases = struct {
        fn chacha(_: *testing_api.T, allocator: grt.std.mem.Allocator) !void {
            _ = allocator;
            _ = try noise_test_utils.runMultiPeerBidirectionalRekey(grt, .chacha_poly, 50, 50 * 1024, 32);
        }

        fn aes(_: *testing_api.T, allocator: grt.std.mem.Allocator) !void {
            _ = allocator;
            _ = try noise_test_utils.runMultiPeerBidirectionalRekey(grt, .aes_256_gcm, 50, 50 * 1024, 32);
        }

        fn plaintext(_: *testing_api.T, allocator: grt.std.mem.Allocator) !void {
            _ = allocator;
            _ = try noise_test_utils.runMultiPeerBidirectionalRekey(grt, .plaintext, 50, 50 * 1024, 32);
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("chacha_poly", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.chacha));
            t.run("aes_256_gcm", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.aes));
            t.run("plaintext", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.plaintext));
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
