const embed = @import("embed");
const testing_api = embed.testing;
const noise_testutils = @import("../../testutils/noise.zig");

pub fn make(comptime std: type) testing_api.TestRunner {
    const Cases = struct {
        fn chacha(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            _ = try noise_testutils.runSinglePeerTransfer(std, .chacha_poly, 20 * 1024 * 1024, std.math.maxInt(u64));
        }

        fn aes(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            _ = try noise_testutils.runSinglePeerTransfer(std, .aes_256_gcm, 20 * 1024 * 1024, std.math.maxInt(u64));
        }

        fn plaintext(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            _ = try noise_testutils.runSinglePeerTransfer(std, .plaintext, 20 * 1024 * 1024, std.math.maxInt(u64));
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("chacha_poly", testing_api.TestRunner.fromFn(std, 512 * 1024, Cases.chacha));
            t.run("aes_256_gcm", testing_api.TestRunner.fromFn(std, 512 * 1024, Cases.aes));
            t.run("plaintext", testing_api.TestRunner.fromFn(std, 512 * 1024, Cases.plaintext));
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
