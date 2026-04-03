const dep = @import("dep");
const testing_api = @import("dep").testing;
const Blake2s = @import("../../../noise.zig").Blake2s;

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;
            runCases(lib, lib.testing) catch |err| {
                t.logErrorf("noise/Blake2s failed: {}", .{err});
                return false;
            };
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

fn runCases(comptime lib: type, testing: anytype) !void {
    _ = lib;
    var out: [Blake2s.digest_length]u8 = undefined;

    Blake2s.hash("", &out, .{});
    const empty_hex = bytesToHex(&out);
    try testing.expectEqualStrings(
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        empty_hex[0..],
    );

    Blake2s.hash("abc", &out, .{});
    const abc_hex = bytesToHex(&out);
    try testing.expectEqualStrings(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        abc_hex[0..],
    );

    var hasher = Blake2s.init(.{});
    hasher.update("a");
    hasher.update("b");
    hasher.update("c");
    const final_hash = hasher.finalResult();
    const final_hex = bytesToHex(&final_hash);
    try testing.expectEqualStrings(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        final_hex[0..],
    );
}

fn bytesToHex(bytes: *const [Blake2s.digest_length]u8) [Blake2s.digest_length * 2]u8 {
    var out: [Blake2s.digest_length * 2]u8 = undefined;
    const chars = "0123456789abcdef";

    for (bytes.*, 0..) |byte, i| {
        out[i * 2] = chars[byte >> 4];
        out[i * 2 + 1] = chars[byte & 0x0f];
    }

    return out;
}
