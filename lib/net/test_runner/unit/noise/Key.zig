const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");

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
                t.logErrorf("noise/Key failed: {}", .{err});
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
    const Key = noise.Key;

    try testing.expect(Key.zero.isZero());

    var non_zero = Key.zero;
    non_zero.data[0] = 1;
    try testing.expect(!non_zero.isZero());

    const hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const parsed = try Key.fromHex(hex);
    try testing.expectEqual(@as(u8, 0x01), parsed.data[0]);
    try testing.expectEqual(@as(u8, 0x20), parsed.data[31]);

    try testing.expectError(noise.KeyError.InvalidLength, Key.fromHex("xyz"));
    try testing.expectError(noise.KeyError.InvalidLength, Key.fromHex("0102"));
    try testing.expectError(noise.KeyError.InvalidLength, Key.fromSlice("short"));

    const lhs = Key.fromBytes([_]u8{1} ** Key.key_size);
    const rhs = Key.fromBytes([_]u8{1} ** Key.key_size);
    const other = Key.fromBytes([_]u8{2} ** Key.key_size);
    try testing.expect(lhs.eql(rhs));
    try testing.expect(!lhs.eql(other));
}
