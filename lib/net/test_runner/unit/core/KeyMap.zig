const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");
const KeyMapFile = @import("../../../core/KeyMap.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib.testing, allocator) catch |err| {
                t.logErrorf("core/KeyMap failed: {}", .{err});
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

fn runCases(testing: anytype, allocator: dep.embed.mem.Allocator) !void {
    var keys = try KeyMapFile.make(u32).init(allocator, 2);
    defer keys.deinit();

    const key_a = noise.Key.fromBytes([_]u8{1} ** noise.Key.key_size);
    const key_b = noise.Key.fromBytes([_]u8{2} ** noise.Key.key_size);
    const key_c = noise.Key.fromBytes([_]u8{3} ** noise.Key.key_size);

    try testing.expectEqual(@as(?u32, null), try keys.put(key_a, 11));
    try testing.expectEqual(@as(?u32, null), try keys.put(key_b, 22));
    try testing.expectEqual(@as(?u32, null), try keys.put(key_c, 33));
    try testing.expectEqual(@as(u32, 22), keys.remove(key_b).?);
    try testing.expectEqual(@as(?u32, null), try keys.put(key_b, 44));
    try testing.expectEqual(@as(u32, 11), keys.get(key_a).?);
    try testing.expectEqual(@as(u32, 33), keys.get(key_c).?);
    try testing.expectEqual(@as(u32, 44), keys.get(key_b).?);
}
