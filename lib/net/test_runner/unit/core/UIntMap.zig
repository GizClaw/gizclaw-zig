const dep = @import("dep");
const testing_api = @import("dep").testing;
const UIntMapFile = @import("../../../core/UIntMap.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib.testing, allocator) catch |err| {
                t.logErrorf("core/UIntMap failed: {}", .{err});
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
    var ints = try UIntMapFile.make(u32, u32).init(allocator, 2);
    defer ints.deinit();

    try testing.expectEqual(@as(?u32, null), try ints.put(1, 10));
    try testing.expectEqual(@as(?u32, null), try ints.put(9, 90));
    try testing.expectEqual(@as(?u32, null), try ints.put(17, 170));
    try testing.expectEqual(@as(u32, 90), ints.get(9).?);
    try testing.expectEqual(@as(u32, 10), ints.remove(1).?);
    try testing.expectEqual(@as(?u32, null), try ints.put(25, 250));
    try testing.expectEqual(@as(u32, 250), ints.get(25).?);
}
