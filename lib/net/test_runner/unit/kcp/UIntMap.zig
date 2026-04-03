const dep = @import("dep");
const testing_api = @import("dep").testing;
const UIntMap = @import("../../../kcp/UIntMap.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        fn makeCaseRunner(
            comptime label: []const u8,
            comptime run_case: *const fn (dep.embed.mem.Allocator) anyerror!void,
        ) testing_api.TestRunner {
            const CaseRunner = struct {
                pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
                    _ = self;
                    _ = allocator;
                }

                pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
                    _ = self;
                    run_case(allocator) catch |err| {
                        t.logErrorf("{s} failed: {}", .{ label, err });
                        return false;
                    };
                    return true;
                }

                pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
                    _ = allocator;
                    lib.testing.allocator.destroy(self);
                }
            };

            const value = lib.testing.allocator.create(CaseRunner) catch @panic("OOM");
            value.* = .{};
            return testing_api.TestRunner.make(CaseRunner).new(value);
        }

        fn runMapOperations(allocator: dep.embed.mem.Allocator) !void {
            const testing = lib.testing;

            var map_value = try UIntMap.make(u64, u64).init(allocator, 1);
            defer map_value.deinit();

            try testing.expectEqual(@as(usize, 0), map_value.count());
            try testing.expect(map_value.getPtr(1) == null);

            try testing.expect((try map_value.put(1, 10)) == null);
            try testing.expectEqual(@as(usize, 1), map_value.count());
            try testing.expectEqual(@as(u64, 10), map_value.getPtr(1).?.*);

            const replaced = try map_value.put(1, 11);
            try testing.expectEqual(@as(u64, 10), replaced.?);
            try testing.expectEqual(@as(u64, 11), map_value.getPtr(1).?.*);

            var i: u64 = 2;
            while (i < 40) : (i += 1) {
                _ = try map_value.put(i, i * 2);
            }
            try testing.expectEqual(@as(usize, 39), map_value.count());
            try testing.expectEqual(@as(u64, 78), map_value.getPtr(39).?.*);

            const removed = map_value.remove(1).?;
            try testing.expectEqual(@as(u64, 11), removed);
            try testing.expect(map_value.getPtr(1) == null);
        }

        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("operations", makeCaseRunner("kcp/UIntMap/operations", runMapOperations));
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
