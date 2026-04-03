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
                t.logErrorf("noise/ReplayFilter failed: {}", .{err});
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
    const T = noise.ReplayFilter.make(lib);
    const window_size = noise.ReplayFilter.window_size;

    var rf = T.init();

    for (0..100) |i| {
        try testing.expect(rf.checkAndUpdate(i));
    }

    try testing.expect(!rf.checkAndUpdate(42));

    var out_of_order = T.init();
    const nonces = [_]u64{ 100, 50, 75, 25, 99, 1 };
    for (nonces) |nonce| {
        try testing.expect(out_of_order.checkAndUpdate(nonce));
    }
    for (nonces) |nonce| {
        try testing.expect(!out_of_order.checkAndUpdate(nonce));
    }

    var boundary = T.init();
    try testing.expect(boundary.checkAndUpdate(window_size + 100));
    try testing.expect(boundary.checkAndUpdate(101));
    try testing.expect(!boundary.checkAndUpdate(100));

    var jump = T.init();
    for (0..10) |i| _ = jump.checkAndUpdate(i);
    try testing.expect(jump.checkAndUpdate(10_000));
    for (0..10) |i| {
        try testing.expect(!jump.checkAndUpdate(i));
    }

    var reset_filter = T.init();
    for (0..100) |i| _ = reset_filter.checkAndUpdate(i);
    reset_filter.reset();
    for (0..100) |i| {
        try testing.expect(reset_filter.checkAndUpdate(i));
    }

    var split = T.init();
    try testing.expect(split.check(7));
    split.update(7);
    try testing.expectEqual(@as(u64, 7), split.maxNonce());
    try testing.expect(!split.check(7));

    var contested = T.init();
    var accepted = lib.atomic.Value(u32).init(0);
    const thread_count = 8;
    var threads: [thread_count]lib.Thread = undefined;
    for (0..thread_count) |i| {
        threads[i] = try lib.Thread.spawn(.{}, struct {
            fn run(filter: *T, ok_count: *lib.atomic.Value(u32)) void {
                if (filter.checkAndUpdate(777)) {
                    _ = ok_count.fetchAdd(1, .seq_cst);
                }
            }
        }.run, .{ &contested, &accepted });
    }
    for (0..thread_count) |i| threads[i].join();
    try testing.expectEqual(@as(u32, 1), accepted.load(.seq_cst));
    try testing.expectEqual(@as(u64, 777), contested.maxNonce());
}
