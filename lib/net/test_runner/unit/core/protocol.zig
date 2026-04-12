const dep = @import("dep");
const testing_api = @import("dep").testing;
const protocol = @import("../../../core/protocol.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;
            runCases(lib.testing) catch |err| {
                t.logErrorf("core/protocol failed: {}", .{err});
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

fn runCases(testing: anytype) !void {
    try testing.expect(protocol.isFoundation(protocol.kcp));
    try testing.expect(!protocol.isFoundation(0x42));

    try testing.expect(protocol.isStream(protocol.kcp));
    try testing.expect(!protocol.isStream(0x03));
    try testing.expect(protocol.isDirect(0x03));
    try testing.expect(protocol.isDirect(0x10));
    try testing.expect(!protocol.isDirect(protocol.kcp));

    try testing.expectEqual(protocol.Kind.stream, try protocol.kind(protocol.kcp));
    try testing.expectEqual(protocol.Kind.direct, try protocol.kind(0x03));
    try protocol.validate(0xfe);
}
