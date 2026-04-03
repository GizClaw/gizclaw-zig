const dep = @import("dep");
const testing_api = @import("dep").testing;
const errors = @import("../../../core/errors.zig");
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
    try testing.expect(protocol.isFoundation(protocol.http));
    try testing.expect(protocol.isFoundation(protocol.rpc));
    try testing.expect(protocol.isFoundation(protocol.event));
    try testing.expect(protocol.isFoundation(protocol.opus));
    try testing.expect(!protocol.isFoundation(0x42));

    try testing.expect(protocol.isStream(protocol.http));
    try testing.expect(protocol.isStream(protocol.rpc));
    try testing.expect(!protocol.isStream(protocol.event));
    try testing.expect(protocol.isDirect(protocol.event));
    try testing.expect(protocol.isDirect(protocol.opus));
    try testing.expect(!protocol.isDirect(protocol.http));

    try testing.expectEqual(protocol.Kind.stream, try protocol.kind(protocol.http));
    try testing.expectEqual(protocol.Kind.direct, try protocol.kind(protocol.event));
    try testing.expectError(errors.Error.UnsupportedProtocol, protocol.kind(0xff));
    try testing.expectError(errors.Error.UnsupportedProtocol, protocol.validate(0xfe));
}
