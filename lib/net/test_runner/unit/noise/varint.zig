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
                t.logErrorf("noise/varint failed: {}", .{err});
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
    const Varint = noise.Varint;

    var buf: [Varint.max_len]u8 = undefined;
    const values = [_]u64{ 0, 1, 127, 128, 255, 300, 16_384, 1 << 32 };

    for (values) |value| {
        const written = Varint.encode(&buf, value);
        const decoded = try Varint.decode(buf[0..written]);
        try testing.expectEqual(value, decoded.value);
        try testing.expectEqual(written, decoded.n);
        try testing.expectEqual(written, Varint.len(value));
    }

    try testing.expectEqual(@as(usize, 1), Varint.encode(&buf, 0));
    try testing.expectEqualSlices(u8, &.{0x00}, buf[0..1]);

    try testing.expectEqual(@as(usize, 1), Varint.encode(&buf, 127));
    try testing.expectEqualSlices(u8, &.{0x7f}, buf[0..1]);

    try testing.expectEqual(@as(usize, 2), Varint.encode(&buf, 128));
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, buf[0..2]);

    try testing.expectEqual(@as(usize, 2), Varint.encode(&buf, 16_383));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0x7f }, buf[0..2]);

    try testing.expectEqual(@as(usize, 3), Varint.encode(&buf, 16_384));
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x80, 0x01 }, buf[0..3]);

    try testing.expectEqual(@as(usize, 10), Varint.encode(&buf, ~@as(u64, 0)));
    try testing.expectEqualSlices(
        u8,
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 },
        buf[0..10],
    );

    const trailing = try Varint.decode(&[_]u8{ 0x80, 0x01, 0xff, 0xff });
    try testing.expectEqual(@as(u64, 128), trailing.value);
    try testing.expectEqual(@as(usize, 2), trailing.n);

    try testing.expectError(noise.MessageError.TooShort, Varint.decode(&[_]u8{0x80}));
    try testing.expectError(noise.MessageError.InvalidVarint, Varint.decode(&[_]u8{ 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 }));
}
