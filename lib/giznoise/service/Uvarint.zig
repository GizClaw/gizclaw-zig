const Uvarint = @This();

value: u64,
len: usize,

pub fn write(value: u64, out: []u8) !usize {
    var x = value;
    var index: usize = 0;
    while (x >= 0x80) {
        if (index >= out.len) return error.BufferTooSmall;
        out[index] = @intCast((x & 0x7f) | 0x80);
        x >>= 7;
        index += 1;
    }
    if (index >= out.len) return error.BufferTooSmall;
    out[index] = @intCast(x);
    return index + 1;
}

pub fn read(data: []const u8) !Uvarint {
    var value: u64 = 0;
    var shift: usize = 0;
    for (data, 0..) |byte, index| {
        if (index > 9) return error.InvalidUvarint;
        if (index == 9 and byte >= 0x80) return error.InvalidUvarint;

        if (byte < 0x80) {
            if (index == 9 and byte > 1) return error.InvalidUvarint;
            value |= @as(u64, byte) << @as(u6, @intCast(shift));
            return .{
                .value = value,
                .len = index + 1,
            };
        }

        value |= @as(u64, byte & 0x7f) << @as(u6, @intCast(shift));
        shift += 7;
    }
    return error.InvalidUvarint;
}

pub fn TestRunner(comptime grt: type) @import("glib").testing.TestRunner {
    const glib = @import("glib");
    const testing_api = glib.testing;

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase() catch |err| {
                t.logErrorf("giznet/service Uvarint unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryCase() !void {
            var buf: [10]u8 = undefined;

            const one_len = try Uvarint.write(1, buf[0..]);
            try grt.std.testing.expectEqual(@as(usize, 1), one_len);
            const one = try Uvarint.read(buf[0..one_len]);
            try grt.std.testing.expectEqual(@as(u64, 1), one.value);
            try grt.std.testing.expectEqual(one_len, one.len);

            const max_len = try Uvarint.write(grt.std.math.maxInt(u64), buf[0..]);
            try grt.std.testing.expectEqual(@as(usize, 10), max_len);
            const max = try Uvarint.read(buf[0..max_len]);
            try grt.std.testing.expectEqual(grt.std.math.maxInt(u64), max.value);
            try grt.std.testing.expectEqual(max_len, max.len);

            try grt.std.testing.expectError(error.BufferTooSmall, Uvarint.write(128, buf[0..1]));
            try grt.std.testing.expectError(error.InvalidUvarint, Uvarint.read(&[_]u8{0x80}));
            try grt.std.testing.expectError(error.InvalidUvarint, Uvarint.read(&[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02 }));
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
