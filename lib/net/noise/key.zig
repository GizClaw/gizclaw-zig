const embed = @import("embed");
const fmt = embed.fmt;
const mem = embed.mem;

const errors = @import("errors.zig");

const Self = @This();

pub const key_size: usize = 32;
pub const zero: Self = .{ .data = [_]u8{0} ** key_size };

data: [key_size]u8 = [_]u8{0} ** key_size,

pub fn fromBytes(bytes: [key_size]u8) Self {
    return .{ .data = bytes };
}

pub fn fromSlice(slice: []const u8) errors.KeyError!Self {
    if (slice.len != key_size) return errors.KeyError.InvalidLength;

    var key = zero;
    @memcpy(key.data[0..], slice);
    return key;
}

pub fn fromHex(hex: []const u8) errors.KeyError!Self {
    if (hex.len != key_size * 2) return errors.KeyError.InvalidLength;

    var key = zero;
    _ = fmt.hexToBytes(&key.data, hex) catch return errors.KeyError.InvalidHex;
    return key;
}

pub fn asBytes(self: *const Self) *const [key_size]u8 {
    return &self.data;
}

pub fn isZero(self: Self) bool {
    return mem.eql(u8, self.data[0..], zero.data[0..]);
}

pub fn eql(self: Self, other: Self) bool {
    var diff: u8 = 0;
    for (self.data, other.data) |lhs, rhs| {
        diff |= lhs ^ rhs;
    }
    return diff == 0;
}

pub fn shortHex(self: Self) [8]u8 {
    var out: [8]u8 = undefined;
    const chars = "0123456789abcdef";

    for (self.data[0..4], 0..) |byte, i| {
        out[i * 2] = chars[byte >> 4];
        out[i * 2 + 1] = chars[byte & 0x0f];
    }

    return out;
}

pub fn format(
    self: Self,
    comptime _: []const u8,
    _: fmt.FormatOptions,
    writer: anytype,
) !void {
    for (self.data) |byte| {
        try writer.print("{x:0>2}", .{byte});
    }
}

pub fn testAll(testing: anytype) !void {
    try testing.expect(zero.isZero());

    var non_zero = zero;
    non_zero.data[0] = 1;
    try testing.expect(!non_zero.isZero());

    const hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const parsed = try fromHex(hex);
    try testing.expectEqual(@as(u8, 0x01), parsed.data[0]);
    try testing.expectEqual(@as(u8, 0x20), parsed.data[31]);

    try testing.expectError(errors.KeyError.InvalidLength, fromHex("xyz"));
    try testing.expectError(errors.KeyError.InvalidLength, fromHex("0102"));
    try testing.expectError(errors.KeyError.InvalidLength, fromSlice("short"));

    const lhs = fromBytes([_]u8{1} ** key_size);
    const rhs = fromBytes([_]u8{1} ** key_size);
    const other = fromBytes([_]u8{2} ** key_size);
    try testing.expect(lhs.eql(rhs));
    try testing.expect(!lhs.eql(other));
}
