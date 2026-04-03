const dep = @import("dep");
const fmt = dep.embed.fmt;
const mem = dep.embed.mem;

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
