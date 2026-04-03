const errors = @import("errors.zig");

const Self = @This();

pub const max_len: usize = 10;

pub fn encode(buf: []u8, value: u64) usize {
    var index: usize = 0;
    var current = value;

    while (current >= 0x80) {
        buf[index] = @intCast(current & 0x7f);
        buf[index] |= 0x80;
        current >>= 7;
        index += 1;
    }

    buf[index] = @intCast(current);
    return index + 1;
}

pub fn decode(buf: []const u8) errors.MessageError!struct { value: u64, n: usize } {
    var value: u64 = 0;

    for (buf, 0..) |byte, index| {
        if (index >= max_len) return errors.MessageError.InvalidVarint;
        value |= @as(u64, byte & 0x7f) << @intCast(index * 7);
        if ((byte & 0x80) == 0) {
            return .{ .value = value, .n = index + 1 };
        }
    }

    if (buf.len >= max_len) return errors.MessageError.InvalidVarint;
    return errors.MessageError.TooShort;
}

pub fn len(value: u64) usize {
    var n: usize = 1;
    var current = value;
    while (current >= 0x80) {
        current >>= 7;
        n += 1;
    }
    return n;
}
