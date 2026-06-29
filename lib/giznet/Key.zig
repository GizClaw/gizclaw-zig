const glib = @import("glib");

const Key = @This();

bytes: [32]u8 = [_]u8{0} ** 32,

pub const zero = Key{};

pub fn eql(self: Key, other: Key) bool {
    return glib.std.mem.eql(u8, &self.bytes, &other.bytes);
}
