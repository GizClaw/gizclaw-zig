const noise = @import("../noise.zig");

fn mix64(value: u64) u64 {
    var hash = value;
    hash ^= hash >> 33;
    hash *%= 0xff51afd7ed558ccd;
    hash ^= hash >> 33;
    hash *%= 0xc4ceb9fe1a85ec53;
    hash ^= hash >> 33;
    return hash;
}

pub fn nextCapacity(min_capacity: usize) usize {
    var capacity: usize = 8;
    while (capacity < min_capacity) : (capacity *= 2) {}
    return capacity;
}

pub fn bucketForInt(capacity: usize, value: anytype) usize {
    return @intCast(mix64(@as(u64, @intCast(value))) & @as(u64, @intCast(capacity - 1)));
}

pub fn bucketForKey(capacity: usize, key: noise.Key) usize {
    var hash: u64 = 0xcbf29ce484222325;
    for (key.asBytes()) |byte| {
        hash ^= byte;
        hash *%= 0x100000001b3;
    }
    return @intCast(mix64(hash) & @as(u64, @intCast(capacity - 1)));
}
