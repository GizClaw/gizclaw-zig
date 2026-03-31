const embed = @import("embed");
const mem = embed.mem;

const Self = @This();

const RoundParam = struct {
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: usize,
    y: usize,
};

pub const digest_length: usize = 32;
pub const block_length: usize = 64;
pub const Options = struct {};

const iv = [8]u32{
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
};

const sigma = [10][16]u8{
    [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    [_]u8{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    [_]u8{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    [_]u8{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    [_]u8{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    [_]u8{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    [_]u8{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    [_]u8{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    [_]u8{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    [_]u8{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

h: [8]u32 = iv,
t: u64 = 0,
buf: [block_length]u8 = [_]u8{0} ** block_length,
buf_len: u8 = 0,

pub fn init(_: Options) Self {
    var out: Self = .{};
    out.h = iv;
    out.h[0] ^= 0x01010000 ^ digest_length;
    return out;
}

pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
    var hasher = Self.init(options);
    hasher.update(data);
    hasher.final(out);
}

pub fn update(self: *Self, data: []const u8) void {
    var offset: usize = 0;

    if (self.buf_len != 0 and self.buf_len + data.len > block_length) {
        offset += block_length - self.buf_len;
        @memcpy(self.buf[self.buf_len..][0..offset], data[0..offset]);
        self.t += block_length;
        self.round(self.buf[0..block_length], false);
        self.buf_len = 0;
    }

    while (offset + block_length < data.len) : (offset += block_length) {
        self.t += block_length;
        self.round(data[offset..][0..block_length], false);
    }

    const remainder = data[offset..];
    @memcpy(self.buf[self.buf_len..][0..remainder.len], remainder);
    self.buf_len += @intCast(remainder.len);
}

pub fn final(self: *Self, out: *[digest_length]u8) void {
    @memset(self.buf[self.buf_len..], 0);
    self.t += self.buf_len;
    self.round(self.buf[0..block_length], true);

    for (&self.h) |*word| {
        word.* = mem.nativeToLittle(u32, word.*);
    }

    out.* = @as(*[digest_length]u8, @ptrCast(&self.h)).*;
}

pub fn finalResult(self: *Self) [digest_length]u8 {
    var out: [digest_length]u8 = undefined;
    self.final(&out);
    return out;
}

pub fn peek(self: Self) [digest_length]u8 {
    var clone = self;
    return clone.finalResult();
}

fn round(self: *Self, block: []const u8, last: bool) void {
    var m: [16]u32 = undefined;
    var v: [16]u32 = undefined;

    for (&m, 0..) |*word, i| {
        word.* = mem.readInt(u32, block[i * 4 ..][0..4], .little);
    }

    for (0..8) |i| {
        v[i] = self.h[i];
        v[i + 8] = iv[i];
    }

    v[12] ^= @truncate(self.t);
    v[13] ^= @intCast(self.t >> 32);
    if (last) v[14] = ~v[14];

    const rounds = [_]RoundParam{
        .{ .a = 0, .b = 4, .c = 8, .d = 12, .x = 0, .y = 1 },
        .{ .a = 1, .b = 5, .c = 9, .d = 13, .x = 2, .y = 3 },
        .{ .a = 2, .b = 6, .c = 10, .d = 14, .x = 4, .y = 5 },
        .{ .a = 3, .b = 7, .c = 11, .d = 15, .x = 6, .y = 7 },
        .{ .a = 0, .b = 5, .c = 10, .d = 15, .x = 8, .y = 9 },
        .{ .a = 1, .b = 6, .c = 11, .d = 12, .x = 10, .y = 11 },
        .{ .a = 2, .b = 7, .c = 8, .d = 13, .x = 12, .y = 13 },
        .{ .a = 3, .b = 4, .c = 9, .d = 14, .x = 14, .y = 15 },
    };

    inline for (0..10) |round_index| {
        inline for (rounds) |r| {
            v[r.a] = v[r.a] +% v[r.b] +% m[sigma[round_index][r.x]];
            v[r.d] = rotr(v[r.d] ^ v[r.a], 16);
            v[r.c] = v[r.c] +% v[r.d];
            v[r.b] = rotr(v[r.b] ^ v[r.c], 12);
            v[r.a] = v[r.a] +% v[r.b] +% m[sigma[round_index][r.y]];
            v[r.d] = rotr(v[r.d] ^ v[r.a], 8);
            v[r.c] = v[r.c] +% v[r.d];
            v[r.b] = rotr(v[r.b] ^ v[r.c], 7);
        }
    }

    for (&self.h, 0..) |*word, i| {
        word.* ^= v[i] ^ v[i + 8];
    }
}

pub fn testAll(testing: anytype) !void {
    var out: [digest_length]u8 = undefined;

    hash("", &out, .{});
    const empty_hex = bytesToHex(&out);
    try testing.expectEqualStrings(
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        empty_hex[0..],
    );

    hash("abc", &out, .{});
    const abc_hex = bytesToHex(&out);
    try testing.expectEqualStrings(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        abc_hex[0..],
    );

    var hasher = Self.init(.{});
    hasher.update("a");
    hasher.update("b");
    hasher.update("c");
    const final_hash = hasher.finalResult();
    const final_hex = bytesToHex(&final_hash);
    try testing.expectEqualStrings(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        final_hex[0..],
    );
}

fn bytesToHex(bytes: *const [digest_length]u8) [digest_length * 2]u8 {
    var out: [digest_length * 2]u8 = undefined;
    const chars = "0123456789abcdef";

    for (bytes.*, 0..) |byte, i| {
        out[i * 2] = chars[byte >> 4];
        out[i * 2 + 1] = chars[byte & 0x0f];
    }

    return out;
}

fn rotr(value: u32, shift: u5) u32 {
    return (value >> shift) | (value << @truncate(32 - @as(u6, shift)));
}
