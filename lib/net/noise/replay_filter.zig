const embed = @import("embed");
const mem = embed.mem;

const Self = @This();

pub const window_size: usize = 2048;
const window_words: usize = window_size / 64;

bitmap: [window_words]u64 = [_]u64{0} ** window_words,
max_nonce: u64 = 0,

pub fn init() Self {
    return .{};
}

pub fn check(self: *const Self, nonce: u64) bool {
    if (nonce > self.max_nonce) return true;

    const delta = self.max_nonce - nonce;
    if (delta >= window_size) return false;

    const word_index: usize = @intCast(delta / 64);
    const bit_index: u6 = @intCast(delta % 64);
    return (self.bitmap[word_index] & (@as(u64, 1) << bit_index)) == 0;
}

pub fn update(self: *Self, nonce: u64) void {
    if (nonce > self.max_nonce) {
        const shift = nonce - self.max_nonce;
        self.slideWindow(shift);
        self.max_nonce = nonce;
        self.bitmap[0] |= 1;
        return;
    }

    const delta = self.max_nonce - nonce;
    if (delta < window_size) {
        const word_index: usize = @intCast(delta / 64);
        const bit_index: u6 = @intCast(delta % 64);
        self.bitmap[word_index] |= @as(u64, 1) << bit_index;
    }
}

pub fn checkAndUpdate(self: *Self, nonce: u64) bool {
    if (!self.check(nonce)) return false;
    self.update(nonce);
    return true;
}

pub fn reset(self: *Self) void {
    self.bitmap = [_]u64{0} ** window_words;
    self.max_nonce = 0;
}

pub fn maxNonce(self: *const Self) u64 {
    return self.max_nonce;
}

fn slideWindow(self: *Self, shift: u64) void {
    if (shift >= window_size) {
        self.bitmap = [_]u64{0} ** window_words;
        return;
    }

    const word_shift: usize = @intCast(shift / 64);
    const bit_shift: u6 = @intCast(shift % 64);

    if (word_shift > 0) {
        const src = self.bitmap[0 .. window_words - word_shift];
        const dst = self.bitmap[word_shift..window_words];
        mem.copyBackwards(u64, dst, src);
        @memset(self.bitmap[0..word_shift], 0);
    }

    if (bit_shift > 0) {
        var carry: u64 = 0;
        const carry_shift: u6 = @intCast(64 - @as(u7, bit_shift));
        for (0..window_words) |i| {
            const next_carry = self.bitmap[i] >> carry_shift;
            self.bitmap[i] = (self.bitmap[i] << bit_shift) | carry;
            carry = next_carry;
        }
    }
}

pub fn testAll(testing: anytype) !void {
    var rf = init();

    for (0..100) |i| {
        try testing.expect(rf.checkAndUpdate(i));
    }

    try testing.expect(!rf.checkAndUpdate(42));

    var out_of_order = init();
    const nonces = [_]u64{ 100, 50, 75, 25, 99, 1 };
    for (nonces) |nonce| {
        try testing.expect(out_of_order.checkAndUpdate(nonce));
    }
    for (nonces) |nonce| {
        try testing.expect(!out_of_order.checkAndUpdate(nonce));
    }

    var boundary = init();
    try testing.expect(boundary.checkAndUpdate(window_size + 100));
    try testing.expect(boundary.checkAndUpdate(101));
    try testing.expect(!boundary.checkAndUpdate(100));

    var jump = init();
    for (0..10) |i| _ = jump.checkAndUpdate(i);
    try testing.expect(jump.checkAndUpdate(10_000));
    for (0..10) |i| {
        try testing.expect(!jump.checkAndUpdate(i));
    }

    var reset_filter = init();
    for (0..100) |i| _ = reset_filter.checkAndUpdate(i);
    reset_filter.reset();
    for (0..100) |i| {
        try testing.expect(reset_filter.checkAndUpdate(i));
    }
}
