const dep = @import("dep");
const mem = dep.embed.mem;

pub const window_size: usize = 2048;
const window_words: usize = window_size / 64;

pub fn make(comptime lib: type) type {
    return struct {
        bitmap: [window_words]u64 = [_]u64{0} ** window_words,
        max_nonce: u64 = 0,
        guard: lib.atomic.Value(u8) = lib.atomic.Value(u8).init(unlocked),

        const Self = @This();
        const unlocked: u8 = 0;
        const locked: u8 = 1;

        pub fn init() Self {
            return .{};
        }

        pub fn check(self: *Self, nonce: u64) bool {
            self.lock();
            defer self.unlock();
            return self.checkLocked(nonce);
        }

        pub fn update(self: *Self, nonce: u64) void {
            self.lock();
            defer self.unlock();
            self.updateLocked(nonce);
        }

        pub fn checkAndUpdate(self: *Self, nonce: u64) bool {
            self.lock();
            defer self.unlock();
            if (!self.checkLocked(nonce)) return false;
            self.updateLocked(nonce);
            return true;
        }

        pub fn reset(self: *Self) void {
            self.lock();
            defer self.unlock();
            self.bitmap = [_]u64{0} ** window_words;
            self.max_nonce = 0;
        }

        pub fn maxNonce(self: *Self) u64 {
            self.lock();
            defer self.unlock();
            return self.max_nonce;
        }

        fn checkLocked(self: *Self, nonce: u64) bool {
            if (nonce > self.max_nonce) return true;

            const delta = self.max_nonce - nonce;
            if (delta >= window_size) return false;

            const word_index: usize = @intCast(delta / 64);
            const bit_index: u6 = @intCast(delta % 64);
            return (self.bitmap[word_index] & (@as(u64, 1) << bit_index)) == 0;
        }

        fn updateLocked(self: *Self, nonce: u64) void {
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

        fn lock(self: *Self) void {
            while (self.guard.cmpxchgStrong(unlocked, locked, .seq_cst, .seq_cst) != null) {
                lib.Thread.yield() catch {};
            }
        }

        fn unlock(self: *Self) void {
            self.guard.store(unlocked, .seq_cst);
        }
    };
}
