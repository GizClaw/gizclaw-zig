const std = @import("std");
const testing = std.testing;

pub fn RingBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        buf: []T,
        head: usize = 0,
        tail: usize = 0,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .buf = &[_]T{},
                .head = 0,
                .tail = 0,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.buf.len > 0) {
                self.allocator.free(self.buf);
            }
        }

        pub fn readableLength(self: *const Self) usize {
            if (self.tail >= self.head) {
                return self.tail - self.head;
            } else {
                return self.buf.len - self.head + self.tail;
            }
        }

        pub fn read(self: *Self, dest: []T) usize {
            const to_read = @min(dest.len, self.readableLength());
            if (to_read == 0) return 0;

            const head = self.head;
            const cap = self.buf.len;

            const part1_len = @min(to_read, cap - head);
            @memcpy(dest[0..part1_len], self.buf[head..][0..part1_len]);

            const part2_len = to_read - part1_len;
            if (part2_len > 0) {
                @memcpy(dest[part1_len..][0..part2_len], self.buf[0..part2_len]);
            }

            self.head = (head + to_read) % cap;
            return to_read;
        }

        pub fn write(self: *Self, src: []const T) !void {
            const needed = self.readableLength() + src.len + 1;
            if (needed > self.buf.len) {
                try self.grow(needed);
            }

            const tail = self.tail;
            const cap = self.buf.len;
            const part1_len = @min(src.len, cap - tail);
            @memcpy(self.buf[tail..][0..part1_len], src[0..part1_len]);

            const part2_len = src.len - part1_len;
            if (part2_len > 0) {
                @memcpy(self.buf[0..part2_len], src[part1_len..][0..part2_len]);
            }

            self.tail = (tail + src.len) % cap;
        }

        fn grow(self: *Self, min_cap: usize) !void {
            var new_cap = if (self.buf.len == 0) 64 else self.buf.len;
            while (new_cap < min_cap) {
                new_cap *= 2;
            }

            const new_buf = try self.allocator.alloc(T, new_cap);
            const len = self.readableLength();

            if (len > 0) {
                const head = self.head;
                const cap = self.buf.len;
                const part1_len = @min(len, cap - head);
                @memcpy(new_buf[0..part1_len], self.buf[head..][0..part1_len]);

                const part2_len = len - part1_len;
                if (part2_len > 0) {
                    @memcpy(new_buf[part1_len..][0..part2_len], self.buf[0..part2_len]);
                }
            }

            if (self.buf.len > 0) {
                self.allocator.free(self.buf);
            }

            self.buf = new_buf;
            self.head = 0;
            self.tail = len;
        }
    };
}

// ── Tests ────────────────────────────────────────────────────────────

test "RingBuffer basic write and read" {
    var rb = RingBuffer(u8).init(testing.allocator);
    defer rb.deinit();

    try rb.write("hello");
    try testing.expectEqual(@as(usize, 5), rb.readableLength());

    var buf: [16]u8 = undefined;
    const n = rb.read(&buf);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualStrings("hello", buf[0..n]);
    try testing.expectEqual(@as(usize, 0), rb.readableLength());
}

test "RingBuffer multiple writes then read" {
    var rb = RingBuffer(u8).init(testing.allocator);
    defer rb.deinit();

    try rb.write("aaa");
    try rb.write("bbb");
    try rb.write("ccc");
    try testing.expectEqual(@as(usize, 9), rb.readableLength());

    var buf: [16]u8 = undefined;
    const n = rb.read(&buf);
    try testing.expectEqualStrings("aaabbbccc", buf[0..n]);
}

test "RingBuffer partial read" {
    var rb = RingBuffer(u8).init(testing.allocator);
    defer rb.deinit();

    try rb.write("abcdef");

    var buf: [3]u8 = undefined;
    const n1 = rb.read(&buf);
    try testing.expectEqual(@as(usize, 3), n1);
    try testing.expectEqualStrings("abc", buf[0..n1]);
    try testing.expectEqual(@as(usize, 3), rb.readableLength());

    const n2 = rb.read(&buf);
    try testing.expectEqual(@as(usize, 3), n2);
    try testing.expectEqualStrings("def", buf[0..n2]);
}

test "RingBuffer read from empty" {
    var rb = RingBuffer(u8).init(testing.allocator);
    defer rb.deinit();

    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), rb.read(&buf));
}

test "RingBuffer grow on large write" {
    var rb = RingBuffer(u8).init(testing.allocator);
    defer rb.deinit();

    var big: [200]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i);

    try rb.write(&big);
    try testing.expectEqual(@as(usize, 200), rb.readableLength());

    var out: [200]u8 = undefined;
    const n = rb.read(&out);
    try testing.expectEqual(@as(usize, 200), n);
    try testing.expectEqualSlices(u8, &big, out[0..n]);
}

test "RingBuffer wrap-around" {
    var rb = RingBuffer(u8).init(testing.allocator);
    defer rb.deinit();

    // Write enough to trigger initial alloc, then read some to advance head
    try rb.write("AAAAAAAAAAAAAAAA"); // 16 bytes
    var discard: [10]u8 = undefined;
    _ = rb.read(&discard); // head moves to 10

    // Now write more — this will wrap around the internal buffer
    try rb.write("BBBBBBBBBBBBBBBB"); // 16 more bytes
    try testing.expectEqual(@as(usize, 22), rb.readableLength()); // 6 + 16

    var out: [22]u8 = undefined;
    const n = rb.read(&out);
    try testing.expectEqual(@as(usize, 22), n);
    try testing.expectEqualStrings("AAAAAA", out[0..6]);
    try testing.expectEqualStrings("BBBBBBBBBBBBBBBB", out[6..22]);
}

test "RingBuffer stress interleaved read/write" {
    var rb = RingBuffer(u8).init(testing.allocator);
    defer rb.deinit();

    var total_written: usize = 0;
    var total_read: usize = 0;
    const chunk = "0123456789";

    for (0..100) |_| {
        try rb.write(chunk);
        total_written += chunk.len;

        var buf: [7]u8 = undefined;
        const n = rb.read(&buf);
        total_read += n;
    }

    // Drain remaining
    var drain: [2048]u8 = undefined;
    total_read += rb.read(&drain);

    try testing.expectEqual(total_written, total_read);
    try testing.expectEqual(@as(usize, 0), rb.readableLength());
}
