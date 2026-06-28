const glib = @import("glib");

const Key = @import("Key.zig");

const KeyPair = @This();

public: Key = Key.zero,
private: Key = Key.zero,

pub fn seed(comptime grt: type, value: u32) KeyPair {
    var private_bytes: [32]u8 = undefined;
    var offset: usize = 0;
    var counter: u32 = 0;
    while (offset < private_bytes.len) : (offset += 4) {
        var chunk: [4]u8 = undefined;
        grt.std.mem.writeInt(u32, &chunk, value +% counter, .little);
        @memcpy(private_bytes[offset .. offset + 4], &chunk);
        counter +%= 1;
    }
    private_bytes[0] |= 1;
    return fromPrivate(grt, .{ .bytes = private_bytes }) catch @panic("invalid test key");
}

pub fn rand(comptime grt: type) KeyPair {
    var private_bytes: [32]u8 = undefined;
    grt.std.crypto.random.bytes(&private_bytes);
    return fromPrivate(grt, .{ .bytes = private_bytes }) catch unreachable;
}

pub fn fromPrivate(comptime grt: type, private: Key) !KeyPair {
    const X25519 = grt.std.crypto.dh.X25519;
    const private_bytes = clamp(private.bytes);
    const public_bytes = try X25519.recoverPublicKey(private_bytes);
    return .{
        .public = .{ .bytes = public_bytes },
        .private = .{ .bytes = private_bytes },
    };
}

fn clamp(private_bytes: [32]u8) [32]u8 {
    var out = private_bytes;
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    return out;
}

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    return glib.testing.TestRunner.fromFn(grt.std, 1024 * 1024, struct {
        fn run(_: *glib.testing.T, _: grt.std.mem.Allocator) !void {
            const testing = grt.std.testing;

            const pair = try fromPrivate(grt, .{ .bytes = [_]u8{0xff} ** 32 });
            try testing.expectEqual(@as(u8, 0xf8), pair.private.bytes[0]);
            try testing.expectEqual(@as(u8, 0x7f), pair.private.bytes[31]);

            const derived = try fromPrivate(grt, pair.private);
            try testing.expect(pair.public.eql(derived.public));

            const random_pair = rand(grt);
            const derived_random = try fromPrivate(grt, random_pair.private);
            try testing.expect(random_pair.public.eql(derived_random.public));
        }
    }.run);
}
