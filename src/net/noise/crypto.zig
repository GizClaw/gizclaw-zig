const std = @import("std");
const runtime = @import("embed").runtime;

const keypair = @import("keypair.zig");
pub const Key = keypair.Key;
pub const key_size = keypair.key_size;

pub const hash_size: usize = 32;
pub const tag_size: usize = 16;
pub const fixed_suite_name = "ChaChaPoly_BLAKE2s";

pub fn CryptoMod(comptime Crypto: type) type {
    const Hash = Crypto.Blake2s256;

    comptime {
        _ = runtime.crypto.hash.from(Crypto.Blake2s256, hash_size);
        _ = runtime.crypto.aead.ChaCha20Poly1305(Crypto.ChaCha20Poly1305);
    }

    return struct {
        pub const suite_name: []const u8 = fixed_suite_name;

        pub fn hash(data: []const []const u8) [hash_size]u8 {
            var h = Hash.init();
            for (data) |d| {
                h.update(d);
            }
            return h.final();
        }

        pub fn hmac(key_data: *const [hash_size]u8, data: []const []const u8) [hash_size]u8 {
            const block_len = Hash.block_length;

            var k_ipad: [block_len]u8 = [_]u8{0x36} ** block_len;
            var k_opad: [block_len]u8 = [_]u8{0x5c} ** block_len;
            for (0..hash_size) |i| {
                k_ipad[i] = key_data[i] ^ 0x36;
                k_opad[i] = key_data[i] ^ 0x5c;
            }

            var inner = Hash.init();
            inner.update(&k_ipad);
            for (data) |d| {
                inner.update(d);
            }
            const inner_hash = inner.final();

            var outer = Hash.init();
            outer.update(&k_opad);
            outer.update(&inner_hash);
            return outer.final();
        }

        pub fn hkdf(chaining_key: *const Key, input: []const u8, comptime num_outputs: usize) [num_outputs]Key {
            comptime {
                if (num_outputs < 1 or num_outputs > 3) {
                    @compileError("num_outputs must be 1-3");
                }
            }

            const secret = hmac(chaining_key.asBytes(), &.{input});
            var outputs: [num_outputs]Key = undefined;

            outputs[0] = Key.fromBytes(hmac(&secret, &.{&[_]u8{0x01}}));

            if (num_outputs >= 2) {
                outputs[1] = Key.fromBytes(hmac(&secret, &.{ outputs[0].asBytes(), &[_]u8{0x02} }));
            }

            if (num_outputs >= 3) {
                outputs[2] = Key.fromBytes(hmac(&secret, &.{ outputs[1].asBytes(), &[_]u8{0x03} }));
            }

            return outputs;
        }

        pub fn kdf2(chaining_key: *const Key, input: []const u8) struct { Key, Key } {
            const keys = hkdf(chaining_key, input, 2);
            return .{ keys[0], keys[1] };
        }

        pub fn kdf3(chaining_key: *const Key, input: []const u8) struct { Key, Key, Key } {
            const keys = hkdf(chaining_key, input, 3);
            return .{ keys[0], keys[1], keys[2] };
        }
    };
}

const TestCrypto = @import("test_crypto.zig");

test "hash consistency (BLAKE2s)" {
    const c = CryptoMod(TestCrypto);
    const h1 = c.hash(&.{"hello"});
    const h2 = c.hash(&.{"hello"});
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "hash concatenation (BLAKE2s)" {
    const c = CryptoMod(TestCrypto);
    const h1 = c.hash(&.{ "hello", "world" });
    const h2 = c.hash(&.{"helloworld"});
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "hkdf derives different keys (BLAKE2s)" {
    const c = CryptoMod(TestCrypto);
    const ck = Key.zero;
    const keys = c.hkdf(&ck, "input", 3);

    try std.testing.expect(!keys[0].isZero());
    try std.testing.expect(!keys[0].eql(keys[1]));
    try std.testing.expect(!keys[1].eql(keys[2]));
}
