const std = @import("std");
const mem = std.mem;

const keypair = @import("keypair.zig");
pub const Key = keypair.Key;
pub const key_size = keypair.key_size;

const crypto_mod = @import("crypto.zig");

pub fn Cipher(comptime Crypto: type) type {
    const Aead = Crypto.ChaCha20Poly1305;

    return struct {
        pub const tag_size: usize = Aead.tag_length;

        pub fn encrypt(
            key: *const [key_size]u8,
            nonce: u64,
            plaintext: []const u8,
            ad: []const u8,
            out: []u8,
        ) void {
            std.debug.assert(out.len >= plaintext.len + tag_size);

            var nonce_bytes: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length;
            mem.writeInt(u64, nonce_bytes[4..12], nonce, .little);

            var tag: [tag_size]u8 = undefined;
            Aead.encryptStatic(
                out[0..plaintext.len],
                &tag,
                plaintext,
                ad,
                nonce_bytes,
                key.*,
            );
            @memcpy(out[plaintext.len..][0..tag_size], &tag);
        }

        pub fn decrypt(
            key: *const [key_size]u8,
            nonce: u64,
            ciphertext: []const u8,
            ad: []const u8,
            out: []u8,
        ) !void {
            if (ciphertext.len < tag_size) return error.InvalidCiphertext;
            const pt_len = ciphertext.len - tag_size;
            std.debug.assert(out.len >= pt_len);

            var nonce_bytes: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length;
            mem.writeInt(u64, nonce_bytes[4..12], nonce, .little);

            const tag = ciphertext[pt_len..][0..tag_size].*;
            Aead.decryptStatic(
                out[0..pt_len],
                ciphertext[0..pt_len],
                tag,
                ad,
                nonce_bytes,
                key.*,
            ) catch {
                return error.DecryptionFailed;
            };
        }

        pub fn encryptWithAd(key: *const Key, ad: []const u8, plaintext: []const u8, out: []u8) void {
            encrypt(key.asBytes(), 0, plaintext, ad, out);
        }

        pub fn decryptWithAd(key: *const Key, ad: []const u8, ciphertext: []const u8, out: []u8) !void {
            try decrypt(key.asBytes(), 0, ciphertext, ad, out);
        }
    };
}

const TestCrypto = @import("test_crypto.zig");
const TestCipher = Cipher(TestCrypto);

test "encrypt decrypt roundtrip" {
    const key = [_]u8{0} ** key_size;
    const plaintext = "Hello, ChaCha20-Poly1305!";
    const ad = "additional data";

    var ciphertext: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    TestCipher.encrypt(&key, 0, plaintext, ad, &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try TestCipher.decrypt(&key, 0, &ciphertext, ad, &decrypted);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "wrong key fails" {
    const key1 = [_]u8{0} ** key_size;
    var key2 = [_]u8{0} ** key_size;
    key2[0] = 1;

    const plaintext = "secret";
    var ciphertext: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    TestCipher.encrypt(&key1, 0, plaintext, "", &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try std.testing.expectError(error.DecryptionFailed, TestCipher.decrypt(&key2, 0, &ciphertext, "", &decrypted));
}

test "different nonces produce different ciphertext" {
    const key = [_]u8{0} ** key_size;
    const plaintext = "hello";

    var ct1: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    var ct2: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    TestCipher.encrypt(&key, 0, plaintext, "", &ct1);
    TestCipher.encrypt(&key, 1, plaintext, "", &ct2);

    try std.testing.expect(!mem.eql(u8, &ct1, &ct2));
}

test "encrypt uses noise chacha20 poly1305 nonce layout" {
    const key = [_]u8{7} ** key_size;
    const plaintext = "noise";
    const ad = "aad";
    const nonce: u64 = 0x0102_0304_0506_0708;

    var ciphertext: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    TestCipher.encrypt(&key, nonce, plaintext, ad, &ciphertext);

    var expected: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    var nonce_bytes: [TestCrypto.ChaCha20Poly1305.nonce_length]u8 = [_]u8{0} ** TestCrypto.ChaCha20Poly1305.nonce_length;
    mem.writeInt(u64, nonce_bytes[4..12], nonce, .little);

    var tag: [TestCipher.tag_size]u8 = undefined;
    TestCrypto.ChaCha20Poly1305.encryptStatic(
        expected[0..plaintext.len],
        &tag,
        plaintext,
        ad,
        nonce_bytes,
        key,
    );
    @memcpy(expected[plaintext.len..], &tag);

    try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
}

test "large data" {
    const key = [_]u8{0} ** key_size;
    const plaintext = [_]u8{0xAB} ** 4096;

    var ciphertext: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    TestCipher.encrypt(&key, 42, &plaintext, "", &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try TestCipher.decrypt(&key, 42, &ciphertext, "", &decrypted);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
