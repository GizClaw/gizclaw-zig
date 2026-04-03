const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;
            runCases(lib, lib.testing) catch |err| {
                t.logErrorf("noise/cipher failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runCases(comptime lib: type, testing: anytype) !void {
    const cipher = noise.Cipher;
    const Key = noise.Key;

    const key = [_]u8{7} ** Key.key_size;
    const plaintext = "hello, noise";
    const ad = "aad";
    const hkdf_input = "input keying material";

    const hash_abc = cipher.hash(lib, &.{"abc"});
    const hash_hex = hex(&hash_abc);
    try testing.expectEqualStrings(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        hash_hex[0..],
    );

    const ck = Key.zero;
    const hkdf_one = cipher.hkdf(lib, &ck, hkdf_input, 1);
    const hkdf_two = cipher.hkdf(lib, &ck, hkdf_input, 2);
    const hkdf_three = cipher.hkdf(lib, &ck, hkdf_input, 3);
    try testing.expect(!hkdf_one[0].isZero());
    try testing.expect(hkdf_one[0].eql(hkdf_two[0]));
    try testing.expect(hkdf_two[0].eql(hkdf_three[0]));
    try testing.expect(hkdf_two[1].eql(hkdf_three[1]));
    try testing.expect(!hkdf_two[0].eql(hkdf_two[1]));
    try testing.expect(!hkdf_three[2].eql(hkdf_three[0]));
    try testing.expect(!hkdf_three[2].eql(hkdf_three[1]));

    const nonce_bytes = buildNonce(lib.crypto.aead.chacha_poly.ChaCha20Poly1305, 9);
    try testing.expectEqualSlices(
        u8,
        &.{ 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        &nonce_bytes,
    );

    var ciphertext: [plaintext.len + cipher.tag_size]u8 = undefined;
    const written = cipher.encrypt(lib, &key, 9, plaintext, ad, &ciphertext);
    try testing.expectEqual(@as(usize, plaintext.len + cipher.tag_size), written);

    var decrypted: [plaintext.len]u8 = undefined;
    const read = try cipher.decrypt(lib, &key, 9, &ciphertext, ad, &decrypted);
    try testing.expectEqual(@as(usize, plaintext.len), read);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..read]);

    var ciphertext_other_nonce: [plaintext.len + cipher.tag_size]u8 = undefined;
    _ = cipher.encrypt(lib, &key, 10, plaintext, ad, &ciphertext_other_nonce);
    try testing.expect(!dep.embed.mem.eql(u8, &ciphertext, &ciphertext_other_nonce));

    var wrong_key = key;
    wrong_key[0] ^= 0xff;
    try testing.expectError(
        noise.CipherError.AuthenticationFailed,
        cipher.decrypt(lib, &wrong_key, 9, &ciphertext, ad, &decrypted),
    );

    try testing.expectError(
        noise.CipherError.AuthenticationFailed,
        cipher.decrypt(lib, &key, 9, &ciphertext, "wrong ad", &decrypted),
    );

    const handshake_key = Key.fromBytes([_]u8{42} ** Key.key_size);
    var handshake_ciphertext: [5 + cipher.tag_size]u8 = undefined;
    const handshake_written = cipher.encryptWithAd(lib, &handshake_key, "additional data", "hello", &handshake_ciphertext);
    try testing.expectEqual(@as(usize, 5 + cipher.tag_size), handshake_written);

    var handshake_plaintext: [5]u8 = undefined;
    const handshake_read = try cipher.decryptWithAd(
        lib,
        &handshake_key,
        "additional data",
        handshake_ciphertext[0..handshake_written],
        &handshake_plaintext,
    );
    try testing.expectEqualSlices(u8, "hello", handshake_plaintext[0..handshake_read]);

    try testing.expectError(
        noise.CipherError.AuthenticationFailed,
        cipher.decryptWithAd(lib, &handshake_key, "wrong ad", handshake_ciphertext[0..handshake_written], &handshake_plaintext),
    );

    var empty_ciphertext: [cipher.tag_size]u8 = undefined;
    const empty_written = cipher.encryptWithAd(lib, &handshake_key, "additional data", "", &empty_ciphertext);
    try testing.expectEqual(@as(usize, cipher.tag_size), empty_written);

    var empty_plaintext: [0]u8 = .{};
    const empty_read = try cipher.decryptWithAd(
        lib,
        &handshake_key,
        "additional data",
        empty_ciphertext[0..empty_written],
        &empty_plaintext,
    );
    try testing.expectEqual(@as(usize, 0), empty_read);
}

fn hex(bytes: *const [noise.HashSize]u8) [noise.HashSize * 2]u8 {
    var out: [noise.HashSize * 2]u8 = undefined;
    const chars = "0123456789abcdef";

    for (bytes.*, 0..) |byte, i| {
        out[i * 2] = chars[byte >> 4];
        out[i * 2 + 1] = chars[byte & 0x0f];
    }

    return out;
}

fn buildNonce(comptime Aead: type, nonce: u64) [Aead.nonce_length]u8 {
    var nonce_bytes: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length;
    dep.embed.mem.writeInt(u64, nonce_bytes[0..8], nonce, .little);
    return nonce_bytes;
}
