const embed = @import("embed");
const mem = embed.mem;

const errors = @import("errors.zig");
const Key = @import("key.zig");
const lib_adapter = @import("lib_adapter.zig");

const Self = @This();

pub const hash_size: usize = 32;
pub const tag_size: usize = 16;
pub const suite_name = "ChaChaPoly_BLAKE2s";

pub fn hash(comptime Crypto: type, parts: []const []const u8) [hash_size]u8 {
    var hasher = Crypto.Blake2s256.init(.{});
    for (parts) |part| hasher.update(part);
    return hasher.finalResult();
}

pub fn hmac(comptime Crypto: type, key_data: *const [hash_size]u8, parts: []const []const u8) [hash_size]u8 {
    const block_len = Crypto.Blake2s256.block_length;

    var k_ipad: [block_len]u8 = [_]u8{0x36} ** block_len;
    var k_opad: [block_len]u8 = [_]u8{0x5c} ** block_len;

    for (0..hash_size) |i| {
        k_ipad[i] = key_data[i] ^ 0x36;
        k_opad[i] = key_data[i] ^ 0x5c;
    }

    var inner = Crypto.Blake2s256.init(.{});
    inner.update(&k_ipad);
    for (parts) |part| inner.update(part);
    const inner_hash = inner.finalResult();

    var outer = Crypto.Blake2s256.init(.{});
    outer.update(&k_opad);
    outer.update(&inner_hash);
    return outer.finalResult();
}

pub fn hkdf(comptime Crypto: type, chaining_key: *const Key, input: []const u8, comptime num_outputs: usize) [num_outputs]Key {
    comptime {
        if (num_outputs < 1 or num_outputs > 3) {
            @compileError("num_outputs must be between 1 and 3");
        }
    }

    const secret = hmac(Crypto, chaining_key.asBytes(), &.{input});
    var outputs: [num_outputs]Key = undefined;

    outputs[0] = Key.fromBytes(hmac(Crypto, &secret, &.{&[_]u8{0x01}}));
    if (num_outputs >= 2) {
        outputs[1] = Key.fromBytes(hmac(Crypto, &secret, &.{ outputs[0].asBytes(), &[_]u8{0x02} }));
    }
    if (num_outputs >= 3) {
        outputs[2] = Key.fromBytes(hmac(Crypto, &secret, &.{ outputs[1].asBytes(), &[_]u8{0x03} }));
    }

    return outputs;
}

pub fn kdf2(comptime Crypto: type, chaining_key: *const Key, input: []const u8) struct { Key, Key } {
    const keys = hkdf(Crypto, chaining_key, input, 2);
    return .{ keys[0], keys[1] };
}

pub fn kdf3(comptime Crypto: type, chaining_key: *const Key, input: []const u8) struct { Key, Key, Key } {
    const keys = hkdf(Crypto, chaining_key, input, 3);
    return .{ keys[0], keys[1], keys[2] };
}

pub fn encrypt(
    comptime Crypto: type,
    key: *const [Key.key_size]u8,
    nonce: u64,
    plaintext: []const u8,
    additional_data: []const u8,
    out: []u8,
) usize {
    const Aead = Crypto.ChaCha20Poly1305;
    const nonce_bytes = buildNonce(Aead, nonce);

    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(out[0..plaintext.len], &tag, plaintext, additional_data, nonce_bytes, key.*);
    @memcpy(out[plaintext.len..][0..Aead.tag_length], &tag);
    return plaintext.len + Aead.tag_length;
}

pub fn decrypt(
    comptime Crypto: type,
    key: *const [Key.key_size]u8,
    nonce: u64,
    ciphertext: []const u8,
    additional_data: []const u8,
    out: []u8,
) errors.CipherError!usize {
    const Aead = Crypto.ChaCha20Poly1305;

    if (ciphertext.len < Aead.tag_length) return errors.CipherError.InvalidCiphertext;

    const plaintext_len = ciphertext.len - Aead.tag_length;
    const tag = ciphertext[plaintext_len..][0..Aead.tag_length].*;

    const nonce_bytes = buildNonce(Aead, nonce);

    Aead.decrypt(out[0..plaintext_len], ciphertext[0..plaintext_len], tag, additional_data, nonce_bytes, key.*) catch {
        return errors.CipherError.AuthenticationFailed;
    };

    return plaintext_len;
}

pub fn encryptWithAd(comptime Crypto: type, key: *const Key, additional_data: []const u8, plaintext: []const u8, out: []u8) usize {
    return encrypt(Crypto, key.asBytes(), 0, plaintext, additional_data, out);
}

pub fn decryptWithAd(comptime Crypto: type, key: *const Key, additional_data: []const u8, ciphertext: []const u8, out: []u8) errors.CipherError!usize {
    return decrypt(Crypto, key.asBytes(), 0, ciphertext, additional_data, out);
}

pub fn testAll(comptime lib: type, testing: anytype) !void {
    const Crypto = lib_adapter.make(lib);
    const key = [_]u8{7} ** Key.key_size;
    const plaintext = "hello, noise";
    const ad = "aad";

    const hash_abc = hash(Crypto, &.{"abc"});
    const hash_hex = hex(&hash_abc);
    try testing.expectEqualStrings(
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        hash_hex[0..],
    );

    const ck = Key.zero;
    const hkdf_keys = hkdf(Crypto, &ck, "input", 3);
    try testing.expect(!hkdf_keys[0].isZero());
    try testing.expect(!hkdf_keys[0].eql(hkdf_keys[1]));
    try testing.expect(!hkdf_keys[1].eql(hkdf_keys[2]));

    const nonce_bytes = buildNonce(Crypto.ChaCha20Poly1305, 9);
    try testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0 },
        &nonce_bytes,
    );

    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    const written = encrypt(Crypto, &key, 9, plaintext, ad, &ciphertext);
    try testing.expectEqual(@as(usize, plaintext.len + tag_size), written);

    var decrypted: [plaintext.len]u8 = undefined;
    const read = try decrypt(Crypto, &key, 9, &ciphertext, ad, &decrypted);
    try testing.expectEqual(@as(usize, plaintext.len), read);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..read]);

    var wrong_key = key;
    wrong_key[0] ^= 0xff;
    try testing.expectError(
        errors.CipherError.AuthenticationFailed,
        decrypt(Crypto, &wrong_key, 9, &ciphertext, ad, &decrypted),
    );
}

fn hex(bytes: *const [hash_size]u8) [hash_size * 2]u8 {
    var out: [hash_size * 2]u8 = undefined;
    const chars = "0123456789abcdef";

    for (bytes.*, 0..) |byte, i| {
        out[i * 2] = chars[byte >> 4];
        out[i * 2 + 1] = chars[byte & 0x0f];
    }

    return out;
}

fn buildNonce(comptime Aead: type, nonce: u64) [Aead.nonce_length]u8 {
    var nonce_bytes: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length;
    mem.writeInt(u64, nonce_bytes[4..12], nonce, .little);
    return nonce_bytes;
}
