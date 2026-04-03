const dep = @import("dep");
const mem = dep.embed.mem;

const Blake2s = @import("Blake2s.zig");
const errors = @import("errors.zig");
const Key = @import("Key.zig");

const Self = @This();

pub const hash_size: usize = 32;
pub const tag_size: usize = 16;
pub const suite_name = "ChaChaPoly_BLAKE2s";

pub fn hash(comptime lib: type, parts: []const []const u8) [hash_size]u8 {
    _ = lib;
    var hasher = Blake2s.init(.{});
    for (parts) |part| hasher.update(part);
    return hasher.finalResult();
}

pub fn hmac(comptime lib: type, key_data: *const [hash_size]u8, parts: []const []const u8) [hash_size]u8 {
    _ = lib;
    const block_len = Blake2s.block_length;

    var k_ipad: [block_len]u8 = [_]u8{0x36} ** block_len;
    var k_opad: [block_len]u8 = [_]u8{0x5c} ** block_len;

    for (0..hash_size) |i| {
        k_ipad[i] = key_data[i] ^ 0x36;
        k_opad[i] = key_data[i] ^ 0x5c;
    }

    var inner = Blake2s.init(.{});
    inner.update(&k_ipad);
    for (parts) |part| inner.update(part);
    const inner_hash = inner.finalResult();

    var outer = Blake2s.init(.{});
    outer.update(&k_opad);
    outer.update(&inner_hash);
    return outer.finalResult();
}

pub fn hkdf(comptime lib: type, chaining_key: *const Key, input: []const u8, comptime num_outputs: usize) [num_outputs]Key {
    comptime {
        if (num_outputs < 1 or num_outputs > 3) {
            @compileError("num_outputs must be between 1 and 3");
        }
    }

    const secret = hmac(lib, chaining_key.asBytes(), &.{input});
    var outputs: [num_outputs]Key = undefined;

    outputs[0] = Key.fromBytes(hmac(lib, &secret, &.{&[_]u8{0x01}}));
    if (num_outputs >= 2) {
        outputs[1] = Key.fromBytes(hmac(lib, &secret, &.{ outputs[0].asBytes(), &[_]u8{0x02} }));
    }
    if (num_outputs >= 3) {
        outputs[2] = Key.fromBytes(hmac(lib, &secret, &.{ outputs[1].asBytes(), &[_]u8{0x03} }));
    }

    return outputs;
}

pub fn kdf2(comptime lib: type, chaining_key: *const Key, input: []const u8) struct { Key, Key } {
    const keys = hkdf(lib, chaining_key, input, 2);
    return .{ keys[0], keys[1] };
}

pub fn kdf3(comptime lib: type, chaining_key: *const Key, input: []const u8) struct { Key, Key, Key } {
    const keys = hkdf(lib, chaining_key, input, 3);
    return .{ keys[0], keys[1], keys[2] };
}

pub fn encrypt(
    comptime lib: type,
    key: *const [Key.key_size]u8,
    nonce: u64,
    plaintext: []const u8,
    additional_data: []const u8,
    out: []u8,
) usize {
    const Aead = lib.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const nonce_bytes = buildNonce(Aead, nonce);

    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(out[0..plaintext.len], &tag, plaintext, additional_data, nonce_bytes, key.*);
    @memcpy(out[plaintext.len..][0..Aead.tag_length], &tag);
    return plaintext.len + Aead.tag_length;
}

pub fn decrypt(
    comptime lib: type,
    key: *const [Key.key_size]u8,
    nonce: u64,
    ciphertext: []const u8,
    additional_data: []const u8,
    out: []u8,
) errors.CipherError!usize {
    const Aead = lib.crypto.aead.chacha_poly.ChaCha20Poly1305;

    if (ciphertext.len < Aead.tag_length) return errors.CipherError.InvalidCiphertext;

    const plaintext_len = ciphertext.len - Aead.tag_length;
    const tag = ciphertext[plaintext_len..][0..Aead.tag_length].*;

    const nonce_bytes = buildNonce(Aead, nonce);

    Aead.decrypt(out[0..plaintext_len], ciphertext[0..plaintext_len], tag, additional_data, nonce_bytes, key.*) catch {
        return errors.CipherError.AuthenticationFailed;
    };

    return plaintext_len;
}

pub fn encryptWithAd(comptime lib: type, key: *const Key, additional_data: []const u8, plaintext: []const u8, out: []u8) usize {
    return encrypt(lib, key.asBytes(), 0, plaintext, additional_data, out);
}

pub fn decryptWithAd(comptime lib: type, key: *const Key, additional_data: []const u8, ciphertext: []const u8, out: []u8) errors.CipherError!usize {
    return decrypt(lib, key.asBytes(), 0, ciphertext, additional_data, out);
}

fn buildNonce(comptime Aead: type, nonce: u64) [Aead.nonce_length]u8 {
    var nonce_bytes: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length;
    mem.writeInt(u64, nonce_bytes[0..8], nonce, .little);
    return nonce_bytes;
}
