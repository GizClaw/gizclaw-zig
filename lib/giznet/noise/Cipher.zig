const embed = @import("embed");
const mem = embed.std.mem;
const debug = embed.std.debug;

const Blake2s = @import("Blake2s.zig");
const Key = @import("Key.zig");

pub const hash_size: usize = 32;
pub const tag_size: usize = 16;
pub const default_kind: Kind = .chacha_poly;

pub const Kind = enum {
    chacha_poly,
    aes_256_gcm,
    plaintext,
};

pub const Error = error{
    InvalidCiphertext,
    AuthenticationFailed,
};

pub fn hash(parts: []const []const u8) [hash_size]u8 {
    var hasher = Blake2s.init(.{});
    for (parts) |part| hasher.update(part);
    return hasher.finalResult();
}

pub fn hmac(key_data: *const [hash_size]u8, parts: []const []const u8) [hash_size]u8 {
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

pub fn hkdf(chaining_key: *const Key, input: []const u8, comptime num_outputs: usize) [num_outputs]Key {
    comptime {
        if (num_outputs < 1 or num_outputs > 3) {
            @compileError("num_outputs must be between 1 and 3");
        }
    }

    const secret = hmac(&chaining_key.bytes, &.{input});
    var outputs: [num_outputs]Key = undefined;

    outputs[0] = .{ .bytes = hmac(&secret, &.{&[_]u8{0x01}}) };
    if (num_outputs >= 2) {
        outputs[1] = .{ .bytes = hmac(&secret, &.{ &outputs[0].bytes, &[_]u8{0x02} }) };
    }
    if (num_outputs >= 3) {
        outputs[2] = .{ .bytes = hmac(&secret, &.{ &outputs[1].bytes, &[_]u8{0x03} }) };
    }

    return outputs;
}

pub fn kdf2(chaining_key: *const Key, input: []const u8) struct { Key, Key } {
    const keys = hkdf(chaining_key, input, 2);
    return .{ keys[0], keys[1] };
}

pub fn make(comptime std: type, comptime kind: Kind) type {
    return switch (kind) {
        .chacha_poly => ChaChaPoly(std),
        .aes_256_gcm => Aes256Gcm(std),
        .plaintext => Plaintext(std),
    };
}

pub fn encrypt(comptime lib: type, key: *const Key, nonce: u64, plaintext: []const u8, ad: []const u8, out: []u8) usize {
    return make(lib, default_kind).encrypt(key, nonce, plaintext, ad, out);
}

pub fn decrypt(comptime lib: type, key: *const Key, nonce: u64, ciphertext: []const u8, ad: []const u8, out: []u8) Error!usize {
    return make(lib, default_kind).decrypt(key, nonce, ciphertext, ad, out);
}

pub fn encryptWithAd(comptime lib: type, key: *const Key, ad: []const u8, plaintext: []const u8, out: []u8) usize {
    return make(lib, default_kind).encryptWithAd(key, ad, plaintext, out);
}

pub fn decryptWithAd(comptime lib: type, key: *const Key, ad: []const u8, ciphertext: []const u8, out: []u8) Error!usize {
    return make(lib, default_kind).decryptWithAd(key, ad, ciphertext, out);
}

fn ChaChaPoly(comptime std: type) type {
    const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    return struct {
        pub const tag_size: usize = Aead.tag_length;

        pub fn encrypt(key: *const Key, nonce: u64, plaintext: []const u8, ad: []const u8, out: []u8) usize {
            return encryptWithAead(Aead, key, nonce, plaintext, ad, out);
        }

        pub fn decrypt(key: *const Key, nonce: u64, ciphertext: []const u8, ad: []const u8, out: []u8) Error!usize {
            return decryptWithAead(Aead, key, nonce, ciphertext, ad, out);
        }

        pub fn encryptWithAd(key: *const Key, ad: []const u8, plaintext: []const u8, out: []u8) usize {
            return @This().encrypt(key, 0, plaintext, ad, out);
        }

        pub fn decryptWithAd(key: *const Key, ad: []const u8, ciphertext: []const u8, out: []u8) Error!usize {
            return @This().decrypt(key, 0, ciphertext, ad, out);
        }
    };
}

fn Aes256Gcm(comptime std: type) type {
    const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;

    return struct {
        pub const tag_size: usize = Aead.tag_length;

        pub fn encrypt(key: *const Key, nonce: u64, plaintext: []const u8, ad: []const u8, out: []u8) usize {
            return encryptWithAead(Aead, key, nonce, plaintext, ad, out);
        }

        pub fn decrypt(key: *const Key, nonce: u64, ciphertext: []const u8, ad: []const u8, out: []u8) Error!usize {
            return decryptWithAead(Aead, key, nonce, ciphertext, ad, out);
        }

        pub fn encryptWithAd(key: *const Key, ad: []const u8, plaintext: []const u8, out: []u8) usize {
            return @This().encrypt(key, 0, plaintext, ad, out);
        }

        pub fn decryptWithAd(key: *const Key, ad: []const u8, ciphertext: []const u8, out: []u8) Error!usize {
            return @This().decrypt(key, 0, ciphertext, ad, out);
        }
    };
}

fn Plaintext(comptime std: type) type {
    _ = std;

    return struct {
        pub const tag_size: usize = 16;

        pub fn encrypt(key: *const Key, nonce: u64, plaintext: []const u8, ad: []const u8, out: []u8) usize {
            _ = key;
            _ = nonce;
            _ = ad;
            debug.assert(out.len >= plaintext.len + @This().tag_size);
            mem.copyForwards(u8, out[0..plaintext.len], plaintext);
            @memset(out[plaintext.len .. plaintext.len + @This().tag_size], 0);
            return plaintext.len + @This().tag_size;
        }

        pub fn decrypt(key: *const Key, nonce: u64, ciphertext: []const u8, ad: []const u8, out: []u8) Error!usize {
            _ = key;
            _ = nonce;
            _ = ad;
            if (ciphertext.len < @This().tag_size) return error.InvalidCiphertext;
            const plaintext_len = ciphertext.len - @This().tag_size;
            debug.assert(out.len >= plaintext_len);
            mem.copyForwards(u8, out[0..plaintext_len], ciphertext[0..plaintext_len]);
            return plaintext_len;
        }

        pub fn encryptWithAd(key: *const Key, ad: []const u8, plaintext: []const u8, out: []u8) usize {
            return @This().encrypt(key, 0, plaintext, ad, out);
        }

        pub fn decryptWithAd(key: *const Key, ad: []const u8, ciphertext: []const u8, out: []u8) Error!usize {
            return @This().decrypt(key, 0, ciphertext, ad, out);
        }
    };
}

fn encryptWithAead(
    comptime Aead: type,
    key: *const Key,
    nonce: u64,
    plaintext: []const u8,
    ad: []const u8,
    out: []u8,
) usize {
    debug.assert(out.len >= plaintext.len + Aead.tag_length);
    const nonce_bytes = buildNonce(Aead, nonce);

    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(out[0..plaintext.len], &tag, plaintext, ad, nonce_bytes, key.bytes);
    @memcpy(out[plaintext.len..][0..Aead.tag_length], &tag);
    return plaintext.len + Aead.tag_length;
}

fn decryptWithAead(
    comptime Aead: type,
    key: *const Key,
    nonce: u64,
    ciphertext: []const u8,
    ad: []const u8,
    out: []u8,
) Error!usize {
    if (ciphertext.len < Aead.tag_length) return error.InvalidCiphertext;

    const plaintext_len = ciphertext.len - Aead.tag_length;
    debug.assert(out.len >= plaintext_len);
    const tag = ciphertext[plaintext_len..][0..Aead.tag_length].*;
    const nonce_bytes = buildNonce(Aead, nonce);

    Aead.decrypt(out[0..plaintext_len], ciphertext[0..plaintext_len], tag, ad, nonce_bytes, key.bytes) catch {
        return error.AuthenticationFailed;
    };

    return plaintext_len;
}

fn buildNonce(comptime Aead: type, nonce: u64) [Aead.nonce_length]u8 {
    var nonce_bytes: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length;
    mem.writeInt(u64, nonce_bytes[0..8], nonce, .little);
    return nonce_bytes;
}
