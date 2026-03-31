const blake2s = @import("../../noise/blake2s.zig");

pub fn TestCrypto(comptime lib: type) type {
    return struct {
        pub const Blake2s256 = blake2s;
        pub const ChaCha20Poly1305 = lib.crypto.aead.chacha_poly.ChaCha20Poly1305;
        pub const X25519 = lib.crypto.dh.X25519;
        pub const random = lib.crypto.random;
    };
}
