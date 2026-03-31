const Key = @import("key.zig");
const cipher = @import("cipher.zig");
const lib_adapter = @import("lib_adapter.zig");
const CipherState = @import("cipher_state.zig").CipherState;

pub fn SymmetricState(comptime Crypto: type) type {
    return struct {
        chaining_key: Key,
        hash: [cipher.hash_size]u8,
        has_key: bool = false,
        cipher_key: Key = Key.zero,

        const Self = @This();

        pub fn init(protocol_name: []const u8) Self {
            var chaining_key: [Key.key_size]u8 = [_]u8{0} ** Key.key_size;

            if (protocol_name.len <= cipher.hash_size) {
                @memcpy(chaining_key[0..protocol_name.len], protocol_name);
            } else {
                chaining_key = cipher.hash(Crypto, &.{protocol_name});
            }

            return .{
                .chaining_key = Key.fromBytes(chaining_key),
                .hash = chaining_key,
            };
        }

        pub fn mixKey(self: *Self, input: []const u8) void {
            const next_ck, const next_key = cipher.kdf2(Crypto, &self.chaining_key, input);
            self.chaining_key = next_ck;
            self.cipher_key = next_key;
            self.has_key = true;
        }

        pub fn mixHash(self: *Self, data: []const u8) void {
            self.hash = cipher.hash(Crypto, &.{ &self.hash, data });
        }

        pub fn mixKeyAndHash(self: *Self, input: []const u8) void {
            const next_ck, const temp_hash, const next_key = cipher.kdf3(Crypto, &self.chaining_key, input);
            self.chaining_key = next_ck;
            self.mixHash(temp_hash.asBytes());
            self.cipher_key = next_key;
            self.has_key = true;
        }

        pub fn encryptAndHash(self: *Self, plaintext: []const u8, out: []u8) usize {
            if (!self.has_key) {
                @memcpy(out[0..plaintext.len], plaintext);
                self.mixHash(plaintext);
                return plaintext.len;
            }

            const written = cipher.encryptWithAd(Crypto, &self.cipher_key, &self.hash, plaintext, out);
            self.mixHash(out[0..written]);
            return written;
        }

        pub fn decryptAndHash(self: *Self, ciphertext: []const u8, out: []u8) !usize {
            if (!self.has_key) {
                @memcpy(out[0..ciphertext.len], ciphertext);
                self.mixHash(ciphertext);
                return ciphertext.len;
            }

            const read = try cipher.decryptWithAd(Crypto, &self.cipher_key, &self.hash, ciphertext, out);
            self.mixHash(ciphertext);
            return read;
        }

        pub fn split(self: *const Self) struct { CipherState(Crypto), CipherState(Crypto) } {
            const keys = cipher.hkdf(Crypto, &self.chaining_key, "", 2);
            return .{
                CipherState(Crypto).init(keys[0]),
                CipherState(Crypto).init(keys[1]),
            };
        }

        pub fn clone(self: Self) Self {
            return self;
        }

        pub fn getHash(self: *const Self) *const [cipher.hash_size]u8 {
            return &self.hash;
        }

        pub fn getChainingKey(self: Self) Key {
            return self.chaining_key;
        }
    };
}

pub fn testAll(comptime lib: type, testing: anytype) !void {
    const Crypto = lib_adapter.make(lib);
    const T = SymmetricState(Crypto);

    var lhs = T.init("Noise_IK_25519_ChaChaPoly_BLAKE2s");
    var rhs = T.init("Noise_IK_25519_ChaChaPoly_BLAKE2s");

    lhs.mixHash("data");
    try testing.expect(!lhs.getChainingKey().isZero());
    try testing.expect(!@import("embed").mem.eql(u8, lhs.getHash(), rhs.getHash()));

    lhs = T.init("Test");
    rhs = T.init("Test");
    lhs.mixKey("key");
    rhs.mixKey("key");
    try testing.expect(lhs.cipher_key.eql(rhs.cipher_key));

    const plaintext = "secret message";
    var ciphertext: [plaintext.len + cipher.tag_size]u8 = undefined;
    const written = lhs.encryptAndHash(plaintext, &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    const read = try rhs.decryptAndHash(ciphertext[0..written], &decrypted);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..read]);
    try testing.expectEqualSlices(u8, lhs.getHash(), rhs.getHash());

    var psk = T.init("PSK");
    psk.mixKeyAndHash("input");
    try testing.expect(psk.has_key);

    const cs1, const cs2 = rhs.split();
    try testing.expect(!cs1.getKey().eql(cs2.getKey()));
}
