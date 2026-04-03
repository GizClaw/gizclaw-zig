const Key = @import("Key.zig");
const cipher = @import("cipher.zig");
const CipherStateFile = @import("CipherState.zig");

pub fn make(comptime lib: type) type {
    const CipherState = CipherStateFile.make(lib);

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
                chaining_key = cipher.hash(lib, &.{protocol_name});
            }

            return .{
                .chaining_key = Key.fromBytes(chaining_key),
                .hash = chaining_key,
            };
        }

        pub fn mixKey(self: *Self, input: []const u8) void {
            const next_ck, const next_key = cipher.kdf2(lib, &self.chaining_key, input);
            self.chaining_key = next_ck;
            self.cipher_key = next_key;
            self.has_key = true;
        }

        pub fn mixHash(self: *Self, data: []const u8) void {
            self.hash = cipher.hash(lib, &.{ &self.hash, data });
        }

        pub fn mixKeyAndHash(self: *Self, input: []const u8) void {
            const next_ck, const temp_hash, const next_key = cipher.kdf3(lib, &self.chaining_key, input);
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

            const written = cipher.encryptWithAd(lib, &self.cipher_key, &self.hash, plaintext, out);
            self.mixHash(out[0..written]);
            return written;
        }

        pub fn decryptAndHash(self: *Self, ciphertext: []const u8, out: []u8) !usize {
            if (!self.has_key) {
                @memcpy(out[0..ciphertext.len], ciphertext);
                self.mixHash(ciphertext);
                return ciphertext.len;
            }

            const read = try cipher.decryptWithAd(lib, &self.cipher_key, &self.hash, ciphertext, out);
            self.mixHash(ciphertext);
            return read;
        }

        pub fn split(self: *const Self) struct { CipherState, CipherState } {
            const keys = cipher.hkdf(lib, &self.chaining_key, "", 2);
            return .{
                CipherState.init(keys[0]),
                CipherState.init(keys[1]),
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
