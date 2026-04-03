const Key = @import("Key.zig");
const cipher = @import("cipher.zig");

pub fn make(comptime lib: type) type {
    return struct {
        key: Key,
        nonce: u64 = 0,

        const Self = @This();

        pub fn init(key: Key) Self {
            return .{ .key = key };
        }

        pub fn encrypt(self: *Self, plaintext: []const u8, additional_data: []const u8, out: []u8) usize {
            const written = cipher.encrypt(lib, self.key.asBytes(), self.nonce, plaintext, additional_data, out);
            self.nonce += 1;
            return written;
        }

        pub fn decrypt(self: *Self, ciphertext: []const u8, additional_data: []const u8, out: []u8) !usize {
            const read = try cipher.decrypt(lib, self.key.asBytes(), self.nonce, ciphertext, additional_data, out);
            self.nonce += 1;
            return read;
        }

        pub fn decryptWithNonce(self: *const Self, nonce: u64, ciphertext: []const u8, additional_data: []const u8, out: []u8) !usize {
            return cipher.decrypt(lib, self.key.asBytes(), nonce, ciphertext, additional_data, out);
        }

        pub fn getNonce(self: Self) u64 {
            return self.nonce;
        }

        pub fn setNonce(self: *Self, nonce: u64) void {
            self.nonce = nonce;
        }

        pub fn getKey(self: Self) Key {
            return self.key;
        }
    };
}
