const Key = @import("key.zig");
const cipher = @import("cipher.zig");

pub fn CipherState(comptime Crypto: type) type {
    return struct {
        key: Key,
        nonce: u64 = 0,

        const Self = @This();

        pub fn init(key: Key) Self {
            return .{ .key = key };
        }

        pub fn encrypt(self: *Self, plaintext: []const u8, additional_data: []const u8, out: []u8) usize {
            const written = cipher.encrypt(Crypto, self.key.asBytes(), self.nonce, plaintext, additional_data, out);
            self.nonce += 1;
            return written;
        }

        pub fn decrypt(self: *Self, ciphertext: []const u8, additional_data: []const u8, out: []u8) !usize {
            const read = try cipher.decrypt(Crypto, self.key.asBytes(), self.nonce, ciphertext, additional_data, out);
            self.nonce += 1;
            return read;
        }

        pub fn decryptWithNonce(self: *const Self, nonce: u64, ciphertext: []const u8, additional_data: []const u8, out: []u8) !usize {
            return cipher.decrypt(Crypto, self.key.asBytes(), nonce, ciphertext, additional_data, out);
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

pub fn testAll(comptime Crypto: type, testing: anytype) !void {
    const T = CipherState(Crypto);
    const key = Key.fromBytes([_]u8{42} ** Key.key_size);
    var alice = T.init(key);
    var bob = T.init(key);

    try testing.expectEqual(@as(u64, 0), alice.getNonce());
    try testing.expect(alice.getKey().eql(key));

    const plaintext = "hello, world!";
    var ciphertext: [plaintext.len + cipher.tag_size]u8 = undefined;
    _ = alice.encrypt(plaintext, "", &ciphertext);
    try testing.expectEqual(@as(u64, 1), alice.getNonce());

    var decrypted: [plaintext.len]u8 = undefined;
    const read = try bob.decrypt(&ciphertext, "", &decrypted);
    try testing.expectEqual(@as(usize, plaintext.len), read);
    try testing.expectEqual(@as(u64, 1), bob.getNonce());
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..read]);

    bob.setNonce(0);
    var second: [plaintext.len + cipher.tag_size]u8 = undefined;
    _ = alice.encrypt(plaintext, "", &second);
    var fail_buf: [plaintext.len]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, bob.decrypt(&second, "", &fail_buf));

    var explicit: [plaintext.len]u8 = undefined;
    const explicit_read = try bob.decryptWithNonce(1, &second, "", &explicit);
    try testing.expectEqualSlices(u8, plaintext, explicit[0..explicit_read]);
    try testing.expectEqual(@as(u64, 0), bob.getNonce());
}
