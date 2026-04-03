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
                t.logErrorf("noise/CipherState failed: {}", .{err});
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
    const T = noise.CipherState.make(lib);
    const Key = noise.Key;
    const cipher = noise.Cipher;

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
    try testing.expectError(noise.CipherError.AuthenticationFailed, bob.decrypt(&second, "", &fail_buf));

    var explicit: [plaintext.len]u8 = undefined;
    const explicit_read = try bob.decryptWithNonce(1, &second, "", &explicit);
    try testing.expectEqualSlices(u8, plaintext, explicit[0..explicit_read]);
    try testing.expectEqual(@as(u64, 0), bob.getNonce());
}
