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
                t.logErrorf("noise/SymmetricState failed: {}", .{err});
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
    const mem = dep.embed.mem;
    const T = noise.SymmetricState.make(lib);
    const cipher = noise.Cipher;

    var short_name = T.init("Noise_IK");
    try testing.expect(!short_name.getChainingKey().isZero());
    try testing.expectEqualSlices(u8, short_name.getChainingKey().asBytes(), short_name.getHash());

    var lhs = T.init("Noise_IK_25519_ChaChaPoly_BLAKE2s");
    var rhs = T.init("Noise_IK_25519_ChaChaPoly_BLAKE2s");
    try testing.expect(!lhs.getChainingKey().isZero());
    try testing.expectEqualSlices(u8, lhs.getChainingKey().asBytes(), lhs.getHash());

    const initial_hash = lhs.getHash().*;
    lhs.mixHash("data");
    try testing.expect(!mem.eql(u8, &initial_hash, lhs.getHash()));

    var deterministic_a = T.init("Test");
    var deterministic_b = T.init("Test");
    deterministic_a.mixHash("data");
    deterministic_b.mixHash("data");
    try testing.expectEqualSlices(u8, deterministic_a.getHash(), deterministic_b.getHash());

    var mix_key = T.init("Test");
    const mix_key_initial_ck = mix_key.getChainingKey();
    mix_key.mixKey("key");
    try testing.expect(!mix_key.getChainingKey().eql(mix_key_initial_ck));
    try testing.expect(mix_key.has_key);
    try testing.expect(!mix_key.cipher_key.isZero());
    try testing.expect(!mix_key.cipher_key.eql(mix_key.getChainingKey()));

    var mix_key_hash = T.init("Test");
    const mix_key_hash_initial_ck = mix_key_hash.getChainingKey();
    const mix_key_hash_initial_hash = mix_key_hash.getHash().*;
    mix_key_hash.mixKeyAndHash("input");
    try testing.expect(!mix_key_hash.getChainingKey().eql(mix_key_hash_initial_ck));
    try testing.expect(!mem.eql(u8, &mix_key_hash_initial_hash, mix_key_hash.getHash()));
    try testing.expect(mix_key_hash.has_key);
    try testing.expect(!mix_key_hash.cipher_key.isZero());

    lhs = T.init("Test");
    rhs = T.init("Test");
    lhs.mixKey("keying material");
    rhs.mixKey("keying material");
    try testing.expect(lhs.cipher_key.eql(rhs.cipher_key));

    const plaintext = "secret message";
    var ciphertext: [plaintext.len + cipher.tag_size]u8 = undefined;
    const written = lhs.encryptAndHash(plaintext, &ciphertext);
    try testing.expectEqual(@as(usize, plaintext.len + cipher.tag_size), written);

    var decrypted: [plaintext.len]u8 = undefined;
    const read = try rhs.decryptAndHash(ciphertext[0..written], &decrypted);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..read]);
    try testing.expectEqualSlices(u8, lhs.getHash(), rhs.getHash());

    const second_plaintext = "second";
    var second_ciphertext: [second_plaintext.len + cipher.tag_size]u8 = undefined;
    const second_written = lhs.encryptAndHash(second_plaintext, &second_ciphertext);
    var second_decrypted: [second_plaintext.len]u8 = undefined;
    const second_read = try rhs.decryptAndHash(second_ciphertext[0..second_written], &second_decrypted);
    try testing.expectEqualSlices(u8, second_plaintext, second_decrypted[0..second_read]);
    try testing.expectEqualSlices(u8, lhs.getHash(), rhs.getHash());

    var empty_lhs = T.init("Test");
    var empty_rhs = T.init("Test");
    empty_lhs.mixKey("key");
    empty_rhs.mixKey("key");
    var empty_ciphertext: [cipher.tag_size]u8 = undefined;
    const empty_written = empty_lhs.encryptAndHash("", &empty_ciphertext);
    try testing.expectEqual(@as(usize, cipher.tag_size), empty_written);
    var empty_plaintext: [0]u8 = .{};
    const empty_read = try empty_rhs.decryptAndHash(empty_ciphertext[0..empty_written], &empty_plaintext);
    try testing.expectEqual(@as(usize, 0), empty_read);
    try testing.expectEqualSlices(u8, empty_lhs.getHash(), empty_rhs.getHash());

    var fail_lhs = T.init("Test");
    var fail_rhs = T.init("Test");
    fail_lhs.mixKey("key");
    fail_rhs.mixKey("key");
    var fail_ciphertext: [plaintext.len + cipher.tag_size]u8 = undefined;
    const fail_written = fail_lhs.encryptAndHash(plaintext, &fail_ciphertext);
    const fail_hash_before = fail_rhs.getHash().*;
    fail_ciphertext[0] ^= 0x01;
    try testing.expectError(noise.CipherError.AuthenticationFailed, fail_rhs.decryptAndHash(fail_ciphertext[0..fail_written], &decrypted));
    try testing.expectEqualSlices(u8, &fail_hash_before, fail_rhs.getHash());

    var clone_source = T.init("Test");
    clone_source.mixHash("data");
    clone_source.mixKey("key");
    var clone = clone_source.clone();
    try testing.expect(clone.getChainingKey().eql(clone_source.getChainingKey()));
    try testing.expectEqualSlices(u8, clone.getHash(), clone_source.getHash());
    clone_source.mixHash("more");
    try testing.expect(!mem.eql(u8, clone.getHash(), clone_source.getHash()));

    var consistent_a = T.init("Noise_IK_25519_ChaChaPoly_BLAKE2s");
    var consistent_b = T.init("Noise_IK_25519_ChaChaPoly_BLAKE2s");
    consistent_a.mixHash("remote public key here!!");
    consistent_b.mixHash("remote public key here!!");
    try testing.expectEqualSlices(u8, consistent_a.getHash(), consistent_b.getHash());
    consistent_a.mixKey("ephemeral public key here");
    consistent_b.mixKey("ephemeral public key here");
    try testing.expect(consistent_a.getChainingKey().eql(consistent_b.getChainingKey()));
    try testing.expect(consistent_a.cipher_key.eql(consistent_b.cipher_key));

    var cs1, var cs2 = consistent_b.split();
    try testing.expect(!cs1.getKey().eql(cs2.getKey()));

    var split_ciphertext_one: [4 + cipher.tag_size]u8 = undefined;
    var split_ciphertext_two: [4 + cipher.tag_size]u8 = undefined;
    _ = cs1.encrypt("test", "", &split_ciphertext_one);
    _ = cs2.encrypt("test", "", &split_ciphertext_two);
    try testing.expect(!mem.eql(u8, &split_ciphertext_one, &split_ciphertext_two));
}
