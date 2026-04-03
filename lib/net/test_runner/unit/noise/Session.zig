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
                t.logErrorf("noise/Session failed: {}", .{err});
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

fn sessionNowMs(comptime lib: type) u64 {
    const now = lib.time.milliTimestamp();
    if (now <= 0) return 0;
    return @intCast(now);
}

fn runCases(comptime lib: type, testing: anytype) !void {
    const T = noise.Session.make(lib);
    const Key = noise.Key;
    const cipher = noise.Cipher;

    const send_key = Key.fromBytes(cipher.hash(lib, &.{"send key"}));
    const recv_key = Key.fromBytes(cipher.hash(lib, &.{"recv key"}));

    var alice = T.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = send_key,
        .recv_key = recv_key,
    });
    var bob = T.init(.{
        .local_index = 2,
        .remote_index = 1,
        .send_key = recv_key,
        .recv_key = send_key,
    });

    const plaintext = "Hello, World!";
    var ciphertext: [plaintext.len + cipher.tag_size]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const before_send = sessionNowMs(lib);
    const send = try alice.encrypt(plaintext, &ciphertext);
    const after_send = sessionNowMs(lib);
    const before_recv = sessionNowMs(lib);
    const read = try bob.decrypt(ciphertext[0..send.n], send.nonce, &decrypted);
    const after_recv = sessionNowMs(lib);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..read]);

    try testing.expectEqual(@as(u64, 1), alice.sendNonce());
    try testing.expectEqual(@as(u64, 0), bob.recvMaxNonce());
    try testing.expect(alice.lastSentMs() >= before_send);
    try testing.expect(alice.lastSentMs() <= after_send);
    try testing.expect(bob.lastReceivedMs() >= before_recv);
    try testing.expect(bob.lastReceivedMs() <= after_recv);

    try testing.expectError(
        noise.SessionError.ReplayDetected,
        bob.decrypt(ciphertext[0..send.n], send.nonce, &decrypted),
    );

    var second_ciphertext: [4 + cipher.tag_size]u8 = undefined;
    const send2 = try alice.encrypt("one!", &second_ciphertext);
    var forged = second_ciphertext;
    forged[0] ^= 0x80;
    try testing.expectError(
        noise.SessionError.DecryptionFailed,
        bob.decrypt(forged[0..send2.n], send2.nonce, &decrypted),
    );
    try testing.expectEqual(send.nonce, bob.recvMaxNonce());
    const second_read = try bob.decrypt(second_ciphertext[0..send2.n], send2.nonce, &decrypted);
    try testing.expectEqualStrings("one!", decrypted[0..second_read]);
    try testing.expectEqual(send2.nonce, bob.recvMaxNonce());
    try testing.expectError(
        noise.SessionError.ReplayDetected,
        bob.decrypt(second_ciphertext[0..send2.n], send2.nonce, &decrypted),
    );

    bob.setState(.expired);
    try testing.expectError(
        noise.SessionError.NotEstablished,
        bob.decrypt(ciphertext[0..send.n], send.nonce, &decrypted),
    );
    try testing.expectError(noise.SessionError.NotEstablished, bob.encrypt("late", &second_ciphertext));

    bob.setState(.established);
    try testing.expect(!bob.isExpired());
    const stale = if (sessionNowMs(lib) > noise.SessionTimeoutMs + 1) sessionNowMs(lib) - (noise.SessionTimeoutMs + 1) else 0;
    bob.testSetLastReceivedMs(stale);
    try testing.expect(bob.isExpired());
}
