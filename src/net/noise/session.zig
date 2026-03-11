const std = @import("std");
const mem = std.mem;

const keypair = @import("keypair.zig");
const replay_mod = @import("replay.zig");
const crypto_mod = @import("crypto.zig");

pub const Key = keypair.Key;
pub const key_size = keypair.key_size;
pub const ReplayFilter = replay_mod.ReplayFilter;
pub const tag_size = crypto_mod.tag_size;

pub const SessionState = enum {
    handshaking,
    established,
    expired,
};

pub const session_timeout_ms: u64 = 180_000;

pub const max_nonce: u64 = std.math.maxInt(u64) - 1;

pub const SessionError = error{
    NotEstablished,
    ReplayDetected,
    NonceExhausted,
    EncryptFailed,
    DecryptFailed,
    AuthenticationFailed,
};

pub const SessionConfig = struct {
    local_index: u32,
    remote_index: u32 = 0,
    send_key: Key,
    recv_key: Key,
    remote_pk: Key = Key.zero,
    now_ms: u64 = 0,
};

pub fn SessionMod(comptime Crypto: type) type {
    const cipher = @import("cipher.zig").Cipher(Crypto);

    return struct {
        pub const Session = struct {
            local_index: u32,
            remote_index: u32,

            send_key: Key,
            recv_key: Key,

            send_nonce: u64 = 0,
            recv_filter: ReplayFilter = ReplayFilter.init(),

            state: SessionState = .established,
            remote_pk: Key,

            created_ms: u64,
            last_received_ms: u64 = 0,
            last_sent_ms: u64 = 0,

            pub fn init(cfg: SessionConfig) Session {
                return .{
                    .local_index = cfg.local_index,
                    .remote_index = cfg.remote_index,
                    .send_key = cfg.send_key,
                    .recv_key = cfg.recv_key,
                    .remote_pk = cfg.remote_pk,
                    .created_ms = cfg.now_ms,
                    .last_received_ms = cfg.now_ms,
                    .last_sent_ms = cfg.now_ms,
                };
            }

            pub fn localIndex(self: *const Session) u32 {
                return self.local_index;
            }

            pub fn remoteIndex(self: *const Session) u32 {
                return self.remote_index;
            }

            pub fn setRemoteIndex(self: *Session, idx: u32) void {
                self.remote_index = idx;
            }

            pub fn remotePk(self: *const Session) Key {
                return self.remote_pk;
            }

            pub fn getState(self: *const Session) SessionState {
                return self.state;
            }

            pub fn setState(self: *Session, new_state: SessionState) void {
                self.state = new_state;
            }

            pub fn encrypt(self: *Session, plaintext: []const u8, out: []u8, now_ms: u64) SessionError!u64 {
                if (self.state != .established) {
                    return SessionError.NotEstablished;
                }

                const nonce = self.send_nonce;
                if (nonce >= max_nonce) {
                    return SessionError.NonceExhausted;
                }
                self.send_nonce += 1;

                cipher.encrypt(&self.send_key.data, nonce, plaintext, "", out);
                self.last_sent_ms = now_ms;

                return nonce;
            }

            pub fn decrypt(self: *Session, ciphertext: []const u8, nonce: u64, out: []u8, now_ms: u64) SessionError!usize {
                if (self.state != .established) {
                    return SessionError.NotEstablished;
                }

                if (ciphertext.len < tag_size) {
                    return SessionError.DecryptFailed;
                }

                if (!self.recv_filter.check(nonce)) {
                    return SessionError.ReplayDetected;
                }

                cipher.decrypt(&self.recv_key.data, nonce, ciphertext, "", out) catch {
                    return SessionError.AuthenticationFailed;
                };

                self.recv_filter.update(nonce);
                self.last_received_ms = now_ms;

                return ciphertext.len - tag_size;
            }

            pub fn isExpired(self: *const Session, now_ms: u64) bool {
                if (self.state == .expired) return true;
                if (now_ms < self.last_received_ms) return false;
                return (now_ms - self.last_received_ms) > session_timeout_ms;
            }

            pub fn expire(self: *Session) void {
                self.state = .expired;
            }

            pub fn sendNonce(self: *const Session) u64 {
                return self.send_nonce;
            }

            pub fn recvMaxNonce(self: *const Session) u64 {
                return self.recv_filter.maxNonce();
            }

            pub fn createdMs(self: *const Session) u64 {
                return self.created_ms;
            }

            pub fn lastReceivedMs(self: *const Session) u64 {
                return self.last_received_ms;
            }

            pub fn lastSentMs(self: *const Session) u64 {
                return self.last_sent_ms;
            }
        };
    };
}

pub fn generateIndexFromBytes(random_bytes: [4]u8) u32 {
    return mem.readInt(u32, &random_bytes, .little);
}

pub fn generateIndex() u32 {
    var buf: [4]u8 = undefined;
    std.crypto.random.bytes(&buf);
    return generateIndexFromBytes(buf);
}

const testing = std.testing;
const TestCrypto = @import("test_crypto.zig");
const TestSession = SessionMod(TestCrypto).Session;
const c = crypto_mod.CryptoMod(TestCrypto);

fn createTestSessions() struct { alice: TestSession, bob: TestSession } {
    const send_key = Key.fromBytes(c.hash(&.{"send key"}));
    const recv_key = Key.fromBytes(c.hash(&.{"recv key"}));

    const alice = TestSession.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = send_key,
        .recv_key = recv_key,
    });

    const bob = TestSession.init(.{
        .local_index = 2,
        .remote_index = 1,
        .send_key = recv_key,
        .recv_key = send_key,
    });

    return .{ .alice = alice, .bob = bob };
}

test "encrypt decrypt" {
    var sessions = createTestSessions();

    const plaintext = "Hello, World!";
    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const nonce = try sessions.alice.encrypt(plaintext, &ciphertext, 0);
    const pt_len = try sessions.bob.decrypt(&ciphertext, nonce, &decrypted, 0);

    try testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}

test "nonce increment" {
    var sessions = createTestSessions();
    var ct: [4 + tag_size]u8 = undefined;

    for (0..10) |i| {
        try testing.expectEqual(@as(u64, i), sessions.alice.sendNonce());
        _ = try sessions.alice.encrypt("test", &ct, 0);
    }
    try testing.expectEqual(@as(u64, 10), sessions.alice.sendNonce());
}

test "replay protection" {
    var sessions = createTestSessions();

    const plaintext = "test";
    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const nonce = try sessions.alice.encrypt(plaintext, &ciphertext, 0);
    _ = try sessions.bob.decrypt(&ciphertext, nonce, &decrypted, 0);
    try testing.expectError(SessionError.ReplayDetected, sessions.bob.decrypt(&ciphertext, nonce, &decrypted, 0));
}

test "forged ciphertext does not advance replay window" {
    var sessions = createTestSessions();

    var ciphertext0: [4 + tag_size]u8 = undefined;
    var ciphertext1: [4 + tag_size]u8 = undefined;
    var decrypted: [4]u8 = undefined;

    const nonce0 = try sessions.alice.encrypt("zero", &ciphertext0, 0);
    const nonce1 = try sessions.alice.encrypt("one!", &ciphertext1, 0);

    _ = try sessions.bob.decrypt(&ciphertext0, nonce0, &decrypted, 10);
    try testing.expectEqual(@as(u64, nonce0), sessions.bob.recvMaxNonce());

    var forged = ciphertext1;
    forged[0] ^= 0x80;
    try testing.expectError(SessionError.AuthenticationFailed, sessions.bob.decrypt(&forged, nonce1, &decrypted, 20));
    try testing.expectEqual(@as(u64, nonce0), sessions.bob.recvMaxNonce());

    const pt_len = try sessions.bob.decrypt(&ciphertext1, nonce1, &decrypted, 30);
    try testing.expectEqualSlices(u8, "one!", decrypted[0..pt_len]);
    try testing.expectEqual(@as(u64, nonce1), sessions.bob.recvMaxNonce());
}

test "state transitions" {
    var sessions = createTestSessions();

    try testing.expectEqual(SessionState.established, sessions.alice.getState());
    sessions.alice.setState(.expired);
    try testing.expectEqual(SessionState.expired, sessions.alice.getState());

    var ct: [4 + tag_size]u8 = undefined;
    try testing.expectError(SessionError.NotEstablished, sessions.alice.encrypt("test", &ct, 0));
}

test "expiry" {
    var sessions = createTestSessions();
    try testing.expect(!sessions.alice.isExpired(0));
    try testing.expect(!sessions.alice.isExpired(session_timeout_ms));
    try testing.expect(sessions.alice.isExpired(session_timeout_ms + 1));

    sessions.alice.expire();
    try testing.expect(sessions.alice.isExpired(0));
}

test "generate index from bytes" {
    const bytes1 = [4]u8{ 1, 0, 0, 0 };
    const bytes2 = [4]u8{ 2, 0, 0, 0 };
    try testing.expect(generateIndexFromBytes(bytes1) != generateIndexFromBytes(bytes2));
}

test "timestamps" {
    var sessions = createTestSessions();
    try testing.expectEqual(@as(u64, 0), sessions.alice.createdMs());
    try testing.expectEqual(@as(u64, 0), sessions.alice.lastSentMs());
    try testing.expectEqual(@as(u64, 0), sessions.alice.lastReceivedMs());

    var ct: [4 + tag_size]u8 = undefined;
    _ = try sessions.alice.encrypt("test", &ct, 1000);
    try testing.expectEqual(@as(u64, 1000), sessions.alice.lastSentMs());

    var pt: [4]u8 = undefined;
    _ = try sessions.bob.decrypt(&ct, 0, &pt, 2000);
    try testing.expectEqual(@as(u64, 2000), sessions.bob.lastReceivedMs());
}
