const Key = @import("key.zig");
const ReplayFilter = @import("replay_filter.zig");
const cipher = @import("cipher.zig");
const lib_adapter = @import("lib_adapter.zig");
const errors = @import("errors.zig");

pub const State = enum {
    handshaking,
    established,
    expired,
};

pub const session_timeout_ms: u64 = 180_000;
pub const max_nonce: u64 = ~@as(u64, 0) - 1;

pub const Config = struct {
    local_index: u32,
    remote_index: u32 = 0,
    send_key: Key,
    recv_key: Key,
    remote_pk: Key = Key.zero,
    now_ms: u64 = 0,
};

pub fn Session(comptime Crypto: type) type {
    return struct {
        local_index: u32,
        remote_index: u32,
        send_key: Key,
        recv_key: Key,
        send_nonce: u64 = 0,
        recv_filter: ReplayFilter = ReplayFilter.init(),
        state: State = .established,
        remote_pk: Key,
        created_ms: u64,
        last_received_ms: u64,
        last_sent_ms: u64,

        const Self = @This();

        pub fn init(config: Config) Self {
            return .{
                .local_index = config.local_index,
                .remote_index = config.remote_index,
                .send_key = config.send_key,
                .recv_key = config.recv_key,
                .remote_pk = config.remote_pk,
                .created_ms = config.now_ms,
                .last_received_ms = config.now_ms,
                .last_sent_ms = config.now_ms,
            };
        }

        pub fn localIndex(self: *const Self) u32 {
            return self.local_index;
        }

        pub fn remoteIndex(self: *const Self) u32 {
            return self.remote_index;
        }

        pub fn setRemoteIndex(self: *Self, index: u32) void {
            self.remote_index = index;
        }

        pub fn remotePublicKey(self: *const Self) Key {
            return self.remote_pk;
        }

        pub fn getState(self: *const Self) State {
            return self.state;
        }

        pub fn setState(self: *Self, next: State) void {
            self.state = next;
        }

        pub fn encrypt(self: *Self, plaintext: []const u8, out: []u8, now_ms: u64) errors.SessionError!struct { nonce: u64, n: usize } {
            if (self.state != .established) return errors.SessionError.NotEstablished;

            const nonce = self.send_nonce;
            if (nonce >= max_nonce) return errors.SessionError.NonceExhausted;
            self.send_nonce += 1;

            const written = cipher.encrypt(Crypto, self.send_key.asBytes(), nonce, plaintext, "", out);
            self.last_sent_ms = now_ms;
            return .{ .nonce = nonce, .n = written };
        }

        pub fn decrypt(self: *Self, ciphertext: []const u8, nonce: u64, out: []u8, now_ms: u64) errors.SessionError!usize {
            if (self.state != .established) return errors.SessionError.NotEstablished;
            if (!self.recv_filter.check(nonce)) return errors.SessionError.ReplayDetected;

            const read = cipher.decrypt(Crypto, self.recv_key.asBytes(), nonce, ciphertext, "", out) catch |err| switch (err) {
                error.InvalidCiphertext => return errors.SessionError.InvalidCiphertext,
                error.AuthenticationFailed => return errors.SessionError.AuthenticationFailed,
            };

            self.recv_filter.update(nonce);
            self.last_received_ms = now_ms;
            return read;
        }

        pub fn isExpired(self: *const Self, now_ms: u64) bool {
            if (self.state == .expired) return true;
            if (now_ms < self.last_received_ms) return false;
            return (now_ms - self.last_received_ms) > session_timeout_ms;
        }

        pub fn expire(self: *Self) void {
            self.state = .expired;
        }

        pub fn sendNonce(self: *const Self) u64 {
            return self.send_nonce;
        }

        pub fn recvMaxNonce(self: *const Self) u64 {
            return self.recv_filter.maxNonce();
        }

        pub fn createdMs(self: *const Self) u64 {
            return self.created_ms;
        }

        pub fn lastReceivedMs(self: *const Self) u64 {
            return self.last_received_ms;
        }

        pub fn lastSentMs(self: *const Self) u64 {
            return self.last_sent_ms;
        }
    };
}

pub fn testAll(comptime lib: type, testing: anytype) !void {
    const Crypto = lib_adapter.make(lib);
    const T = Session(Crypto);
    const send_key = Key.fromBytes(cipher.hash(Crypto, &.{"send key"}));
    const recv_key = Key.fromBytes(cipher.hash(Crypto, &.{"recv key"}));

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

    const send = try alice.encrypt(plaintext, &ciphertext, 100);
    const read = try bob.decrypt(ciphertext[0..send.n], send.nonce, &decrypted, 200);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..read]);

    try testing.expectEqual(@as(u64, 1), alice.sendNonce());
    try testing.expectEqual(@as(u64, 0), bob.recvMaxNonce());
    try testing.expectEqual(@as(u64, 100), alice.lastSentMs());
    try testing.expectEqual(@as(u64, 200), bob.lastReceivedMs());

    try testing.expectError(
        errors.SessionError.ReplayDetected,
        bob.decrypt(ciphertext[0..send.n], send.nonce, &decrypted, 300),
    );

    var second_ciphertext: [4 + cipher.tag_size]u8 = undefined;
    const send2 = try alice.encrypt("one!", &second_ciphertext, 400);
    var forged = second_ciphertext;
    forged[0] ^= 0x80;
    try testing.expectError(
        errors.SessionError.AuthenticationFailed,
        bob.decrypt(forged[0..send2.n], send2.nonce, &decrypted, 500),
    );
    try testing.expectEqual(@as(u64, 0), bob.recvMaxNonce());

    bob.setState(.expired);
    try testing.expectError(
        errors.SessionError.NotEstablished,
        bob.decrypt(ciphertext[0..send.n], send.nonce, &decrypted, 600),
    );

    bob.setState(.established);
    try testing.expect(!bob.isExpired(200));
    try testing.expect(bob.isExpired(200 + session_timeout_ms + 1));
}
