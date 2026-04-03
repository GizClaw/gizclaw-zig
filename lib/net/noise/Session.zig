const Key = @import("Key.zig");
const ReplayFilterFile = @import("ReplayFilter.zig");
const cipher = @import("cipher.zig");
const errors = @import("errors.zig");

pub const State = enum(u8) {
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
};

pub fn make(comptime lib: type) type {
    const ReplayFilter = ReplayFilterFile.make(lib);

    return struct {
        local_index: u32,
        remote_index: lib.atomic.Value(u32),
        send_key: Key,
        recv_key: Key,
        send_nonce: lib.atomic.Value(u64) = lib.atomic.Value(u64).init(0),
        recv_filter: ReplayFilter = ReplayFilter.init(),
        state: lib.atomic.Value(u8),
        remote_pk: Key,
        created_ms: u64,
        last_received_ms: lib.atomic.Value(u64),
        last_sent_ms: lib.atomic.Value(u64),

        const Self = @This();

        pub fn init(config: Config) Self {
            const now = nowMs();
            return .{
                .local_index = config.local_index,
                .remote_index = lib.atomic.Value(u32).init(config.remote_index),
                .send_key = config.send_key,
                .recv_key = config.recv_key,
                .state = lib.atomic.Value(u8).init(@intFromEnum(State.established)),
                .remote_pk = config.remote_pk,
                .created_ms = now,
                .last_received_ms = lib.atomic.Value(u64).init(now),
                .last_sent_ms = lib.atomic.Value(u64).init(now),
            };
        }

        pub fn localIndex(self: *const Self) u32 {
            return self.local_index;
        }

        pub fn remoteIndex(self: *const Self) u32 {
            return self.remote_index.load(.seq_cst);
        }

        pub fn setRemoteIndex(self: *Self, index: u32) void {
            self.remote_index.store(index, .seq_cst);
        }

        pub fn remotePublicKey(self: *const Self) Key {
            return self.remote_pk;
        }

        pub fn getState(self: *const Self) State {
            return @enumFromInt(self.state.load(.seq_cst));
        }

        pub fn setState(self: *Self, next: State) void {
            self.state.store(@intFromEnum(next), .seq_cst);
        }

        pub fn encrypt(self: *Self, plaintext: []const u8, out: []u8) errors.SessionError!struct { nonce: u64, n: usize } {
            if (self.getState() != .established) return errors.SessionError.NotEstablished;

            const nonce = self.send_nonce.fetchAdd(1, .seq_cst);
            if (nonce >= max_nonce) return errors.SessionError.NonceExhausted;

            const written = cipher.encrypt(lib, self.send_key.asBytes(), nonce, plaintext, "", out);
            self.last_sent_ms.store(nowMs(), .seq_cst);
            return .{ .nonce = nonce, .n = written };
        }

        pub fn decrypt(self: *Self, ciphertext: []const u8, nonce: u64, out: []u8) errors.SessionError!usize {
            if (self.getState() != .established) return errors.SessionError.NotEstablished;
            const accepted = self.recv_filter.check(nonce);
            if (!accepted) return errors.SessionError.ReplayDetected;

            const read = cipher.decrypt(lib, self.recv_key.asBytes(), nonce, ciphertext, "", out) catch {
                return errors.SessionError.DecryptionFailed;
            };

            self.recv_filter.update(nonce);
            self.last_received_ms.store(nowMs(), .seq_cst);
            return read;
        }

        pub fn isExpired(self: *const Self) bool {
            if (self.getState() == .expired) return true;
            const now_ms = nowMs();
            const last_received_ms = self.last_received_ms.load(.seq_cst);
            if (now_ms < last_received_ms) return false;
            return (now_ms - last_received_ms) > session_timeout_ms;
        }

        pub fn expire(self: *Self) void {
            self.setState(.expired);
        }

        pub fn sendNonce(self: *const Self) u64 {
            return self.send_nonce.load(.seq_cst);
        }

        pub fn recvMaxNonce(self: *const Self) u64 {
            return @constCast(&self.recv_filter).maxNonce();
        }

        pub fn createdMs(self: *const Self) u64 {
            return self.created_ms;
        }

        pub fn lastReceivedMs(self: *const Self) u64 {
            return self.last_received_ms.load(.seq_cst);
        }

        pub fn testSetLastReceivedMs(self: *Self, value: u64) void {
            self.last_received_ms.store(value, .seq_cst);
        }

        pub fn lastSentMs(self: *const Self) u64 {
            return self.last_sent_ms.load(.seq_cst);
        }

        fn nowMs() u64 {
            const now = lib.time.milliTimestamp();
            if (now <= 0) return 0;
            return @intCast(now);
        }
    };
}
