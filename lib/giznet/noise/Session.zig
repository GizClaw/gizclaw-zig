const embed = @import("embed");
const mem = embed.std.mem;
const fmt = embed.std.fmt;

const Key = @import("Key.zig");
const AddrPort = embed.net.netip.AddrPort;

const Message = @import("Message.zig");
const Cipher = @import("Cipher.zig");

pub const min_packet_size_capacity: usize = Message.TransportHeaderSize + Message.tag_size;

// Preserve the historic 1024-byte payload budget for callers
// that still expose the old fixed-capacity API.
pub const legacy_packet_size_capacity: usize = min_packet_size_capacity + 1024;

pub fn make(
    comptime std: type,
    comptime packet_size_capacity_value: usize,
    comptime cipher_kind_value: Cipher.Kind,
) type {
    const capacity = packet_size_capacity_value;
    const CipherSuite = Cipher.make(std, cipher_kind_value);
    if (capacity < min_packet_size_capacity) {
        @compileError(fmt.comptimePrint(
            "noise.Session packet_size_capacity {} is smaller than minimum {}",
            .{ capacity, min_packet_size_capacity },
        ));
    }

    return struct {
        var started: ?std.time.Instant = null;

        pub const State = enum(u8) {
            established,
            expired,
        };

        pub const session_timeout_ms: u64 = 180_000;
        pub const replay_window_size: u64 = 2048;
        pub const replay_window_words: usize = replay_window_size / 64;
        pub const packet_size_capacity: usize = capacity;
        pub const cipher_kind: Cipher.Kind = cipher_kind_value;
        pub const outer_header_len: usize = Message.TransportHeaderSize;
        pub const tag_len: usize = CipherSuite.tag_size;
        pub const max_ciphertext_len: usize = packet_size_capacity - outer_header_len;
        pub const max_plaintext_len: usize = max_ciphertext_len - tag_len;
        pub const max_nonce: u64 = ~@as(u64, 0) - 1;

        pub const Config = struct {
            local_index: u32,
            remote_index: u32,
            peer_key: Key,
            endpoint: AddrPort,
            send_key: Key,
            recv_key: Key,
            key_phase: u8 = 0,
            timeout_ms: u64 = session_timeout_ms,
            now_ms: ?u64 = null,
        };

        local_index: u32,
        remote_index: u32,
        peer_key: Key,
        endpoint: AddrPort,
        send_key: Key,
        recv_key: Key,
        key_phase: u8,
        timeout_ms: u64,
        state: State = .established,
        send_nonce: u64 = 0,
        recv_seen_any: bool = false,
        recv_max_nonce: u64 = 0,
        recv_bitmap: [replay_window_words]u64 = [_]u64{0} ** replay_window_words,
        created_ms: u64,
        last_rx_ms: u64,
        last_tx_ms: u64,

        const Self = @This();

        pub fn init(config: Config) Self {
            const now_ms = config.now_ms orelse nowMs();
            return .{
                .local_index = config.local_index,
                .remote_index = config.remote_index,
                .peer_key = config.peer_key,
                .endpoint = config.endpoint,
                .send_key = config.send_key,
                .recv_key = config.recv_key,
                .key_phase = config.key_phase,
                .timeout_ms = config.timeout_ms,
                .created_ms = now_ms,
                .last_rx_ms = now_ms,
                .last_tx_ms = now_ms,
            };
        }

        pub fn canSend(self: Self) bool {
            return self.state == .established and !self.isExpired();
        }

        pub fn canRecv(self: Self) bool {
            return self.state == .established and !self.isExpired();
        }

        pub fn canSendAt(self: Self, now_ms: u64) bool {
            return self.state == .established and !self.isExpiredAt(now_ms);
        }

        pub fn canRecvAt(self: Self, now_ms: u64) bool {
            return self.state == .established and !self.isExpiredAt(now_ms);
        }

        pub fn markExpired(self: *Self) void {
            self.state = .expired;
        }

        pub fn localIndex(self: Self) u32 {
            return self.local_index;
        }

        pub fn remoteIndex(self: Self) u32 {
            return self.remote_index;
        }

        pub fn peerKey(self: Self) Key {
            return self.peer_key;
        }

        pub fn recvKey(self: Self) Key {
            return self.recv_key;
        }

        pub fn sendKey(self: Self) Key {
            return self.send_key;
        }

        pub fn endpointValue(self: Self) AddrPort {
            return self.endpoint;
        }

        pub fn setEndpoint(self: *Self, endpoint: AddrPort) void {
            self.endpoint = endpoint;
        }

        pub fn keyPhase(self: Self) u8 {
            return self.key_phase;
        }

        pub fn sendNonce(self: Self) u64 {
            return self.send_nonce;
        }

        pub fn claimSendCounter(self: *Self, now_ms: u64) !u64 {
            if (!self.canSendAt(now_ms)) return error.SessionExpired;
            if (self.send_nonce >= max_nonce) return error.NonceExhausted;

            const counter = self.send_nonce;
            self.send_nonce += 1;
            self.last_tx_ms = now_ms;
            return counter;
        }

        pub fn recvMaxNonce(self: Self) u64 {
            return self.recv_max_nonce;
        }

        pub fn createdMs(self: Self) u64 {
            return self.created_ms;
        }

        pub fn lastReceivedMs(self: Self) u64 {
            return self.last_rx_ms;
        }

        pub fn lastSentMs(self: Self) u64 {
            return self.last_tx_ms;
        }

        pub fn commitRecv(self: *Self, counter: u64, now_ms: u64) !void {
            if (!self.canRecvAt(now_ms)) return error.SessionExpired;
            try acceptNonce(self, counter);
            noteNonce(self, counter);
            self.last_rx_ms = now_ms;
        }

        pub fn isExpired(self: Self) bool {
            return self.isExpiredAt(nowMs());
        }

        pub fn isExpiredAt(self: Self, now_ms: u64) bool {
            if (self.state == .expired) return true;
            const last_activity_ms = @max(self.last_rx_ms, self.last_tx_ms);
            return now_ms >= last_activity_ms and (now_ms - last_activity_ms) >= self.timeout_ms;
        }

        fn acceptNonce(self: *Self, nonce: u64) !void {
            if (!self.recv_seen_any) return;
            if (nonce > self.recv_max_nonce) return;

            const delta = self.recv_max_nonce - nonce;
            if (delta >= replay_window_size) return error.ReplayDetected;

            const word_index: usize = @intCast(delta / 64);
            const bit_index: u6 = @intCast(delta % 64);
            if ((self.recv_bitmap[word_index] & (@as(u64, 1) << bit_index)) != 0) {
                return error.ReplayDetected;
            }
        }

        fn noteNonce(self: *Self, nonce: u64) void {
            if (!self.recv_seen_any) {
                self.recv_seen_any = true;
                self.recv_max_nonce = nonce;
                self.recv_bitmap[0] = 1;
                return;
            }

            if (nonce > self.recv_max_nonce) {
                slideWindow(self, nonce - self.recv_max_nonce);
                self.recv_max_nonce = nonce;
                self.recv_bitmap[0] |= 1;
                return;
            }

            const delta = self.recv_max_nonce - nonce;
            if (delta < replay_window_size) {
                const word_index: usize = @intCast(delta / 64);
                const bit_index: u6 = @intCast(delta % 64);
                self.recv_bitmap[word_index] |= @as(u64, 1) << bit_index;
            }
        }

        /// AEAD-decrypt a transport frame in `buffer[0..len]` and rewrite the buffer to
        /// plaintext payload bytes (same wire semantics as runtime `InboundPacket.decryptTransport`,
        /// but session-owned for single-threaded runtimes).
        pub fn decryptTransportBuffer(
            self: *const Self,
            comptime lib2: type,
            buffer: []u8,
            len: *usize,
        ) !void {
            const transport = Message.parseTransportMessage(buffer[0..len.*]) catch return error.InvalidTransportPacket;
            if (transport.receiver_index != self.local_index) return error.SessionIndexMismatch;
            if (transport.counter == std.math.maxInt(u64)) return error.InvalidTransportPacket;

            var scratch: [max_plaintext_len]u8 = undefined;
            const plaintext_len = transport.ciphertext.len - tag_len;
            if (scratch.len < plaintext_len) return error.BufferTooSmall;

            const CipherSuite2 = Cipher.make(lib2, cipher_kind);
            const written = CipherSuite2.decrypt(&self.recv_key, transport.counter, transport.ciphertext, "", scratch[0..plaintext_len]) catch |err| switch (err) {
                error.AuthenticationFailed => return error.AuthenticationFailed,
                else => return error.InvalidTransportPacket,
            };

            if (buffer.len < written) return error.BufferTooSmall;
            @memcpy(buffer[0..written], scratch[0..written]);
            len.* = written;
        }

        /// AEAD-encrypt `payload` into a full transport wire image in `out_buffer`.
        /// `counter` must match the engine-chosen send counter for this packet (already claimed).
        pub fn encryptTransportBuffer(
            self: *const Self,
            comptime lib2: type,
            payload: []const u8,
            out_buffer: []u8,
            counter: u64,
        ) !usize {
            var plaintext: [max_plaintext_len]u8 = undefined;
            const plaintext_len = try Message.encodePayload(payload, &plaintext);

            const ciphertext = out_buffer[outer_header_len..];
            if (ciphertext.len < plaintext_len + tag_len) return error.BufferTooSmall;

            const CipherSuite2 = Cipher.make(lib2, cipher_kind);
            const cipher_len = CipherSuite2.encrypt(
                &self.send_key,
                counter,
                plaintext[0..plaintext_len],
                "",
                ciphertext,
            );
            return try Message.buildTransportMessage(
                self.remote_index,
                counter,
                ciphertext[0..cipher_len],
                out_buffer,
            );
        }

        fn slideWindow(self: *Self, shift: u64) void {
            if (shift >= replay_window_size) {
                @memset(&self.recv_bitmap, 0);
                return;
            }

            const word_shift: usize = @intCast(shift / 64);
            const bit_shift: u6 = @intCast(shift % 64);

            if (word_shift > 0) {
                var index: usize = self.recv_bitmap.len;
                while (index > word_shift) {
                    index -= 1;
                    self.recv_bitmap[index] = self.recv_bitmap[index - word_shift];
                }
                for (self.recv_bitmap[0..word_shift]) |*word| word.* = 0;
            }

            if (bit_shift > 0) {
                var carry: u64 = 0;
                for (&self.recv_bitmap) |*word| {
                    const carry_shift: u6 = @intCast(64 - @as(u7, bit_shift));
                    const next_carry = word.* >> carry_shift;
                    word.* = (word.* << bit_shift) | carry;
                    carry = next_carry;
                }
            }
        }

        fn nowMs() u64 {
            const now = std.time.Instant.now() catch @panic("noise.Session requires std.time.Instant");
            if (started == null) {
                started = now;
                return 0;
            }
            return now.since(started.?) / std.time.ns_per_ms;
        }
    };
}

pub fn testRunner(comptime lib: type) embed.testing.TestRunner {
    const testing_api = embed.testing;
    const giznet = @import("../../giznet.zig");

    const Runner = struct {
        pub fn init(self: *@This(), allocator: mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase(lib) catch |err| {
                t.logErrorf("giznet/noise Session unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }

        fn tryCase(comptime any_lib: type) !void {
            const Session = make(any_lib, legacy_packet_size_capacity, Cipher.default_kind);

            const send_key = giznet.noise.Key{ .bytes = [_]u8{0x11} ** 32 };
            const recv_key = giznet.noise.Key{ .bytes = [_]u8{0x22} ** 32 };
            var sender = Session.init(.{
                .local_index = 1,
                .remote_index = 2,
                .peer_key = giznet.noise.Key{ .bytes = [_]u8{0x33} ** 32 },
                .endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 4000),
                .send_key = send_key,
                .recv_key = recv_key,
            });
            var receiver = Session.init(.{
                .local_index = 2,
                .remote_index = 1,
                .peer_key = giznet.noise.Key{ .bytes = [_]u8{0x44} ** 32 },
                .endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 4001),
                .send_key = recv_key,
                .recv_key = send_key,
            });

            try any_lib.testing.expectEqual(@as(u64, 0), sender.sendNonce());
            try any_lib.testing.expectEqual(@as(u64, 0), try sender.claimSendCounter(0));
            try any_lib.testing.expectEqual(@as(u64, 1), sender.sendNonce());
            try any_lib.testing.expectEqual(@as(u64, 1), try sender.claimSendCounter(1));
            try any_lib.testing.expectEqual(@as(u64, 2), sender.sendNonce());

            try receiver.commitRecv(0, 100);
            try any_lib.testing.expectEqual(@as(u64, 0), receiver.recvMaxNonce());
            try any_lib.testing.expectEqual(@as(u64, 100), receiver.lastReceivedMs());
            try any_lib.testing.expectError(error.ReplayDetected, receiver.commitRecv(0, 101));
            try receiver.commitRecv(2, 102);
            try any_lib.testing.expectEqual(@as(u64, 2), receiver.recvMaxNonce());
            try receiver.commitRecv(1, 103);
            try any_lib.testing.expectEqual(@as(u64, 103), receiver.lastReceivedMs());
            try any_lib.testing.expectError(error.ReplayDetected, receiver.commitRecv(1, 104));

            var timeout_sender = Session.init(.{
                .local_index = 1,
                .remote_index = 2,
                .peer_key = giznet.noise.Key{ .bytes = [_]u8{0x33} ** 32 },
                .endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 4000),
                .send_key = send_key,
                .recv_key = recv_key,
                .timeout_ms = 0,
            });
            try any_lib.testing.expect(!timeout_sender.canSend());
            try any_lib.testing.expectError(error.SessionExpired, timeout_sender.claimSendCounter(1));

            receiver.markExpired();
            try any_lib.testing.expect(!receiver.canRecv());
            try any_lib.testing.expectError(error.SessionExpired, receiver.commitRecv(3, 105));

            // Transport AEAD helpers (single-threaded runtime path).
            var wire_buf: [Session.packet_size_capacity]u8 = undefined;
            const payload = "hello-transport";
            const counter: u64 = 7;
            const written = try sender.encryptTransportBuffer(any_lib, payload, &wire_buf, counter);
            var rx_len: usize = written;
            var rx_buf: [Session.packet_size_capacity]u8 = undefined;
            @memcpy(rx_buf[0..rx_len], wire_buf[0..written]);
            try receiver.decryptTransportBuffer(any_lib, &rx_buf, &rx_len);
            try any_lib.testing.expectEqualStrings(payload, rx_buf[0..rx_len]);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
