const std = @import("std");
const runtime = @import("embed").runtime;
const consts = @import("consts.zig");
const errors = @import("errors.zig");
const endpoint_mod = @import("endpoint.zig");

const Allocator = std.mem.Allocator;
const Endpoint = endpoint_mod.Endpoint;
const ConnError = errors.ConnError;

fn encodeUvarint(buf: []u8, value: u64) usize {
    var n: usize = 0;
    var x = value;
    while (x >= 0x80) {
        buf[n] = @intCast((x & 0x7f) | 0x80);
        x >>= 7;
        n += 1;
    }
    buf[n] = @intCast(x);
    return n + 1;
}

fn decodeUvarint(data: []const u8) ConnError!struct { value: u64, bytes_read: usize } {
    var x: u64 = 0;
    var shift: u6 = 0;

    for (data, 0..) |byte, idx| {
        if (idx == 10) return ConnError.MessageError;
        const low = @as(u64, byte & 0x7f);
        if (idx == 9 and byte > 1) return ConnError.MessageError;

        x |= low << shift;
        if ((byte & 0x80) == 0) {
            return .{ .value = x, .bytes_read = idx + 1 };
        }
        shift += 7;
    }

    return ConnError.MessageError;
}

pub const ConnState = enum {
    new,
    handshaking,
    established,
    closed,
};

pub const max_inbound_queue = 64;

/// An inbound packet delivered by the listener.
pub const InboundPacket = struct {
    receiver_index: u32,
    counter: u64,
    ciphertext: []u8,
    addr: Endpoint,
    allocator: Allocator,

    pub fn deinit(self: *InboundPacket) void {
        self.allocator.free(self.ciphertext);
    }
};

/// Noise connection — manages handshake, session rotation, keepalive, rekey.
///
/// Generic over:
///   - `Session`    — Noise session (encrypt/decrypt/nonces/expire)
///   - `Handshake`  — Noise handshake state machine
///   - `Transport`  — datagram transport (sendTo/recvFrom)
///   - `MutexImpl`  — runtime Mutex
///   - `CondImpl`   — runtime Condition
///   - `TimeImpl`   — runtime Time (instance passed at init)
///
/// giztoy-zig is client-only, so Listener/accept is omitted.
pub fn Conn(
    comptime Session: type,
    comptime Handshake: type,
    comptime TransportImpl: type,
    comptime MutexImpl: type,
    comptime CondImpl: type,
    comptime TimeImpl: type,
) type {
    comptime {
        _ = runtime.sync.Mutex(MutexImpl);
        _ = runtime.sync.Condition(CondImpl);
        _ = runtime.time.from(TimeImpl);
    }

    return struct {
        const Self = @This();
        const max_plaintext_payload_size = 65535 - (1 + 4 + 8) - Session.tag_size - 11;

        allocator: Allocator,
        mu: MutexImpl,

        // Configuration
        local_key: Session.KeyPair,
        remote_pk: Session.Key,
        transport: TransportImpl,
        remote_addr: ?Endpoint,

        // State
        state: ConnState,
        local_idx: u32,

        // Session rotation (WireGuard-style)
        current: ?Session,
        previous: ?Session,

        // Handshake
        hs_state: ?Handshake,
        pending_local_idx: ?u32,
        handshake_attempt_start_ms: ?u64,
        last_handshake_sent_ms: ?u64,

        // Role
        is_initiator: bool,
        rekey_triggered: bool,

        // Timestamps (ms)
        session_created_ms: ?u64,
        last_sent_ms: ?u64,
        last_received_ms: ?u64,

        // Inbound queue for listener-managed connections
        inbound_queue: ?std.ArrayListUnmanaged(InboundPacket),
        inbound_signal: CondImpl,

        // Time instance
        time: TimeImpl,

        pub const Config = struct {
            local_key: Session.KeyPair,
            remote_pk: ?Session.Key = null,
            transport: TransportImpl,
            remote_addr: ?Endpoint = null,
        };

        pub fn init(allocator: Allocator, cfg: Config, time: TimeImpl) Self {
            return Self{
                .allocator = allocator,
                .mu = MutexImpl.init(),
                .local_key = cfg.local_key,
                .remote_pk = cfg.remote_pk orelse Session.Key.zero,
                .transport = cfg.transport,
                .remote_addr = cfg.remote_addr,
                .state = .new,
                .local_idx = Session.generateIndex(),
                .current = null,
                .previous = null,
                .hs_state = null,
                .pending_local_idx = null,
                .handshake_attempt_start_ms = null,
                .last_handshake_sent_ms = null,
                .is_initiator = false,
                .rekey_triggered = false,
                .session_created_ms = null,
                .last_sent_ms = null,
                .last_received_ms = null,
                .inbound_queue = null,
                .inbound_signal = CondImpl.init(),
                .time = time,
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            if (self.inbound_queue) |*queue| {
                for (queue.items) |*pkt| {
                    pkt.deinit();
                }
                queue.deinit(self.allocator);
            }
        }

        // -----------------------------------------------------------------
        // State accessors
        // -----------------------------------------------------------------

        pub fn getState(self: *Self) ConnState {
            self.mu.lock();
            defer self.mu.unlock();
            return self.state;
        }

        pub fn setState(self: *Self, new_state: ConnState) void {
            self.mu.lock();
            defer self.mu.unlock();
            self.state = new_state;
        }

        pub fn getRemotePublicKey(self: *Self) Session.Key {
            self.mu.lock();
            defer self.mu.unlock();
            return self.remote_pk;
        }

        pub fn getLocalIndex(self: *Self) u32 {
            return self.local_idx;
        }

        pub fn setRemoteAddr(self: *Self, addr: Endpoint) void {
            self.mu.lock();
            defer self.mu.unlock();
            self.remote_addr = addr;
        }

        pub fn setInitiator(self: *Self, is_initiator: bool) void {
            self.mu.lock();
            defer self.mu.unlock();
            self.is_initiator = is_initiator;
        }

        pub fn setSession(self: *Self, session: Session) void {
            self.mu.lock();
            defer self.mu.unlock();
            self.current = session;
            self.session_created_ms = self.time.nowMs();
            const now = self.time.nowMs();
            self.last_sent_ms = now;
            self.last_received_ms = now;
            self.rekey_triggered = false;
        }

        // -----------------------------------------------------------------
        // Send / Recv
        // -----------------------------------------------------------------

        pub fn send(self: *Self, service_port: u64, protocol: u8, payload: []const u8) ConnError!void {
            var remote_addr: Endpoint = undefined;
            const msg = blk: {
                self.mu.lock();
                defer self.mu.unlock();

                if (self.state != .established)
                    return ConnError.NotEstablished;
                remote_addr = self.remote_addr orelse return ConnError.MissingRemoteAddr;

                var session = &(self.current orelse return ConnError.NotEstablished);
                if (payload.len > max_plaintext_payload_size)
                    return ConnError.MessageTooLarge;

                var service_buf: [10]u8 = undefined;
                const service_len = encodeUvarint(&service_buf, service_port);
                const plaintext = self.allocator.alloc(u8, service_len + 1 + payload.len) catch return ConnError.OutOfMemory;
                defer self.allocator.free(plaintext);
                @memcpy(plaintext[0..service_len], service_buf[0..service_len]);
                plaintext[service_len] = protocol;
                @memcpy(plaintext[service_len + 1 ..], payload);

                const now = self.time.nowMs();
                const ciphertext = self.allocator.alloc(u8, plaintext.len + Session.tag_size) catch return ConnError.OutOfMemory;
                defer self.allocator.free(ciphertext);

                const counter = session.encrypt(plaintext, ciphertext, now) catch return ConnError.SessionError;
                break :blk Session.buildTransportMessage(self.allocator, session.remoteIndex(), counter, ciphertext) catch return ConnError.OutOfMemory;
            };
            defer self.allocator.free(msg);

            self.transport.sendTo(msg, remote_addr) catch return ConnError.TransportError;

            self.mu.lock();
            self.last_sent_ms = self.time.nowMs();
            self.mu.unlock();
        }

        pub const RecvResult = struct {
            service_port: u64,
            protocol: u8,
            bytes_read: usize,
        };

        pub fn recv(self: *Self, out_buf: []u8) ConnError!RecvResult {
            self.mu.lock();
            if (self.state != .established) {
                self.mu.unlock();
                return ConnError.NotEstablished;
            }

            if (self.inbound_queue) |*queue| {
                while (queue.items.len == 0 and self.state == .established) {
                    self.inbound_signal.wait(&self.mu);
                }
                if (self.state != .established) {
                    self.mu.unlock();
                    return ConnError.NotEstablished;
                }
                if (queue.items.len == 0) {
                    self.mu.unlock();
                    return ConnError.NotEstablished;
                }

                var pkt = queue.orderedRemove(0);
                defer pkt.deinit();

                if (pkt.ciphertext.len < Session.tag_size) {
                    self.mu.unlock();
                    return ConnError.MessageError;
                }

                var session = self.selectRecvSessionLocked(pkt.receiver_index) orelse {
                    self.mu.unlock();
                    return ConnError.InvalidReceiverIndex;
                };

                const plaintext_len = pkt.ciphertext.len - Session.tag_size;
                const plaintext = self.allocator.alloc(u8, plaintext_len) catch {
                    self.mu.unlock();
                    return ConnError.OutOfMemory;
                };
                defer self.allocator.free(plaintext);

                const now = self.time.nowMs();
                _ = session.decrypt(pkt.ciphertext, pkt.counter, plaintext, now) catch {
                    self.mu.unlock();
                    return ConnError.SessionError;
                };

                if (plaintext_len == 0) {
                    self.mu.unlock();
                    return ConnError.MessageError;
                }

                const service = try decodeUvarint(plaintext);
                if (plaintext_len <= service.bytes_read) {
                    self.mu.unlock();
                    return ConnError.MessageError;
                }

                const proto = plaintext[service.bytes_read];
                const payload = plaintext[service.bytes_read + 1 ..];
                const n = @min(out_buf.len, payload.len);
                @memcpy(out_buf[0..n], payload[0..n]);

                self.remote_addr = pkt.addr;
                self.last_received_ms = self.time.nowMs();
                self.mu.unlock();
                return RecvResult{ .service_port = service.value, .protocol = proto, .bytes_read = n };
            }
            self.mu.unlock();

            // Direct connection: read from transport
            var buf: [65536]u8 = undefined;
            const result = self.transport.recvFrom(&buf) catch return ConnError.TransportError;

            self.mu.lock();
            defer self.mu.unlock();

            if (self.state != .established)
                return ConnError.NotEstablished;

            const tmsg = Session.parseTransportMessage(buf[0..result.bytes_read]) catch return ConnError.MessageError;

            if (tmsg.ciphertext.len < Session.tag_size)
                return ConnError.MessageError;

            var session = self.selectRecvSessionLocked(tmsg.receiver_index) orelse
                return ConnError.InvalidReceiverIndex;

            const plaintext_len = tmsg.ciphertext.len - Session.tag_size;
            const plaintext = self.allocator.alloc(u8, plaintext_len) catch return ConnError.OutOfMemory;
            defer self.allocator.free(plaintext);

            const now = self.time.nowMs();
            _ = session.decrypt(tmsg.ciphertext, tmsg.counter, plaintext, now) catch return ConnError.SessionError;

            if (plaintext_len == 0)
                return ConnError.MessageError;

            const service = try decodeUvarint(plaintext);
            if (plaintext_len <= service.bytes_read)
                return ConnError.MessageError;

            const proto = plaintext[service.bytes_read];
            const payload = plaintext[service.bytes_read + 1 ..];
            const n = @min(out_buf.len, payload.len);
            @memcpy(out_buf[0..n], payload[0..n]);

            self.remote_addr = result.from_addr;
            self.last_received_ms = self.time.nowMs();
            return RecvResult{ .service_port = service.value, .protocol = proto, .bytes_read = n };
        }

        // -----------------------------------------------------------------
        // Inbound queue (for listener-managed connections)
        // -----------------------------------------------------------------

        pub fn setupInbound(self: *Self) void {
            self.mu.lock();
            defer self.mu.unlock();
            self.inbound_queue = .{};
        }

        pub fn deliverPacket(self: *Self, pkt: InboundPacket) bool {
            self.mu.lock();
            defer self.mu.unlock();

            if (self.state == .closed) return false;

            if (self.inbound_queue) |*queue| {
                if (queue.items.len >= max_inbound_queue) return false;
                queue.append(self.allocator, pkt) catch return false;
                self.inbound_signal.signal();
                return true;
            }
            return false;
        }

        fn selectRecvSessionLocked(self: *Self, receiver_index: u32) ?*Session {
            if (self.current) |*session| {
                if (receiver_index == session.localIndex()) return session;
            }
            if (self.previous) |*session| {
                if (receiver_index == session.localIndex()) return session;
            }
            return null;
        }

        // -----------------------------------------------------------------
        // Tick — periodic maintenance (WireGuard timer model)
        // -----------------------------------------------------------------

        pub fn tick(self: *Self) ConnError!void {
            const now = self.time.nowMs();

            var state: ConnState = undefined;
            var last_sent_ms: ?u64 = null;
            var last_recv_ms: ?u64 = null;
            var session_created_ms: ?u64 = null;
            var hs_attempt_start: ?u64 = null;
            var last_hs_sent: ?u64 = null;
            var is_initiator: bool = false;
            var rekey_triggered: bool = false;
            var has_hs: bool = false;
            var send_nonce: u64 = 0;
            var recv_nonce: u64 = 0;

            {
                self.mu.lock();
                defer self.mu.unlock();

                state = self.state;
                last_sent_ms = self.last_sent_ms;
                last_recv_ms = self.last_received_ms;
                session_created_ms = self.session_created_ms;
                hs_attempt_start = self.handshake_attempt_start_ms;
                last_hs_sent = self.last_handshake_sent_ms;
                is_initiator = self.is_initiator;
                rekey_triggered = self.rekey_triggered;
                has_hs = self.hs_state != null;

                if (self.current) |*session| {
                    send_nonce = session.sendNonce();
                    recv_nonce = session.recvMaxNonce();
                }
            }

            switch (state) {
                .new => return,
                .handshaking => {
                    if (hs_attempt_start) |start| {
                        if (now - start > consts.rekey_attempt_time_ms)
                            return ConnError.HandshakeTimeout;
                    }
                    if (has_hs) {
                        if (last_hs_sent) |sent| {
                            if (now - sent > consts.rekey_timeout_ms)
                                try self.retransmitHandshake();
                        }
                    }
                    return;
                },
                .established => {
                    if (last_recv_ms) |lr| {
                        if (now - lr > consts.reject_after_time_ms)
                            return ConnError.ConnTimeout;
                    }

                    if (send_nonce > consts.reject_after_messages or recv_nonce > consts.reject_after_messages)
                        return ConnError.SessionExpired;

                    if (has_hs) {
                        if (hs_attempt_start) |start| {
                            if (now - start > consts.rekey_attempt_time_ms)
                                return ConnError.HandshakeTimeout;
                        }
                        if (last_hs_sent) |sent| {
                            if (now - sent > consts.rekey_timeout_ms)
                                try self.retransmitHandshake();
                        }
                        return;
                    }

                    const disconnection_threshold = consts.keepalive_timeout_ms + consts.rekey_timeout_ms;
                    if (is_initiator) {
                        if (last_recv_ms) |lr| {
                            if (now - lr > disconnection_threshold) {
                                try self.initiateRekey();
                                return;
                            }
                        }
                    }

                    if (is_initiator and !rekey_triggered) {
                        var needs_rekey = false;
                        if (session_created_ms) |sc| {
                            if (now - sc > consts.rekey_after_time_ms)
                                needs_rekey = true;
                        }
                        if (send_nonce > consts.rekey_after_messages)
                            needs_rekey = true;

                        if (needs_rekey) {
                            try self.initiateRekey();
                            return;
                        }
                    }

                    return;
                },
                .closed => return ConnError.InvalidState,
            }
        }

        // -----------------------------------------------------------------
        // Handshake / Rekey
        // -----------------------------------------------------------------

        fn initiateRekey(self: *Self) ConnError!void {
            var remote_addr: Endpoint = undefined;
            var new_idx: u32 = undefined;
            {
                self.mu.lock();
                defer self.mu.unlock();
                if (self.hs_state != null) return;
                remote_addr = self.remote_addr orelse return ConnError.MissingRemoteAddr;
                new_idx = Session.generateIndex();
            }

            var hs = Handshake.init(.{
                .pattern = .IK,
                .initiator = true,
                .local_static = self.local_key,
                .remote_static = self.remote_pk,
            }) catch return ConnError.HandshakeFailed;

            var msg_buf: [65536]u8 = undefined;
            var wire_buf: [65541]u8 = undefined;
            const msg_len = hs.writeMessage(&.{}, &msg_buf) catch return ConnError.HandshakeFailed;

            const ephemeral = hs.localEphemeral() orelse return ConnError.HandshakeFailed;
            const wire_msg = Session.buildHandshakeInit(&wire_buf, new_idx, &ephemeral, msg_buf[Session.key_size..msg_len]) catch return ConnError.HandshakeFailed;

            self.transport.sendTo(wire_msg, remote_addr) catch return ConnError.TransportError;

            const now = self.time.nowMs();
            self.mu.lock();
            defer self.mu.unlock();

            if (self.hs_state != null) return;

            self.hs_state = hs;
            self.pending_local_idx = new_idx;
            self.handshake_attempt_start_ms = now;
            self.last_handshake_sent_ms = now;
            self.is_initiator = true;
            self.rekey_triggered = true;
        }

        fn retransmitHandshake(self: *Self) ConnError!void {
            var remote_addr: Endpoint = undefined;
            var local_idx: u32 = undefined;
            {
                self.mu.lock();
                defer self.mu.unlock();
                if (self.hs_state == null) return;
                remote_addr = self.remote_addr orelse return ConnError.MissingRemoteAddr;
                local_idx = self.pending_local_idx orelse self.local_idx;
            }

            var hs = Handshake.init(.{
                .pattern = .IK,
                .initiator = true,
                .local_static = self.local_key,
                .remote_static = self.remote_pk,
            }) catch return ConnError.HandshakeFailed;

            var msg_buf: [65536]u8 = undefined;
            var wire_buf: [65541]u8 = undefined;
            const msg_len = hs.writeMessage(&.{}, &msg_buf) catch return ConnError.HandshakeFailed;

            const ephemeral = hs.localEphemeral() orelse return ConnError.HandshakeFailed;
            const wire_msg = Session.buildHandshakeInit(&wire_buf, local_idx, &ephemeral, msg_buf[Session.key_size..msg_len]) catch return ConnError.HandshakeFailed;

            self.transport.sendTo(wire_msg, remote_addr) catch return ConnError.TransportError;

            const now = self.time.nowMs();
            self.mu.lock();
            defer self.mu.unlock();
            self.hs_state = hs;
            self.last_handshake_sent_ms = now;
        }

        pub fn completeHandshake(self: *Self, hs: *const Handshake, remote_idx: u32, remote_pk: ?Session.Key) ConnError!void {
            self.mu.lock();
            defer self.mu.unlock();

            if (!hs.isFinished())
                return ConnError.HandshakeIncomplete;

            const send_cipher, const recv_cipher = hs.split() catch return ConnError.HandshakeError;

            if (remote_pk) |pk| {
                self.remote_pk = pk;
            }

            if (self.previous) |*previous| {
                previous.expire();
            }
            if (self.current) |prev| {
                self.previous = prev;
            }

            const local_idx = self.pending_local_idx orelse self.local_idx;

            self.current = Session.init(.{
                .local_index = local_idx,
                .remote_index = remote_idx,
                .send_key = send_cipher.getKey(),
                .recv_key = recv_cipher.getKey(),
                .remote_pk = self.remote_pk,
                .now_ms = self.time.nowMs(),
            });

            const now = self.time.nowMs();
            self.local_idx = local_idx;
            self.state = .established;
            self.session_created_ms = now;
            self.last_sent_ms = now;
            self.last_received_ms = now;
            self.hs_state = null;
            self.pending_local_idx = null;
            self.handshake_attempt_start_ms = null;
            self.last_handshake_sent_ms = null;
            self.rekey_triggered = false;
        }

        // -----------------------------------------------------------------
        // Close
        // -----------------------------------------------------------------

        pub fn close(self: *Self) void {
            self.mu.lock();
            defer self.mu.unlock();

            if (self.state == .closed) return;
            self.state = .closed;
            self.pending_local_idx = null;
            if (self.current) |*session| {
                session.expire();
            }
            if (self.previous) |*session| {
                session.expire();
            }
            self.inbound_signal.broadcast();
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════
// Tests — real std runtime, mock Session / Transport
// ═══════════════════════════════════════════════════════════════════════

const testing = std.testing;
const rt = @import("embed").runtime;

const Mutex = rt.std.Mutex;
const Condition = rt.std.Condition;
const Time = rt.std.Time;

const MockSession = struct {
    pub const Key = struct {
        data: [32]u8 = [_]u8{0} ** 32,
        pub const zero = Key{};
        pub fn isZero(self: Key) bool {
            for (self.data) |b| {
                if (b != 0) return false;
            }
            return true;
        }
    };
    pub const KeyPair = struct { public: Key = Key{}, secret: Key = Key{} };

    pub const tag_size: usize = 4;
    pub const key_size: usize = 32;

    local_index: u32,
    remote_index: u32,
    created_ms: u64 = 0,
    last_received_ms: u64 = 0,
    last_sent_ms: u64 = 0,
    send_nonce_val: u64 = 0,
    recv_max_nonce_val: u64 = 0,
    expired: bool = false,

    pub fn generateIndex() u32 {
        const ts: u64 = @intCast(std.time.milliTimestamp());
        return @truncate(ts);
    }

    pub fn init(cfg: struct {
        local_index: u32,
        remote_index: u32,
        send_key: Key,
        recv_key: Key,
        remote_pk: Key,
        now_ms: u64,
    }) MockSession {
        _ = cfg.send_key;
        _ = cfg.recv_key;
        _ = cfg.remote_pk;
        return .{
            .local_index = cfg.local_index,
            .remote_index = cfg.remote_index,
            .created_ms = cfg.now_ms,
            .last_received_ms = cfg.now_ms,
            .last_sent_ms = cfg.now_ms,
        };
    }

    pub fn remoteIndex(self: *MockSession) u32 {
        return self.remote_index;
    }

    pub fn localIndex(self: *const MockSession) u32 {
        return self.local_index;
    }

    pub fn sendNonce(self: *MockSession) u64 {
        return self.send_nonce_val;
    }

    pub fn recvMaxNonce(self: *MockSession) u64 {
        return self.recv_max_nonce_val;
    }

    pub fn expire(self: *MockSession) void {
        self.expired = true;
    }

    pub fn encrypt(self: *MockSession, plaintext: []const u8, ciphertext: []u8, _: u64) !u64 {
        @memcpy(ciphertext[0..plaintext.len], plaintext);
        // tag = 4 bytes of 0xAA
        @memset(ciphertext[plaintext.len..][0..tag_size], 0xAA);
        self.send_nonce_val += 1;
        return self.send_nonce_val - 1;
    }

    pub fn decrypt(self: *MockSession, ciphertext: []const u8, _: u64, plaintext: []u8, _: u64) !usize {
        const payload_len = ciphertext.len - tag_size;
        @memcpy(plaintext[0..payload_len], ciphertext[0..payload_len]);
        self.recv_max_nonce_val += 1;
        return payload_len;
    }

    // Wire format: [4 receiver_index][8 counter][...ciphertext]
    pub fn buildTransportMessage(allocator: Allocator, receiver_index: u32, counter: u64, ciphertext: []const u8) ![]u8 {
        const msg = try allocator.alloc(u8, 4 + 8 + ciphertext.len);
        std.mem.writeInt(u32, msg[0..4], receiver_index, .little);
        std.mem.writeInt(u64, msg[4..12], counter, .little);
        @memcpy(msg[12..], ciphertext);
        return msg;
    }

    pub const TransportMsg = struct {
        receiver_index: u32,
        counter: u64,
        ciphertext: []const u8,
    };

    pub fn parseTransportMessage(data: []const u8) !TransportMsg {
        if (data.len < 12) return error.MessageTooShort;
        return TransportMsg{
            .receiver_index = std.mem.readInt(u32, data[0..4], .little),
            .counter = std.mem.readInt(u64, data[4..12], .little),
            .ciphertext = data[12..],
        };
    }

    pub fn buildHandshakeInit(out: []u8, _: u32, _: anytype, static_encrypted: []const u8) ![]u8 {
        const msg_len = 1 + 4 + 32 + static_encrypted.len;
        if (out.len < msg_len) return error.BufferTooSmall;
        @memset(out[0..msg_len], 0);
        return out[0..msg_len];
    }
};

const MockTransport = struct {
    const max_pkts = 256;
    const PktSlot = struct { data: [4096]u8 = undefined, len: usize = 0 };

    mu: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    queue: [max_pkts]PktSlot = [_]PktSlot{.{}} ** max_pkts,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    closed: bool = false,

    pub const RecvResult = struct {
        bytes_read: usize,
        from_addr: Endpoint,
    };

    pub fn sendTo(self: *MockTransport, data: []const u8, _: Endpoint) !void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.closed) return error.Closed;
        if (self.count >= max_pkts) return error.QueueFull;
        @memcpy(self.queue[self.tail].data[0..data.len], data);
        self.queue[self.tail].len = data.len;
        self.tail = (self.tail + 1) % max_pkts;
        self.count += 1;
        self.cond.signal();
    }

    pub fn recvFrom(self: *MockTransport, buf: []u8) !RecvResult {
        self.mu.lock();
        defer self.mu.unlock();
        while (self.count == 0 and !self.closed) {
            self.cond.wait(&self.mu);
        }
        if (self.count == 0) return error.Closed;
        const slot = &self.queue[self.head];
        const n = slot.len;
        @memcpy(buf[0..n], slot.data[0..n]);
        self.head = (self.head + 1) % max_pkts;
        self.count -= 1;
        return RecvResult{ .bytes_read = n, .from_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 9999) };
    }

    pub fn closeTx(self: *MockTransport) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.closed = true;
        self.cond.broadcast();
    }
};

const MockHandshake = struct {
    finished: bool = false,

    pub const InitConfig = struct {
        pattern: enum { IK },
        initiator: bool,
        local_static: MockSession.KeyPair,
        remote_static: MockSession.Key,
    };

    pub fn init(_: InitConfig) !MockHandshake {
        return .{};
    }

    pub fn writeMessage(_: *MockHandshake, _: []const u8, out: []u8) !usize {
        const msg_len = MockSession.key_size + 48;
        @memset(out[0..msg_len], 0);
        return msg_len;
    }

    pub fn readMessage(_: *MockHandshake, _: []const u8, _: []u8) !usize {
        return 0;
    }

    pub fn localEphemeral(_: *MockHandshake) ?MockSession.Key {
        return MockSession.Key{};
    }

    pub fn isFinished(self: *const MockHandshake) bool {
        return self.finished;
    }

    pub fn split(_: *const MockHandshake) !struct { MockCipher, MockCipher } {
        return .{ .{}, .{} };
    }

    const MockCipher = struct {
        pub fn getKey(_: MockCipher) MockSession.Key {
            return MockSession.Key{};
        }
    };
};

const TestConn = Conn(MockSession, MockHandshake, *MockTransport, Mutex, Condition, Time);

fn makeEstablishedConn(allocator: Allocator, transport: *MockTransport) TestConn {
    var c = TestConn.init(allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{1} ** 32 },
        .transport = transport,
        .remote_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 5000),
    }, Time{});

    c.state = .established;
    c.current = MockSession{
        .local_index = c.local_idx,
        .remote_index = 42,
    };
    const now = (Time{}).nowMs();
    c.session_created_ms = now;
    c.last_sent_ms = now;
    c.last_received_ms = now;
    return c;
}

// ── Basic state tests ───────────────────────────────────────────────

test "conn: new state" {
    var transport = MockTransport{};
    var c = TestConn.init(testing.allocator, .{
        .local_key = .{},
        .transport = &transport,
    }, Time{});
    defer c.deinit();

    try testing.expectEqual(ConnState.new, c.getState());
    try testing.expect(c.local_idx != 0);
}

test "conn: close transitions to closed" {
    var transport = MockTransport{};
    var c = TestConn.init(testing.allocator, .{
        .local_key = .{},
        .transport = &transport,
    }, Time{});

    c.close();
    try testing.expectEqual(ConnState.closed, c.getState());
    // double close is safe
    c.close();
    try testing.expectEqual(ConnState.closed, c.getState());
}

test "conn: send on non-established returns error" {
    var transport = MockTransport{};
    var c = TestConn.init(testing.allocator, .{
        .local_key = .{},
        .transport = &transport,
    }, Time{});
    defer c.deinit();

    try testing.expectError(ConnError.NotEstablished, c.send(7, 1, "hello"));
}

test "conn: recv on non-established returns error" {
    var transport = MockTransport{};
    var c = TestConn.init(testing.allocator, .{
        .local_key = .{},
        .transport = &transport,
    }, Time{});
    defer c.deinit();

    var buf: [64]u8 = undefined;
    try testing.expectError(ConnError.NotEstablished, c.recv(&buf));
}

// ── Send / Recv roundtrip via direct transport ──────────────────────

test "conn: send+recv roundtrip (direct transport)" {
    var a_to_b = MockTransport{};
    var b_to_a = MockTransport{};

    var a = makeEstablishedConn(testing.allocator, &a_to_b);
    defer a.deinit();
    var b = makeEstablishedConn(testing.allocator, &b_to_a);
    defer b.deinit();

    // Make B's local_idx match A's session remote_index so recv works
    b.local_idx = 42;
    b.current.?.local_index = 42;

    // A sends to B
    try a.send(7, 0x10, "hello from A");

    // Move packet from a_to_b into b_to_a (simulating network)
    var relay_buf: [4096]u8 = undefined;
    const r = try a_to_b.recvFrom(&relay_buf);
    try b_to_a.sendTo(relay_buf[0..r.bytes_read], Endpoint.init(.{ 127, 0, 0, 1 }, 5000));

    // B receives
    var out: [256]u8 = undefined;
    const result = try b.recv(&out);
    try testing.expectEqual(@as(u64, 7), result.service_port);
    try testing.expectEqual(@as(u8, 0x10), result.protocol);
    try testing.expectEqualStrings("hello from A", out[0..result.bytes_read]);
    b.mu.lock();
    defer b.mu.unlock();
    try testing.expect(b.remote_addr != null);
    try testing.expectEqual(@as(u16, 9999), b.remote_addr.?.port);
}

// ── Inbound queue tests (listener-style) ────────────────────────────

test "conn: inbound queue deliver and recv" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();
    c.setupInbound();

    // Build a fake ciphertext: service_port(varint) + protocol(1) + payload + tag(4)
    const service_port: u8 = 5;
    const payload = "inbound data";
    const plaintext_len = 2 + payload.len;
    const ct_len = plaintext_len + MockSession.tag_size;
    const ct = try testing.allocator.alloc(u8, ct_len);
    ct[0] = service_port;
    ct[1] = 0x20;
    @memcpy(ct[2..plaintext_len], payload);
    @memset(ct[plaintext_len..], 0xAA);

    const delivered = c.deliverPacket(.{
        .receiver_index = c.local_idx,
        .counter = 0,
        .ciphertext = ct,
        .addr = Endpoint.init(.{ 10, 0, 0, 1 }, 3000),
        .allocator = testing.allocator,
    });
    try testing.expect(delivered);

    var out: [256]u8 = undefined;
    const result = try c.recv(&out);
    try testing.expectEqual(@as(u64, service_port), result.service_port);
    try testing.expectEqual(@as(u8, 0x20), result.protocol);
    try testing.expectEqualStrings("inbound data", out[0..result.bytes_read]);
}

test "conn: deliver to closed conn returns false" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    c.setupInbound();
    c.close();

    const ct = try testing.allocator.alloc(u8, 8);
    defer testing.allocator.free(ct);
    @memset(ct, 0);

    try testing.expect(!c.deliverPacket(.{
        .receiver_index = c.local_idx,
        .counter = 0,
        .ciphertext = ct,
        .addr = Endpoint.zero,
        .allocator = testing.allocator,
    }));
}

// ── Tick tests ──────────────────────────────────────────────────────

test "conn: tick on new conn is no-op" {
    var transport = MockTransport{};
    var c = TestConn.init(testing.allocator, .{
        .local_key = .{},
        .transport = &transport,
    }, Time{});
    defer c.deinit();

    try c.tick();
}

test "conn: tick on closed conn returns InvalidState" {
    var transport = MockTransport{};
    var c = TestConn.init(testing.allocator, .{
        .local_key = .{},
        .transport = &transport,
    }, Time{});
    c.close();

    try testing.expectError(ConnError.InvalidState, c.tick());
}

test "conn: tick detects connection timeout" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    // Simulate old last_received
    c.mu.lock();
    c.last_received_ms = (Time{}).nowMs() - consts.reject_after_time_ms - 1000;
    c.mu.unlock();

    try testing.expectError(ConnError.ConnTimeout, c.tick());
}

test "conn: tick handshake timeout" {
    var transport = MockTransport{};
    var c = TestConn.init(testing.allocator, .{
        .local_key = .{},
        .transport = &transport,
    }, Time{});
    defer c.deinit();

    c.mu.lock();
    c.state = .handshaking;
    c.handshake_attempt_start_ms = (Time{}).nowMs() - consts.rekey_attempt_time_ms - 1000;
    c.mu.unlock();

    try testing.expectError(ConnError.HandshakeTimeout, c.tick());
}

test "conn: tick no action when recent" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    try c.tick();
}

test "conn: tick responder does not rekey" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    c.mu.lock();
    c.is_initiator = false;
    c.session_created_ms = (Time{}).nowMs() - consts.rekey_after_time_ms - 1000;
    c.mu.unlock();

    try c.tick();
    // Responder should NOT have hs_state
    c.mu.lock();
    defer c.mu.unlock();
    try testing.expect(c.hs_state == null);
}

test "conn: tick initiator triggers rekey after silence threshold" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    const now = (Time{}).nowMs();
    c.mu.lock();
    c.is_initiator = true;
    c.last_received_ms = now - (consts.keepalive_timeout_ms + consts.rekey_timeout_ms) - 1000;
    c.session_created_ms = now;
    c.mu.unlock();

    try c.tick();

    c.mu.lock();
    defer c.mu.unlock();
    try testing.expect(c.hs_state != null);
    try testing.expectEqual(c.current.?.local_index, c.local_idx);
    try testing.expect(c.pending_local_idx != null);
    try testing.expect(c.rekey_triggered);
    try testing.expect(c.handshake_attempt_start_ms != null);
    try testing.expect(c.last_handshake_sent_ms != null);
}

test "conn: rekey uses actual handshake message length (not hardcoded 48)" {
    const VariableLenHandshake = struct {
        finished: bool = false,

        pub const InitConfig = struct {
            pattern: enum { IK },
            initiator: bool,
            local_static: MockSession.KeyPair,
            remote_static: MockSession.Key,
        };

        pub fn init(_: InitConfig) !@This() {
            return .{};
        }

        pub fn writeMessage(_: *@This(), _: []const u8, out: []u8) !usize {
            const msg_len = MockSession.key_size + 64;
            @memset(out[0..msg_len], 0xAB);
            return msg_len;
        }

        pub fn readMessage(_: *@This(), _: []const u8, _: []u8) !usize {
            return 0;
        }

        pub fn localEphemeral(_: *@This()) ?MockSession.Key {
            return MockSession.Key{};
        }

        pub fn isFinished(self: *const @This()) bool {
            return self.finished;
        }

        pub fn split(_: *const @This()) !struct { MockCipher, MockCipher } {
            return .{ .{}, .{} };
        }

        const MockCipher = struct {
            pub fn getKey(_: MockCipher) MockSession.Key {
                return MockSession.Key{};
            }
        };
    };

    const RecordingTransport = struct {
        last_sent: [256]u8 = undefined,
        last_sent_len: usize = 0,

        pub const RecvResult = struct {
            bytes_read: usize,
            from_addr: Endpoint,
        };

        pub fn sendTo(self: *@This(), data: []const u8, _: Endpoint) !void {
            @memcpy(self.last_sent[0..data.len], data);
            self.last_sent_len = data.len;
        }

        pub fn recvFrom(_: *@This(), _: []u8) !RecvResult {
            return error.WouldBlock;
        }
    };

    const VarConn = Conn(MockSession, VariableLenHandshake, *RecordingTransport, Mutex, Condition, Time);

    var transport = RecordingTransport{};
    var c = VarConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{1} ** 32 },
        .transport = &transport,
        .remote_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 5000),
    }, Time{});
    defer c.deinit();

    c.state = .established;
    c.current = MockSession{ .local_index = c.local_idx, .remote_index = 42 };
    const now = (Time{}).nowMs();
    c.session_created_ms = now;
    c.last_sent_ms = now;
    c.last_received_ms = now;
    c.is_initiator = true;

    c.mu.lock();
    c.last_received_ms = now - (consts.keepalive_timeout_ms + consts.rekey_timeout_ms) - 1000;
    c.mu.unlock();

    try c.tick();

    try testing.expectEqual(@as(usize, 1 + 4 + MockSession.key_size + 64), transport.last_sent_len);
    c.mu.lock();
    defer c.mu.unlock();
    try testing.expect(c.hs_state != null);
}

// ── Concurrent send/recv test ───────────────────────────────────────

test "conn: concurrent send from multiple threads" {
    var a_to_b = MockTransport{};
    var a = makeEstablishedConn(testing.allocator, &a_to_b);
    defer a.deinit();

    const num_threads = 4;
    const msgs_per_thread = 20;

    const Worker = struct {
        fn run(conn_ptr: *TestConn, thread_id: u8) void {
            var i: usize = 0;
            while (i < msgs_per_thread) : (i += 1) {
                conn_ptr.send(0, thread_id, "concurrent msg") catch {};
            }
        }
    };

    var threads: [num_threads]std.Thread = undefined;
    for (0..num_threads) |t| {
        threads[t] = try std.Thread.spawn(.{}, Worker.run, .{ &a, @as(u8, @intCast(t)) });
    }
    for (&threads) |*th| {
        th.join();
    }

    // Drain the transport queue — should have num_threads * msgs_per_thread packets
    var count: usize = 0;
    var drain_buf: [4096]u8 = undefined;
    while (a_to_b.count > 0) {
        _ = a_to_b.recvFrom(&drain_buf) catch break;
        count += 1;
    }
    try testing.expectEqual(@as(usize, num_threads * msgs_per_thread), count);
}

// ── Close unblocks inbound recv ─────────────────────────────────────

test "conn: close unblocks blocked inbound recv" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    c.setupInbound();

    var recv_err: ?ConnError = null;
    const reader_thread = try std.Thread.spawn(.{}, struct {
        fn run(conn_ptr: *TestConn, err_out: *?ConnError) void {
            var buf: [64]u8 = undefined;
            _ = conn_ptr.recv(&buf) catch |e| {
                err_out.* = e;
                return;
            };
        }
    }.run, .{ &c, &recv_err });

    // Give the reader time to block on the empty inbound queue
    (Time{}).sleepMs(20);

    c.close();

    reader_thread.join();
    try testing.expectEqual(ConnError.NotEstablished, recv_err.?);
}

// ── Bidirectional ping-pong via direct transport ────────────────────

test "conn: bidirectional ping-pong" {
    var a_out = MockTransport{};
    var b_out = MockTransport{};

    var a = makeEstablishedConn(testing.allocator, &a_out);
    defer a.deinit();
    var b = makeEstablishedConn(testing.allocator, &b_out);
    defer b.deinit();

    b.local_idx = 42;
    b.current.?.local_index = 42;
    a.current.?.remote_index = b.local_idx;

    const rounds = 5;
    var i: usize = 0;
    while (i < rounds) : (i += 1) {
        // A -> B
        try a.send(1, 0x01, "ping");
        var relay: [4096]u8 = undefined;
        const r1 = try a_out.recvFrom(&relay);
        try b_out.sendTo(relay[0..r1.bytes_read], Endpoint.zero);

        var buf: [256]u8 = undefined;
        const res1 = try b.recv(&buf);
        try testing.expectEqual(@as(u64, 1), res1.service_port);
        try testing.expectEqualStrings("ping", buf[0..res1.bytes_read]);

        // B -> A
        try b.send(1, 0x02, "pong");
        const r2 = try b_out.recvFrom(&relay);
        // For A to recv, we need the receiver_index to match A's local_idx
        // Patch the wire message
        std.mem.writeInt(u32, relay[0..4], a.local_idx, .little);
        try a_out.sendTo(relay[0..r2.bytes_read], Endpoint.zero);

        const res2 = try a.recv(&buf);
        try testing.expectEqual(@as(u64, 1), res2.service_port);
        try testing.expectEqualStrings("pong", buf[0..res2.bytes_read]);
    }
}

pub fn StdConn(comptime Session: type, comptime Handshake: type, comptime TransportImpl: type) type {
    return Conn(
        Session,
        Handshake,
        TransportImpl,
        runtime.std.Mutex,
        runtime.std.Condition,
        runtime.std.Time,
    );
}

// ── setSession / setRemoteAddr ──────────────────────────────────────

test "conn: setSession transitions to usable state" {
    var transport = MockTransport{};
    var c = TestConn.init(testing.allocator, .{
        .local_key = .{},
        .transport = &transport,
        .remote_addr = Endpoint.init(.{ 10, 0, 0, 1 }, 8080),
    }, Time{});
    defer c.deinit();

    c.setSession(MockSession{ .local_index = c.local_idx, .remote_index = 99 });
    c.setState(.established);

    try testing.expectEqual(ConnState.established, c.getState());
    try testing.expect(c.session_created_ms != null);
    try testing.expect(c.last_sent_ms != null);
}

test "conn: completeHandshake seeds session timestamps from clock" {
    const FrozenTime = struct {
        pub fn nowMs(_: @This()) u64 {
            return 7777;
        }

        pub fn sleepMs(_: @This(), _: u32) void {}
    };
    const FrozenConn = Conn(MockSession, MockHandshake, *MockTransport, Mutex, Condition, FrozenTime);

    var transport = MockTransport{};
    var c = FrozenConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{1} ** 32 },
        .transport = &transport,
        .remote_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 5000),
    }, FrozenTime{});
    defer c.deinit();

    c.pending_local_idx = c.local_idx +% 1;
    var hs = MockHandshake{ .finished = true };
    try c.completeHandshake(&hs, 42, null);

    c.mu.lock();
    defer c.mu.unlock();
    try testing.expect(c.current != null);
    try testing.expectEqual(@as(u64, 7777), c.current.?.created_ms);
    try testing.expectEqual(@as(u64, 7777), c.current.?.last_sent_ms);
    try testing.expectEqual(@as(u64, 7777), c.current.?.last_received_ms);
}

test "conn: setRemoteAddr updates address" {
    var transport = MockTransport{};
    var c = TestConn.init(testing.allocator, .{
        .local_key = .{},
        .transport = &transport,
    }, Time{});
    defer c.deinit();

    const addr = Endpoint.init(.{ 192, 168, 1, 100 }, 4000);
    c.setRemoteAddr(addr);

    c.mu.lock();
    defer c.mu.unlock();
    try testing.expect(c.remote_addr != null);
    try testing.expect(c.remote_addr.?.eql(addr));
}

test "conn: send without remote address returns error" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    c.remote_addr = null;
    try testing.expectError(ConnError.MissingRemoteAddr, c.send(7, 1, "payload"));
}

test "conn: send rejects payloads above transport limit" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    const oversized_len = 65535 - (1 + 4 + 8) - MockSession.tag_size - 11 + 1;
    const payload = try testing.allocator.alloc(u8, oversized_len);
    defer testing.allocator.free(payload);
    @memset(payload, 0xAB);

    try testing.expectError(ConnError.MessageTooLarge, c.send(7, 1, payload));
}

test "conn: recv rejects too-short transport message" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    try transport.sendTo(&.{ 1, 2, 3 }, Endpoint.init(.{ 127, 0, 0, 1 }, 4000));

    var buf: [32]u8 = undefined;
    try testing.expectError(ConnError.MessageError, c.recv(&buf));
}

test "conn: recv rejects invalid receiver index on direct transport" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    const ciphertext = [_]u8{ 0, 1, 'x', 0xAA, 0xAA, 0xAA, 0xAA };
    const msg = try MockSession.buildTransportMessage(testing.allocator, c.local_idx + 1, 0, &ciphertext);
    defer testing.allocator.free(msg);
    try transport.sendTo(msg, Endpoint.init(.{ 127, 0, 0, 1 }, 4001));

    var buf: [32]u8 = undefined;
    try testing.expectError(ConnError.InvalidReceiverIndex, c.recv(&buf));
}

test "conn: direct recv does not update remote_addr on invalid packet" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    const original_addr = c.remote_addr.?;
    const ciphertext = [_]u8{ 0, 1, 'x', 0xAA, 0xAA, 0xAA, 0xAA };
    const msg = try MockSession.buildTransportMessage(testing.allocator, c.local_idx + 1, 0, &ciphertext);
    defer testing.allocator.free(msg);
    try transport.sendTo(msg, Endpoint.init(.{ 127, 0, 0, 1 }, 4001));

    var buf: [32]u8 = undefined;
    try testing.expectError(ConnError.InvalidReceiverIndex, c.recv(&buf));

    c.mu.lock();
    defer c.mu.unlock();
    try testing.expect(c.remote_addr != null);
    try testing.expect(c.remote_addr.?.eql(original_addr));
}

test "conn: recv rejects missing protocol byte after service varint" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    const ciphertext = [_]u8{ 0, 0xAA, 0xAA, 0xAA, 0xAA };
    const msg = try MockSession.buildTransportMessage(testing.allocator, c.local_idx, 0, &ciphertext);
    defer testing.allocator.free(msg);
    try transport.sendTo(msg, Endpoint.init(.{ 127, 0, 0, 1 }, 4002));

    var buf: [32]u8 = undefined;
    try testing.expectError(ConnError.MessageError, c.recv(&buf));
}

test "conn: recv accepts previous session packets during rekey" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    const old_idx = c.local_idx;
    const new_idx = old_idx +% 1;

    c.mu.lock();
    c.previous = c.current.?;
    c.current = MockSession{ .local_index = new_idx, .remote_index = 42 };
    c.local_idx = new_idx;
    c.mu.unlock();

    const ciphertext = [_]u8{ 7, 0x33, 'o', 'l', 'd', 0xAA, 0xAA, 0xAA, 0xAA };
    const msg = try MockSession.buildTransportMessage(testing.allocator, old_idx, 0, &ciphertext);
    defer testing.allocator.free(msg);
    try transport.sendTo(msg, Endpoint.init(.{ 127, 0, 0, 1 }, 4003));

    var buf: [32]u8 = undefined;
    const result = try c.recv(&buf);
    try testing.expectEqual(@as(u64, 7), result.service_port);
    try testing.expectEqual(@as(u8, 0x33), result.protocol);
    try testing.expectEqualStrings("old", buf[0..result.bytes_read]);
}

test "conn: recv rejects truncated ciphertext on direct transport" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();

    const truncated = [_]u8{ 1, 2, 3 };
    const msg = try MockSession.buildTransportMessage(testing.allocator, c.local_idx, 0, &truncated);
    defer testing.allocator.free(msg);
    try transport.sendTo(msg, Endpoint.init(.{ 127, 0, 0, 1 }, 4004));

    var buf: [32]u8 = undefined;
    try testing.expectError(ConnError.MessageError, c.recv(&buf));
}

test "conn: recv rejects truncated ciphertext in inbound queue" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();
    c.setupInbound();

    const truncated = try testing.allocator.dupe(u8, &.{ 1, 2, 3 });
    const delivered = c.deliverPacket(.{
        .receiver_index = c.local_idx,
        .counter = 0,
        .ciphertext = truncated,
        .addr = Endpoint.init(.{ 10, 0, 0, 1 }, 3001),
        .allocator = testing.allocator,
    });
    try testing.expect(delivered);

    var buf: [32]u8 = undefined;
    try testing.expectError(ConnError.MessageError, c.recv(&buf));
}

test "conn: inbound recv does not update remote_addr on invalid packet" {
    var transport = MockTransport{};
    var c = makeEstablishedConn(testing.allocator, &transport);
    defer c.deinit();
    c.setupInbound();

    const original_addr = c.remote_addr.?;
    const truncated = try testing.allocator.dupe(u8, &.{ 1, 2, 3 });
    const delivered = c.deliverPacket(.{
        .receiver_index = c.local_idx,
        .counter = 0,
        .ciphertext = truncated,
        .addr = Endpoint.init(.{ 10, 0, 0, 2 }, 3002),
        .allocator = testing.allocator,
    });
    try testing.expect(delivered);

    var buf: [32]u8 = undefined;
    try testing.expectError(ConnError.MessageError, c.recv(&buf));

    c.mu.lock();
    defer c.mu.unlock();
    try testing.expect(c.remote_addr != null);
    try testing.expect(c.remote_addr.?.eql(original_addr));
}

// ═══════════════════════════════════════════════════════════════════════
// Real UDP network tests
// ═══════════════════════════════════════════════════════════════════════

const posix = std.posix;
const net = std.net;

const UdpTransport = struct {
    fd: posix.fd_t,
    bound_port: u16,

    pub const RecvResult = struct {
        bytes_read: usize,
        from_addr: Endpoint,
    };

    fn open(bind_port: u16) !UdpTransport {
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        errdefer posix.close(fd);

        const bind_addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, bind_port);
        try posix.bind(fd, &bind_addr.any, bind_addr.getOsSockLen());

        var actual: net.Address = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(fd, &actual.any, &len);

        return .{ .fd = fd, .bound_port = actual.getPort() };
    }

    fn close(self: *UdpTransport) void {
        posix.close(self.fd);
    }

    pub fn sendTo(self: *UdpTransport, data: []const u8, ep: Endpoint) !void {
        const dest = net.Address.initIp4(ep.addr, ep.port);
        _ = try posix.sendto(self.fd, data, 0, &dest.any, dest.getOsSockLen());
    }

    pub fn recvFrom(self: *UdpTransport, buf: []u8) !RecvResult {
        var from: net.Address = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const n = try posix.recvfrom(self.fd, buf, 0, &from.any, &from_len);

        var ep_addr: [4]u8 = .{ 0, 0, 0, 0 };
        const sa4: *const posix.sockaddr.in = @ptrCast(@alignCast(&from.any));
        @memcpy(&ep_addr, @as(*const [4]u8, @ptrCast(&sa4.addr)));

        return RecvResult{
            .bytes_read = n,
            .from_addr = Endpoint.init(ep_addr, from.getPort()),
        };
    }
};

const UdpConn = Conn(MockSession, MockHandshake, *UdpTransport, Mutex, Condition, Time);

test "conn: real UDP send+recv roundtrip" {
    var sock_a = try UdpTransport.open(0);
    defer sock_a.close();
    var sock_b = try UdpTransport.open(0);
    defer sock_b.close();

    const addr_a = Endpoint.init(.{ 127, 0, 0, 1 }, sock_a.bound_port);
    const addr_b = Endpoint.init(.{ 127, 0, 0, 1 }, sock_b.bound_port);

    // A sends to B's socket, B reads from its own socket
    var conn_a = UdpConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{1} ** 32 },
        .transport = &sock_a,
        .remote_addr = addr_b,
    }, Time{});
    defer conn_a.deinit();

    conn_a.mu.lock();
    conn_a.state = .established;
    conn_a.current = MockSession{ .local_index = conn_a.local_idx, .remote_index = 77 };
    const now_a = (Time{}).nowMs();
    conn_a.session_created_ms = now_a;
    conn_a.last_sent_ms = now_a;
    conn_a.last_received_ms = now_a;
    conn_a.mu.unlock();

    // B's conn reads from sock_b
    var conn_b = UdpConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{2} ** 32 },
        .transport = &sock_b,
        .remote_addr = addr_a,
    }, Time{});
    defer conn_b.deinit();

    // B's local_idx must match A's session remote_index (77)
    conn_b.mu.lock();
    conn_b.local_idx = 77;
    conn_b.state = .established;
    conn_b.current = MockSession{ .local_index = 77, .remote_index = conn_a.local_idx };
    const now_b = (Time{}).nowMs();
    conn_b.session_created_ms = now_b;
    conn_b.last_sent_ms = now_b;
    conn_b.last_received_ms = now_b;
    conn_b.mu.unlock();

    // A sends "hello over UDP"
    try conn_a.send(11, 0x42, "hello over UDP");

    // B receives via real network
    var out: [256]u8 = undefined;
    const result = try conn_b.recv(&out);
    try testing.expectEqual(@as(u64, 11), result.service_port);
    try testing.expectEqual(@as(u8, 0x42), result.protocol);
    try testing.expectEqualStrings("hello over UDP", out[0..result.bytes_read]);
}

test "conn: real UDP bidirectional" {
    var sock_a = try UdpTransport.open(0);
    defer sock_a.close();
    var sock_b = try UdpTransport.open(0);
    defer sock_b.close();

    const addr_a = Endpoint.init(.{ 127, 0, 0, 1 }, sock_a.bound_port);
    const addr_b = Endpoint.init(.{ 127, 0, 0, 1 }, sock_b.bound_port);

    var conn_a = UdpConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{1} ** 32 },
        .transport = &sock_a,
        .remote_addr = addr_b,
    }, Time{});
    defer conn_a.deinit();

    var conn_b = UdpConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{2} ** 32 },
        .transport = &sock_b,
        .remote_addr = addr_a,
    }, Time{});
    defer conn_b.deinit();

    // Setup: A.remote_index = B.local_idx, B.remote_index = A.local_idx
    const a_idx = conn_a.local_idx;
    const b_idx: u32 = a_idx +% 1000;
    conn_b.local_idx = b_idx;

    conn_a.mu.lock();
    conn_a.state = .established;
    conn_a.current = MockSession{ .local_index = a_idx, .remote_index = b_idx };
    const now1 = (Time{}).nowMs();
    conn_a.session_created_ms = now1;
    conn_a.last_sent_ms = now1;
    conn_a.last_received_ms = now1;
    conn_a.mu.unlock();

    conn_b.mu.lock();
    conn_b.state = .established;
    conn_b.current = MockSession{ .local_index = b_idx, .remote_index = a_idx };
    const now2 = (Time{}).nowMs();
    conn_b.session_created_ms = now2;
    conn_b.last_sent_ms = now2;
    conn_b.last_received_ms = now2;
    conn_b.mu.unlock();

    var out: [256]u8 = undefined;

    // A -> B
    try conn_a.send(3, 0x01, "ping");
    const r1 = try conn_b.recv(&out);
    try testing.expectEqual(@as(u64, 3), r1.service_port);
    try testing.expectEqual(@as(u8, 0x01), r1.protocol);
    try testing.expectEqualStrings("ping", out[0..r1.bytes_read]);

    // B -> A
    try conn_b.send(3, 0x02, "pong");
    const r2 = try conn_a.recv(&out);
    try testing.expectEqual(@as(u64, 3), r2.service_port);
    try testing.expectEqual(@as(u8, 0x02), r2.protocol);
    try testing.expectEqualStrings("pong", out[0..r2.bytes_read]);
}

test "conn: real UDP concurrent senders" {
    var sock_a = try UdpTransport.open(0);
    defer sock_a.close();
    var sock_b = try UdpTransport.open(0);
    defer sock_b.close();

    const addr_b = Endpoint.init(.{ 127, 0, 0, 1 }, sock_b.bound_port);

    var conn_a = UdpConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{1} ** 32 },
        .transport = &sock_a,
        .remote_addr = addr_b,
    }, Time{});
    defer conn_a.deinit();

    const b_idx: u32 = 500;
    conn_a.mu.lock();
    conn_a.state = .established;
    conn_a.current = MockSession{ .local_index = conn_a.local_idx, .remote_index = b_idx };
    const now = (Time{}).nowMs();
    conn_a.session_created_ms = now;
    conn_a.last_sent_ms = now;
    conn_a.last_received_ms = now;
    conn_a.mu.unlock();

    const num_threads = 4;
    const msgs_per_thread = 10;

    var threads: [num_threads]std.Thread = undefined;
    for (0..num_threads) |t| {
        threads[t] = try std.Thread.spawn(.{}, struct {
            fn run(c: *UdpConn, tid: u8) void {
                var i: usize = 0;
                while (i < msgs_per_thread) : (i += 1) {
                    c.send(0, tid, "udp concurrent") catch {};
                }
            }
        }.run, .{ &conn_a, @as(u8, @intCast(t)) });
    }
    for (&threads) |*th| th.join();

    // Drain sock_b — should have received all packets over real loopback
    var count: usize = 0;
    var drain_buf: [4096]u8 = undefined;

    // Set a short recv timeout so we don't block forever
    const tv = posix.timeval{ .sec = 0, .usec = 200_000 };
    try posix.setsockopt(sock_b.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));

    while (true) {
        _ = posix.recvfrom(sock_b.fd, &drain_buf, 0, null, null) catch break;
        count += 1;
    }
    try testing.expectEqual(@as(usize, num_threads * msgs_per_thread), count);
}

test "conn: real UDP large message" {
    var sock_a = try UdpTransport.open(0);
    defer sock_a.close();
    var sock_b = try UdpTransport.open(0);
    defer sock_b.close();

    const addr_b = Endpoint.init(.{ 127, 0, 0, 1 }, sock_b.bound_port);
    const addr_a = Endpoint.init(.{ 127, 0, 0, 1 }, sock_a.bound_port);

    var conn_a = UdpConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{1} ** 32 },
        .transport = &sock_a,
        .remote_addr = addr_b,
    }, Time{});
    defer conn_a.deinit();

    var conn_b = UdpConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{2} ** 32 },
        .transport = &sock_b,
        .remote_addr = addr_a,
    }, Time{});
    defer conn_b.deinit();

    const a_idx = conn_a.local_idx;
    const b_idx: u32 = 999;
    conn_b.local_idx = b_idx;

    conn_a.mu.lock();
    conn_a.state = .established;
    conn_a.current = MockSession{ .local_index = a_idx, .remote_index = b_idx };
    const now1 = (Time{}).nowMs();
    conn_a.session_created_ms = now1;
    conn_a.last_sent_ms = now1;
    conn_a.last_received_ms = now1;
    conn_a.mu.unlock();

    conn_b.mu.lock();
    conn_b.state = .established;
    conn_b.current = MockSession{ .local_index = b_idx, .remote_index = a_idx };
    const now2 = (Time{}).nowMs();
    conn_b.session_created_ms = now2;
    conn_b.last_sent_ms = now2;
    conn_b.last_received_ms = now2;
    conn_b.mu.unlock();

    // Send a ~8KB payload (well within UDP limits on loopback)
    var big_payload: [8000]u8 = undefined;
    for (&big_payload, 0..) |*b, i| b.* = @truncate(i);

    try conn_a.send(13, 0x55, &big_payload);

    var out: [9000]u8 = undefined;
    const result = try conn_b.recv(&out);
    try testing.expectEqual(@as(u64, 13), result.service_port);
    try testing.expectEqual(@as(u8, 0x55), result.protocol);
    try testing.expectEqual(@as(usize, 8000), result.bytes_read);
    try testing.expectEqualSlices(u8, &big_payload, out[0..result.bytes_read]);
}

test "conn: real UDP recv updates from_addr (NAT traversal)" {
    var sock_a = try UdpTransport.open(0);
    defer sock_a.close();
    var sock_b = try UdpTransport.open(0);
    defer sock_b.close();

    const addr_b = Endpoint.init(.{ 127, 0, 0, 1 }, sock_b.bound_port);

    var conn_a = UdpConn.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = MockSession.Key{ .data = [_]u8{1} ** 32 },
        .transport = &sock_a,
        .remote_addr = addr_b,
    }, Time{});
    defer conn_a.deinit();

    const b_idx: u32 = 300;
    conn_a.mu.lock();
    conn_a.state = .established;
    conn_a.current = MockSession{ .local_index = conn_a.local_idx, .remote_index = b_idx };
    const now = (Time{}).nowMs();
    conn_a.session_created_ms = now;
    conn_a.last_sent_ms = now;
    conn_a.last_received_ms = now;
    conn_a.mu.unlock();

    // A sends a packet — it arrives at sock_b from A's ephemeral port
    try conn_a.send(0, 0x01, "nat test");

    // Read raw packet from sock_b to verify source address
    var raw: [4096]u8 = undefined;
    const recv_result = try sock_b.recvFrom(&raw);
    try testing.expect(recv_result.bytes_read > 0);
    try testing.expectEqual(@as(u8, 127), recv_result.from_addr.addr[0]);
    try testing.expectEqual(sock_a.bound_port, recv_result.from_addr.port);
}
