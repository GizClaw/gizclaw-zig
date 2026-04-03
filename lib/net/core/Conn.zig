const noise = @import("../noise.zig");

const consts = @import("consts.zig");
const errors = @import("errors.zig");
const protocol = @import("protocol.zig");

// Single-threaded: callers must serialize all Conn access.
pub const State = enum {
    new,
    handshaking,
    established,
    closed,
};

pub const TickAction = union(enum) {
    none,
    send_keepalive,
    rekey,
};

pub const DecryptResult = struct {
    protocol_byte: u8,
    payload: []const u8,
    used_previous: bool,
    should_rekey: bool,
};

pub fn make(comptime Noise: type) type {
    const Handshake = Noise.Handshake;
    const Session = Noise.Session;
    const KeyPair = Noise.KeyPair;

    return struct {
        local_static: KeyPair,
        remote_static: noise.Key = noise.Key.zero,
        local_index: u32,
        state_value: State = .new,
        current: ?Session = null,
        previous: ?Session = null,
        handshake: ?Handshake = null,
        handshake_started_ms: u64 = 0,
        handshake_attempt_start_ms: u64 = 0,
        last_handshake_sent_ms: u64 = 0,
        session_created_ms: u64 = 0,
        last_sent_ms: u64 = 0,
        last_received_ms: u64 = 0,
        is_initiator: bool = false,
        rekey_triggered: bool = false,

        const Self = @This();

        pub fn initInitiator(local_static: KeyPair, remote_static: noise.Key, local_index: u32) Self {
            return .{
                .local_static = local_static,
                .remote_static = remote_static,
                .local_index = local_index,
                .is_initiator = true,
            };
        }

        pub fn initResponder(local_static: KeyPair, local_index: u32) Self {
            return .{
                .local_static = local_static,
                .local_index = local_index,
                .is_initiator = false,
            };
        }

        pub fn state(self: *const Self) State {
            return self.state_value;
        }

        pub fn localIndex(self: *const Self) u32 {
            return self.local_index;
        }

        pub fn remotePublicKey(self: *const Self) noise.Key {
            return self.remote_static;
        }

        pub fn currentSession(self: *Self) ?*Session {
            if (self.current) |*session| return session;
            return null;
        }

        pub fn previousSession(self: *Self) ?*Session {
            if (self.previous) |*session| return session;
            return null;
        }

        pub fn close(self: *Self) void {
            self.handshake = null;
            self.current = null;
            self.previous = null;
            self.state_value = .closed;
        }

        pub fn beginHandshake(self: *Self, wire_out: []u8, now_ms: u64) !usize {
            if (self.state_value == .closed) return errors.Error.ConnClosed;
            if (self.remote_static.isZero()) return errors.Error.MissingRemotePublicKey;

            var handshake = try Handshake.init(.{
                .initiator = true,
                .local_static = self.local_static,
                .remote_static = self.remote_static,
            });

            var handshake_buf: [noise.Key.key_size + 96]u8 = undefined;
            const noise_len = try handshake.writeMessage("", &handshake_buf);
            const ephemeral = handshake.localEphemeralPublic() orelse return errors.Error.HandshakeIncomplete;
            const wire_len = try noise.Message.buildHandshakeInit(
                wire_out,
                self.local_index,
                ephemeral,
                handshake_buf[noise.Key.key_size..noise_len],
            );

            const had_inflight_handshake = self.handshake != null;
            self.handshake = handshake;
            self.handshake_started_ms = now_ms;
            if (!had_inflight_handshake or self.handshake_attempt_start_ms == 0) {
                self.handshake_attempt_start_ms = now_ms;
            }
            self.last_handshake_sent_ms = now_ms;
            if (self.current == null) self.state_value = .handshaking;
            self.is_initiator = true;
            return wire_len;
        }

        pub fn acceptHandshakeInit(self: *Self, data: []const u8, wire_out: []u8, now_ms: u64) !usize {
            if (self.state_value == .closed) return errors.Error.ConnClosed;

            const init_msg = try noise.Message.parseHandshakeInit(data);
            var handshake = try Handshake.init(.{
                .initiator = false,
                .local_static = self.local_static,
            });
            var discard: [0]u8 = .{};

            var noise_msg: [noise.Key.key_size + 96]u8 = undefined;
            @memcpy(noise_msg[0..noise.Key.key_size], init_msg.ephemeral.asBytes());
            @memcpy(noise_msg[noise.Key.key_size .. noise.Key.key_size + init_msg.ciphertext.len], init_msg.ciphertext);
            _ = try handshake.readMessage(noise_msg[0 .. noise.Key.key_size + init_msg.ciphertext.len], &discard);

            self.remote_static = handshake.remoteStatic();

            var response_msg: [noise.Key.key_size + 64]u8 = undefined;
            const response_len = try handshake.writeMessage("", &response_msg);
            const ephemeral = handshake.localEphemeralPublic() orelse return errors.Error.HandshakeIncomplete;

            const split = try handshake.split();
            const session = Session.init(.{
                .local_index = self.local_index,
                .remote_index = init_msg.sender_index,
                .send_key = split.send.getKey(),
                .recv_key = split.recv.getKey(),
                .remote_pk = self.remote_static,
            });
            self.installSession(session, now_ms);
            self.handshake = null;
            self.state_value = .established;
            self.is_initiator = false;

            return try noise.Message.buildHandshakeResp(
                wire_out,
                self.local_index,
                init_msg.sender_index,
                ephemeral,
                response_msg[noise.Key.key_size..response_len],
            );
        }

        pub fn handleHandshakeResponse(self: *Self, data: []const u8, now_ms: u64) !void {
            var discard: [0]u8 = .{};
            var handshake = if (self.handshake) |*value| value else return errors.Error.HandshakeIncomplete;
            const resp = try noise.Message.parseHandshakeResp(data);
            if (resp.receiver_index != self.local_index) return errors.Error.InvalidReceiverIndex;

            var noise_msg: [noise.Key.key_size + 64]u8 = undefined;
            @memcpy(noise_msg[0..noise.Key.key_size], resp.ephemeral.asBytes());
            @memcpy(noise_msg[noise.Key.key_size .. noise.Key.key_size + resp.ciphertext.len], resp.ciphertext);
            _ = try handshake.readMessage(noise_msg[0 .. noise.Key.key_size + resp.ciphertext.len], &discard);

            const split = try handshake.split();
            const session = Session.init(.{
                .local_index = self.local_index,
                .remote_index = resp.sender_index,
                .send_key = split.send.getKey(),
                .recv_key = split.recv.getKey(),
                .remote_pk = self.remote_static,
            });
            self.installSession(session, now_ms);
            self.handshake = null;
            self.state_value = .established;
        }

        pub fn send(
            self: *Self,
            protocol_byte: u8,
            payload: []const u8,
            plaintext_buf: []u8,
            ciphertext_buf: []u8,
            wire_out: []u8,
            now_ms: u64,
        ) !usize {
            if (self.state_value == .closed) return errors.Error.ConnClosed;
            try protocol.validate(protocol_byte);
            if (protocol.isStream(protocol_byte)) {
                return if (protocol_byte == protocol.rpc)
                    errors.Error.RPCMustUseStream
                else
                    errors.Error.HTTPMustUseStream;
            }

            const session = self.currentSession() orelse return errors.Error.NotEstablished;
            const plaintext_n = try noise.Message.encodePayload(plaintext_buf, protocol_byte, payload);
            const encrypted = try session.encrypt(plaintext_buf[0..plaintext_n], ciphertext_buf);
            const wire_n = try noise.Message.buildTransportMessage(
                wire_out,
                session.remoteIndex(),
                encrypted.nonce,
                ciphertext_buf[0..encrypted.n],
            );
            self.last_sent_ms = now_ms;
            return wire_n;
        }

        pub fn sendKeepalive(
            self: *Self,
            ciphertext_buf: []u8,
            wire_out: []u8,
            now_ms: u64,
        ) !usize {
            const session = self.currentSession() orelse return errors.Error.NotEstablished;
            const encrypted = try session.encrypt("", ciphertext_buf);
            const wire_n = try noise.Message.buildTransportMessage(
                wire_out,
                session.remoteIndex(),
                encrypted.nonce,
                ciphertext_buf[0..encrypted.n],
            );
            self.last_sent_ms = now_ms;
            return wire_n;
        }

        pub fn decryptPayload(self: *Self, data: []const u8, plaintext_out: []u8, now_ms: u64) !DecryptResult {
            if (self.state_value == .closed) return errors.Error.ConnClosed;

            const msg = try noise.Message.parseTransportMessage(data);
            var matched = false;
            var last_err: ?anyerror = null;

            if (self.current) |*current| {
                if (current.localIndex() == msg.receiver_index) {
                    matched = true;
                    if (current.decrypt(msg.ciphertext, msg.counter, plaintext_out)) |read| {
                        return self.finishDecrypt(current, plaintext_out[0..read], false, now_ms);
                    } else |err| {
                        last_err = err;
                    }
                }
            }

            if (self.previous) |*previous| {
                if (previous.localIndex() == msg.receiver_index) {
                    matched = true;
                    if (previous.decrypt(msg.ciphertext, msg.counter, plaintext_out)) |read| {
                        return self.finishDecrypt(previous, plaintext_out[0..read], true, now_ms);
                    } else |err| {
                        last_err = err;
                    }
                }
            }

            if (matched and last_err != null) return last_err.?;
            return errors.Error.InvalidReceiverIndex;
        }

        pub fn recv(self: *Self, data: []const u8, plaintext_out: []u8, now_ms: u64) !DecryptResult {
            const result = try self.decryptPayload(data, plaintext_out, now_ms);
            if (protocol.isStream(result.protocol_byte)) {
                return if (result.protocol_byte == protocol.rpc)
                    errors.Error.RPCMustUseStream
                else
                    errors.Error.HTTPMustUseStream;
            }
            return result;
        }

        pub fn tick(self: *Self, now_ms: u64, skip_keepalive: bool) !TickAction {
            if (self.state_value == .closed) return errors.Error.ConnClosed;

            if (self.handshake != null and self.handshake_attempt_start_ms != 0) {
                if (now_ms > self.handshake_attempt_start_ms and
                    now_ms - self.handshake_attempt_start_ms >= consts.rekey_attempt_time_ms)
                {
                    self.abortHandshakeAttempt();
                    return errors.Error.HandshakeTimeout;
                }
            }

            const session = self.currentSession() orelse return errors.Error.NotEstablished;
            if (session.isExpired()) {
                session.expire();
                return errors.Error.ConnTimeout;
            }

            if (self.is_initiator and !self.rekey_triggered) {
                if (now_ms >= self.session_created_ms and
                    now_ms - self.session_created_ms >= consts.rekey_after_time_ms)
                {
                    self.rekey_triggered = true;
                    return .rekey;
                }
                if (session.sendNonce() >= consts.rekey_after_messages) {
                    self.rekey_triggered = true;
                    return .rekey;
                }
            }

            if (!skip_keepalive and now_ms >= self.last_received_ms and now_ms >= self.last_sent_ms) {
                if (now_ms - self.last_received_ms >= consts.keepalive_timeout_ms and
                    now_ms - self.last_sent_ms >= consts.keepalive_timeout_ms)
                {
                    return .send_keepalive;
                }
            }

            return .none;
        }

        fn finishDecrypt(
            self: *Self,
            session: *Session,
            plaintext: []const u8,
            used_previous: bool,
            now_ms: u64,
        ) !DecryptResult {
            const decoded = try noise.Message.decodePayload(plaintext);
            self.last_received_ms = now_ms;
            return .{
                .protocol_byte = decoded.protocol,
                .payload = decoded.payload,
                .used_previous = used_previous,
                .should_rekey = self.is_initiator and !self.rekey_triggered and
                    now_ms >= self.session_created_ms and
                    now_ms - self.session_created_ms >= consts.rekey_on_recv_threshold_ms and
                    !used_previous and
                    session.getState() == .established,
            };
        }

        fn installSession(self: *Self, session: Session, now_ms: u64) void {
            if (self.current) |existing| {
                self.previous = existing;
            }
            self.current = session;
            self.handshake_attempt_start_ms = 0;
            self.handshake_started_ms = 0;
            self.last_handshake_sent_ms = 0;
            self.session_created_ms = now_ms;
            self.last_sent_ms = now_ms;
            self.last_received_ms = now_ms;
            self.rekey_triggered = false;
        }

        pub fn abortHandshakeAttempt(self: *Self) void {
            self.handshake = null;
            self.handshake_attempt_start_ms = 0;
            self.handshake_started_ms = 0;
            self.last_handshake_sent_ms = 0;
            if (self.current == null) self.state_value = .handshaking;
        }
    };
}

