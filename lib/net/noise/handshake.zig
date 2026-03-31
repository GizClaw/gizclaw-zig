const Key = @import("key.zig");
const KeyPair = @import("key_pair.zig").KeyPair;
const SymmetricState = @import("symmetric_state.zig").SymmetricState;
const lib_adapter = @import("lib_adapter.zig");
const errors = @import("errors.zig");

pub const Pattern = enum {
    IK,
};

pub fn Handshake(comptime Crypto: type) type {
    const KP = KeyPair(Crypto);
    const SS = SymmetricState(Crypto);
    const CS = @import("cipher_state.zig").CipherState(Crypto);

    return struct {
        pub const Config = struct {
            pattern: Pattern = .IK,
            initiator: bool,
            local_static: KP,
            remote_static: ?Key = null,
            prologue: []const u8 = "",
        };

        pub const SplitResult = struct {
            send: CS,
            recv: CS,
        };

        config: Config,
        symmetric_state: SS,
        local_ephemeral: ?KP = null,
        remote_ephemeral: Key = Key.zero,
        remote_static: Key = Key.zero,
        msg_index: usize = 0,
        finished: bool = false,

        const Self = @This();
        const protocol_name = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

        pub fn init(config: Config) errors.HandshakeError!Self {
            if (config.pattern != .IK) return errors.HandshakeError.UnsupportedPattern;
            if (config.initiator and config.remote_static == null) return errors.HandshakeError.MissingRemoteStatic;

            var symmetric_state = SS.init(protocol_name);
            symmetric_state.mixHash(config.prologue);

            var remote_static = Key.zero;
            if (config.initiator) {
                remote_static = config.remote_static.?;
                symmetric_state.mixHash(remote_static.asBytes());
            } else {
                symmetric_state.mixHash(config.local_static.public.asBytes());
            }

            return .{
                .config = config,
                .symmetric_state = symmetric_state,
                .remote_static = remote_static,
            };
        }

        pub fn isFinished(self: Self) bool {
            return self.finished;
        }

        pub fn remoteStatic(self: Self) Key {
            return self.remote_static;
        }

        pub fn localEphemeralPublic(self: Self) ?Key {
            if (self.local_ephemeral) |kp| return kp.public;
            return null;
        }

        pub fn writeMessage(self: *Self, payload: []const u8, out: []u8) !usize {
            if (self.finished) return errors.HandshakeError.Finished;
            if (!isMyTurn(self.*)) return errors.HandshakeError.WrongTurn;

            return switch (self.msg_index) {
                0 => self.writeInitiatorMessage(payload, out),
                1 => self.writeResponderMessage(payload, out),
                else => errors.HandshakeError.Finished,
            };
        }

        pub fn readMessage(self: *Self, message: []const u8, out: []u8) !usize {
            if (self.finished) return errors.HandshakeError.Finished;
            if (isMyTurn(self.*)) return errors.HandshakeError.WrongTurn;

            return switch (self.msg_index) {
                0 => self.readInitiatorMessage(message, out),
                1 => self.readResponderMessage(message, out),
                else => errors.HandshakeError.Finished,
            };
        }

        pub fn split(self: *Self) errors.HandshakeError!SplitResult {
            if (!self.finished) return errors.HandshakeError.NotReady;

            const cs1, const cs2 = self.symmetric_state.split();
            if (self.config.initiator) {
                return .{ .send = cs1, .recv = cs2 };
            }
            return .{ .send = cs2, .recv = cs1 };
        }

        fn writeInitiatorMessage(self: *Self, payload: []const u8, out: []u8) !usize {
            if (!self.config.initiator) return errors.HandshakeError.WrongTurn;

            const local_ephemeral = try KP.generate();
            self.local_ephemeral = local_ephemeral;

            var offset: usize = 0;
            @memcpy(out[offset..][0..Key.key_size], local_ephemeral.public.asBytes());
            offset += Key.key_size;
            self.symmetric_state.mixHash(local_ephemeral.public.asBytes());

            const es = try local_ephemeral.dh(self.remote_static);
            self.symmetric_state.mixKey(es.asBytes());

            offset += self.symmetric_state.encryptAndHash(self.config.local_static.public.asBytes(), out[offset..]);

            const ss = try self.config.local_static.dh(self.remote_static);
            self.symmetric_state.mixKey(ss.asBytes());

            offset += self.symmetric_state.encryptAndHash(payload, out[offset..]);

            self.msg_index += 1;
            return offset;
        }

        fn writeResponderMessage(self: *Self, payload: []const u8, out: []u8) !usize {
            if (self.config.initiator) return errors.HandshakeError.WrongTurn;

            const local_ephemeral = try KP.generate();
            self.local_ephemeral = local_ephemeral;

            var offset: usize = 0;
            @memcpy(out[offset..][0..Key.key_size], local_ephemeral.public.asBytes());
            offset += Key.key_size;
            self.symmetric_state.mixHash(local_ephemeral.public.asBytes());

            const ee = try local_ephemeral.dh(self.remote_ephemeral);
            self.symmetric_state.mixKey(ee.asBytes());

            const se = try local_ephemeral.dh(self.remote_static);
            self.symmetric_state.mixKey(se.asBytes());

            offset += self.symmetric_state.encryptAndHash(payload, out[offset..]);

            self.msg_index += 1;
            self.finished = true;
            return offset;
        }

        fn readInitiatorMessage(self: *Self, message: []const u8, out: []u8) !usize {
            if (self.config.initiator) return errors.HandshakeError.WrongTurn;
            if (message.len < Key.key_size + 48 + 16) return errors.HandshakeError.InvalidMessage;

            var offset: usize = 0;
            self.remote_ephemeral = try Key.fromSlice(message[offset .. offset + Key.key_size]);
            offset += Key.key_size;
            self.symmetric_state.mixHash(self.remote_ephemeral.asBytes());

            const es = try self.config.local_static.dh(self.remote_ephemeral);
            self.symmetric_state.mixKey(es.asBytes());

            var remote_static_bytes: [Key.key_size]u8 = undefined;
            const static_read = try self.symmetric_state.decryptAndHash(message[offset .. offset + 48], &remote_static_bytes);
            if (static_read != Key.key_size) return errors.HandshakeError.InvalidMessage;
            self.remote_static = Key.fromBytes(remote_static_bytes);
            offset += 48;

            const ss = try self.config.local_static.dh(self.remote_static);
            self.symmetric_state.mixKey(ss.asBytes());

            const payload_len = try self.symmetric_state.decryptAndHash(message[offset..], out);

            self.msg_index += 1;
            return payload_len;
        }

        fn readResponderMessage(self: *Self, message: []const u8, out: []u8) !usize {
            if (!self.config.initiator) return errors.HandshakeError.WrongTurn;
            if (message.len < Key.key_size + 16) return errors.HandshakeError.InvalidMessage;
            if (self.local_ephemeral == null) return errors.HandshakeError.InvalidMessage;

            var offset: usize = 0;
            self.remote_ephemeral = try Key.fromSlice(message[offset .. offset + Key.key_size]);
            offset += Key.key_size;
            self.symmetric_state.mixHash(self.remote_ephemeral.asBytes());

            const ee = try self.local_ephemeral.?.dh(self.remote_ephemeral);
            self.symmetric_state.mixKey(ee.asBytes());

            const se = try self.config.local_static.dh(self.remote_ephemeral);
            self.symmetric_state.mixKey(se.asBytes());

            const payload_len = try self.symmetric_state.decryptAndHash(message[offset..], out);

            self.msg_index += 1;
            self.finished = true;
            return payload_len;
        }

        fn isMyTurn(self: Self) bool {
            return (self.config.initiator and self.msg_index % 2 == 0) or
                (!self.config.initiator and self.msg_index % 2 == 1);
        }
    };
}

pub fn testAll(comptime lib: type, testing: anytype) !void {
    const Crypto = lib_adapter.make(lib);
    const H = Handshake(Crypto);
    const KP = KeyPair(Crypto);

    const alice_static = try KP.fromPrivate(Key.fromBytes([_]u8{1} ** Key.key_size));
    const bob_static = try KP.fromPrivate(Key.fromBytes([_]u8{2} ** Key.key_size));

    var initiator = try H.init(.{
        .initiator = true,
        .local_static = alice_static,
        .remote_static = bob_static.public,
        .prologue = "giztoy",
    });
    var responder = try H.init(.{
        .initiator = false,
        .local_static = bob_static,
        .prologue = "giztoy",
    });

    var msg1: [128]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);
    try testing.expectEqual(@as(usize, 96), msg1_len);

    var payload_buf: [32]u8 = undefined;
    const payload1_len = try responder.readMessage(msg1[0..msg1_len], &payload_buf);
    try testing.expectEqual(@as(usize, 0), payload1_len);
    try testing.expect(responder.remoteStatic().eql(alice_static.public));

    var msg2: [96]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);
    try testing.expectEqual(@as(usize, 48), msg2_len);

    const payload2_len = try initiator.readMessage(msg2[0..msg2_len], &payload_buf);
    try testing.expectEqual(@as(usize, 0), payload2_len);
    try testing.expect(initiator.isFinished());
    try testing.expect(responder.isFinished());

    var init_payload_initiator = try H.init(.{
        .initiator = true,
        .local_static = alice_static,
        .remote_static = bob_static.public,
        .prologue = "giztoy",
    });
    var init_payload_responder = try H.init(.{
        .initiator = false,
        .local_static = bob_static,
        .prologue = "giztoy",
    });
    const init_payload = "hi";
    const init_payload_len = try init_payload_initiator.writeMessage(init_payload, &msg1);
    try testing.expectEqual(@as(usize, 96 + init_payload.len), init_payload_len);
    const read_init_payload_len = try init_payload_responder.readMessage(
        msg1[0..init_payload_len],
        &payload_buf,
    );
    try testing.expectEqual(@as(usize, init_payload.len), read_init_payload_len);
    try testing.expectEqualSlices(u8, init_payload, payload_buf[0..read_init_payload_len]);

    var initiator_split = try initiator.split();
    var responder_split = try responder.split();

    const plaintext = "ping";
    var ciphertext: [plaintext.len + 16]u8 = undefined;
    _ = initiator_split.send.encrypt(plaintext, "", &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    const read = try responder_split.recv.decrypt(&ciphertext, "", &decrypted);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..read]);

    try testing.expectError(
        errors.HandshakeError.MissingRemoteStatic,
        H.init(.{ .initiator = true, .local_static = alice_static }),
    );

    var wrong_turn = try H.init(.{
        .initiator = false,
        .local_static = bob_static,
    });
    try testing.expectError(errors.HandshakeError.WrongTurn, wrong_turn.writeMessage("", &msg2));

    var mismatch_initiator = try H.init(.{
        .initiator = true,
        .local_static = alice_static,
        .remote_static = bob_static.public,
        .prologue = "giztoy",
    });
    var mismatch = try H.init(.{
        .initiator = false,
        .local_static = bob_static,
        .prologue = "wrong",
    });
    const mismatch_msg_len = try mismatch_initiator.writeMessage("", &msg1);
    try testing.expectError(
        error.AuthenticationFailed,
        mismatch.readMessage(msg1[0..mismatch_msg_len], &payload_buf),
    );
}
