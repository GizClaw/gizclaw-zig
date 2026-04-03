const Key = @import("Key.zig");
const KeyPairFile = @import("KeyPair.zig");
const SymmetricStateFile = @import("SymmetricState.zig");
const CipherStateFile = @import("CipherState.zig");
const cipher = @import("cipher.zig");
const errors = @import("errors.zig");

pub const Pattern = enum {
    IK,
    XX,
    NN,
};

const Token = enum {
    e,
    s,
    ee,
    es,
    se,
    ss,
};

const no_tokens = [_]Token{};

const ik_responder_pre = [_]Token{.s};
const ik_tokens_msg1 = [_]Token{ .e, .es, .s, .ss };
const ik_tokens_msg2 = [_]Token{ .e, .ee, .se };
const ik_messages = [_][]const Token{
    ik_tokens_msg1[0..],
    ik_tokens_msg2[0..],
};

const xx_tokens_msg1 = [_]Token{.e};
const xx_tokens_msg2 = [_]Token{ .e, .ee, .s, .es };
const xx_tokens_msg3 = [_]Token{ .s, .se };
const xx_messages = [_][]const Token{
    xx_tokens_msg1[0..],
    xx_tokens_msg2[0..],
    xx_tokens_msg3[0..],
};

const nn_tokens_msg1 = [_]Token{.e};
const nn_tokens_msg2 = [_]Token{ .e, .ee };
const nn_messages = [_][]const Token{
    nn_tokens_msg1[0..],
    nn_tokens_msg2[0..],
};

const PatternSpec = struct {
    protocol_name: []const u8,
    initiator_pre: []const Token,
    responder_pre: []const Token,
    messages: []const []const Token,
};

fn patternSpec(pattern: Pattern) PatternSpec {
    return switch (pattern) {
        .IK => .{
            .protocol_name = "Noise_IK_25519_ChaChaPoly_BLAKE2s",
            .initiator_pre = no_tokens[0..],
            .responder_pre = ik_responder_pre[0..],
            .messages = ik_messages[0..],
        },
        .XX => .{
            .protocol_name = "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            .initiator_pre = no_tokens[0..],
            .responder_pre = no_tokens[0..],
            .messages = xx_messages[0..],
        },
        .NN => .{
            .protocol_name = "Noise_NN_25519_ChaChaPoly_BLAKE2s",
            .initiator_pre = no_tokens[0..],
            .responder_pre = no_tokens[0..],
            .messages = nn_messages[0..],
        },
    };
}

pub fn make(comptime lib: type) type {
    const KP = KeyPairFile.make(lib);
    const SS = SymmetricStateFile.make(lib);
    const CS = CipherStateFile.make(lib);

    return struct {
        pub const Config = struct {
            pattern: Pattern = .IK,
            initiator: bool,
            local_static: ?KP = null,
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

        pub fn init(config: Config) errors.HandshakeError!Self {
            try validateConfig(config);

            const spec = patternSpec(config.pattern);
            var symmetric_state = SS.init(spec.protocol_name);
            symmetric_state.mixHash(config.prologue);

            var remote_static = Key.zero;
            if (config.initiator) {
                try mixPreMessages(&symmetric_state, config, spec.responder_pre, &remote_static, true);
                try mixPreMessages(&symmetric_state, config, spec.initiator_pre, &remote_static, false);
            } else {
                try mixPreMessages(&symmetric_state, config, spec.initiator_pre, &remote_static, true);
                try mixPreMessages(&symmetric_state, config, spec.responder_pre, &remote_static, false);
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

            const spec = patternSpec(self.config.pattern);
            if (self.msg_index >= spec.messages.len) return errors.HandshakeError.Finished;

            var offset: usize = 0;
            for (spec.messages[self.msg_index]) |token| {
                offset += try self.writeToken(token, out[offset..]);
            }

            offset += self.symmetric_state.encryptAndHash(payload, out[offset..]);
            self.advance();
            return offset;
        }

        pub fn readMessage(self: *Self, message: []const u8, out: []u8) !usize {
            if (self.finished) return errors.HandshakeError.Finished;
            if (isMyTurn(self.*)) return errors.HandshakeError.WrongTurn;

            const spec = patternSpec(self.config.pattern);
            if (self.msg_index >= spec.messages.len) return errors.HandshakeError.Finished;

            var offset: usize = 0;
            for (spec.messages[self.msg_index]) |token| {
                try self.readToken(token, message, &offset);
            }

            const payload = message[offset..];
            if (payload.len == 0) {
                if (self.symmetric_state.has_key) return errors.HandshakeError.InvalidMessage;
                const payload_len = try self.symmetric_state.decryptAndHash(payload, out);
                self.advance();
                return payload_len;
            }

            const payload_len = try self.symmetric_state.decryptAndHash(payload, out);
            self.advance();
            return payload_len;
        }

        pub fn split(self: *Self) errors.HandshakeError!SplitResult {
            if (!self.finished) return errors.HandshakeError.NotReady;

            const cs1, const cs2 = self.symmetric_state.split();
            if (self.config.initiator) {
                return .{ .send = cs1, .recv = cs2 };
            }
            return .{ .send = cs2, .recv = cs1 };
        }

        fn validateConfig(config: Config) errors.HandshakeError!void {
            switch (config.pattern) {
                .IK => {
                    if (config.local_static == null) return errors.HandshakeError.MissingLocalStatic;
                    if (config.initiator and config.remote_static == null) {
                        return errors.HandshakeError.MissingRemoteStatic;
                    }
                },
                .XX => {
                    if (config.local_static == null) return errors.HandshakeError.MissingLocalStatic;
                },
                .NN => {},
            }
        }

        fn mixPreMessages(
            symmetric_state: *SS,
            config: Config,
            tokens: []const Token,
            remote_static: *Key,
            use_remote_static: bool,
        ) errors.HandshakeError!void {
            for (tokens) |token| {
                switch (token) {
                    .s => {
                        if (use_remote_static) {
                            const value = config.remote_static orelse return errors.HandshakeError.MissingRemoteStatic;
                            symmetric_state.mixHash(value.asBytes());
                            remote_static.* = value;
                        } else {
                            const value = config.local_static orelse return errors.HandshakeError.MissingLocalStatic;
                            symmetric_state.mixHash(value.public.asBytes());
                        }
                    },
                    else => return errors.HandshakeError.UnsupportedPattern,
                }
            }
        }

        fn writeToken(self: *Self, token: Token, out: []u8) !usize {
            return switch (token) {
                .e => blk: {
                    const local_ephemeral = try KP.generate();
                    self.local_ephemeral = local_ephemeral;
                    @memcpy(out[0..Key.key_size], local_ephemeral.public.asBytes());
                    self.symmetric_state.mixHash(local_ephemeral.public.asBytes());
                    break :blk Key.key_size;
                },
                .s => blk: {
                    const local_static = try self.localStaticRequired();
                    break :blk self.symmetric_state.encryptAndHash(local_static.public.asBytes(), out);
                },
                .ee => blk: {
                    const local_ephemeral = try self.localEphemeralRequired();
                    const shared = try local_ephemeral.dh(try self.remoteEphemeralRequired());
                    self.symmetric_state.mixKey(shared.asBytes());
                    break :blk 0;
                },
                .es => blk: {
                    const shared = if (self.config.initiator)
                        try (try self.localEphemeralRequired()).dh(try self.remoteStaticRequired())
                    else
                        try (try self.localStaticRequired()).dh(try self.remoteEphemeralRequired());
                    self.symmetric_state.mixKey(shared.asBytes());
                    break :blk 0;
                },
                .se => blk: {
                    const shared = if (self.config.initiator)
                        try (try self.localStaticRequired()).dh(try self.remoteEphemeralRequired())
                    else
                        try (try self.localEphemeralRequired()).dh(try self.remoteStaticRequired());
                    self.symmetric_state.mixKey(shared.asBytes());
                    break :blk 0;
                },
                .ss => blk: {
                    const shared = try (try self.localStaticRequired()).dh(try self.remoteStaticRequired());
                    self.symmetric_state.mixKey(shared.asBytes());
                    break :blk 0;
                },
            };
        }

        fn readToken(self: *Self, token: Token, message: []const u8, offset: *usize) !void {
            switch (token) {
                .e => {
                    if (offset.* + Key.key_size > message.len) return errors.HandshakeError.InvalidMessage;
                    self.remote_ephemeral = try Key.fromSlice(message[offset.* .. offset.* + Key.key_size]);
                    offset.* += Key.key_size;
                    self.symmetric_state.mixHash(self.remote_ephemeral.asBytes());
                },
                .s => {
                    const encrypted_len: usize = if (self.symmetric_state.has_key)
                        Key.key_size + cipher.tag_size
                    else
                        Key.key_size;
                    if (offset.* + encrypted_len > message.len) return errors.HandshakeError.InvalidMessage;

                    var remote_static_bytes: [Key.key_size]u8 = undefined;
                    const static_read = try self.symmetric_state.decryptAndHash(
                        message[offset.* .. offset.* + encrypted_len],
                        &remote_static_bytes,
                    );
                    if (static_read != Key.key_size) return errors.HandshakeError.InvalidMessage;

                    self.remote_static = Key.fromBytes(remote_static_bytes);
                    offset.* += encrypted_len;
                },
                .ee => {
                    const local_ephemeral = try self.localEphemeralRequired();
                    const shared = try local_ephemeral.dh(try self.remoteEphemeralRequired());
                    self.symmetric_state.mixKey(shared.asBytes());
                },
                .es => {
                    const shared = if (self.config.initiator)
                        try (try self.localEphemeralRequired()).dh(try self.remoteStaticRequired())
                    else
                        try (try self.localStaticRequired()).dh(try self.remoteEphemeralRequired());
                    self.symmetric_state.mixKey(shared.asBytes());
                },
                .se => {
                    const shared = if (self.config.initiator)
                        try (try self.localStaticRequired()).dh(try self.remoteEphemeralRequired())
                    else
                        try (try self.localEphemeralRequired()).dh(try self.remoteStaticRequired());
                    self.symmetric_state.mixKey(shared.asBytes());
                },
                .ss => {
                    const shared = try (try self.localStaticRequired()).dh(try self.remoteStaticRequired());
                    self.symmetric_state.mixKey(shared.asBytes());
                },
            }
        }

        fn localStaticRequired(self: *const Self) errors.HandshakeError!KP {
            return self.config.local_static orelse errors.HandshakeError.MissingLocalStatic;
        }

        fn remoteStaticRequired(self: *const Self) errors.HandshakeError!Key {
            if (self.remote_static.isZero()) return errors.HandshakeError.MissingRemoteStatic;
            return self.remote_static;
        }

        fn localEphemeralRequired(self: *const Self) errors.HandshakeError!KP {
            return self.local_ephemeral orelse errors.HandshakeError.InvalidMessage;
        }

        fn remoteEphemeralRequired(self: *const Self) errors.HandshakeError!Key {
            if (self.remote_ephemeral.isZero()) return errors.HandshakeError.InvalidMessage;
            return self.remote_ephemeral;
        }

        fn advance(self: *Self) void {
            const spec = patternSpec(self.config.pattern);
            self.msg_index += 1;
            if (self.msg_index >= spec.messages.len) {
                self.finished = true;
            }
        }

        fn isMyTurn(self: Self) bool {
            return (self.config.initiator and self.msg_index % 2 == 0) or
                (!self.config.initiator and self.msg_index % 2 == 1);
        }
    };
}

