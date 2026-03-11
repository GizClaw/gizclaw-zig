const std = @import("std");
const mem = std.mem;

const keypair_mod = @import("keypair.zig");
const crypto_mod = @import("crypto.zig");

const Key = keypair_mod.Key;
const key_size = keypair_mod.key_size;
const tag_size = crypto_mod.tag_size;
const hash_size = crypto_mod.hash_size;

pub const Pattern = enum {
    IK,
    XX,
    NN,

    fn name(self: Pattern) []const u8 {
        return switch (self) {
            .IK => "IK",
            .XX => "XX",
            .NN => "NN",
        };
    }

    fn responderPreMessage(self: Pattern) []const Token {
        return switch (self) {
            .IK => &[_]Token{.s},
            .XX, .NN => &[_]Token{},
        };
    }

    fn messagePatterns(self: Pattern) []const []const Token {
        return switch (self) {
            .IK => &[_][]const Token{
                &[_]Token{ .e, .es, .s, .ss },
                &[_]Token{ .e, .ee, .se },
            },
            .XX => &[_][]const Token{
                &[_]Token{.e},
                &[_]Token{ .e, .ee, .s, .es },
                &[_]Token{ .s, .se },
            },
            .NN => &[_][]const Token{
                &[_]Token{.e},
                &[_]Token{ .e, .ee },
            },
        };
    }
};

const Token = enum { e, s, ee, es, se, ss };

pub const Error = error{
    Finished,
    NotReady,
    InvalidMessage,
    MissingLocalStatic,
    MissingRemoteStatic,
    NotOurTurn,
    DecryptionFailed,
    DhFailed,
    LowOrderPoint,
};

pub fn Handshake(comptime Crypto: type) type {
    const KP = keypair_mod.KeyPair(Crypto);
    const c = crypto_mod.CryptoMod(Crypto);
    const state_mod = @import("state.zig").State(Crypto);
    const CipherState = state_mod.CipherState;
    const SymmetricState = state_mod.SymmetricState;

    return struct {
        pub const Config = struct {
            pattern: Pattern,
            initiator: bool,
            local_static: ?KP = null,
            remote_static: ?Key = null,
            prologue: []const u8 = "",
        };

        pub const HandshakeState = struct {
            pattern: Pattern,
            initiator: bool,
            local_static: ?KP,
            remote_static: Key,
            ss: SymmetricState,
            local_ephemeral: ?KP,
            remote_ephemeral: Key,
            msg_index: usize,
            finished: bool,

            pub fn init(config: Config) Error!HandshakeState {
                try validateConfig(config);

                var protocol_buf: [64]u8 = undefined;
                const protocol_name = std.fmt.bufPrint(&protocol_buf, "Noise_{s}_25519_{s}", .{ config.pattern.name(), c.suite_name }) catch unreachable;

                var ss = SymmetricState.init(protocol_name);
                ss.mixHash(config.prologue);

                var remote_static = Key.zero;

                if (config.initiator) {
                    for (config.pattern.responderPreMessage()) |token| {
                        if (token == .s) {
                            const rs = config.remote_static orelse return Error.MissingRemoteStatic;
                            ss.mixHash(rs.asBytes());
                            remote_static = rs;
                        }
                    }
                } else {
                    for (config.pattern.responderPreMessage()) |token| {
                        if (token == .s) {
                            const ls = config.local_static orelse return Error.MissingLocalStatic;
                            ss.mixHash(ls.public.asBytes());
                        }
                    }
                }

                return .{
                    .pattern = config.pattern,
                    .initiator = config.initiator,
                    .local_static = config.local_static,
                    .remote_static = remote_static,
                    .ss = ss,
                    .local_ephemeral = null,
                    .remote_ephemeral = Key.zero,
                    .msg_index = 0,
                    .finished = false,
                };
            }

            fn validateConfig(config: Config) Error!void {
                const needs_local_static = config.pattern == .IK or config.pattern == .XX;
                if (needs_local_static and config.local_static == null) {
                    return Error.MissingLocalStatic;
                }
                if (config.pattern == .IK and config.initiator and config.remote_static == null) {
                    return Error.MissingRemoteStatic;
                }
            }

            pub fn writeMessage(self: *HandshakeState, payload: []const u8, out: []u8) Error!usize {
                if (self.finished) return Error.Finished;

                const my_turn = (self.initiator and self.msg_index % 2 == 0) or
                    (!self.initiator and self.msg_index % 2 == 1);
                if (!my_turn) return Error.NotOurTurn;

                const patterns = self.pattern.messagePatterns();
                if (self.msg_index >= patterns.len) return Error.Finished;

                const tokens = patterns[self.msg_index];
                var offset: usize = 0;

                for (tokens) |token| {
                    switch (token) {
                        .e => {
                            var seed: [32]u8 = undefined;
                            Crypto.Rng.fill(&seed);
                            const ephemeral = KP.fromSeed(seed);
                            @memcpy(out[offset..][0..key_size], ephemeral.public.asBytes());
                            offset += key_size;
                            self.ss.mixHash(ephemeral.public.asBytes());
                            self.local_ephemeral = ephemeral;
                        },
                        .s => {
                            const ls = self.local_static orelse return Error.MissingLocalStatic;
                            if (self.ss.has_key) {
                                self.ss.encryptAndHash(ls.public.asBytes(), out[offset..][0 .. key_size + tag_size]);
                                offset += key_size + tag_size;
                            } else {
                                self.ss.encryptAndHash(ls.public.asBytes(), out[offset..][0..key_size]);
                                offset += key_size;
                            }
                        },
                        .ee => {
                            const le = self.local_ephemeral orelse return Error.InvalidMessage;
                            const shared = le.dh(self.remote_ephemeral) catch return Error.DhFailed;
                            self.ss.mixKey(shared.asBytes());
                        },
                        .es => {
                            const shared = if (self.initiator) blk: {
                                const le = self.local_ephemeral orelse return Error.InvalidMessage;
                                break :blk le.dh(self.remote_static) catch return Error.DhFailed;
                            } else blk: {
                                const ls = self.local_static orelse return Error.MissingLocalStatic;
                                break :blk ls.dh(self.remote_ephemeral) catch return Error.DhFailed;
                            };
                            self.ss.mixKey(shared.asBytes());
                        },
                        .se => {
                            const shared = if (self.initiator) blk: {
                                const ls = self.local_static orelse return Error.MissingLocalStatic;
                                break :blk ls.dh(self.remote_ephemeral) catch return Error.DhFailed;
                            } else blk: {
                                const le = self.local_ephemeral orelse return Error.InvalidMessage;
                                break :blk le.dh(self.remote_static) catch return Error.DhFailed;
                            };
                            self.ss.mixKey(shared.asBytes());
                        },
                        .ss => {
                            const ls = self.local_static orelse return Error.MissingLocalStatic;
                            const shared = ls.dh(self.remote_static) catch return Error.DhFailed;
                            self.ss.mixKey(shared.asBytes());
                        },
                    }
                }

                if (payload.len > 0 or self.msg_index == patterns.len - 1) {
                    if (self.ss.has_key) {
                        self.ss.encryptAndHash(payload, out[offset..][0 .. payload.len + tag_size]);
                        offset += payload.len + tag_size;
                    } else {
                        self.ss.encryptAndHash(payload, out[offset..][0..payload.len]);
                        offset += payload.len;
                    }
                }

                self.msg_index += 1;
                if (self.msg_index >= patterns.len) {
                    self.finished = true;
                }

                return offset;
            }

            pub fn readMessage(self: *HandshakeState, msg: []const u8, payload_out: []u8) Error!usize {
                if (self.finished) return Error.Finished;

                const my_turn = (self.initiator and self.msg_index % 2 == 0) or
                    (!self.initiator and self.msg_index % 2 == 1);
                if (my_turn) return Error.NotOurTurn;

                const patterns = self.pattern.messagePatterns();
                if (self.msg_index >= patterns.len) return Error.Finished;

                const tokens = patterns[self.msg_index];
                var offset: usize = 0;

                for (tokens) |token| {
                    switch (token) {
                        .e => {
                            if (offset + key_size > msg.len) return Error.InvalidMessage;
                            self.remote_ephemeral = Key.fromSlice(msg[offset..][0..key_size]) catch return Error.InvalidMessage;
                            offset += key_size;
                            self.ss.mixHash(self.remote_ephemeral.asBytes());
                        },
                        .s => {
                            if (self.ss.has_key) {
                                const encrypted_len = key_size + tag_size;
                                if (offset + encrypted_len > msg.len) return Error.InvalidMessage;
                                var rs_bytes: [key_size]u8 = undefined;
                                self.ss.decryptAndHash(msg[offset..][0..encrypted_len], &rs_bytes) catch return Error.DecryptionFailed;
                                self.remote_static = Key.fromBytes(rs_bytes);
                                offset += encrypted_len;
                            } else {
                                if (offset + key_size > msg.len) return Error.InvalidMessage;
                                var rs_bytes: [key_size]u8 = undefined;
                                self.ss.decryptAndHash(msg[offset..][0..key_size], &rs_bytes) catch return Error.DecryptionFailed;
                                self.remote_static = Key.fromBytes(rs_bytes);
                                offset += key_size;
                            }
                        },
                        .ee => {
                            const le = self.local_ephemeral orelse return Error.InvalidMessage;
                            const shared = le.dh(self.remote_ephemeral) catch return Error.DhFailed;
                            self.ss.mixKey(shared.asBytes());
                        },
                        .es => {
                            const shared = if (self.initiator) blk: {
                                const le = self.local_ephemeral orelse return Error.InvalidMessage;
                                break :blk le.dh(self.remote_static) catch return Error.DhFailed;
                            } else blk: {
                                const ls = self.local_static orelse return Error.MissingLocalStatic;
                                break :blk ls.dh(self.remote_ephemeral) catch return Error.DhFailed;
                            };
                            self.ss.mixKey(shared.asBytes());
                        },
                        .se => {
                            const shared = if (self.initiator) blk: {
                                const ls = self.local_static orelse return Error.MissingLocalStatic;
                                break :blk ls.dh(self.remote_ephemeral) catch return Error.DhFailed;
                            } else blk: {
                                const le = self.local_ephemeral orelse return Error.InvalidMessage;
                                break :blk le.dh(self.remote_static) catch return Error.DhFailed;
                            };
                            self.ss.mixKey(shared.asBytes());
                        },
                        .ss => {
                            const ls = self.local_static orelse return Error.MissingLocalStatic;
                            const shared = ls.dh(self.remote_static) catch return Error.DhFailed;
                            self.ss.mixKey(shared.asBytes());
                        },
                    }
                }

                const is_final_message = self.msg_index == patterns.len - 1;
                const must_read_payload = offset < msg.len or (self.ss.has_key and is_final_message);
                var payload_len: usize = 0;
                if (must_read_payload) {
                    const remaining = msg.len - offset;
                    if (self.ss.has_key) {
                        if (remaining < tag_size) return Error.InvalidMessage;
                        payload_len = remaining - tag_size;
                    } else {
                        payload_len = remaining;
                    }
                    self.ss.decryptAndHash(msg[offset..], payload_out[0..payload_len]) catch return Error.DecryptionFailed;
                }

                self.msg_index += 1;
                if (self.msg_index >= self.pattern.messagePatterns().len) {
                    self.finished = true;
                }

                return payload_len;
            }

            pub fn isFinished(self: HandshakeState) bool {
                return self.finished;
            }

            pub fn split(self: *const HandshakeState) Error!struct { CipherState, CipherState } {
                if (!self.finished) return Error.NotReady;

                const cs1, const cs2 = self.ss.split();
                if (self.initiator) {
                    return .{ cs1, cs2 };
                } else {
                    return .{ cs2, cs1 };
                }
            }

            pub fn getRemoteStatic(self: HandshakeState) Key {
                return self.remote_static;
            }

            pub fn getHash(self: *const HandshakeState) *const [hash_size]u8 {
                return self.ss.getHash();
            }

            pub fn localEphemeral(self: HandshakeState) ?Key {
                if (self.local_ephemeral) |le| return le.public;
                return null;
            }
        };
    };
}

const TestCrypto = @import("test_crypto.zig");
const TestHS = Handshake(TestCrypto);
const TestKP = keypair_mod.KeyPair(TestCrypto);
const TestHandshakeState = TestHS.HandshakeState;

test "handshake IK" {
    const initiator_static = TestKP.fromSeed([_]u8{11} ** 32);
    const responder_static = TestKP.fromSeed([_]u8{12} ** 32);

    var initiator = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = initiator_static,
        .remote_static = responder_static.public,
    });

    var responder = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = false,
        .local_static = responder_static,
    });

    var msg1: [256]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);

    var payload1: [64]u8 = undefined;
    _ = try responder.readMessage(msg1[0..msg1_len], &payload1);
    try std.testing.expect(responder.getRemoteStatic().eql(initiator_static.public));

    var msg2: [256]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);

    var payload2: [64]u8 = undefined;
    _ = try initiator.readMessage(msg2[0..msg2_len], &payload2);

    try std.testing.expect(initiator.isFinished());
    try std.testing.expect(responder.isFinished());

    var send_i, var recv_i = try initiator.split();
    var send_r, var recv_r = try responder.split();

    const plaintext = "hello from initiator";
    var ct: [plaintext.len + tag_size]u8 = undefined;
    send_i.encrypt(plaintext, "", &ct);

    var pt: [plaintext.len]u8 = undefined;
    try recv_r.decrypt(&ct, "", &pt);
    try std.testing.expectEqualSlices(u8, plaintext, &pt);

    const reply = "hello from responder";
    var ct2: [reply.len + tag_size]u8 = undefined;
    send_r.encrypt(reply, "", &ct2);

    var pt2: [reply.len]u8 = undefined;
    try recv_i.decrypt(&ct2, "", &pt2);
    try std.testing.expectEqualSlices(u8, reply, &pt2);
}

test "handshake NN" {
    var initiator = try TestHandshakeState.init(.{
        .pattern = .NN,
        .initiator = true,
    });

    var responder = try TestHandshakeState.init(.{
        .pattern = .NN,
        .initiator = false,
    });

    var msg1: [256]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);
    var p1: [64]u8 = undefined;
    _ = try responder.readMessage(msg1[0..msg1_len], &p1);

    var msg2: [256]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);
    var p2: [64]u8 = undefined;
    _ = try initiator.readMessage(msg2[0..msg2_len], &p2);

    try std.testing.expect(initiator.isFinished());
    try std.testing.expect(responder.isFinished());

    var send_i, _ = try initiator.split();
    _, var recv_r = try responder.split();

    const plaintext = "NN test";
    var ct: [plaintext.len + tag_size]u8 = undefined;
    send_i.encrypt(plaintext, "", &ct);

    var pt: [plaintext.len]u8 = undefined;
    try recv_r.decrypt(&ct, "", &pt);
    try std.testing.expectEqualSlices(u8, plaintext, &pt);
}

test "handshake errors" {
    const rs = TestKP.fromSeed([_]u8{13} ** 32);
    try std.testing.expectError(Error.MissingLocalStatic, TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .remote_static = rs.public,
    }));

    const ls = TestKP.fromSeed([_]u8{14} ** 32);
    try std.testing.expectError(Error.MissingRemoteStatic, TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = ls,
    }));
}

test "split before finish" {
    const initiator = try TestHandshakeState.init(.{
        .pattern = .NN,
        .initiator = true,
    });

    try std.testing.expectError(Error.NotReady, initiator.split());
}

test "handshake XX" {
    const initiator_static = TestKP.fromSeed([_]u8{21} ** 32);
    const responder_static = TestKP.fromSeed([_]u8{22} ** 32);

    var initiator = try TestHandshakeState.init(.{
        .pattern = .XX,
        .initiator = true,
        .local_static = initiator_static,
    });

    var responder = try TestHandshakeState.init(.{
        .pattern = .XX,
        .initiator = false,
        .local_static = responder_static,
    });

    var msg1: [256]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);
    var p1: [64]u8 = undefined;
    _ = try responder.readMessage(msg1[0..msg1_len], &p1);

    var msg2: [256]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);
    var p2: [64]u8 = undefined;
    _ = try initiator.readMessage(msg2[0..msg2_len], &p2);
    try std.testing.expect(initiator.getRemoteStatic().eql(responder_static.public));

    var msg3: [256]u8 = undefined;
    const msg3_len = try initiator.writeMessage("", &msg3);
    var p3: [64]u8 = undefined;
    _ = try responder.readMessage(msg3[0..msg3_len], &p3);
    try std.testing.expect(responder.getRemoteStatic().eql(initiator_static.public));

    try std.testing.expect(initiator.isFinished());
    try std.testing.expect(responder.isFinished());

    var send_i, var recv_i = try initiator.split();
    var send_r, var recv_r = try responder.split();

    const plaintext = "XX hello";
    var ct: [plaintext.len + tag_size]u8 = undefined;
    send_i.encrypt(plaintext, "", &ct);
    var pt: [plaintext.len]u8 = undefined;
    try recv_r.decrypt(&ct, "", &pt);
    try std.testing.expectEqualSlices(u8, plaintext, &pt);

    const reply = "XX reply";
    var ct2: [reply.len + tag_size]u8 = undefined;
    send_r.encrypt(reply, "", &ct2);
    var pt2: [reply.len]u8 = undefined;
    try recv_i.decrypt(&ct2, "", &pt2);
    try std.testing.expectEqualSlices(u8, reply, &pt2);
}

test "handshake IK with payload" {
    const initiator_static = TestKP.fromSeed([_]u8{31} ** 32);
    const responder_static = TestKP.fromSeed([_]u8{32} ** 32);

    var initiator = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = initiator_static,
        .remote_static = responder_static.public,
    });

    var responder = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = false,
        .local_static = responder_static,
    });

    var msg1: [512]u8 = undefined;
    const msg1_len = try initiator.writeMessage("init payload", &msg1);
    var payload1: [64]u8 = undefined;
    const p1_len = try responder.readMessage(msg1[0..msg1_len], &payload1);
    try std.testing.expectEqualSlices(u8, "init payload", payload1[0..p1_len]);

    var msg2: [512]u8 = undefined;
    const msg2_len = try responder.writeMessage("resp payload", &msg2);
    var payload2: [64]u8 = undefined;
    const p2_len = try initiator.readMessage(msg2[0..msg2_len], &payload2);
    try std.testing.expectEqualSlices(u8, "resp payload", payload2[0..p2_len]);
}

test "truncated handshake payload returns invalid message" {
    const initiator_static = TestKP.fromSeed([_]u8{41} ** 32);
    const responder_static = TestKP.fromSeed([_]u8{42} ** 32);

    var initiator = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = initiator_static,
        .remote_static = responder_static.public,
    });

    var msg: [512]u8 = undefined;
    const msg_len = try initiator.writeMessage("payload", &msg);

    // IK msg1 has encrypted payload (has_key is true after es+ss DH)
    try std.testing.expect(msg_len > key_size + tag_size);

    var responder = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = false,
        .local_static = responder_static,
    });

    var payload_out: [64]u8 = undefined;
    // Truncate the encrypted payload portion — should fail with either InvalidMessage or DecryptionFailed
    const min_tokens_len = key_size + key_size + tag_size; // e(32) + encrypted_s(32+16)
    for (1..tag_size) |trailing_len| {
        var resp_copy = try TestHandshakeState.init(.{
            .pattern = .IK,
            .initiator = false,
            .local_static = responder_static,
        });
        _ = &responder;
        if (resp_copy.readMessage(msg[0 .. min_tokens_len + trailing_len], &payload_out)) |_| {
            return error.TestExpectedError;
        } else |err| {
            try std.testing.expect(err == Error.InvalidMessage or err == Error.DecryptionFailed);
        }
    }
}

test "final encrypted handshake message requires trailing tag" {
    const initiator_static = TestKP.fromSeed([_]u8{51} ** 32);
    const responder_static = TestKP.fromSeed([_]u8{52} ** 32);

    var initiator = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = initiator_static,
        .remote_static = responder_static.public,
    });
    var responder = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = false,
        .local_static = responder_static,
    });

    var msg1: [256]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);
    var payload1: [1]u8 = undefined;
    _ = try responder.readMessage(msg1[0..msg1_len], &payload1);

    var msg2: [256]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);
    try std.testing.expect(msg2_len >= tag_size);

    var payload2: [1]u8 = undefined;
    try std.testing.expectError(
        Error.InvalidMessage,
        initiator.readMessage(msg2[0 .. msg2_len - tag_size], &payload2),
    );
    try std.testing.expect(!initiator.isFinished());
}

test "write when not our turn" {
    var initiator = try TestHandshakeState.init(.{
        .pattern = .NN,
        .initiator = true,
    });

    var msg: [256]u8 = undefined;
    _ = try initiator.writeMessage("", &msg);

    try std.testing.expectError(Error.NotOurTurn, initiator.writeMessage("", &msg));
}

test "handshake IK deterministic vector: split keys are consistent and asymmetric" {
    const seed_i = [_]u8{0x01} ** 32;
    const seed_r = [_]u8{0x02} ** 32;
    const initiator_static = TestKP.fromSeed(seed_i);
    const responder_static = TestKP.fromSeed(seed_r);

    var initiator = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = initiator_static,
        .remote_static = responder_static.public,
    });

    var responder = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = false,
        .local_static = responder_static,
    });

    var msg1: [512]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);
    try std.testing.expect(msg1_len > 0);

    var p1: [64]u8 = undefined;
    _ = try responder.readMessage(msg1[0..msg1_len], &p1);
    try std.testing.expect(responder.getRemoteStatic().eql(initiator_static.public));

    var msg2: [512]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);
    try std.testing.expect(msg2_len > 0);

    var p2: [64]u8 = undefined;
    _ = try initiator.readMessage(msg2[0..msg2_len], &p2);

    try std.testing.expect(initiator.isFinished());
    try std.testing.expect(responder.isFinished());

    var send_i, var recv_i = try initiator.split();
    var send_r, var recv_r = try responder.split();

    // Noise spec: initiator's send key == responder's recv key and vice versa
    try std.testing.expect(send_i.getKey().eql(recv_r.getKey()));
    try std.testing.expect(send_r.getKey().eql(recv_i.getKey()));

    // Send/recv keys must be different (asymmetric)
    try std.testing.expect(!send_i.getKey().eql(recv_i.getKey()));

    // Verify bidirectional data exchange
    const msg_a = "initiator to responder";
    var ct_a: [msg_a.len + tag_size]u8 = undefined;
    send_i.encrypt(msg_a, "", &ct_a);
    var pt_a: [msg_a.len]u8 = undefined;
    try recv_r.decrypt(&ct_a, "", &pt_a);
    try std.testing.expectEqualSlices(u8, msg_a, &pt_a);

    const msg_b = "responder to initiator";
    var ct_b: [msg_b.len + tag_size]u8 = undefined;
    send_r.encrypt(msg_b, "", &ct_b);
    var pt_b: [msg_b.len]u8 = undefined;
    try recv_i.decrypt(&ct_b, "", &pt_b);
    try std.testing.expectEqualSlices(u8, msg_b, &pt_b);

    // Cross-channel decryption must fail
    var pt_fail: [msg_a.len]u8 = undefined;
    try std.testing.expectError(error.DecryptionFailed, recv_i.decryptWithNonce(0, &ct_a, "", &pt_fail));
}

test "handshake IK message sizes are not fixed to 48 bytes" {
    const initiator_static = TestKP.fromSeed([_]u8{0x51} ** 32);
    const responder_static = TestKP.fromSeed([_]u8{0x52} ** 32);

    var initiator = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = initiator_static,
        .remote_static = responder_static.public,
    });

    var msg1: [512]u8 = undefined;
    const msg1_len = try initiator.writeMessage("extra payload data", &msg1);

    // IK msg1: e(32) + encrypted_s(32+16) + encrypted_payload(18+16) = 114
    // The payload portion makes it != the old hardcoded 48-byte assumption
    try std.testing.expect(msg1_len != 48);
    try std.testing.expect(msg1_len > key_size + 48);

    var responder = try TestHandshakeState.init(.{
        .pattern = .IK,
        .initiator = false,
        .local_static = responder_static,
    });

    var p1: [64]u8 = undefined;
    const p1_len = try responder.readMessage(msg1[0..msg1_len], &p1);
    try std.testing.expectEqualSlices(u8, "extra payload data", p1[0..p1_len]);
}
