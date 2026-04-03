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
            return runCases(lib, lib.testing, t);
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

fn runCases(comptime lib: type, testing: anytype, t: *testing_api.T) bool {
    const H = noise.Handshake.make(lib);
    const KP = noise.KeyPair.make(lib);

    const alice_static = KP.fromPrivate(noise.Key.fromBytes([_]u8{1} ** noise.Key.key_size)) catch |err| {
        t.logErrorf("noise/Handshake/setup/alice_static failed: {}", .{err});
        return false;
    };
    const bob_static = KP.fromPrivate(noise.Key.fromBytes([_]u8{2} ** noise.Key.key_size)) catch |err| {
        t.logErrorf("noise/Handshake/setup/bob_static failed: {}", .{err});
        return false;
    };
    const xx_alice_static = KP.fromPrivate(noise.Key.fromBytes([_]u8{5} ** noise.Key.key_size)) catch |err| {
        t.logErrorf("noise/Handshake/setup/xx_alice_static failed: {}", .{err});
        return false;
    };
    const xx_bob_static = KP.fromPrivate(noise.Key.fromBytes([_]u8{6} ** noise.Key.key_size)) catch |err| {
        t.logErrorf("noise/Handshake/setup/xx_bob_static failed: {}", .{err});
        return false;
    };

    runIkRoundTrip(H, testing, alice_static, bob_static) catch |err| {
        t.logErrorf("noise/Handshake/ik_round_trip failed: {}", .{err});
        return false;
    };

    runIkInitPayload(H, testing, alice_static, bob_static) catch |err| {
        t.logErrorf("noise/Handshake/ik_init_payload failed: {}", .{err});
        return false;
    };

    runIkSplit(H, testing, alice_static, bob_static) catch |err| {
        t.logErrorf("noise/Handshake/ik_split failed: {}", .{err});
        return false;
    };

    runConfigErrors(H, testing, alice_static, bob_static) catch |err| {
        t.logErrorf("noise/Handshake/config_errors failed: {}", .{err});
        return false;
    };

    runXxMessage2(H, testing, xx_alice_static, xx_bob_static) catch |err| {
        t.logErrorf("noise/Handshake/xx_message2 failed: {}", .{err});
        return false;
    };

    runXxMessage3(H, testing, xx_alice_static, xx_bob_static) catch |err| {
        t.logErrorf("noise/Handshake/xx_message3 failed: {}", .{err});
        return false;
    };

    runXxSplit(H, testing, xx_alice_static, xx_bob_static) catch |err| {
        t.logErrorf("noise/Handshake/xx_split failed: {}", .{err});
        return false;
    };

    runNnRoundTrip(H, testing) catch |err| {
        t.logErrorf("noise/Handshake/nn_round_trip failed: {}", .{err});
        return false;
    };

    runPrologueMismatch(H, testing, alice_static, bob_static) catch |err| {
        t.logErrorf("noise/Handshake/prologue_mismatch failed: {}", .{err});
        return false;
    };

    return true;
}

fn runIkRoundTrip(
    comptime H: type,
    testing: anytype,
    alice_static: anytype,
    bob_static: anytype,
) !void {

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
}

fn runIkInitPayload(
    comptime H: type,
    testing: anytype,
    alice_static: anytype,
    bob_static: anytype,
) !void {
    var msg1: [128]u8 = undefined;
    var payload_buf: [32]u8 = undefined;

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
}

fn runIkSplit(
    comptime H: type,
    testing: anytype,
    alice_static: anytype,
    bob_static: anytype,
) !void {
    var msg1: [128]u8 = undefined;
    var payload_buf: [32]u8 = undefined;
    var msg2: [96]u8 = undefined;
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
    const msg1_len = try initiator.writeMessage("", &msg1);
    _ = try responder.readMessage(msg1[0..msg1_len], &payload_buf);
    const msg2_len = try responder.writeMessage("", &msg2);
    _ = try initiator.readMessage(msg2[0..msg2_len], &payload_buf);

    var initiator_split = try initiator.split();
    var responder_split = try responder.split();

    const plaintext = "ping";
    var ciphertext: [plaintext.len + noise.TagSize]u8 = undefined;
    _ = initiator_split.send.encrypt(plaintext, "", &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    const read = try responder_split.recv.decrypt(&ciphertext, "", &decrypted);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..read]);
}

fn runConfigErrors(
    comptime H: type,
    testing: anytype,
    alice_static: anytype,
    bob_static: anytype,
) !void {
    var msg2: [96]u8 = undefined;
    try testing.expectError(
        noise.HandshakeError.MissingRemoteStatic,
        H.init(.{ .initiator = true, .local_static = alice_static }),
    );

    var wrong_turn = try H.init(.{
        .initiator = false,
        .local_static = bob_static,
    });
    try testing.expectError(noise.HandshakeError.WrongTurn, wrong_turn.writeMessage("", &msg2));
}

fn runXxMessage2(
    comptime H: type,
    testing: anytype,
    xx_alice_static: anytype,
    xx_bob_static: anytype,
) !void {
    var payload_buf: [32]u8 = undefined;
    var xx_initiator = try H.init(.{
        .pattern = .XX,
        .initiator = true,
        .local_static = xx_alice_static,
    });
    var xx_responder = try H.init(.{
        .pattern = .XX,
        .initiator = false,
        .local_static = xx_bob_static,
    });

    var xx_msg1_buf: [64]u8 = undefined;
    const xx_msg1_len = try xx_initiator.writeMessage("", &xx_msg1_buf);
    try testing.expectEqual(@as(usize, 32), xx_msg1_len);
    try testing.expectEqual(@as(usize, 0), try xx_responder.readMessage(xx_msg1_buf[0..xx_msg1_len], &payload_buf));

    var xx_msg2_buf: [128]u8 = undefined;
    const xx_msg2_len = try xx_responder.writeMessage("", &xx_msg2_buf);
    try testing.expectEqual(@as(usize, 96), xx_msg2_len);
    try testing.expectEqual(@as(usize, 0), try xx_initiator.readMessage(xx_msg2_buf[0..xx_msg2_len], &payload_buf));
    try testing.expect(xx_initiator.remoteStatic().eql(xx_bob_static.public));
}

fn runXxMessage3(
    comptime H: type,
    testing: anytype,
    xx_alice_static: anytype,
    xx_bob_static: anytype,
) !void {
    var payload_buf: [32]u8 = undefined;
    var xx_initiator = try H.init(.{
        .pattern = .XX,
        .initiator = true,
        .local_static = xx_alice_static,
    });
    var xx_responder = try H.init(.{
        .pattern = .XX,
        .initiator = false,
        .local_static = xx_bob_static,
    });
    var xx_msg1_buf: [64]u8 = undefined;
    const xx_msg1_len = try xx_initiator.writeMessage("", &xx_msg1_buf);
    _ = try xx_responder.readMessage(xx_msg1_buf[0..xx_msg1_len], &payload_buf);
    var xx_msg2_buf: [128]u8 = undefined;
    const xx_msg2_len = try xx_responder.writeMessage("", &xx_msg2_buf);
    _ = try xx_initiator.readMessage(xx_msg2_buf[0..xx_msg2_len], &payload_buf);
    var xx_msg3_buf: [96]u8 = undefined;
    const xx_msg3_len = try xx_initiator.writeMessage("", &xx_msg3_buf);
    try testing.expectEqual(@as(usize, 64), xx_msg3_len);
    try testing.expectEqual(@as(usize, 0), try xx_responder.readMessage(xx_msg3_buf[0..xx_msg3_len], &payload_buf));
    try testing.expect(xx_responder.remoteStatic().eql(xx_alice_static.public));
    try testing.expect(xx_initiator.isFinished());
    try testing.expect(xx_responder.isFinished());
}

fn runXxSplit(
    comptime H: type,
    testing: anytype,
    xx_alice_static: anytype,
    xx_bob_static: anytype,
) !void {
    var payload_buf: [32]u8 = undefined;
    var xx_initiator = try H.init(.{
        .pattern = .XX,
        .initiator = true,
        .local_static = xx_alice_static,
    });
    var xx_responder = try H.init(.{
        .pattern = .XX,
        .initiator = false,
        .local_static = xx_bob_static,
    });
    var xx_msg1_buf: [64]u8 = undefined;
    const xx_msg1_len = try xx_initiator.writeMessage("", &xx_msg1_buf);
    _ = try xx_responder.readMessage(xx_msg1_buf[0..xx_msg1_len], &payload_buf);
    var xx_msg2_buf: [128]u8 = undefined;
    const xx_msg2_len = try xx_responder.writeMessage("", &xx_msg2_buf);
    _ = try xx_initiator.readMessage(xx_msg2_buf[0..xx_msg2_len], &payload_buf);
    var xx_msg3_buf: [96]u8 = undefined;
    const xx_msg3_len = try xx_initiator.writeMessage("", &xx_msg3_buf);
    _ = try xx_responder.readMessage(xx_msg3_buf[0..xx_msg3_len], &payload_buf);

    var xx_split_i = try xx_initiator.split();
    var xx_split_r = try xx_responder.split();
    var xx_ciphertext: [7 + noise.TagSize]u8 = undefined;
    _ = xx_split_i.send.encrypt("XX test", "", &xx_ciphertext);
    var xx_plaintext: [7]u8 = undefined;
    const xx_read = try xx_split_r.recv.decrypt(&xx_ciphertext, "", &xx_plaintext);
    try testing.expectEqualSlices(u8, "XX test", xx_plaintext[0..xx_read]);

    var xx_reply: [8 + noise.TagSize]u8 = undefined;
    _ = xx_split_r.send.encrypt("XX reply", "", &xx_reply);
    var xx_back: [8]u8 = undefined;
    const xx_back_n = try xx_split_i.recv.decrypt(&xx_reply, "", &xx_back);
    try testing.expectEqualSlices(u8, "XX reply", xx_back[0..xx_back_n]);
}

fn runNnRoundTrip(comptime H: type, testing: anytype) !void {
    var payload_buf: [32]u8 = undefined;
    var nn_initiator = try H.init(.{
        .pattern = .NN,
        .initiator = true,
    });
    var nn_responder = try H.init(.{
        .pattern = .NN,
        .initiator = false,
    });

    var nn_msg1_buf: [64]u8 = undefined;
    const nn_msg1_len = try nn_initiator.writeMessage("", &nn_msg1_buf);
    try testing.expectEqual(@as(usize, 32), nn_msg1_len);
    try testing.expectEqual(@as(usize, 0), try nn_responder.readMessage(nn_msg1_buf[0..nn_msg1_len], &payload_buf));

    var nn_msg2_buf: [64]u8 = undefined;
    const nn_msg2_len = try nn_responder.writeMessage("", &nn_msg2_buf);
    try testing.expectEqual(@as(usize, 48), nn_msg2_len);
    try testing.expectEqual(@as(usize, 0), try nn_initiator.readMessage(nn_msg2_buf[0..nn_msg2_len], &payload_buf));
    try testing.expect(nn_initiator.isFinished());
    try testing.expect(nn_responder.isFinished());

    var nn_split_i = try nn_initiator.split();
    var nn_split_r = try nn_responder.split();
    var nn_ciphertext: [7 + noise.TagSize]u8 = undefined;
    _ = nn_split_i.send.encrypt("NN test", "", &nn_ciphertext);
    var nn_plaintext: [7]u8 = undefined;
    const nn_read = try nn_split_r.recv.decrypt(&nn_ciphertext, "", &nn_plaintext);
    try testing.expectEqualSlices(u8, "NN test", nn_plaintext[0..nn_read]);
    var nn_reply: [8 + noise.TagSize]u8 = undefined;
    _ = nn_split_r.send.encrypt("NN reply", "", &nn_reply);
    var nn_back: [8]u8 = undefined;
    const nn_back_n = try nn_split_i.recv.decrypt(&nn_reply, "", &nn_back);
    try testing.expectEqualSlices(u8, "NN reply", nn_back[0..nn_back_n]);
}

fn runPrologueMismatch(
    comptime H: type,
    testing: anytype,
    alice_static: anytype,
    bob_static: anytype,
) !void {
    var msg1: [128]u8 = undefined;
    var payload_buf: [32]u8 = undefined;
    try testing.expectError(
        noise.HandshakeError.MissingLocalStatic,
        H.init(.{ .pattern = .XX, .initiator = true }),
    );

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
        noise.CipherError.AuthenticationFailed,
        mismatch.readMessage(msg1[0..mismatch_msg_len], &payload_buf),
    );
}
