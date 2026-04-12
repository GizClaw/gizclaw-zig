const dep = @import("dep");
const testing_api = @import("dep").testing;
const consts = @import("../../../core/consts.zig");
const ConnFile = @import("../../../core/Conn.zig");
const errors = @import("../../../core/errors.zig");
const noise = @import("../../../noise.zig");
const protocol = @import("../../../core/protocol.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;
            runCases(lib, lib.testing) catch |err| {
                t.logErrorf("core/Conn failed: {}", .{err});
                return false;
            };
            return true;
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

fn runCases(comptime lib: type, testing: anytype) !void {
    const Noise = noise.make(lib);
    const ConnType = ConnFile.make(Noise);
    const direct_protocol: u8 = 0x03;

    const alice_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{1} ** noise.Key.key_size));
    const bob_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{2} ** noise.Key.key_size));

    var initiator = ConnType.initInitiator(alice_static, bob_static.public, 10);
    var responder = ConnType.initResponder(bob_static, 20);

    var init_wire: [128]u8 = undefined;
    const init_n = try initiator.beginHandshake(&init_wire, 1);

    var resp_wire: [128]u8 = undefined;
    const resp_n = try responder.acceptHandshakeInit(init_wire[0..init_n], &resp_wire, 2);
    try initiator.handleHandshakeResponse(resp_wire[0..resp_n], 3);

    try testing.expectEqual(ConnFile.State.established, initiator.state());
    try testing.expectEqual(ConnFile.State.established, responder.state());

    var plaintext: [64]u8 = undefined;
    var ciphertext: [80]u8 = undefined;
    var wire: [96]u8 = undefined;
    const wire_n = try initiator.send(direct_protocol, "hello", &plaintext, &ciphertext, &wire, 10);
    var recv_plaintext: [64]u8 = undefined;
    const received = try responder.recv(wire[0..wire_n], &recv_plaintext, 11);
    try testing.expectEqual(direct_protocol, received.protocol_byte);
    try testing.expectEqualStrings("hello", received.payload);

    try testing.expectError(
        errors.Error.KCPMustUseStream,
        initiator.send(protocol.kcp, "rpc", &plaintext, &ciphertext, &wire, 12),
    );

    try testing.expectEqual(ConnFile.TickAction.none, try initiator.tick(12, true));
    try testing.expectEqual(ConnFile.TickAction.send_keepalive, try responder.tick(consts.keepalive_timeout_ms + 12, false));
    const keepalive_n = try responder.sendKeepalive(&ciphertext, &wire, consts.keepalive_timeout_ms + 13);
    try testing.expect(keepalive_n > 0);
    try testing.expectEqual(@as(u64, consts.keepalive_timeout_ms + 13), responder.last_sent_ms);
    try testing.expectEqual(ConnFile.TickAction.rekey, try initiator.tick(consts.rekey_after_time_ms + 4, true));

    const rekey_init_n = try initiator.beginHandshake(&init_wire, consts.rekey_after_time_ms + 5);
    const rekey_resp_n = try responder.acceptHandshakeInit(
        init_wire[0..rekey_init_n],
        &resp_wire,
        consts.rekey_after_time_ms + 6,
    );
    try initiator.handleHandshakeResponse(resp_wire[0..rekey_resp_n], consts.rekey_after_time_ms + 7);
    try testing.expectEqual(ConnFile.State.established, initiator.state());
    try testing.expect(initiator.previous != null);

    _ = try initiator.beginHandshake(&init_wire, consts.rekey_after_time_ms + 20);
    try testing.expectError(
        errors.Error.HandshakeTimeout,
        initiator.tick(consts.rekey_after_time_ms + 20 + consts.rekey_attempt_time_ms + 1, true),
    );
    _ = try initiator.beginHandshake(&init_wire, consts.rekey_after_time_ms + consts.rekey_attempt_time_ms + 30);
    try testing.expectEqual(
        ConnFile.TickAction.none,
        try initiator.tick(consts.rekey_after_time_ms + consts.rekey_attempt_time_ms + 31, true),
    );
}
