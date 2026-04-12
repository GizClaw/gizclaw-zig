const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");
const ConnFile = @import("../../../core/Conn.zig");
const protocol = @import("../../../core/protocol.zig");
const ListenerFile = @import("../../../core/Listener.zig");
const DialerFile = @import("../../../core/Dialer.zig");
const errors = @import("../../../core/errors.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib, lib.testing, allocator) catch |err| {
                t.logErrorf("core/Listener failed: {}", .{err});
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

fn runCases(comptime lib: type, testing: anytype, allocator: dep.embed.mem.Allocator) !void {
    const Noise = noise.make(lib);
    const ListenerType = ListenerFile.make(lib, Noise);
    const DialerType = DialerFile.make(lib, Noise);
    const direct_protocol: u8 = 0x03;

    const alice_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{7} ** noise.Key.key_size));
    const bob_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{8} ** noise.Key.key_size));

    var listener = try ListenerType.init(allocator, bob_static, 4);
    defer listener.deinit();

    var dialer = DialerType.init(alice_static, bob_static.public, 30);
    var init_wire: [128]u8 = undefined;
    const init_n = try dialer.start(&init_wire, 1);

    var response_wire: [128]u8 = undefined;
    var plaintext: [64]u8 = undefined;
    const response = try listener.receive(init_wire[0..init_n], &plaintext, &response_wire, 2);
    const response_n = response.response;
    try dialer.handleResponse(response_wire[0..response_n], 3);

    const accepted = try listener.accept();
    try testing.expectEqual(ConnFile.State.established, accepted.state());

    var send_plaintext: [64]u8 = undefined;
    var send_ciphertext: [80]u8 = undefined;
    var send_wire: [96]u8 = undefined;
    const send_n = try dialer.connection().send(direct_protocol, "listener", &send_plaintext, &send_ciphertext, &send_wire, 10);
    const payload_result = try listener.receive(send_wire[0..send_n], &plaintext, &response_wire, 11);
    try testing.expectEqualStrings("listener", payload_result.payload.payload);

    const send_session = dialer.connection().currentSession().?;
    const prefix_len = noise.Varint.encode(&send_plaintext, 9);
    @memcpy(send_plaintext[prefix_len .. prefix_len + 2], "hi");
    var encoded_payload: [noise.Message.max_payload_size]u8 = undefined;
    const wrapped_len = try noise.Message.encodePayload(&encoded_payload, protocol.kcp, send_plaintext[0 .. prefix_len + 2]);
    const encrypted = try send_session.encrypt(encoded_payload[0..wrapped_len], &send_ciphertext);
    const stream_wire_n = try noise.Message.buildTransportMessage(
        &send_wire,
        send_session.remoteIndex(),
        encrypted.nonce,
        send_ciphertext[0..encrypted.n],
    );
    try testing.expectError(errors.Error.KCPMustUseStream, listener.receive(send_wire[0..stream_wire_n], &plaintext, &response_wire, 13));

    var tight_listener = try ListenerType.init(allocator, bob_static, 1);
    defer tight_listener.deinit();
    var dialer_b = DialerType.init(alice_static, bob_static.public, 31);
    const dialer_c_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{9} ** noise.Key.key_size));
    var dialer_c = DialerType.init(dialer_c_static, bob_static.public, 32);

    const init_b_n = try dialer_b.start(&init_wire, 20);
    _ = try tight_listener.receive(init_wire[0..init_b_n], &plaintext, &response_wire, 21);

    const init_c_n = try dialer_c.start(&init_wire, 22);
    try testing.expectError(errors.Error.QueueFull, tight_listener.receive(init_wire[0..init_c_n], &plaintext, &response_wire, 23));
}
