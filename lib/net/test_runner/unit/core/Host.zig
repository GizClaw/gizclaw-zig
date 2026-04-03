const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");
const errors = @import("../../../core/errors.zig");
const protocol = @import("../../../core/protocol.zig");
const HostFile = @import("../../../core/Host.zig");
const ServiceMuxFile = @import("../../../core/ServiceMux.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib, lib.testing, allocator) catch |err| {
                t.logErrorf("core/Host failed: {}", .{err});
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
    const HostType = HostFile.make(lib, Noise);

    const alice_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{9} ** noise.Key.key_size));
    const bob_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{10} ** noise.Key.key_size));

    var stream_capture = StreamCapture{};
    var client = try HostType.init(allocator, alice_static, false, .{
        .on_new_service = allowAllServices,
    });
    defer client.deinit();
    var server = try HostType.init(allocator, bob_static, true, .{
        .on_new_service = allowAllServices,
        .stream_adapter = streamCaptureAdapter(&stream_capture),
    });
    defer server.deinit();

    var init_wire: [128]u8 = undefined;
    const init_n = try client.beginDial(bob_static.public, &init_wire, 1);

    var plaintext: [128]u8 = undefined;
    var response_wire: [128]u8 = undefined;
    const response = try server.handlePacket(init_wire[0..init_n], &plaintext, &response_wire, 2);
    const response_n = response.response.n;
    _ = try client.handlePacket(response_wire[0..response_n], &plaintext, &response_wire, 3);

    try testing.expectEqual(@as(usize, 1), client.peerCount());
    try testing.expectEqual(@as(usize, 1), server.peerCount());

    var send_plaintext: [64]u8 = undefined;
    var send_ciphertext: [80]u8 = undefined;
    var send_wire: [96]u8 = undefined;
    const send_n = try client.sendDirect(
        bob_static.public,
        protocol.event,
        "host",
        &send_plaintext,
        &send_ciphertext,
        &send_wire,
        10,
    );
    const routed = try server.handlePacket(send_wire[0..send_n], &plaintext, &response_wire, 11);
    try testing.expectEqual(protocol.event, routed.direct.protocol_byte);
    try testing.expectEqualStrings("host", routed.direct.payload);

    var stream_plaintext: [64]u8 = undefined;
    const stream_n = try client.sendStream(
        bob_static.public,
        7,
        protocol.http,
        "ok",
        &stream_plaintext,
        &send_ciphertext,
        &send_wire,
        12,
    );
    try testing.expectEqual(@as(u64, 12), client.connection(bob_static.public).?.last_sent_ms);
    _ = try server.handlePacket(send_wire[0..stream_n], &plaintext, &response_wire, 13);
    try testing.expectEqual(@as(u64, 7), stream_capture.service);
    try testing.expectEqual(protocol.http, stream_capture.protocol_byte);
    try testing.expectEqualStrings("ok", stream_capture.payload[0..stream_capture.len]);

    var locked_server = try HostType.init(allocator, bob_static, false, .{
        .on_new_service = allowAllServices,
    });
    defer locked_server.deinit();
    try locked_server.registerPeer(alice_static.public);

    var stranger_static = try HostType.init(allocator, bob_static, false, .{
        .on_new_service = allowAllServices,
    });
    defer stranger_static.deinit();
    try testing.expectError(errors.Error.UnknownPeer, stranger_static.handlePacket(init_wire[0..init_n], &plaintext, &response_wire, 19));

    const init_again_n = try client.beginDial(bob_static.public, &init_wire, 20);
    const locked_response = try locked_server.handlePacket(init_wire[0..init_again_n], &plaintext, &response_wire, 21);
    try testing.expect(locked_response == .response);
    try testing.expect(locked_response.response.peer.eql(alice_static.public));

    var small_buffer_server = try HostType.init(allocator, bob_static, true, .{
        .on_new_service = allowAllServices,
    });
    defer small_buffer_server.deinit();
    const small_init_n = try client.beginDial(bob_static.public, &init_wire, 22);
    var tiny_response: [8]u8 = undefined;
    const too_small = small_buffer_server.handlePacketResult(
        init_wire[0..small_init_n],
        &plaintext,
        &tiny_response,
        23,
    );
    try testing.expectEqual(errors.Error.BufferTooSmall, too_small.err.?);
    try testing.expectEqual(@as(usize, 0), small_buffer_server.peerCount());
    try testing.expect(small_buffer_server.connection(alice_static.public) == null);

    const second_wire_n = try client.beginDial(bob_static.public, &init_wire, 30);
    try testing.expect(client.pending_by_index.count() == 1);

    const bad_response_n = try server.handlePacket(init_wire[0..second_wire_n], &plaintext, &response_wire, 31);
    response_wire[bad_response_n.response.n - 1] ^= 1;
    try testing.expectError(error.AuthenticationFailed, client.handlePacket(response_wire[0..bad_response_n.response.n], &plaintext, &send_wire, 32));
    try testing.expect(client.pending_by_index.count() == 0);
}

fn allowAllServices(_: noise.Key, _: u64) bool {
    return true;
}

const StreamCapture = struct {
    service: u64 = 0,
    protocol_byte: u8 = 0,
    payload: [32]u8 = [_]u8{0} ** 32,
    len: usize = 0,
};

fn streamCaptureAdapter(ctx: *StreamCapture) ServiceMuxFile.StreamAdapter {
    return .{
        .ctx = ctx,
        .input = streamCaptureInput,
    };
}

fn streamCaptureInput(ctx: *anyopaque, service: u64, protocol_byte: u8, data: []const u8, _: u64) !void {
    const capture: *StreamCapture = @ptrCast(@alignCast(ctx));
    if (data.len > capture.payload.len) return errors.Error.BufferTooSmall;
    capture.service = service;
    capture.protocol_byte = protocol_byte;
    capture.len = data.len;
    @memcpy(capture.payload[0..data.len], data);
}
