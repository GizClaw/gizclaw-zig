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
            runCases(lib, lib.testing) catch |err| {
                t.logErrorf("noise/message failed: {}", .{err});
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
    _ = lib;
    const mem = dep.embed.mem;
    const Message = noise.Message;
    const Key = noise.Key;

    const ephemeral = Key.fromBytes([_]u8{0xaa} ** Key.key_size);
    const init_ciphertext = [_]u8{0xbb} ** Message.handshake_init_ciphertext_size;
    var init_buf: [128]u8 = undefined;
    const init_len = try Message.buildHandshakeInit(&init_buf, 12345, ephemeral, &init_ciphertext);
    try testing.expectEqual(@as(usize, Message.min_handshake_init_size), init_len);
    try testing.expectEqual(@as(u8, @intFromEnum(Message.MessageType.handshake_init)), init_buf[0]);
    try testing.expectEqual(@as(u32, 12345), mem.readInt(u32, init_buf[1..5], .little));
    try testing.expectEqualSlices(u8, ephemeral.asBytes(), init_buf[5 .. 5 + Key.key_size]);
    try testing.expectEqualSlices(u8, &init_ciphertext, init_buf[Message.handshake_init_header_size..Message.min_handshake_init_size]);
    const init = try Message.parseHandshakeInit(init_buf[0..init_len]);
    try testing.expectEqual(@as(u32, 12345), init.sender_index);
    try testing.expect(init.ephemeral.eql(ephemeral));
    try testing.expectEqualSlices(u8, &init_ciphertext, init.ciphertext);
    var init_with_extra: [Message.min_handshake_init_size + 2]u8 = undefined;
    @memcpy(init_with_extra[0..init_len], init_buf[0..init_len]);
    init_with_extra[init_len] = 0x01;
    init_with_extra[init_len + 1] = 0x02;
    const init_extra = try Message.parseHandshakeInit(&init_with_extra);
    try testing.expectEqualSlices(u8, &init_ciphertext, init_extra.ciphertext);

    const empty = [_]u8{0xdd} ** 16;
    var resp_buf: [96]u8 = undefined;
    const resp_len = try Message.buildHandshakeResp(&resp_buf, 11, 22, ephemeral, &empty);
    try testing.expectEqual(@as(usize, Message.min_handshake_resp_size), resp_len);
    try testing.expectEqual(@as(u8, @intFromEnum(Message.MessageType.handshake_resp)), resp_buf[0]);
    try testing.expectEqual(@as(u32, 11), mem.readInt(u32, resp_buf[1..5], .little));
    try testing.expectEqual(@as(u32, 22), mem.readInt(u32, resp_buf[5..9], .little));
    try testing.expectEqualSlices(u8, ephemeral.asBytes(), resp_buf[9 .. 9 + Key.key_size]);
    try testing.expectEqualSlices(u8, &empty, resp_buf[Message.handshake_resp_header_size..Message.min_handshake_resp_size]);
    const resp = try Message.parseHandshakeResp(resp_buf[0..resp_len]);
    try testing.expectEqual(@as(u32, 11), resp.sender_index);
    try testing.expectEqual(@as(u32, 22), resp.receiver_index);
    try testing.expect(resp.ephemeral.eql(ephemeral));
    try testing.expectEqualSlices(u8, &empty, resp.ciphertext);

    const transport_ciphertext = [_]u8{0xee} ** 32;
    var transport_buf: [64]u8 = undefined;
    const transport_len = try Message.buildTransportMessage(&transport_buf, 333, 444, &transport_ciphertext);
    try testing.expectEqual(@as(u8, @intFromEnum(Message.MessageType.transport)), transport_buf[0]);
    try testing.expectEqual(@as(u32, 333), mem.readInt(u32, transport_buf[1..5], .little));
    try testing.expectEqual(@as(u64, 444), mem.readInt(u64, transport_buf[5..13], .little));
    try testing.expectEqualSlices(u8, &transport_ciphertext, transport_buf[Message.transport_header_size..transport_len]);
    const transport = try Message.parseTransportMessage(transport_buf[0..transport_len]);
    try testing.expectEqual(@as(u32, 333), transport.receiver_index);
    try testing.expectEqual(@as(u64, 444), transport.counter);
    try testing.expectEqualSlices(u8, &transport_ciphertext, transport.ciphertext);

    var payload_buf: [32]u8 = undefined;
    const payload_len = try Message.encodePayload(&payload_buf, 0x81, "hello");
    const payload = try Message.decodePayload(payload_buf[0..payload_len]);
    try testing.expectEqual(@as(u8, 0x81), payload.protocol);
    try testing.expectEqualStrings("hello", payload.payload);
    try testing.expectEqualSlices(u8, &.{ 0x81, 'h', 'e', 'l', 'l', 'o' }, payload_buf[0..payload_len]);

    try testing.expectEqual(Message.MessageType.handshake_init, try Message.getMessageType(init_buf[0..init_len]));

    try testing.expectError(noise.MessageError.TooShort, Message.parseHandshakeInit(&[_]u8{ 1, 2, 3 }));
    var wrong_type_init: [Message.min_handshake_init_size]u8 = [_]u8{0} ** Message.min_handshake_init_size;
    wrong_type_init[0] = @intFromEnum(Message.MessageType.transport);
    try testing.expectError(noise.MessageError.InvalidType, Message.parseHandshakeInit(&wrong_type_init));
    try testing.expectError(noise.MessageError.TooShort, Message.buildHandshakeInit(&init_buf, 1, ephemeral, &[_]u8{0xaa} ** (Message.handshake_init_ciphertext_size - 1)));
    try testing.expectError(noise.MessageError.TooShort, Message.buildHandshakeResp(&resp_buf, 1, 2, ephemeral, &[_]u8{0xaa} ** 15));
    try testing.expectError(noise.MessageError.InvalidType, Message.parseTransportMessage(init_buf[0..init_len]));
    try testing.expectError(noise.MessageError.TooShort, Message.decodePayload(&[_]u8{}));
}
