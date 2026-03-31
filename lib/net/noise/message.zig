const embed = @import("embed");
const mem = embed.mem;

const Key = @import("key.zig");
const cipher = @import("cipher.zig");
const errors = @import("errors.zig");

pub const MessageType = enum(u8) {
    handshake_init = 1,
    handshake_resp = 2,
    cookie_reply = 3,
    transport = 4,
    _,
};

pub const handshake_init_header_size: usize = 1 + 4 + Key.key_size;
pub const min_handshake_init_size: usize = handshake_init_header_size + 48;
pub const handshake_resp_header_size: usize = 1 + 4 + 4 + Key.key_size;
pub const min_handshake_resp_size: usize = handshake_resp_header_size + cipher.tag_size;
pub const transport_header_size: usize = 1 + 4 + 8;
pub const max_payload_size: usize = 65535 - transport_header_size - cipher.tag_size - 1;
pub const max_packet_size: usize = 65535;

pub const HandshakeInit = struct {
    sender_index: u32,
    ephemeral: Key,
    static_encrypted: []const u8,
};

pub const HandshakeResp = struct {
    sender_index: u32,
    receiver_index: u32,
    ephemeral: Key,
    ciphertext: []const u8,
};

pub const TransportMessage = struct {
    receiver_index: u32,
    counter: u64,
    ciphertext: []const u8,
};

pub const DecodePayload = struct {
    protocol: u8,
    payload: []const u8,
};

pub fn parseHandshakeInit(data: []const u8) errors.MessageError!HandshakeInit {
    if (data.len < min_handshake_init_size) return errors.MessageError.TooShort;
    if (data[0] != @intFromEnum(MessageType.handshake_init)) return errors.MessageError.InvalidType;

    return .{
        .sender_index = mem.readInt(u32, data[1..5], .little),
        .ephemeral = Key.fromBytes(data[5 .. 5 + Key.key_size].*),
        .static_encrypted = data[handshake_init_header_size..],
    };
}

pub fn buildHandshakeInit(out: []u8, sender_index: u32, ephemeral: Key, static_encrypted: []const u8) errors.MessageError!usize {
    if (static_encrypted.len < 48) return errors.MessageError.TooShort;
    const total = handshake_init_header_size + static_encrypted.len;
    if (out.len < total) return errors.MessageError.TooShort;

    out[0] = @intFromEnum(MessageType.handshake_init);
    mem.writeInt(u32, out[1..5], sender_index, .little);
    @memcpy(out[5 .. 5 + Key.key_size], ephemeral.asBytes());
    @memcpy(out[handshake_init_header_size..total], static_encrypted);
    return total;
}

pub fn parseHandshakeResp(data: []const u8) errors.MessageError!HandshakeResp {
    if (data.len < min_handshake_resp_size) return errors.MessageError.TooShort;
    if (data[0] != @intFromEnum(MessageType.handshake_resp)) return errors.MessageError.InvalidType;

    return .{
        .sender_index = mem.readInt(u32, data[1..5], .little),
        .receiver_index = mem.readInt(u32, data[5..9], .little),
        .ephemeral = Key.fromBytes(data[9 .. 9 + Key.key_size].*),
        .ciphertext = data[handshake_resp_header_size..],
    };
}

pub fn buildHandshakeResp(out: []u8, sender_index: u32, receiver_index: u32, ephemeral: Key, ciphertext: []const u8) errors.MessageError!usize {
    if (ciphertext.len < cipher.tag_size) return errors.MessageError.TooShort;
    const total = handshake_resp_header_size + ciphertext.len;
    if (out.len < total) return errors.MessageError.TooShort;

    out[0] = @intFromEnum(MessageType.handshake_resp);
    mem.writeInt(u32, out[1..5], sender_index, .little);
    mem.writeInt(u32, out[5..9], receiver_index, .little);
    @memcpy(out[9 .. 9 + Key.key_size], ephemeral.asBytes());
    @memcpy(out[handshake_resp_header_size..total], ciphertext);
    return total;
}

pub fn parseTransportMessage(data: []const u8) errors.MessageError!TransportMessage {
    if (data.len < transport_header_size + cipher.tag_size) return errors.MessageError.TooShort;
    if (data[0] != @intFromEnum(MessageType.transport)) return errors.MessageError.InvalidType;

    return .{
        .receiver_index = mem.readInt(u32, data[1..5], .little),
        .counter = mem.readInt(u64, data[5..13], .little),
        .ciphertext = data[transport_header_size..],
    };
}

pub fn buildTransportMessage(out: []u8, receiver_index: u32, counter: u64, ciphertext: []const u8) errors.MessageError!usize {
    const total = transport_header_size + ciphertext.len;
    if (out.len < total) return errors.MessageError.TooShort;
    if (ciphertext.len < cipher.tag_size) return errors.MessageError.TooShort;

    out[0] = @intFromEnum(MessageType.transport);
    mem.writeInt(u32, out[1..5], receiver_index, .little);
    mem.writeInt(u64, out[5..13], counter, .little);
    @memcpy(out[transport_header_size..total], ciphertext);
    return total;
}

pub fn encodePayload(out: []u8, protocol: u8, payload: []const u8) errors.MessageError!usize {
    const total = 1 + payload.len;
    if (out.len < total) return errors.MessageError.TooShort;
    if (payload.len > max_payload_size) return errors.MessageError.Oversize;

    out[0] = protocol;
    @memcpy(out[1..total], payload);
    return total;
}

pub fn decodePayload(data: []const u8) errors.MessageError!DecodePayload {
    if (data.len < 1) return errors.MessageError.TooShort;
    return .{
        .protocol = data[0],
        .payload = data[1..],
    };
}

pub fn getMessageType(data: []const u8) errors.MessageError!MessageType {
    if (data.len < 1) return errors.MessageError.TooShort;
    return @enumFromInt(data[0]);
}

pub fn testAll(testing: anytype) !void {
    const ephemeral = Key.fromBytes([_]u8{0xaa} ** Key.key_size);
    const static_encrypted = [_]u8{0xbb} ** 48;
    var init_buf: [96]u8 = undefined;
    const init_len = try buildHandshakeInit(&init_buf, 12345, ephemeral, &static_encrypted);
    const init = try parseHandshakeInit(init_buf[0..init_len]);
    try testing.expectEqual(@as(u32, 12345), init.sender_index);
    try testing.expect(init.ephemeral.eql(ephemeral));
    try testing.expectEqualSlices(u8, &static_encrypted, init.static_encrypted);

    const empty = [_]u8{0xdd} ** 16;
    var resp_buf: [96]u8 = undefined;
    const resp_len = try buildHandshakeResp(&resp_buf, 11, 22, ephemeral, &empty);
    const resp = try parseHandshakeResp(resp_buf[0..resp_len]);
    try testing.expectEqual(@as(u32, 11), resp.sender_index);
    try testing.expectEqual(@as(u32, 22), resp.receiver_index);
    try testing.expect(resp.ephemeral.eql(ephemeral));
    try testing.expectEqualSlices(u8, &empty, resp.ciphertext);

    const transport_ciphertext = [_]u8{0xee} ** 32;
    var transport_buf: [64]u8 = undefined;
    const transport_len = try buildTransportMessage(&transport_buf, 333, 444, &transport_ciphertext);
    const transport = try parseTransportMessage(transport_buf[0..transport_len]);
    try testing.expectEqual(@as(u32, 333), transport.receiver_index);
    try testing.expectEqual(@as(u64, 444), transport.counter);
    try testing.expectEqualSlices(u8, &transport_ciphertext, transport.ciphertext);

    var payload_buf: [32]u8 = undefined;
    const payload_len = try encodePayload(&payload_buf, 0x81, "hello");
    const payload = try decodePayload(payload_buf[0..payload_len]);
    try testing.expectEqual(@as(u8, 0x81), payload.protocol);
    try testing.expectEqualStrings("hello", payload.payload);

    try testing.expectEqual(MessageType.handshake_init, try getMessageType(init_buf[0..init_len]));

    try testing.expectError(errors.MessageError.TooShort, parseHandshakeInit(&[_]u8{ 1, 2, 3 }));
    try testing.expectError(errors.MessageError.InvalidType, parseTransportMessage(init_buf[0..init_len]));
    try testing.expectError(errors.MessageError.TooShort, decodePayload(&[_]u8{}));
}
