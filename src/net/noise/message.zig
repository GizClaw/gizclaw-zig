const std = @import("std");
const crypto = @import("crypto.zig");
const keypair = @import("keypair.zig");

const Key = keypair.Key;
const key_size = keypair.key_size;

pub const MessageType = enum(u8) {
    handshake_init = 1,
    handshake_resp = 2,
    cookie_reply = 3,
    transport = 4,
    _,
};

pub const Protocol = enum(u8) {
    fec = 0x00,
    event = 0x03,
    opus = 0x10,
    http_kcp = 0x80,
    rpc_kcp = 0x81,
    _,
};

pub const tag_size = crypto.tag_size;

pub const handshake_init_header_size = 1 + 4 + 32;
pub const min_handshake_init_size = handshake_init_header_size + 48;
pub const handshake_resp_size = 1 + 4 + 4 + 32 + 16;
pub const transport_header_size = 1 + 4 + 8;
pub const max_payload_size = 65535 - transport_header_size - tag_size - 11;
pub const max_packet_size = 65535;

pub const MessageError = error{
    TooShort,
    InvalidType,
    InvalidVarint,
};

pub const HandshakeInit = struct {
    sender_index: u32,
    ephemeral: Key,
    static_encrypted: []const u8,
};

pub const HandshakeResp = struct {
    sender_index: u32,
    receiver_index: u32,
    ephemeral: Key,
    empty_encrypted: [16]u8,
};

pub const TransportMessage = struct {
    receiver_index: u32,
    counter: u64,
    ciphertext: []const u8,
};

pub fn parseHandshakeInit(data: []const u8) MessageError!HandshakeInit {
    if (data.len < min_handshake_init_size) {
        return MessageError.TooShort;
    }
    if (data[0] != @intFromEnum(MessageType.handshake_init)) {
        return MessageError.InvalidType;
    }

    const sender_index = std.mem.readInt(u32, data[1..5], .little);

    var ephemeral: Key = undefined;
    @memcpy(&ephemeral.data, data[5..37]);

    return HandshakeInit{
        .sender_index = sender_index,
        .ephemeral = ephemeral,
        .static_encrypted = data[37..],
    };
}

pub fn buildHandshakeInit(
    out: []u8,
    sender_index: u32,
    ephemeral: *const Key,
    static_encrypted: []const u8,
) MessageError![]u8 {
    if (static_encrypted.len < 48) {
        return MessageError.TooShort;
    }

    const msg_len = handshake_init_header_size + static_encrypted.len;
    if (out.len < msg_len) {
        return MessageError.TooShort;
    }

    out[0] = @intFromEnum(MessageType.handshake_init);
    std.mem.writeInt(u32, out[1..5], sender_index, .little);
    @memcpy(out[5..37], ephemeral.asBytes());
    @memcpy(out[37..msg_len], static_encrypted);
    return out[0..msg_len];
}

pub fn parseHandshakeResp(data: []const u8) MessageError!HandshakeResp {
    if (data.len < handshake_resp_size) {
        return MessageError.TooShort;
    }
    if (data[0] != @intFromEnum(MessageType.handshake_resp)) {
        return MessageError.InvalidType;
    }

    const sender_index = std.mem.readInt(u32, data[1..5], .little);
    const receiver_index = std.mem.readInt(u32, data[5..9], .little);

    var ephemeral: Key = undefined;
    @memcpy(&ephemeral.data, data[9..41]);

    var empty_encrypted: [16]u8 = undefined;
    @memcpy(&empty_encrypted, data[41..57]);

    return HandshakeResp{
        .sender_index = sender_index,
        .receiver_index = receiver_index,
        .ephemeral = ephemeral,
        .empty_encrypted = empty_encrypted,
    };
}

pub fn buildHandshakeResp(
    sender_index: u32,
    receiver_index: u32,
    ephemeral: *const Key,
    empty_encrypted: []const u8,
) [handshake_resp_size]u8 {
    var msg: [handshake_resp_size]u8 = undefined;
    msg[0] = @intFromEnum(MessageType.handshake_resp);
    std.mem.writeInt(u32, msg[1..5], sender_index, .little);
    std.mem.writeInt(u32, msg[5..9], receiver_index, .little);
    @memcpy(msg[9..41], ephemeral.asBytes());
    @memcpy(msg[41..57], empty_encrypted[0..16]);
    return msg;
}

pub fn parseTransportMessage(data: []const u8) MessageError!TransportMessage {
    if (data.len < transport_header_size + tag_size) {
        return MessageError.TooShort;
    }
    if (data[0] != @intFromEnum(MessageType.transport)) {
        return MessageError.InvalidType;
    }

    const receiver_index = std.mem.readInt(u32, data[1..5], .little);
    const counter = std.mem.readInt(u64, data[5..13], .little);

    return TransportMessage{
        .receiver_index = receiver_index,
        .counter = counter,
        .ciphertext = data[13..],
    };
}

pub fn buildTransportHeader(
    receiver_index: u32,
    counter: u64,
) [transport_header_size]u8 {
    var header: [transport_header_size]u8 = undefined;
    header[0] = @intFromEnum(MessageType.transport);
    std.mem.writeInt(u32, header[1..5], receiver_index, .little);
    std.mem.writeInt(u64, header[5..13], counter, .little);
    return header;
}

pub fn buildTransportMessage(
    allocator: std.mem.Allocator,
    receiver_index: u32,
    counter: u64,
    ciphertext: []const u8,
) ![]u8 {
    const msg = try allocator.alloc(u8, transport_header_size + ciphertext.len);
    const header = buildTransportHeader(receiver_index, counter);
    @memcpy(msg[0..transport_header_size], &header);
    @memcpy(msg[transport_header_size..], ciphertext);
    return msg;
}

fn encodeUvarint(buf: []u8, value: u64) usize {
    var n: usize = 0;
    var x = value;
    while (x >= 0x80) {
        buf[n] = @intCast((x & 0x7f) | 0x80);
        x >>= 7;
        n += 1;
    }
    buf[n] = @intCast(x);
    return n + 1;
}

fn decodeUvarint(data: []const u8) MessageError!struct { value: u64, bytes_read: usize } {
    var x: u64 = 0;
    var shift: u6 = 0;

    for (data, 0..) |byte, idx| {
        if (idx == 10) return MessageError.InvalidVarint;
        const low = @as(u64, byte & 0x7f);

        if (idx == 9 and byte > 1) return MessageError.InvalidVarint;

        x |= low << shift;
        if ((byte & 0x80) == 0) {
            return .{ .value = x, .bytes_read = idx + 1 };
        }
        shift += 7;
    }

    return MessageError.TooShort;
}

pub fn encodePayload(
    allocator: std.mem.Allocator,
    service_port: u64,
    protocol: u8,
    payload: []const u8,
) ![]u8 {
    var service_buf: [10]u8 = undefined;
    const service_len = encodeUvarint(&service_buf, service_port);
    const result = try allocator.alloc(u8, service_len + 1 + payload.len);
    @memcpy(result[0..service_len], service_buf[0..service_len]);
    result[service_len] = protocol;
    @memcpy(result[service_len + 1 ..], payload);
    return result;
}

pub const DecodeResult = struct {
    service_port: u64,
    protocol: u8,
    payload: []const u8,
};

pub fn decodePayload(data: []const u8) MessageError!DecodeResult {
    const service = try decodeUvarint(data);
    if (data.len <= service.bytes_read) {
        return MessageError.TooShort;
    }

    return DecodeResult{
        .service_port = service.value,
        .protocol = data[service.bytes_read],
        .payload = data[service.bytes_read + 1 ..],
    };
}

pub fn getMessageType(data: []const u8) MessageError!MessageType {
    if (data.len == 0) {
        return MessageError.TooShort;
    }
    return @enumFromInt(data[0]);
}

test "handshake init roundtrip" {
    const sender_index: u32 = 12345;
    const ephemeral = Key{ .data = [_]u8{0xAA} ** 32 };
    const static_encrypted = [_]u8{0xBB} ** 48;
    var buf: [min_handshake_init_size]u8 = undefined;

    const msg = try buildHandshakeInit(&buf, sender_index, &ephemeral, &static_encrypted);
    try std.testing.expectEqual(msg.len, min_handshake_init_size);

    const parsed = try parseHandshakeInit(msg);
    try std.testing.expectEqual(parsed.sender_index, sender_index);
    try std.testing.expectEqualSlices(u8, &parsed.ephemeral.data, &ephemeral.data);
    try std.testing.expectEqualSlices(u8, parsed.static_encrypted, &static_encrypted);
}

test "handshake init preserves variable-length payload" {
    const sender_index: u32 = 54321;
    const ephemeral = Key{ .data = [_]u8{0xCD} ** 32 };
    const static_encrypted = [_]u8{0xEF} ** 64;
    var buf: [handshake_init_header_size + static_encrypted.len]u8 = undefined;

    const msg = try buildHandshakeInit(&buf, sender_index, &ephemeral, &static_encrypted);
    try std.testing.expectEqual(@as(usize, handshake_init_header_size + static_encrypted.len), msg.len);

    const parsed = try parseHandshakeInit(msg);
    try std.testing.expectEqual(parsed.sender_index, sender_index);
    try std.testing.expectEqualSlices(u8, &parsed.ephemeral.data, &ephemeral.data);
    try std.testing.expectEqualSlices(u8, parsed.static_encrypted, &static_encrypted);
}

test "handshake resp roundtrip" {
    const sender_index: u32 = 11111;
    const receiver_index: u32 = 22222;
    const ephemeral = Key{ .data = [_]u8{0xCC} ** 32 };
    const empty_encrypted = [_]u8{0xDD} ** 16;

    const msg = buildHandshakeResp(sender_index, receiver_index, &ephemeral, &empty_encrypted);
    try std.testing.expectEqual(msg.len, handshake_resp_size);

    const parsed = try parseHandshakeResp(&msg);
    try std.testing.expectEqual(parsed.sender_index, sender_index);
    try std.testing.expectEqual(parsed.receiver_index, receiver_index);
    try std.testing.expectEqualSlices(u8, &parsed.ephemeral.data, &ephemeral.data);
    try std.testing.expectEqualSlices(u8, &parsed.empty_encrypted, &empty_encrypted);
}

test "transport message roundtrip" {
    const allocator = std.testing.allocator;
    const receiver_index: u32 = 33333;
    const counter: u64 = 44444;
    const ciphertext = [_]u8{0xEE} ** 100;

    const msg = try buildTransportMessage(allocator, receiver_index, counter, &ciphertext);
    defer allocator.free(msg);
    try std.testing.expectEqual(msg.len, transport_header_size + ciphertext.len);

    const parsed = try parseTransportMessage(msg);
    try std.testing.expectEqual(parsed.receiver_index, receiver_index);
    try std.testing.expectEqual(parsed.counter, counter);
    try std.testing.expectEqualSlices(u8, parsed.ciphertext, &ciphertext);
}

test "payload roundtrip" {
    const allocator = std.testing.allocator;
    const service_port: u64 = 128;
    const protocol = @intFromEnum(Protocol.rpc_kcp);
    const payload = "hello world";

    const encoded = try encodePayload(allocator, service_port, protocol, payload);
    defer allocator.free(encoded);
    try std.testing.expectEqual(encoded.len, 3 + payload.len);

    const decoded = try decodePayload(encoded);
    try std.testing.expectEqual(decoded.service_port, service_port);
    try std.testing.expectEqual(decoded.protocol, protocol);
    try std.testing.expectEqualSlices(u8, decoded.payload, payload);
}

test "payload roundtrip with service 0" {
    const allocator = std.testing.allocator;
    const encoded = try encodePayload(allocator, 0, @intFromEnum(Protocol.event), "");
    defer allocator.free(encoded);

    const decoded = try decodePayload(encoded);
    try std.testing.expectEqual(@as(u64, 0), decoded.service_port);
    try std.testing.expectEqual(@as(u8, @intFromEnum(Protocol.event)), decoded.protocol);
    try std.testing.expectEqual(@as(usize, 0), decoded.payload.len);
}

test "payload roundtrip with large service id" {
    const allocator = std.testing.allocator;
    const service_port = std.math.maxInt(u32) + 99;
    const encoded = try encodePayload(allocator, service_port, @intFromEnum(Protocol.opus), "abc");
    defer allocator.free(encoded);

    const decoded = try decodePayload(encoded);
    try std.testing.expectEqual(service_port, decoded.service_port);
    try std.testing.expectEqual(@as(u8, @intFromEnum(Protocol.opus)), decoded.protocol);
    try std.testing.expectEqualStrings("abc", decoded.payload);
}

test "message too short" {
    try std.testing.expectError(MessageError.TooShort, parseHandshakeInit(&[_]u8{ 1, 2, 3 }));
    try std.testing.expectError(MessageError.TooShort, parseHandshakeResp(&[_]u8{ 1, 2, 3 }));
    try std.testing.expectError(MessageError.TooShort, parseTransportMessage(&[_]u8{ 1, 2, 3 }));
    try std.testing.expectError(MessageError.TooShort, decodePayload(&[_]u8{}));
    try std.testing.expectError(MessageError.TooShort, getMessageType(&[_]u8{}));
    try std.testing.expectError(MessageError.TooShort, decodePayload(&[_]u8{0x80}));
    try std.testing.expectError(MessageError.TooShort, decodePayload(&[_]u8{0x01}));
}

test "payload rejects invalid varint" {
    const invalid = [_]u8{ 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
    try std.testing.expectError(MessageError.InvalidVarint, decodePayload(&invalid));
}

test "invalid message type" {
    var msg = [_]u8{0} ** min_handshake_init_size;
    msg[0] = @intFromEnum(MessageType.transport);
    try std.testing.expectError(MessageError.InvalidType, parseHandshakeInit(&msg));

    var msg2 = [_]u8{0} ** handshake_resp_size;
    msg2[0] = @intFromEnum(MessageType.handshake_init);
    try std.testing.expectError(MessageError.InvalidType, parseHandshakeResp(&msg2));

    var msg3 = [_]u8{0} ** (transport_header_size + tag_size);
    msg3[0] = @intFromEnum(MessageType.handshake_init);
    try std.testing.expectError(MessageError.InvalidType, parseTransportMessage(&msg3));
}

test "giztoy-go protocol constants" {
    try std.testing.expectEqual(@intFromEnum(Protocol.fec), 0x00);
    try std.testing.expectEqual(@intFromEnum(Protocol.event), 0x03);
    try std.testing.expectEqual(@intFromEnum(Protocol.opus), 0x10);
    try std.testing.expectEqual(@intFromEnum(Protocol.http_kcp), 0x80);
    try std.testing.expectEqual(@intFromEnum(Protocol.rpc_kcp), 0x81);
}
