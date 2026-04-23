const embed = @import("embed");
const std = embed.std;
const mem = std.mem;

const Key = @import("Key.zig");

pub const MessageTypeHandshakeInit: u8 = 1;
pub const MessageTypeHandshakeResp: u8 = 2;
pub const MessageTypeCookieReply: u8 = 3;
pub const MessageTypeTransport: u8 = 4;

pub const tag_size: usize = 16;
pub const key_size: usize = 32;

pub const HandshakeInitSize: usize = 1 + 4 + 32 + 48;
pub const HandshakeRespSize: usize = 1 + 4 + 4 + 32 + 16;
pub const TransportHeaderSize: usize = 1 + 4 + 8;
pub const MaxPayloadSize: usize = 65535 - TransportHeaderSize - tag_size;
pub const MaxPacketSize: usize = 65535;

pub const TransportMessage = struct {
    receiver_index: u32,
    counter: u64,
    ciphertext: []const u8,
};

pub const HandshakeInitMessage = struct {
    sender_index: u32,
    ephemeral: Key,
    static_encrypted: [48]u8,
};

pub const HandshakeRespMessage = struct {
    sender_index: u32,
    receiver_index: u32,
    ephemeral: Key,
    empty_encrypted: [16]u8,
};

pub fn parseTransportMessage(data: []const u8) !TransportMessage {
    if (data.len < TransportHeaderSize + tag_size) return error.MessageTooShort;
    if (data[0] != MessageTypeTransport) return error.InvalidMessageType;

    return .{
        .receiver_index = mem.readInt(u32, data[1..5], .little),
        .counter = mem.readInt(u64, data[5..13], .little),
        .ciphertext = data[13..],
    };
}

pub fn buildTransportMessage(receiver_index: u32, counter: u64, ciphertext: []const u8, out: []u8) !usize {
    const needed = TransportHeaderSize + ciphertext.len;
    if (out.len < needed) return error.BufferTooSmall;

    out[0] = MessageTypeTransport;
    mem.writeInt(u32, out[1..5], receiver_index, .little);
    mem.writeInt(u64, out[5..13], counter, .little);
    var index: usize = 0;
    while (index < ciphertext.len) : (index += 1) {
        out[13 + index] = ciphertext[index];
    }
    return needed;
}

pub fn encodePayload(payload: []const u8, out: []u8) !usize {
    const needed = payload.len;
    if (out.len < needed) return error.BufferTooSmall;
    @memcpy(out[0..payload.len], payload);
    return needed;
}

pub fn parseHandshakeInit(data: []const u8) !HandshakeInitMessage {
    if (data.len < HandshakeInitSize) return error.MessageTooShort;
    if (data[0] != MessageTypeHandshakeInit) return error.InvalidMessageType;

    return .{
        .sender_index = mem.readInt(u32, data[1..5], .little),
        .ephemeral = .{ .bytes = data[5..37].* },
        .static_encrypted = data[37..85].*,
    };
}

pub fn buildHandshakeInit(sender_index: u32, ephemeral: Key, static_encrypted: []const u8, out: []u8) !usize {
    if (static_encrypted.len != 48) return error.InvalidMessage;
    if (out.len < HandshakeInitSize) return error.BufferTooSmall;

    out[0] = MessageTypeHandshakeInit;
    mem.writeInt(u32, out[1..5], sender_index, .little);
    @memcpy(out[5..37], &ephemeral.bytes);
    @memcpy(out[37..85], static_encrypted);
    return HandshakeInitSize;
}

pub fn parseHandshakeResp(data: []const u8) !HandshakeRespMessage {
    if (data.len < HandshakeRespSize) return error.MessageTooShort;
    if (data[0] != MessageTypeHandshakeResp) return error.InvalidMessageType;

    return .{
        .sender_index = mem.readInt(u32, data[1..5], .little),
        .receiver_index = mem.readInt(u32, data[5..9], .little),
        .ephemeral = .{ .bytes = data[9..41].* },
        .empty_encrypted = data[41..57].*,
    };
}

pub fn buildHandshakeResp(sender_index: u32, receiver_index: u32, ephemeral: Key, empty_encrypted: []const u8, out: []u8) !usize {
    if (empty_encrypted.len != 16) return error.InvalidMessage;
    if (out.len < HandshakeRespSize) return error.BufferTooSmall;

    out[0] = MessageTypeHandshakeResp;
    mem.writeInt(u32, out[1..5], sender_index, .little);
    mem.writeInt(u32, out[5..9], receiver_index, .little);
    @memcpy(out[9..41], &ephemeral.bytes);
    @memcpy(out[41..57], empty_encrypted);
    return HandshakeRespSize;
}

pub fn getMessageType(data: []const u8) !u8 {
    if (data.len < 1) return error.MessageTooShort;
    return data[0];
}
