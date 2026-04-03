const dep = @import("dep");
const mem = dep.embed.mem;

const Key = @import("Key.zig");
const cipher = @import("cipher.zig");
const errors = @import("errors.zig");

pub const MessageType = enum(u8) {
    handshake_init = 1,
    handshake_resp = 2,
    cookie_reply = 3,
    transport = 4,
    _,
};

pub const handshake_init_ciphertext_size: usize = 48 + cipher.tag_size;
pub const handshake_init_header_size: usize = 1 + 4 + Key.key_size;
pub const min_handshake_init_size: usize = handshake_init_header_size + handshake_init_ciphertext_size;
pub const handshake_resp_ciphertext_size: usize = cipher.tag_size;
pub const handshake_resp_header_size: usize = 1 + 4 + 4 + Key.key_size;
pub const min_handshake_resp_size: usize = handshake_resp_header_size + handshake_resp_ciphertext_size;
pub const transport_header_size: usize = 1 + 4 + 8;
pub const max_payload_size: usize = 65535 - transport_header_size - cipher.tag_size - 1;
pub const max_packet_size: usize = 65535;

pub const HandshakeInit = struct {
    sender_index: u32,
    ephemeral: Key,
    ciphertext: []const u8,
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
        .ciphertext = data[handshake_init_header_size..min_handshake_init_size],
    };
}

pub fn buildHandshakeInit(out: []u8, sender_index: u32, ephemeral: Key, ciphertext: []const u8) errors.MessageError!usize {
    if (ciphertext.len < handshake_init_ciphertext_size) return errors.MessageError.TooShort;
    const total = min_handshake_init_size;
    if (out.len < total) return errors.MessageError.TooShort;

    out[0] = @intFromEnum(MessageType.handshake_init);
    mem.writeInt(u32, out[1..5], sender_index, .little);
    @memcpy(out[5 .. 5 + Key.key_size], ephemeral.asBytes());
    @memcpy(out[handshake_init_header_size..total], ciphertext[0..handshake_init_ciphertext_size]);
    return total;
}

pub fn parseHandshakeResp(data: []const u8) errors.MessageError!HandshakeResp {
    if (data.len < min_handshake_resp_size) return errors.MessageError.TooShort;
    if (data[0] != @intFromEnum(MessageType.handshake_resp)) return errors.MessageError.InvalidType;

    return .{
        .sender_index = mem.readInt(u32, data[1..5], .little),
        .receiver_index = mem.readInt(u32, data[5..9], .little),
        .ephemeral = Key.fromBytes(data[9 .. 9 + Key.key_size].*),
        .ciphertext = data[handshake_resp_header_size..min_handshake_resp_size],
    };
}

pub fn buildHandshakeResp(out: []u8, sender_index: u32, receiver_index: u32, ephemeral: Key, ciphertext: []const u8) errors.MessageError!usize {
    if (ciphertext.len < handshake_resp_ciphertext_size) return errors.MessageError.TooShort;
    const total = min_handshake_resp_size;
    if (out.len < total) return errors.MessageError.TooShort;

    out[0] = @intFromEnum(MessageType.handshake_resp);
    mem.writeInt(u32, out[1..5], sender_index, .little);
    mem.writeInt(u32, out[5..9], receiver_index, .little);
    @memcpy(out[9 .. 9 + Key.key_size], ephemeral.asBytes());
    @memcpy(out[handshake_resp_header_size..total], ciphertext[0..handshake_resp_ciphertext_size]);
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
