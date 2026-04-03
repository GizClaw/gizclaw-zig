const errors = @import("errors.zig");

pub const max_varint_len: usize = 10;

pub const open: u8 = 0;
pub const data: u8 = 1;
pub const close: u8 = 2;
pub const close_ack: u8 = 3;

pub const close_reason_close: u8 = 0;
pub const close_reason_abort: u8 = 1;
pub const close_reason_invalid: u8 = 2;

pub const Decoded = struct {
    stream_id: u64,
    frame_type: u8,
    payload: []const u8,
};

pub fn encodedLen(stream_id: u64, payload_len: usize) usize {
    return varintLen(stream_id) + 1 + payload_len;
}

pub fn encode(out: []u8, stream_id: u64, frame_type: u8, payload: []const u8) !usize {
    const need = encodedLen(stream_id, payload.len);
    if (out.len < need) return errors.Error.BufferTooSmall;

    const prefix_n = encodeVarint(out, stream_id);
    out[prefix_n] = frame_type;
    @memcpy(out[prefix_n + 1 .. need], payload);
    return need;
}

pub fn decode(in: []const u8) !Decoded {
    // Callers must pass exactly one mux frame in `in`.
    const decoded = try decodeVarint(in);
    if (decoded.value > std_max_u32) return errors.Error.InvalidServiceFrame;
    if (decoded.n >= in.len) return errors.Error.InvalidServiceFrame;

    return .{
        .stream_id = decoded.value,
        .frame_type = in[decoded.n],
        .payload = in[decoded.n + 1 ..],
    };
}

fn encodeVarint(out: []u8, value: u64) usize {
    var current = value;
    var index: usize = 0;

    while (current >= 0x80) {
        out[index] = @intCast(current & 0x7f);
        out[index] |= 0x80;
        current >>= 7;
        index += 1;
    }

    out[index] = @intCast(current);
    return index + 1;
}

fn decodeVarint(in: []const u8) !struct { value: u64, n: usize } {
    var value: u64 = 0;

    for (in, 0..) |byte, index| {
        if (index >= max_varint_len) return errors.Error.InvalidServiceFrame;
        value |= @as(u64, byte & 0x7f) << @intCast(index * 7);
        if ((byte & 0x80) == 0) {
            return .{ .value = value, .n = index + 1 };
        }
    }

    return errors.Error.InvalidServiceFrame;
}

fn varintLen(value: u64) usize {
    var n: usize = 1;
    var current = value;
    while (current >= 0x80) {
        current >>= 7;
        n += 1;
    }
    return n;
}

const std_max_u32 = 0xffff_ffff;
