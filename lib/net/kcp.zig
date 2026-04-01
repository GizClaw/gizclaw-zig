const config = @import("kcp/config.zig");
const conn = @import("kcp/conn.zig");
const errors = @import("kcp/errors.zig");
const frame = @import("kcp/frame.zig");
const mux = @import("kcp/mux.zig");

pub const Error = errors.Error;

pub const Output = config.Output;
pub const ConnConfig = config.Conn;
pub const MuxConfig = config.Mux;

pub const frame_open = frame.open;
pub const frame_data = frame.data;
pub const frame_close = frame.close;
pub const frame_close_ack = frame.close_ack;

pub const close_reason_close = frame.close_reason_close;
pub const close_reason_abort = frame.close_reason_abort;
pub const close_reason_invalid = frame.close_reason_invalid;

pub const DecodedFrame = frame.Decoded;

pub const Conn = conn;
pub const Mux = mux;

pub fn decodeFrame(data: []const u8) !DecodedFrame {
    return frame.decode(data);
}
