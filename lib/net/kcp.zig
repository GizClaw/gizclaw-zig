const dep = @import("dep");

const AdapterFile = @import("kcp/Adapter.zig");
const config = @import("kcp/config.zig");
const ConnFile = @import("kcp/Conn.zig");
const errors = @import("kcp/errors.zig");
const frame = @import("kcp/frame.zig");
const MuxFile = @import("kcp/Mux.zig");
const StreamFile = @import("kcp/Stream.zig");

const mem = dep.embed.mem;

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

pub const Conn = ConnFile;
pub const Mux = MuxFile;
pub const Stream = StreamFile.make(MuxFile);
pub const Adapter = AdapterFile;

pub fn decodeFrame(data: []const u8) !DecodedFrame {
    return frame.decode(data);
}

pub fn getConv(packet: []const u8) !u32 {
    return ConnFile.getConvFromPacket(packet);
}

pub fn newConn(allocator: mem.Allocator, conv: u32, conn_config: ConnConfig) !Conn {
    return ConnFile.init(allocator, conv, conn_config);
}

pub fn newMux(allocator: mem.Allocator, service_id: u64, mux_config: MuxConfig) !Mux {
    return MuxFile.init(allocator, service_id, mux_config);
}

pub fn make(comptime Core: type) type {
    return struct {
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

        pub const Conn = ConnFile;
        pub const Mux = MuxFile;
        pub const Stream = StreamFile.make(MuxFile);
        pub const Adapter = AdapterFile.make(Core);

        pub fn getConv(packet: []const u8) !u32 {
            return ConnFile.getConvFromPacket(packet);
        }

        pub fn newConn(allocator: mem.Allocator, conv: u32, conn_config: config.Conn) !ConnFile {
            return ConnFile.init(allocator, conv, conn_config);
        }

        pub fn newMux(allocator: mem.Allocator, service_id: u64, mux_config: config.Mux) !MuxFile {
            return MuxFile.init(allocator, service_id, mux_config);
        }
    };
}
