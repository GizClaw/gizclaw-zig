const errors = @import("errors.zig");

pub const http: u8 = 0x80;
pub const rpc: u8 = 0x81;
pub const event: u8 = 0x03;
pub const opus: u8 = 0x10;

pub const Kind = enum {
    stream,
    direct,
};

pub fn isFoundation(protocol: u8) bool {
    return switch (protocol) {
        http, rpc, event, opus => true,
        else => false,
    };
}

pub fn kind(protocol: u8) errors.Error!Kind {
    return switch (protocol) {
        http, rpc => .stream,
        event, opus => .direct,
        else => errors.Error.UnsupportedProtocol,
    };
}

pub fn isStream(protocol: u8) bool {
    return switch (protocol) {
        http, rpc => true,
        else => false,
    };
}

pub fn isDirect(protocol: u8) bool {
    return switch (protocol) {
        event, opus => true,
        else => false,
    };
}

pub fn validate(protocol: u8) errors.Error!void {
    if (!isFoundation(protocol)) return errors.Error.UnsupportedProtocol;
}
