const errors = @import("errors.zig");

pub const kcp: u8 = 0x00;

pub const Kind = enum {
    stream,
    direct,
};

pub fn isFoundation(protocol: u8) bool {
    return switch (protocol) {
        kcp => true,
        else => false,
    };
}

pub fn kind(protocol: u8) errors.Error!Kind {
    return switch (protocol) {
        kcp => .stream,
        else => .direct,
    };
}

pub fn isStream(protocol: u8) bool {
    return switch (protocol) {
        kcp => true,
        else => false,
    };
}

pub fn isDirect(protocol: u8) bool {
    return !isStream(protocol);
}

pub fn validate(protocol: u8) errors.Error!void {
    _ = protocol;
}
