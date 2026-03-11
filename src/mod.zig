const std = @import("std");

pub const net = struct {
    pub const core = @import("net/core/mod.zig");
    pub const kcp = @import("net/kcp/mod.zig");
    pub const noise = @import("net/noise/mod.zig");
};

test {
    std.testing.refAllDecls(@This());

    _ = net;
}
