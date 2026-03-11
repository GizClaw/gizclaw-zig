const std = @import("std");

const consts = @import("consts.zig");
const endpoint = @import("endpoint.zig");
const errors = @import("errors.zig");
const conn = @import("conn.zig");
const dial = @import("dial.zig");
const service = @import("service.zig");

test {
    std.testing.refAllDecls(@This());

    _ = consts;
    _ = endpoint;
    _ = errors;
    _ = conn;
    _ = dial;
    _ = service;
}
