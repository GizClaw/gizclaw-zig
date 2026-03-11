const std = @import("std");

const consts = @import("consts.zig");
const endpoint = @import("endpoint.zig");
const errors = @import("errors.zig");
const conn = @import("conn.zig");
const dial_mod = @import("dial.zig");
const service = @import("service.zig");

pub const Endpoint = endpoint.Endpoint;
pub const ConnState = conn.ConnState;
pub const Conn = conn.StdConn;
pub const ServiceMux = service.StdServiceMux;
pub const DialOptions = dial_mod.StdDialOptions;
pub const dial = dial_mod.stdDial;

pub const ConnError = errors.ConnError;
pub const DialError = errors.DialError;
pub const ServiceError = service.ServiceError;
pub const rekey_timeout_ms = consts.rekey_timeout_ms;
pub const keepalive_timeout_ms = consts.keepalive_timeout_ms;
pub const reject_after_time_ms = consts.reject_after_time_ms;
pub const rekey_after_time_ms = consts.rekey_after_time_ms;
pub const rekey_after_messages = consts.rekey_after_messages;
pub const rekey_attempt_time_ms = consts.rekey_attempt_time_ms;

test {
    std.testing.refAllDecls(@This());

    _ = consts;
    _ = endpoint;
    _ = errors;
    _ = conn;
    _ = dial_mod;
    _ = service;
}
