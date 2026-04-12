const root = @This();
const conn = @import("peer/Conn.zig");
const listener = @import("peer/Listener.zig");
const stream = @import("peer/Stream.zig");
const errors = @import("peer/errors.zig");

pub const Error = errors.Error;

pub fn make(comptime Core: type) type {
    return struct {
        pub const Error = errors.Error;

        pub const Stream = stream.make(Core);
        pub const Conn = conn.make(Core);
        pub const Listener = listener.make(Core);
    };
}
