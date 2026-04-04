pub fn make(comptime Core: type) type {
    return struct {
        ctx: *anyopaque,
        retain: *const fn (ctx: *anyopaque) void,
        release: *const fn (ctx: *anyopaque) void,
        udp: *const fn (ctx: *anyopaque) *Core.UDP,
    };
}
