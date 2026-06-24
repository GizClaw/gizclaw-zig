pub const Reducers = struct {
    app: @import("reducers/app.zig").Reducer = .{},
    chat: @import("reducers/chat.zig").Reducer = .{},
    gizclaw: @import("reducers/gizclaw.zig").Reducer = .{},
    mode: @import("reducers/mode.zig").Reducer = .{},
    wifi: @import("reducers/wifi.zig").Reducer = .{},
};

pub fn init() Reducers {
    return .{};
}
