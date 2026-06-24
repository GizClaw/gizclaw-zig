pub const Renders = struct {
    button: @import("renders/button.zig").Render = .{},
    led: @import("renders/led.zig").Render = .{},
    ui: @import("renders/ui.zig").Render = .{},
    wifi: @import("renders/wifi.zig").Render = .{},
};

pub fn init() Renders {
    return .{};
}
