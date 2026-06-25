const button_mod = @import("renders/button.zig");
const ui_mod = @import("renders/ui.zig");
const wifi_mod = @import("renders/wifi.zig");

pub fn make(comptime platform_ctx: type, comptime grt: type, comptime ZuxAppType: type, comptime RuntimeType: type) type {
    const Button = button_mod.make(grt, ZuxAppType);
    const Ui = ui_mod.make(ZuxAppType, RuntimeType);
    const Wifi = wifi_mod.make(platform_ctx, grt, ZuxAppType);

    return struct {
        button: Button,
        ui: Ui,
        wifi: Wifi,

        const Self = @This();

        pub const InitConfig = struct {
            allocator: @import("glib").std.mem.Allocator,
            zux_app: *ZuxAppType,
        };

        pub fn init(config: InitConfig) Self {
            return .{
                .button = Button.init(config.allocator, config.zux_app),
                .ui = Ui.init(),
                .wifi = Wifi.init(config.zux_app),
            };
        }

        pub fn bindRuntime(self: *Self, runtime: *RuntimeType) void {
            self.ui.bindRuntime(runtime);
        }
    };
}
