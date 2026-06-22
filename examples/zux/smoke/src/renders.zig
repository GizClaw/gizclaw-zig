const button_mod = @import("renders/button.zig");
const led_mod = @import("renders/led.zig");
const wifi_mod = @import("renders/wifi.zig");

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const Button = button_mod.make(grt, ZuxAppType);
    const Led = led_mod.make(grt, ZuxAppType);
    const Wifi = wifi_mod.make(grt, ZuxAppType);

    return struct {
        button: Button,
        led: Led,
        wifi: Wifi,

        const Self = @This();

        pub const InitConfig = struct {
            allocator: @import("glib").std.mem.Allocator,
            zux_app: *ZuxAppType,
        };

        pub fn init(config: InitConfig) Self {
            return .{
                .button = Button.init(config.allocator, config.zux_app),
                .led = Led.init(config.zux_app),
                .wifi = Wifi.init(config.zux_app),
            };
        }
    };
}
