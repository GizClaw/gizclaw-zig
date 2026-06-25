const led_brightness: u8 = 255;

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const Stores = ZuxAppType.Store.Stores;
    const AppState = @FieldType(Stores, "app_state").StateType;
    const WifiState = @FieldType(Stores, "wifi_state").StateType;
    const WifiStaState = @FieldType(Stores, "wifi").StateType;
    const GizclawState = @FieldType(Stores, "gizclaw_state").StateType;
    const StripState = @FieldType(Stores, "strip").StateType;
    const Color = StripState.Color;

    return struct {
        const log = grt.std.log.scoped(.led);

        zux_app: *ZuxAppType,

        const Self = @This();

        pub fn init(zux_app: *ZuxAppType) Self {
            return .{
                .zux_app = zux_app,
            };
        }

        pub fn render(self: *Self, app: *ZuxAppType.ImplType) !void {
            _ = app;
            const stores = &self.zux_app.store.stores;
            const app_state = stores.app_state.get();
            const wifi_state = stores.wifi_state.get();
            const wifi = stores.wifi.get();
            const gizclaw = stores.gizclaw_state.get();
            const color = statusColor(
                app_state,
                wifi_state,
                wifi,
                gizclaw,
            );
            log.info("led color rgb=({d},{d},{d}) app={s} wifi_intent={s} wifi_status={s} wifi_connected={} wifi_has_ip={} gizclaw={s}", .{
                color.r,
                color.g,
                color.b,
                @tagName(app_state.state),
                @tagName(wifi_state.state),
                @tagName(wifi.status),
                wifi.connected,
                wifi.has_ip,
                @tagName(gizclaw.state),
            });
            try self.zux_app.set_led_strip_pixels(.strip, ZuxAppType.FrameType.solid(color), led_brightness);
        }

        fn statusColor(app_state: AppState, wifi_state: WifiState, wifi: WifiStaState, gizclaw: GizclawState) Color {
            if (app_state.state == .off) return Color.black;
            if (wifi_state.state == .off) return Color.red;

            if (wifi.has_ip) {
                if (gizclaw.state == .connected) return Color.white;
                return Color.green;
            }

            return switch (wifi.status) {
                .disconnected => Color.red,
                .connecting => Color.rgb(255, 255, 0),
                .connected, .online => Color.blue,
            };
        }
    };
}
