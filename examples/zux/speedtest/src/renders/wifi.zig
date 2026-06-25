const embed = @import("embed");
const consts = @import("../consts.zig");

pub fn make(comptime platform_ctx: type, comptime grt: type, comptime ZuxAppType: type) type {
    const Stores = ZuxAppType.Store.Stores;
    const AppState = @FieldType(Stores, "app_state").StateType;
    const WifiState = @FieldType(Stores, "wifi_state").StateType;
    const WifiStaState = @FieldType(Stores, "wifi").StateType;
    const WifiConnectConfig = embed.drivers.wifi.Sta.ConnectConfig;

    return struct {
        const log = grt.std.log.scoped(.wifi);

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
            try self.syncIntent(stores.app_state.get(), stores.wifi_state.get(), stores.wifi.get());
        }

        pub fn recover(self: *Self, app: *ZuxAppType.ImplType) !void {
            _ = app;
            const stores = &self.zux_app.store.stores;
            try self.reconnectOffline(stores.app_state.get(), stores.wifi_state.get(), stores.wifi.get());
        }

        fn syncIntent(self: *Self, app_state: AppState, wifi_state: WifiState, wifi: WifiStaState) !void {
            if (!manageWifi()) {
                log.info("wifi management skipped by platform", .{});
                return;
            }
            if (app_state.state == .on and wifi_state.state == .on) {
                try self.disablePowerSave();
                log.info("wifi connect ssid={s}", .{consts.wifi_ssid});
                try self.connectWifiSta("wifi connect", .{
                    .ssid = consts.wifi_ssid,
                    .password = consts.wifi_password,
                    .timeout = consts.wifi_connect_timeout,
                });
                log.info("wifi connect requested", .{});
                return;
            }

            if (!wifi.connected and wifi.status != .connecting) {
                log.info("wifi disconnect skipped: already idle status={s}", .{@tagName(wifi.status)});
                return;
            }
            log.info("wifi disconnect", .{});
            try self.zux_app.impl.disconnect_wifi_sta(.wifi);
            log.info("wifi disconnect requested", .{});
        }

        fn reconnectOffline(self: *Self, app_state: AppState, wifi_state: WifiState, wifi: WifiStaState) !void {
            if (app_state.state != .on or wifi_state.state != .on) return;
            if (wifi.status == .connecting) return;
            if (wifi.connected and !wifi.connect_timeout) return;
            if (wifi.reconnect_at != 0) {
                log.info("wifi reconnect waiting reconnect_at={d}", .{wifi.reconnect_at});
                return;
            }

            try self.disablePowerSave();
            if (wifi.connect_timeout) {
                log.warn("wifi reconnect after ip timeout connected_at={d}", .{wifi.connected_at});
                try self.zux_app.impl.disconnect_wifi_sta(.wifi);
                return;
            }
            log.info("wifi reconnect ssid={s}", .{consts.wifi_ssid});
            try self.connectWifiSta("wifi reconnect", .{
                .ssid = consts.wifi_ssid,
                .password = consts.wifi_password,
                .timeout = consts.wifi_connect_timeout,
            });
            log.info("wifi reconnect requested", .{});
        }

        fn connectWifiSta(self: *Self, comptime action: []const u8, config: WifiConnectConfig) !void {
            self.zux_app.impl.connect_wifi_sta(.wifi, config) catch |err| switch (err) {
                error.Busy => {
                    log.warn("{s} skipped: wifi sta is busy", .{action});
                    return;
                },
                else => return err,
            };
        }

        fn disablePowerSave(self: *Self) !void {
            self.zux_app.impl.set_wifi_sta_power_save(.wifi, .none) catch |err| switch (err) {
                error.Unsupported => {
                    log.debug("wifi power-save unsupported; skipping", .{});
                    return;
                },
                else => return err,
            };
        }

        fn manageWifi() bool {
            if (comptime @hasDecl(platform_ctx, "smokeManageWifi")) {
                return platform_ctx.smokeManageWifi();
            }
            return true;
        }
    };
}
