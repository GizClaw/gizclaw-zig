const consts = @import("../consts.zig");
const app_mod = @import("../reducers/app.zig");
const wifi_mod = @import("../reducers/wifi.zig");
const glib = @import("glib");

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const Store = ZuxAppType.ImplType.Store;
    const Stores = Store.Stores;
    const AppStateValue = @FieldType(@FieldType(Stores, "app_state").StateType, "state");
    const WifiStateValue = @FieldType(@FieldType(Stores, "wifi_state").StateType, "state");

    return struct {
        const log = grt.std.log.scoped(.button);

        allocator: glib.std.mem.Allocator,
        zux_app: *ZuxAppType,
        last_long_press_pressed_at: ?glib.time.instant.Time = null,

        pub fn init(allocator: glib.std.mem.Allocator, zux_app: *ZuxAppType) @This() {
            return .{
                .allocator = allocator,
                .zux_app = zux_app,
            };
        }

        pub fn render(self: *@This(), app: *ZuxAppType.ImplType) !void {
            _ = app;

            const store = self.zux_app.store;
            const button = store.stores.boot.get();

            const gesture_kind = button.gesture_kind orelse return;
            switch (gesture_kind) {
                .click => {
                    self.last_long_press_pressed_at = null;
                    if (button.click_count == 0) return;

                    const app_state = store.stores.app_state.get();
                    if (app_state.state == .off) {
                        return;
                    }

                    const wifi_state = store.stores.wifi_state.get();
                    const next_wifi_state: WifiStateValue = switch (wifi_state.state) {
                        .off => .on,
                        .on => .off,
                    };
                    try self.dispatchWifiState(next_wifi_state);
                },
                .long_press => {
                    const same_press = self.last_long_press_pressed_at == button.pressed_at;
                    if (button.long_press < consts.power_hold_interval) {
                        return;
                    }
                    if (same_press) {
                        return;
                    }

                    self.last_long_press_pressed_at = button.pressed_at;
                    const app_state = store.stores.app_state.get();
                    const next_app_state: AppStateValue = switch (app_state.state) {
                        .off => .on,
                        .on => .off,
                    };
                    log.info("button long_press accepted app_state={s} next_app_state={s} held={} pressed_at={}", .{
                        @tagName(app_state.state),
                        @tagName(next_app_state),
                        button.long_press,
                        button.pressed_at,
                    });
                    self.dispatchAppState(next_app_state) catch |err| {
                        log.err("button dispatch app_state failed state={s} err={s}", .{
                            @tagName(next_app_state),
                            @errorName(err),
                        });
                        return err;
                    };
                    if (next_app_state == .off) {
                        try self.dispatchWifiState(.off);
                    }
                },
            }
        }

        fn dispatchAppState(self: *@This(), v: AppStateValue) !void {
            const event_state: app_mod.Event.State = switch (v) {
                .off => .off,
                .on => .on,
            };
            const payload = try app_mod.Event.init(self.allocator, event_state);
            errdefer payload.deinit();
            const custom = self.zux_app.initCustomEvent(
                app_mod.Event,
                app_mod.source_id,
                payload,
            );
            _ = try self.zux_app.dispatch(.{
                .origin = .source,
                .timestamp = grt.time.instant.now(),
                .body = .{ .custom = custom },
            });
        }

        fn dispatchWifiState(self: *@This(), v: WifiStateValue) !void {
            const event_state: wifi_mod.Event.State = switch (v) {
                .off => .off,
                .on => .on,
            };
            const payload = try wifi_mod.Event.init(self.allocator, event_state);
            errdefer payload.deinit();
            const custom = self.zux_app.initCustomEvent(
                wifi_mod.Event,
                wifi_mod.source_id,
                payload,
            );
            _ = try self.zux_app.dispatch(.{
                .origin = .source,
                .timestamp = grt.time.instant.now(),
                .body = .{ .custom = custom },
            });
        }
    };
}
