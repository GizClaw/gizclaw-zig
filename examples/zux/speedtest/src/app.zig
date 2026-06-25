const embed = @import("embed");
const glib = @import("glib");
const launcher = @import("launcher");
const zux = embed.zux;

const reducers_mod = @import("reducers.zig");
const renders_mod = @import("renders.zig");
const runtime_mod = @import("runtime.zig");

pub const DesktopPlatformCtx = struct {
    pub fn smokeManageWifi() bool {
        return false;
    }

    pub fn gizclawAllocator(default_allocator: anytype) @TypeOf(default_allocator) {
        return default_allocator;
    }
};

pub const TestPlatformCtx = struct {
    pub fn gizclawAllocator(default_allocator: anytype) @TypeOf(default_allocator) {
        return default_allocator;
    }
};

pub const SpecType = blk: {
    var builder = zux.spec.Builder.init();
    builder.addSpecSlices(&.{
        @embedFile("spec/component.json"),
        @embedFile("spec/state.json"),
        @embedFile("spec/hooks.json"),
        @embedFile("spec/user_stories/boot_app_state_starts_off.json"),
        @embedFile("spec/user_stories/boot_does_not_connect.json"),
        @embedFile("spec/user_stories/boot_wifi_state_starts_off.json"),
        @embedFile("spec/user_stories/button_press_only_changes_intent_state.json"),
        @embedFile("spec/user_stories/gizclaw_connected_event_updates_state.json"),
        @embedFile("spec/user_stories/gizclaw_connecting_event_updates_state.json"),
        @embedFile("spec/user_stories/gizclaw_disconnected_event_updates_state.json"),
        @embedFile("spec/user_stories/off_hold_3s_does_not_request_connect.json"),
        @embedFile("spec/user_stories/off_hold_3s_keeps_wifi_off.json"),
        @embedFile("spec/user_stories/off_hold_3s_sets_app_on.json"),
        @embedFile("spec/user_stories/off_hold_less_than_3s_keeps_app_off.json"),
        @embedFile("spec/user_stories/off_hold_less_than_3s_keeps_wifi_off.json"),
        @embedFile("spec/user_stories/off_hold_over_3s_fires_power_on_once.json"),
        @embedFile("spec/user_stories/off_hold_over_3s_keeps_app_on.json"),
        @embedFile("spec/user_stories/off_hold_over_3s_keeps_wifi_off.json"),
        @embedFile("spec/user_stories/off_hold_release_keeps_app_on.json"),
        @embedFile("spec/user_stories/off_hold_release_keeps_wifi_off.json"),
        @embedFile("spec/user_stories/off_raw_hold_over_3s_keeps_app_on.json"),
        @embedFile("spec/user_stories/off_short_click_does_not_request_connect.json"),
        @embedFile("spec/user_stories/off_short_click_keeps_app_off.json"),
        @embedFile("spec/user_stories/off_short_click_keeps_wifi_off.json"),
        @embedFile("spec/user_stories/on_click_keeps_app_on.json"),
        @embedFile("spec/user_stories/on_click_connect_request_keeps_wifi_disconnected_until_event.json"),
        @embedFile("spec/user_stories/on_click_requests_connect_when_wifi_off.json"),
        @embedFile("spec/user_stories/on_click_requests_disconnect_when_wifi_on.json"),
        @embedFile("spec/user_stories/on_click_sets_wifi_off_when_wifi_on.json"),
        @embedFile("spec/user_stories/on_click_sets_wifi_on_when_wifi_off.json"),
        @embedFile("spec/user_stories/on_hold_3s_enters_app_off.json"),
        @embedFile("spec/user_stories/on_hold_3s_requests_disconnect_when_wifi_on.json"),
        @embedFile("spec/user_stories/on_hold_3s_sets_wifi_off.json"),
        @embedFile("spec/user_stories/on_hold_less_than_3s_keeps_app_on.json"),
        @embedFile("spec/user_stories/on_hold_less_than_3s_keeps_wifi_state.json"),
        @embedFile("spec/user_stories/wifi_sta_connected_event_does_not_change_app_state.json"),
        @embedFile("spec/user_stories/wifi_sta_connected_event_does_not_change_wifi_intent.json"),
        @embedFile("spec/user_stories/wifi_sta_connected_starts_ip_timeout_window.json"),
        @embedFile("spec/user_stories/wifi_sta_connected_with_zero_timestamp_starts_ip_timeout_window.json"),
        @embedFile("spec/user_stories/wifi_sta_connected_without_ip_waits_before_timeout.json"),
        @embedFile("spec/user_stories/wifi_sta_connected_without_ip_reconnects_when_intent_on.json"),
        @embedFile("spec/user_stories/wifi_sta_connected_without_ip_times_out_after_3s.json"),
        @embedFile("spec/user_stories/wifi_sta_disconnected_event_does_not_change_app_state.json"),
        @embedFile("spec/user_stories/wifi_sta_disconnected_event_does_not_change_wifi_intent.json"),
        @embedFile("spec/user_stories/wifi_sta_disconnected_backs_off_before_reconnect.json"),
        @embedFile("spec/user_stories/wifi_sta_got_ip_clears_connect_timeout.json"),
    });
    break :blk builder.build();
};

fn ZuxAppType(comptime platform_grt: type) type {
    const assembler_config: zux.AssemblerConfig = .{
        .max_single_buttons = 1,
        .max_wifi_sta = 1,
        .max_displays = 1,
        .max_reducers = 4,
        .max_custom_events = 5,
        .store = .{
            .max_stores = 8,
            .max_state_nodes = 16,
            .max_store_refs = 8,
            .max_depth = 4,
        },
    };
    var spec = SpecType.init();
    var assembler = spec.assembler(platform_grt, assembler_config);
    reducers_mod.registerCustomEvents(&assembler);
    const BuildConfig = assembler.BuildConfig();
    return assembler.build(spec.defaultBuildConfig(BuildConfig));
}

pub fn make(comptime platform_ctx: type, comptime platform_grt: type) type {
    return launcher.make(struct {
        const Self = @This();

        pub const ZuxApp = ZuxAppType(platform_grt);

        pub const title = "gizclaw-zux-speedtest";
        pub const description = "WiFi, GizClaw, and 240x240 LVGL speed test app.";
        pub const initialStateProvidedByLauncher = true;
        const Reducers = reducers_mod.make(platform_grt, ZuxApp);
        const Runtime = runtime_mod.make(platform_ctx, platform_grt, ZuxApp);
        const Renders = renders_mod.make(platform_ctx, platform_grt, ZuxApp, Runtime);

        allocator: glib.std.mem.Allocator,
        zux_app: ZuxApp,
        renders: Renders = undefined,
        reducers: Reducers = undefined,
        runtime: Runtime = undefined,

        pub fn init(allocator: glib.std.mem.Allocator, base_config: ZuxApp.InitConfig) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            self.* = .{
                .allocator = allocator,
                .zux_app = undefined,
            };
            self.reducers = Reducers.init(allocator, &self.zux_app);
            self.renders = Renders.init(.{ .allocator = allocator, .zux_app = &self.zux_app });

            var init_config = base_config;
            init_config.allocator = allocator;
            init_config.initial_state = .{
                .boot = .{},
                .wifi = .{},
                .display = .{
                    .enabled = true,
                    .brightness = 255,
                },
                .app_state = .{
                    .state = .off,
                },
                .wifi_state = .{
                    .state = .off,
                },
                .gizclaw_state = .{
                    .state = .disconnected,
                },
                .smoke_status = .{
                    .round = 0,
                    .ping_rtt_ms = 0,
                    .up_bytes = 0,
                    .down_bytes = 0,
                    .up_total = 0,
                    .down_total = 0,
                    .up_mbps_milli = 0,
                    .down_mbps_milli = 0,
                    .duplex_up_mbps_milli = 0,
                    .duplex_down_mbps_milli = 0,
                    .cpu0_percent = 0,
                    .cpu1_percent = 0,
                    .mem_internal_free_kib = 0,
                    .mem_psram_free_kib = 0,
                },
            };
            init_config.app_reducer = ZuxApp.ReducerHook.init(&self.reducers.app);
            init_config.wifi_reducer = ZuxApp.ReducerHook.init(&self.reducers.wifi);
            init_config.gizclaw_reducer = ZuxApp.ReducerHook.init(&self.reducers.gizclaw);
            init_config.smoke_status_reducer = ZuxApp.ReducerHook.init(&self.reducers.smoke_status);
            init_config.button_render = ZuxApp.RenderHook.init(&self.renders.button);
            init_config.smoke_status_render = ZuxApp.RenderHook.init(&self.renders.ui);
            init_config.wifi_status_render = ZuxApp.RenderHook.init(&self.renders.ui);
            init_config.wifi_intent_render = ZuxApp.RenderHook.init(&self.renders.wifi);
            init_config.wifi_recovery_render = ZuxApp.RenderHook.initFn(&self.renders.wifi, "recover");

            self.zux_app = try ZuxApp.init(init_config);
            errdefer self.zux_app.deinit();
            self.runtime = try Runtime.init(.{
                .allocator = allocator,
                .zux_app = &self.zux_app,
                .reducers = &self.reducers,
            });
            self.renders.bindRuntime(&self.runtime);
            try self.runtime.start();
            errdefer self.runtime.deinit();
            return self;
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            self.runtime.deinit();
            self.zux_app.deinit();
            self.* = undefined;
            allocator.destroy(self);
        }

        pub fn createTestRunner() glib.testing.TestRunner {
            return speedtestTestRunner(platform_grt);
        }
    });
}

pub fn speedtestTestRunner(comptime platform_grt: type) glib.testing.TestRunner {
    const ZuxApp = ZuxAppType(platform_grt);
    const Reducers = reducers_mod.make(platform_grt, ZuxApp);
    const TestRuntime = struct {
        ui: Ui = .{},

        const Ui = struct {
            pub fn requestRender(_: *@This()) !void {}
        };
    };
    const Renders = renders_mod.make(TestPlatformCtx, platform_grt, ZuxApp, TestRuntime);
    const UserStoryConfigFactoryImpl = struct {
        instance: Instance = undefined,

        pub const Instance = struct {
            init_config: ZuxApp.InitConfig,
            zux_app: ZuxApp = undefined,
            renders: Renders = undefined,
            reducers: Reducers = undefined,

            pub fn config(self_instance: *@This()) ZuxApp.InitConfig {
                return self_instance.init_config;
            }

            pub fn start(self_instance: *@This(), app: *ZuxApp) !void {
                self_instance.renders = Renders.init(.{ .allocator = self_instance.init_config.allocator, .zux_app = app });
            }

            pub fn deinit(self_instance: *@This()) void {
                _ = self_instance;
            }
        };

        pub fn make(self_factory: *@This(), init_config: ZuxApp.InitConfig) !*Instance {
            self_factory.instance = .{ .init_config = init_config };
            self_factory.instance.reducers = Reducers.init(init_config.allocator, &self_factory.instance.zux_app);
            self_factory.instance.init_config.app_reducer = ZuxApp.ReducerHook.init(&self_factory.instance.reducers.app);
            self_factory.instance.init_config.wifi_reducer = ZuxApp.ReducerHook.init(&self_factory.instance.reducers.wifi);
            self_factory.instance.init_config.gizclaw_reducer = ZuxApp.ReducerHook.init(&self_factory.instance.reducers.gizclaw);
            self_factory.instance.init_config.smoke_status_reducer = ZuxApp.ReducerHook.init(&self_factory.instance.reducers.smoke_status);
            self_factory.instance.init_config.button_render = ZuxApp.RenderHook.init(&self_factory.instance.renders.button);
            self_factory.instance.init_config.smoke_status_render = ZuxApp.RenderHook.init(&self_factory.instance.renders.ui);
            self_factory.instance.init_config.wifi_status_render = ZuxApp.RenderHook.init(&self_factory.instance.renders.ui);
            self_factory.instance.init_config.wifi_intent_render = ZuxApp.RenderHook.init(&self_factory.instance.renders.wifi);
            self_factory.instance.init_config.wifi_recovery_render = ZuxApp.RenderHook.initFn(&self_factory.instance.renders.wifi, "recover");
            return &self_factory.instance;
        }
    };

    const spec = SpecType.init();
    return spec.testRunner(ZuxApp, UserStoryConfigFactoryImpl);
}

pub fn run(comptime platform_ctx: type, comptime platform_grt: type) !void {
    const Launcher = make(platform_ctx, platform_grt);

    try platform_ctx.setup();
    defer platform_ctx.teardown();

    var t = glib.testing.T.new(platform_grt.std, platform_grt.time, .zux_app);
    defer t.deinit();

    t.run("gizclaw-zux-speedtest/stories", Launcher.createTestRunner());
    if (!t.wait()) return error.TestFailed;
}
