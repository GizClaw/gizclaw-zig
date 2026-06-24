const embed = @import("embed");
const glib = @import("glib");
const gizclaw = @import("gizclaw");
const launcher = @import("launcher");
const build_config = @import("build_config");

const consts = @import("consts.zig");
const reducers_mod = @import("reducers.zig");
const renders_mod = @import("renders.zig");
const runtime_mod = @import("runtime.zig");

const Preferences = embed.system.Preferences;

var desktop_preferences = MemoryPreferencesProvider{};
var test_preferences = MemoryPreferencesProvider{};

pub const DesktopPlatformCtx = struct {
    pub fn preferencesProvider(_: anytype) !Preferences.Provider {
        return Preferences.Provider.init(&desktop_preferences);
    }
};

pub const TestPlatformCtx = struct {
    pub fn preferencesProvider(_: anytype) !Preferences.Provider {
        return Preferences.Provider.init(&test_preferences);
    }
};

fn EmptyRegistry(comptime T: type) type {
    return struct {
        periphs: [0]T = .{},
        len: usize = 0,
    };
}

fn SingleRegistry(comptime T: type, comptime periph: T) type {
    return struct {
        periphs: [1]T = .{periph},
        len: usize = 1,
    };
}

const EmptyPeriph = struct {
    label: @Type(.enum_literal) = .none,
};

fn ChatSmokeZuxApp(comptime platform_grt: type) type {
    return struct {
        const Self = @This();
        const log = platform_grt.std.log.scoped(.chat_smoke);

        pub const PipelineConfig = struct {
            capacity: usize = 64,
            tick_interval: platform_grt.time.duration.Duration = 10 * platform_grt.time.duration.MilliSecond,
            task_options: glib.task.Options = .{ .min_stack_size = 16 * 1024 },
        };
        pub const PollerConfig = struct {
            poll_interval: platform_grt.time.duration.Duration = 10 * platform_grt.time.duration.MilliSecond,
            task_options: glib.task.Options = .{ .min_stack_size = 8 * 1024 },
        };
        pub const InitConfig = struct {
            allocator: platform_grt.std.mem.Allocator,
            boot: embed.drivers.button.Single,
            wifi: embed.drivers.wifi.Sta,
            pipeline_config: PipelineConfig = .{},
            poller_config: PollerConfig = .{},
        };
        pub const StartConfig = struct {};
        pub const PeriphLabel = enum {
            boot,
            wifi,
        };
        pub const registries = .{
            .adc_button = EmptyRegistry(EmptyPeriph){},
            .bt = EmptyRegistry(EmptyPeriph){},
            .audio_system = EmptyRegistry(EmptyPeriph){},
            .display = EmptyRegistry(EmptyPeriph){},
            .single_button = SingleRegistry(EmptyPeriph, .{ .label = .boot }){},
            .imu = EmptyRegistry(EmptyPeriph){},
            .ledstrip = EmptyRegistry(EmptyPeriph){},
            .modem = EmptyRegistry(EmptyPeriph){},
            .nfc = EmptyRegistry(EmptyPeriph){},
            .switch_output = EmptyRegistry(EmptyPeriph){},
            .pwm = EmptyRegistry(EmptyPeriph){},
            .touch = EmptyRegistry(EmptyPeriph){},
            .wifi_sta = SingleRegistry(EmptyPeriph, .{ .label = .wifi }){},
            .wifi_ap = EmptyRegistry(EmptyPeriph){},
        };

        allocator: platform_grt.std.mem.Allocator,
        boot: embed.drivers.button.Single,
        wifi: embed.drivers.wifi.Sta,
        started: bool = false,

        pub fn init(config: InitConfig) !Self {
            _ = config.pipeline_config;
            _ = config.poller_config;
            return .{
                .allocator = config.allocator,
                .boot = config.boot,
                .wifi = config.wifi,
            };
        }

        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        pub fn start(self: *Self, config: StartConfig) !void {
            _ = config;
            self.started = true;
        }

        pub fn stop(self: *Self) !void {
            self.started = false;
        }

        pub fn press_single_button(self: *Self, label: PeriphLabel) !void {
            _ = self;
            log.info("single button press label={s}", .{@tagName(label)});
        }

        pub fn release_single_button(self: *Self, label: PeriphLabel) !void {
            _ = self;
            log.info("single button release label={s}", .{@tagName(label)});
        }

        pub fn press_grouped_button(self: *Self, label: PeriphLabel, index: u32) !void {
            _ = self;
            log.info("grouped button press label={s} index={d}", .{ @tagName(label), index });
        }

        pub fn release_grouped_button(self: *Self, label: PeriphLabel) !void {
            _ = self;
            log.info("grouped button release label={s}", .{@tagName(label)});
        }
    };
}

pub fn make(comptime platform_ctx: type, comptime platform_grt: type) type {
    const log = platform_grt.std.log.scoped(.chat_smoke);
    const sdk = gizclaw.make(platform_grt, .{});
    return launcher.make(struct {
        const Self = @This();

        pub const ZuxApp = ChatSmokeZuxApp(platform_grt);
        pub const title = "gizclaw-chat-smoke";
        pub const description = "Smoke app for the firmware GizClaw chat path.";

        allocator: glib.std.mem.Allocator,
        zux_app: ZuxApp,
        reducers: reducers_mod.Reducers = .{},
        renders: renders_mod.Renders = .{},
        runtime: runtime_mod.Runtime = .{},
        gizclaw_config: sdk.Context.Config,
        started: bool = false,

        pub fn init(allocator: glib.std.mem.Allocator, base_config: ZuxApp.InitConfig) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            var init_config = base_config;
            init_config.allocator = allocator;
            const gizclaw_config = try loadGizClawConfig(allocator);
            self.* = .{
                .allocator = allocator,
                .zux_app = try ZuxApp.init(init_config),
                .gizclaw_config = gizclaw_config,
            };
            errdefer self.zux_app.deinit();

            self.reducers = reducers_mod.init();
            self.renders = renders_mod.init();
            self.runtime = runtime_mod.init(.{
                .workspace = build_config.chat_workspace,
                .workflow = build_config.chat_workflow,
                .mode = parseMode(build_config.chat_default_mode),
            });

            var public_buf: [52]u8 = undefined;
            log.info("chat_smoke gizclaw context ready server={s} public={s}", .{
                self.gizclaw_config.server_addr,
                sdk.key.format(self.gizclaw_config.key_pair.public, &public_buf),
            });
            return self;
        }

        pub fn start(self: *Self) !void {
            if (self.started) return;
            self.started = true;
            try self.zux_app.start(.{});
            log.info(
                "chat_smoke start mode={s} workspace={s} workflow={s} server={s}",
                .{
                    modeName(self.runtime.mode),
                    self.runtime.workspace,
                    self.runtime.workflow,
                    build_config.gizclaw_server_addr,
                },
            );
        }

        pub fn stop(self: *Self) void {
            self.started = false;
            self.zux_app.stop() catch {};
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            self.zux_app.deinit();
            self.* = undefined;
            allocator.destroy(self);
        }

        pub fn createTestRunner() glib.testing.TestRunner {
            return chatSmokeTestRunner(platform_grt);
        }

        fn loadGizClawConfig(allocator: glib.std.mem.Allocator) !sdk.Context.Config {
            if (comptime @hasDecl(platform_ctx, "preferencesProvider")) {
                var provider_impl = try platform_ctx.preferencesProvider(allocator);
                const provider = if (@TypeOf(provider_impl) == Preferences.Provider)
                    provider_impl
                else
                    provider_impl.handle();
                return try sdk.Context.fromPreferences(.{
                    .server_addr = build_config.gizclaw_server_addr,
                    .server_key = build_config.gizclaw_server_key,
                    .client_key = build_config.gizclaw_client_key,
                }, provider);
            }

            return try sdk.Context.fromExplicit(.{
                .server_addr = build_config.gizclaw_server_addr,
                .server_key = build_config.gizclaw_server_key,
                .client_key = build_config.gizclaw_client_key,
            });
        }
    });
}

pub fn chatSmokeTestRunner(comptime platform_grt: type) glib.testing.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: platform_grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *glib.testing.T, allocator: platform_grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;
            t.expect("chat_smoke skeleton has a selected mode", parseMode(build_config.chat_default_mode) != .unknown);
            t.expect("chat_smoke has a runtime split", @sizeOf(runtime_mod.Runtime) > 0);
            return true;
        }
    };
    return glib.testing.TestRunner.make("zux/chat_smoke", Runner{});
}

fn parseMode(value: []const u8) consts.Mode {
    if (glib.std.mem.eql(u8, value, "push_to_talk")) return .push_to_talk;
    if (glib.std.mem.eql(u8, value, "realtime")) return .realtime;
    return .unknown;
}

fn modeName(mode: consts.Mode) []const u8 {
    return switch (mode) {
        .push_to_talk => "push_to_talk",
        .realtime => "realtime",
        .unknown => "unknown",
    };
}

const MemoryPreferencesProvider = struct {
    store: MemoryPreferencesStore = .{},

    pub fn open(self: *MemoryPreferencesProvider, namespace: []const u8, options: Preferences.OpenOptions) Preferences.OpenError!Preferences.Store {
        _ = options;
        if (!glib.std.mem.eql(u8, namespace, "gizclaw")) return error.NotFound;
        return Preferences.Store.init(&self.store);
    }
};

const MemoryPreferencesStore = struct {
    value: [64]u8 = undefined,
    len: usize = 0,

    pub fn get(self: *MemoryPreferencesStore, key: []const u8, out: []u8) Preferences.GetError!usize {
        if (!glib.std.mem.eql(u8, key, "client_key")) return error.NotFound;
        if (self.len == 0) return error.NotFound;
        if (out.len < self.len) return error.BufferTooSmall;
        @memcpy(out[0..self.len], self.value[0..self.len]);
        return self.len;
    }

    pub fn put(self: *MemoryPreferencesStore, key: []const u8, value: []const u8) Preferences.PutError!void {
        if (!glib.std.mem.eql(u8, key, "client_key")) return error.InvalidKey;
        if (value.len > self.value.len) return error.ValueTooLarge;
        @memcpy(self.value[0..value.len], value);
        self.len = value.len;
    }

    pub fn remove(self: *MemoryPreferencesStore, key: []const u8) Preferences.RemoveError!void {
        if (!glib.std.mem.eql(u8, key, "client_key")) return error.NotFound;
        self.len = 0;
    }

    pub fn contains(self: *MemoryPreferencesStore, key: []const u8) bool {
        return glib.std.mem.eql(u8, key, "client_key") and self.len != 0;
    }

    pub fn clear(self: *MemoryPreferencesStore) Preferences.ClearError!void {
        self.len = 0;
    }
};
