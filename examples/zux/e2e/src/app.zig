const glib = @import("glib");
const embed = @import("embed");
const launcher = @import("launcher");
const build_config = @import("build_config");
const common = @import("e2e_common");
const e2e_assets = @import("e2e_assets");
const e2e_runners = @import("e2e_runners");
const RpcRunner = e2e_runners.rpc;
const RpcServerRunRunner = e2e_runners.rpc_server_run;
const RpcResourcesRunner = e2e_runners.rpc_resources;
const SpeedRunner = @import("SpeedRunner.zig");
const ChatRunner = e2e_runners.chat;

const grt = common.grt;
const duration = grt.time.duration;

pub const DesktopPlatformCtx = struct {};
pub const TestPlatformCtx = struct {};

const E2ESuite = enum {
    rpc,
    rpc_server_run,
    rpc_resources,
    speed,
    chat,
    all,
};

const selected_suite = parseE2ESuite(build_config.e2e_suite);
const wifi_connect_timeout: glib.time.duration.Duration = 30 * glib.time.duration.Second;
const wifi_connect_retry_interval: glib.time.duration.Duration = 5 * glib.time.duration.Second;
const wifi_connect_poll_interval: glib.time.duration.Duration = 100 * glib.time.duration.MilliSecond;

const embedded_chat_audio = [_]ChatRunner.ChatAudioAsset{
    .{
        .name = e2e_assets.chat_round_01.name,
        .expected_text = "请问你能听清楚我说话吗",
        .ogg_opus = e2e_assets.chat_round_01.ogg_opus,
    },
    .{
        .name = e2e_assets.chat_round_02.name,
        .expected_text = "请用一句话回答你现在状态好吗",
        .ogg_opus = e2e_assets.chat_round_02.ogg_opus,
    },
    .{
        .name = e2e_assets.chat_round_03.name,
        .expected_text = "好的我们继续下一轮测试",
        .ogg_opus = e2e_assets.chat_round_03.ogg_opus,
    },
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

fn MinimalZuxApp(comptime platform_grt: type) type {
    return struct {
        const Self = @This();

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
            wifi: embed.drivers.wifi.Sta = undefined,
            pipeline_config: PipelineConfig = .{},
            poller_config: PollerConfig = .{},
        };
        pub const StartConfig = struct {};
        pub const PeriphLabel = enum { none };
        pub const registries = .{
            .adc_button = EmptyRegistry(EmptyPeriph){},
            .bt = EmptyRegistry(EmptyPeriph){},
            .audio_system = EmptyRegistry(EmptyPeriph){},
            .display = EmptyRegistry(EmptyPeriph){},
            .single_button = EmptyRegistry(EmptyPeriph){},
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
        wifi: embed.drivers.wifi.Sta,
        started: bool = false,

        pub fn init(config: InitConfig) !Self {
            return .{
                .allocator = config.allocator,
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
            _ = label;
            return error.InvalidPeriphKind;
        }

        pub fn release_single_button(self: *Self, label: PeriphLabel) !void {
            _ = self;
            _ = label;
            return error.InvalidPeriphKind;
        }

        pub fn press_grouped_button(self: *Self, label: PeriphLabel, button_id: u32) !void {
            _ = self;
            _ = label;
            _ = button_id;
            return error.InvalidPeriphKind;
        }

        pub fn release_grouped_button(self: *Self, label: PeriphLabel) !void {
            _ = self;
            _ = label;
            return error.InvalidPeriphKind;
        }
    };
}

pub fn make(comptime platform_ctx: type, comptime platform_grt: type) type {
    return launcher.make(struct {
        const Self = @This();

        pub const ZuxApp = MinimalZuxApp(platform_grt);
        pub const title = "gizclaw-e2e";
        pub const description = "Runs GizClaw e2e TestRunner suites on the selected platform.";

        allocator: glib.std.mem.Allocator,
        zux_app: ZuxApp,
        e2e_ran: bool = false,

        pub fn init(allocator: glib.std.mem.Allocator, base_config: ZuxApp.InitConfig) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            var init_config = base_config;
            init_config.allocator = allocator;
            self.* = .{
                .allocator = allocator,
                .zux_app = try ZuxApp.init(init_config),
            };
            errdefer self.zux_app.deinit();

            return self;
        }

        pub fn start(self: *Self) !void {
            if (self.e2e_ran) return;
            self.e2e_ran = true;
            if (build_config.wifi_ssid.len != 0) {
                try connectWifiBeforeTestRunner(platform_grt, self.zux_app.wifi);
            }
            try runTestRunner(platform_ctx, platform_grt, self.allocator);
        }

        pub fn stop(self: *Self) void {
            _ = self;
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            self.zux_app.deinit();
            self.* = undefined;
            allocator.destroy(self);
        }

        pub fn createTestRunner() glib.testing.TestRunner {
            return testRunner(platform_ctx, platform_grt);
        }
    });
}

pub fn testRunner(comptime platform_ctx: type, comptime platform_grt: type) glib.testing.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: platform_grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *glib.testing.T, allocator: platform_grt.std.mem.Allocator) bool {
            _ = self;
            runSelectedSuite(platform_ctx, platform_grt, allocator) catch |err| {
                t.fail("gizclaw/e2e", err);
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: platform_grt.std.mem.Allocator) void {
            _ = self;
            _ = allocator;
        }
    };

    const Holder = struct {
        var runner: Runner = .{};
    };
    return glib.testing.TestRunner.make(Runner).new(&Holder.runner);
}

pub fn run(comptime platform_ctx: type, comptime platform_grt: type) !void {
    try runTestRunner(platform_ctx, platform_grt, platform_grt.std.heap.page_allocator);
}

fn runTestRunner(comptime platform_ctx: type, comptime platform_grt: type, allocator: glib.std.mem.Allocator) !void {
    if (comptime @hasDecl(platform_ctx, "setup")) {
        try platform_ctx.setup();
    }
    defer {
        if (comptime @hasDecl(platform_ctx, "teardown")) {
            platform_ctx.teardown();
        }
    }

    const log = platform_grt.std.log.scoped(.gizclaw_e2e_app);
    log.info("gizclaw e2e start suite={s}", .{@tagName(selected_suite)});
    try runSelectedSuite(platform_ctx, platform_grt, allocator);
    log.info("gizclaw e2e passed suite={s}", .{@tagName(selected_suite)});
}

fn connectWifiBeforeTestRunner(comptime platform_grt: type, wifi: embed.drivers.wifi.Sta) !void {
    const log = platform_grt.std.log.scoped(.gizclaw_e2e_app);
    var state = WifiConnectState(platform_grt){};
    wifi.addEventHook(&state, WifiConnectState(platform_grt).onEvent);
    defer wifi.removeEventHook(&state, WifiConnectState(platform_grt).onEvent);

    wifi.setPowerSave(.none) catch |err| {
        log.warn("wifi power save setup failed: {s}", .{@errorName(err)});
    };

    const deadline = glib.time.instant.add(platform_grt.time.instant.now(), wifi_connect_timeout);
    var next_connect: glib.time.instant.Time = 0;
    log.info("wifi connect before e2e suite ssid={s} timeout_ns={d}", .{ build_config.wifi_ssid, wifi_connect_timeout });

    while (platform_grt.time.instant.now() < deadline) {
        if (wifi.getIpInfo() != null or state.got_ip) {
            log.info("wifi ready before e2e suite", .{});
            return;
        }

        const now = platform_grt.time.instant.now();
        const wifi_state = wifi.getState();
        if (wifi_state != .connecting and now >= next_connect) {
            log.info("wifi connect request state={s}", .{@tagName(wifi_state)});
            wifi.connect(.{
                .ssid = build_config.wifi_ssid,
                .password = build_config.wifi_password,
            }) catch |err| switch (err) {
                error.Busy => log.warn("wifi connect skipped: busy", .{}),
                else => return err,
            };
            next_connect = glib.time.instant.add(now, wifi_connect_retry_interval);
        }

        platform_grt.time.sleep(wifi_connect_poll_interval);
    }

    return error.WifiConnectTimeout;
}

fn WifiConnectState(comptime platform_grt: type) type {
    return struct {
        got_ip: bool = false,

        pub fn onEvent(ctx: ?*anyopaque, event: embed.drivers.wifi.Sta.Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx orelse return));
            const log = platform_grt.std.log.scoped(.gizclaw_e2e_app);
            switch (event) {
                .got_ip => {
                    self.got_ip = true;
                    log.info("wifi got ip before e2e suite", .{});
                },
                .disconnected => |info| {
                    self.got_ip = false;
                    log.warn("wifi disconnected before e2e suite reason={d}", .{info.reason});
                },
                else => log.info("wifi event before e2e suite event={s}", .{@tagName(event)}),
            }
        }
    };
}

fn runSelectedSuite(comptime platform_ctx: type, comptime platform_grt: type, allocator: glib.std.mem.Allocator) !void {
    _ = platform_ctx;
    switch (selected_suite) {
        .rpc => try runRpc(platform_grt, allocator, RpcRunner),
        .rpc_server_run => try runRpc(platform_grt, allocator, RpcServerRunRunner),
        .rpc_resources => try runRpc(platform_grt, allocator, RpcResourcesRunner),
        .speed => try runSpeed(platform_grt, allocator),
        .chat => try runChat(platform_grt, allocator),
        .all => {
            try runRpc(platform_grt, allocator, RpcRunner);
            try runRpc(platform_grt, allocator, RpcServerRunRunner);
            try runRpc(platform_grt, allocator, RpcResourcesRunner);
            try runSpeed(platform_grt, allocator);
            try runChat(platform_grt, allocator);
        },
    }
}

fn runRpc(comptime platform_grt: type, allocator: glib.std.mem.Allocator, comptime Runner: type) !void {
    const config = Runner.Config{
        .base = baseOptions(),
        .allow_mutations = build_config.e2e_allow_mutations,
    };
    var reporter = Reporter(platform_grt, Runner.Summary).init();
    const summary = try runWithSelectedSdk(Runner, allocator, config, &reporter);
    try finishSummary(platform_grt, "rpc", summary.passed, summary.skipped, summary.failed);
}

fn runSpeed(comptime platform_grt: type, allocator: glib.std.mem.Allocator) !void {
    const bytes = @as(i64, @intCast(build_config.e2e_speed_bytes));
    const config = SpeedRunner.Config{
        .base = baseOptions(),
        .up_bytes = bytes,
        .down_bytes = bytes,
        .timeout_ms = build_config.e2e_speed_timeout_ms,
    };
    var reporter = Reporter(platform_grt, SpeedRunner.Summary).init();
    const summary = try runWithSelectedSdk(SpeedRunner, allocator, config, &reporter);
    try finishSummary(platform_grt, "speed", summary.passed, summary.skipped, summary.failed);
}

fn runChat(comptime platform_grt: type, allocator: glib.std.mem.Allocator) !void {
    const config = ChatRunner.Config{
        .base = baseOptions(),
        .workspace_config_json = e2e_assets.doubao_realtime_workspace_config_json,
        .workspace_name = build_config.chat_workspace,
        .mode = chatMode(),
        .embedded_audio = &embedded_chat_audio,
        .rounds = build_config.e2e_chat_rounds,
        .min_rounds = 3,
        .run_timeout_ms = build_config.e2e_chat_run_timeout_ms,
        .conversation_timeout_ms = build_config.e2e_chat_conversation_timeout_ms,
    };
    var reporter = Reporter(platform_grt, ChatRunner.Summary).init();
    const summary = try runWithSelectedSdk(ChatRunner, allocator, config, &reporter);
    try finishSummary(platform_grt, "chat", summary.passed, summary.skipped, summary.failed);
}

fn runWithSelectedSdk(comptime Runner: type, allocator: glib.std.mem.Allocator, config: Runner.Config, reporter: anytype) !Runner.Summary {
    var ctx = try common.loadContext(allocator, config.base);
    defer ctx.deinit();
    return switch (ctx.cipher_mode) {
        .chacha_poly => try Runner.runWithContext(common.chacha_sdk, allocator, ctx, config, reporter),
        .aes_256_gcm => try Runner.runWithContext(common.aes_256_gcm_sdk, allocator, ctx, config, reporter),
        .plaintext => try Runner.runWithContext(common.plaintext_sdk, allocator, ctx, config, reporter),
    };
}

fn baseOptions() common.BaseOptions {
    return .{
        .server_addr = build_config.server_addr,
        .server_pub_key = build_config.server_pub_key,
        .client_pri_key = build_config.client_pri_key,
        .cipher_mode = cipherMode(),
        .connect_timeout_ms = build_config.e2e_connect_timeout_ms,
    };
}

fn cipherMode() ?common.CipherMode {
    if (build_config.e2e_cipher_mode.len == 0) return null;
    return common.parseCipherMode(build_config.e2e_cipher_mode) catch null;
}

fn chatMode() ChatRunner.Mode {
    if (glib.std.mem.eql(u8, build_config.chat_default_mode, "realtime")) return .realtime;
    return .push_to_talk;
}

fn Reporter(comptime platform_grt: type, comptime Summary: type) type {
    return struct {
        pub fn init() @This() {
            return .{};
        }

        pub fn pass(self: *@This(), name: []const u8) !void {
            _ = self;
            const log = platform_grt.std.log.scoped(.gizclaw_e2e_app);
            log.info("PASS {s}", .{name});
        }

        pub fn fail(self: *@This(), name: []const u8, err: anyerror) !void {
            _ = self;
            const log = platform_grt.std.log.scoped(.gizclaw_e2e_app);
            log.err("FAIL {s}: {s}", .{ name, @errorName(err) });
        }

        pub fn metric(self: *@This(), name: []const u8, value: u64, unit: []const u8) !void {
            _ = self;
            const log = platform_grt.std.log.scoped(.gizclaw_e2e_app);
            log.info("METRIC {s}={d}{s}", .{ name, value, unit });
        }

        pub fn speed(self: *@This(), summary: Summary) !void {
            _ = self;
            const log = platform_grt.std.log.scoped(.gizclaw_e2e_app);
            log.info(
                "SPEED up_bytes={d} down_bytes={d} duration_ms={d} up_mbps={d}.{d:0>3} down_mbps={d}.{d:0>3}",
                .{
                    summary.up_bytes,
                    summary.down_bytes,
                    @divTrunc(summary.duration_ns, duration.MilliSecond),
                    @divTrunc(summary.up_mbps_milli, 1000),
                    @mod(summary.up_mbps_milli, 1000),
                    @divTrunc(summary.down_mbps_milli, 1000),
                    @mod(summary.down_mbps_milli, 1000),
                },
            );
        }
    };
}

fn finishSummary(comptime platform_grt: type, label: []const u8, passed: usize, skipped: usize, failed: usize) !void {
    const log = platform_grt.std.log.scoped(.gizclaw_e2e_app);
    log.info("SUMMARY {s} pass={d} skip={d} fail={d}", .{ label, passed, skipped, failed });
    if (failed != 0) return error.E2EFailed;
}

fn parseE2ESuite(comptime value: []const u8) E2ESuite {
    if (glib.std.mem.eql(u8, value, "rpc")) return .rpc;
    if (glib.std.mem.eql(u8, value, "rpc_server_run")) return .rpc_server_run;
    if (glib.std.mem.eql(u8, value, "rpc_resources")) return .rpc_resources;
    if (glib.std.mem.eql(u8, value, "speed")) return .speed;
    if (glib.std.mem.eql(u8, value, "chat")) return .chat;
    if (glib.std.mem.eql(u8, value, "all")) return .all;
    @compileError("unknown gizclaw e2e suite: " ++ value);
}
