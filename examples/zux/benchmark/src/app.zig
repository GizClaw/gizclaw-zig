const glib = @import("glib");
const embed = @import("embed");
const giznet = @import("giznet");
const launcher = @import("launcher");
const build_config = @import("build_config");

const GizNetBenchmarkRunner = giznet.test_runner.benchmark;
const GizNetBenchmark = giznet.test_runner.benchmark.giz_net;
const NoiseBenchmark = giznet.test_runner.benchmark.noise;
const ServiceBenchmark = giznet.test_runner.benchmark.service;
const KcpStreamBenchmark = giznet.test_runner.benchmark.kcp_stream;
const KcpStreamRealUdpBenchmark = giznet.test_runner.benchmark.kcp_stream_real_udp;

const BenchmarkSuite = enum {
    service,
    kcp_stream,
    kcp_stream_real_udp,
    kcp_stream_relay_udp,
    noise,
    giz_net,
    all,
};

const benchmark_suite = parseBenchmarkSuite(build_config.giznet_benchmark_suite);
const benchmark_requires_wifi = benchmark_suite == .kcp_stream_real_udp or benchmark_suite == .kcp_stream_relay_udp;
const wifi_connect_timeout: glib.time.duration.Duration = 30 * glib.time.duration.Second;
const wifi_connect_retry_interval: glib.time.duration.Duration = 5 * glib.time.duration.Second;
const wifi_connect_poll_interval: glib.time.duration.Duration = 100 * glib.time.duration.MilliSecond;

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
            wifi: ?embed.drivers.wifi.Sta = null,
            pipeline_config: PipelineConfig = .{},
            poller_config: PollerConfig = .{},
        };
        pub const StartConfig = struct {};
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
            .wifi_sta = if (benchmark_requires_wifi)
                SingleRegistry(EmptyPeriph, .{ .label = .wifi }){}
            else
                EmptyRegistry(EmptyPeriph){},
            .wifi_ap = EmptyRegistry(EmptyPeriph){},
        };

        allocator: platform_grt.std.mem.Allocator,
        wifi: ?embed.drivers.wifi.Sta = null,
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
    };
}

pub fn make(comptime platform_ctx: type, comptime platform_grt: type) type {
    return launcher.make(struct {
        const Self = @This();

        pub const ZuxApp = MinimalZuxApp(platform_grt);
        pub const title = "giznet-benchmark";
        pub const description = "Runs giznet TestRunner benchmarks on the selected platform.";

        allocator: glib.std.mem.Allocator,
        zux_app: ZuxApp,
        benchmark_ran: bool = false,

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
            if (self.benchmark_ran) return;
            self.benchmark_ran = true;
            if (comptime benchmark_requires_wifi) {
                try connectWifiBeforeBenchmark(platform_grt, self.zux_app.wifi orelse return error.WifiUnavailable);
            }
            try runBenchmark(platform_ctx, platform_grt);
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
            return benchmarkRunner(platform_ctx, platform_grt);
        }
    });
}

pub fn benchmarkRunner(comptime platform_ctx: type, comptime platform_grt: type) glib.testing.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: platform_grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *glib.testing.T, allocator: platform_grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            runSelectedSuite(platform_ctx, platform_grt, t);
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
    try runBenchmark(platform_ctx, platform_grt);
}

fn runBenchmark(comptime platform_ctx: type, comptime platform_grt: type) !void {
    if (comptime @hasDecl(platform_ctx, "setup")) {
        try platform_ctx.setup();
    }
    defer {
        if (comptime @hasDecl(platform_ctx, "teardown")) {
            platform_ctx.teardown();
        }
    }

    const log = platform_grt.std.log.scoped(.giznet_benchmark_app);
    log.info("giznet benchmark start suite={s}", .{@tagName(benchmark_suite)});

    var t = glib.testing.T.new(platform_grt.std, platform_grt.time, .benchmark);
    defer t.deinit();

    t.run("giznet/benchmark", benchmarkRunner(platform_ctx, platform_grt));
    if (!t.wait()) return error.TestFailed;

    log.info("giznet benchmark passed suite={s}", .{@tagName(benchmark_suite)});
}

fn connectWifiBeforeBenchmark(comptime platform_grt: type, wifi: embed.drivers.wifi.Sta) !void {
    const log = platform_grt.std.log.scoped(.giznet_benchmark_app);
    var state = WifiConnectState(platform_grt){};
    wifi.addEventHook(&state, WifiConnectState(platform_grt).onEvent);
    defer wifi.removeEventHook(&state, WifiConnectState(platform_grt).onEvent);

    wifi.setPowerSave(.none) catch |err| {
        log.warn("wifi power save setup failed: {s}", .{@errorName(err)});
    };

    const deadline = glib.time.instant.add(platform_grt.time.instant.now(), wifi_connect_timeout);
    var next_connect: glib.time.instant.Time = 0;
    log.info("wifi connect before benchmark ssid={s} timeout_ns={d}", .{ build_config.wifi_ssid, wifi_connect_timeout });

    while (platform_grt.time.instant.now() < deadline) {
        if (wifi.getIpInfo() != null or state.got_ip.load(.acquire)) {
            log.info("wifi ready before benchmark", .{});
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
        got_ip: platform_grt.std.atomic.Value(bool) = platform_grt.std.atomic.Value(bool).init(false),

        pub fn onEvent(ctx: ?*anyopaque, event: embed.drivers.wifi.Sta.Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx orelse return));
            const log = platform_grt.std.log.scoped(.giznet_benchmark_app);
            switch (event) {
                .got_ip => {
                    self.got_ip.store(true, .release);
                    log.info("wifi got ip before benchmark", .{});
                },
                .disconnected => |info| {
                    self.got_ip.store(false, .release);
                    log.warn("wifi disconnected before benchmark reason={d}", .{info.reason});
                },
                else => log.info("wifi event before benchmark event={s}", .{@tagName(event)}),
            }
        }
    };
}

fn runSelectedSuite(comptime platform_ctx: type, comptime platform_grt: type, t: *glib.testing.T) void {
    _ = platform_ctx;
    switch (benchmark_suite) {
        .service => t.run("service", ServiceBenchmark.make(platform_grt)),
        .kcp_stream => t.run("service/kcp_stream", KcpStreamBenchmark.make(platform_grt)),
        .kcp_stream_real_udp => t.run("service/kcp_stream_real_udp", KcpStreamRealUdpBenchmark.make(platform_grt)),
        .kcp_stream_relay_udp => t.run("service/kcp_stream_relay_udp", KcpStreamRealUdpBenchmark.makeRelay(
            platform_grt,
            build_config.giznet_benchmark_relay_host,
            build_config.giznet_benchmark_relay_base_port,
        )),
        .noise => t.run("noise", NoiseBenchmark.make(platform_grt)),
        .giz_net => t.run("giz_net", GizNetBenchmark.make(platform_grt)),
        .all => t.run("all", GizNetBenchmarkRunner.make(platform_grt)),
    }
}

fn parseBenchmarkSuite(comptime value: []const u8) BenchmarkSuite {
    if (glib.std.mem.eql(u8, value, "service")) return .service;
    if (glib.std.mem.eql(u8, value, "kcp_stream")) return .kcp_stream;
    if (glib.std.mem.eql(u8, value, "kcp_stream_real_udp")) return .kcp_stream_real_udp;
    if (glib.std.mem.eql(u8, value, "kcp_stream_relay_udp")) return .kcp_stream_relay_udp;
    if (glib.std.mem.eql(u8, value, "noise")) return .noise;
    if (glib.std.mem.eql(u8, value, "giz_net")) return .giz_net;
    if (glib.std.mem.eql(u8, value, "all")) return .all;
    @compileError("unknown giznet benchmark suite: " ++ value);
}
