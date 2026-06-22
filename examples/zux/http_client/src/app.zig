const build_config = @import("build_config");
const embed = @import("embed");
const glib = @import("glib");
const launcher = @import("launcher");

const http_download_host = "192.168.1.6";
const http_download_ips = [_][4]u8{
    .{ 192, 168, 1, 6 },
};
const http_download_path = "/dl?size=10485760";
const http_download_bytes: i64 = 10 * 1024 * 1024;
const http_download_port: u16 = 18080;
const http_download_url = "http://192.168.1.6:18080/dl?size=10485760";
const http_read_buffer_size = 64 * 1024;

const wifi_connect_timeout: glib.time.duration.Duration = 30 * glib.time.duration.Second;
const wifi_connect_retry_interval: glib.time.duration.Duration = 5 * glib.time.duration.Second;
const wifi_connect_poll_interval: glib.time.duration.Duration = 100 * glib.time.duration.MilliSecond;

const HttpProbeResult = extern struct {
    rc: c_int = 0,
    status_code: c_int = 0,
    errno_value: c_int = 0,
    body_bytes: i64 = 0,
    duration_us: i64 = 0,
    connect_us: i64 = 0,
    recv_calls: u64 = 0,
    slow_recv_calls: u64 = 0,
    max_recv_us: i64 = 0,
    max_recv_bytes: usize = 0,
};

extern fn gizclaw_esp_http_client_download(
    url: [*:0]const u8,
    expected_bytes: i64,
    out: *HttpProbeResult,
) c_int;

extern fn gizclaw_posix_http_download(
    host: [*:0]const u8,
    ip: *const [4]u8,
    port: u16,
    path: [*:0]const u8,
    expected_bytes: i64,
    out: *HttpProbeResult,
) c_int;

pub const DesktopPlatformCtx = struct {};
pub const TestPlatformCtx = struct {};

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
            .wifi_sta = SingleRegistry(EmptyPeriph, .{ .label = .wifi }){},
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
    _ = platform_ctx;
    return launcher.make(struct {
        const Self = @This();
        const log = platform_grt.std.log.scoped(.zux_http_client);

        pub const ZuxApp = MinimalZuxApp(platform_grt);
        pub const title = "zux-http-client-test";
        pub const description = "Connect WiFi and run HTTP download tests synchronously.";

        allocator: glib.std.mem.Allocator,
        zux_app: ZuxApp,
        test_ran: bool = false,

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
            if (self.test_ran) return;
            self.test_ran = true;

            const wifi = self.zux_app.wifi orelse return error.WifiUnavailable;
            connectWifi(platform_grt, wifi) catch |err| {
                log.err("wifi connect failed: {s}", .{@errorName(err)});
                return;
            };
            for (0..3) |round_index| {
                const round = round_index + 1;
                runZigHttpDownload(platform_grt, self.allocator, round) catch |err| {
                    log.warn("zig glib net http round={d} failed: {s}", .{ round, @errorName(err) });
                };
                if (round_index + 1 < 3) {
                    platform_grt.time.sleep(5 * platform_grt.time.duration.Second);
                }
            }
            log.info("http client test done", .{});
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
            return emptyRunner(platform_grt);
        }
    });
}

pub fn run(comptime platform_ctx: type, comptime platform_grt: type) !void {
    _ = platform_ctx;
    var t = glib.testing.T.new(platform_grt.std, platform_grt.time, .zux_app);
    defer t.deinit();

    t.run("zux-http-client-test/empty", emptyRunner(platform_grt));
    if (!t.wait()) return error.TestFailed;
}

fn emptyRunner(comptime platform_grt: type) glib.testing.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: platform_grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *glib.testing.T, allocator: platform_grt.std.mem.Allocator) bool {
            _ = self;
            _ = t;
            _ = allocator;
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

fn connectWifi(comptime platform_grt: type, wifi: embed.drivers.wifi.Sta) !void {
    const log = platform_grt.std.log.scoped(.zux_http_client);
    var state = WifiConnectState(platform_grt){};
    wifi.addEventHook(&state, WifiConnectState(platform_grt).onEvent);
    defer wifi.removeEventHook(&state, WifiConnectState(platform_grt).onEvent);

    wifi.setPowerSave(.none) catch |err| {
        log.warn("wifi power save setup failed: {s}", .{@errorName(err)});
    };

    const deadline = glib.time.instant.add(platform_grt.time.instant.now(), wifi_connect_timeout);
    var next_connect: glib.time.instant.Time = 0;
    log.info("wifi connect ssid={s} timeout_ns={d}", .{ build_config.wifi_ssid, wifi_connect_timeout });

    while (platform_grt.time.instant.now() < deadline) {
        if (wifi.getIpInfo() != null or state.got_ip.load(.acquire)) {
            log.info("wifi ready", .{});
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
            const log = platform_grt.std.log.scoped(.zux_http_client);
            switch (event) {
                .got_ip => {
                    self.got_ip.store(true, .release);
                    log.info("wifi got ip", .{});
                },
                .disconnected => |info| {
                    self.got_ip.store(false, .release);
                    log.warn("wifi disconnected reason={d}", .{info.reason});
                },
                else => log.info("wifi event event={s}", .{@tagName(event)}),
            }
        }
    };
}

fn runZigHttpDownload(comptime grt: type, allocator: grt.std.mem.Allocator, round: usize) !void {
    const log = grt.std.log.scoped(.zux_http_client);
    var last_err: ?anyerror = null;
    for (http_download_ips) |ip| {
        runZigHttpDownloadTo(grt, allocator, round, ip) catch |err| {
            last_err = err;
            log.warn("zig raw http attempt failed ip={d}.{d}.{d}.{d}: {s}", .{
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                @errorName(err),
            });
            continue;
        };
        return;
    }
    return last_err orelse error.ZigHttpDownloadFailed;
}

fn runZigHttpDownloadTo(comptime grt: type, allocator: grt.std.mem.Allocator, round: usize, ip: [4]u8) !void {
    const log = grt.std.log.scoped(.zux_http_client);
    const target = grt.net.netip.AddrPort.from4(ip, http_download_port);
    log.info("zig glib net http round={d} start host={s} ip={d}.{d}.{d}.{d} port={d} path={s} bytes={d}", .{
        round,
        http_download_host,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        http_download_port,
        http_download_path,
        http_download_bytes,
    });

    var context_root = try grt.context.init(allocator);
    defer context_root.deinit();
    var dial_ctx = try context_root.withTimeout(context_root.background(), 10 * glib.time.duration.Second);
    defer dial_ctx.deinit();
    var dialer = grt.net.Dialer.init(allocator, .{});
    const connect_started = grt.time.instant.now();
    var conn = try dialer.dialContext(dial_ctx, .tcp, target);
    const connect_duration = glib.time.instant.sub(grt.time.instant.now(), connect_started);
    defer conn.deinit();
    const io_deadline = grt.time.instant.add(grt.time.instant.now(), 60 * glib.time.duration.Second);
    conn.setReadDeadline(io_deadline);
    conn.setWriteDeadline(io_deadline);

    var request_buf: [256]u8 = undefined;
    const request = try grt.std.fmt.bufPrint(
        &request_buf,
        "GET {s} HTTP/1.1\r\nHost: {s}\r\nRange: bytes=0-{d}\r\nConnection: close\r\nUser-Agent: gizclaw-zig-esp-http-client\r\nAccept: */*\r\n\r\n",
        .{
            http_download_path,
            http_download_host,
            http_download_bytes - 1,
        },
    );
    try writeAll(grt, conn, request);

    const read_buf = try allocator.alloc(u8, http_read_buffer_size);
    defer allocator.free(read_buf);

    var header_buf: [4096]u8 = undefined;
    var header_len: usize = 0;
    var header_done = false;
    var body_bytes: i64 = 0;
    var recv_calls: u64 = 0;
    var slow_recv_calls: u64 = 0;
    var max_recv_us: i64 = 0;
    var max_recv_bytes: usize = 0;
    const started = grt.time.instant.now();
    var next_progress_bytes: i64 = 512 * 1024;

    while (body_bytes < http_download_bytes) {
        const recv_started = grt.time.instant.now();
        const n = conn.read(read_buf) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const recv_us: i64 = @intCast(@divTrunc(glib.time.instant.sub(grt.time.instant.now(), recv_started), glib.time.duration.MicroSecond));
        recv_calls += 1;
        if (recv_us > max_recv_us) {
            max_recv_us = recv_us;
            max_recv_bytes = n;
        }
        if (recv_us >= 100 * 1000) slow_recv_calls += 1;
        if (n == 0) break;
        const chunk = read_buf[0..n];
        if (header_done) {
            body_bytes += @intCast(chunk.len);
            if (body_bytes >= next_progress_bytes) {
                logDownloadProgress(grt, "zig_glib_net_http", round, body_bytes, started);
                while (next_progress_bytes <= body_bytes) next_progress_bytes += 512 * 1024;
            }
            continue;
        }

        const prev_header_len = header_len;
        const available = header_buf.len - header_len;
        const copy_len = @min(chunk.len, available);
        @memcpy(header_buf[header_len..][0..copy_len], chunk[0..copy_len]);
        header_len += copy_len;
        if (grt.std.mem.indexOf(u8, header_buf[0..header_len], "\r\n\r\n")) |header_end| {
            header_done = true;
            const body_start = header_end + 4;
            log.info("zig glib net http round={d} response status='{s}' header_bytes={d}", .{ round, statusLine(grt, header_buf[0..header_len]), body_start });
            body_bytes += @intCast(prev_header_len + chunk.len - body_start);
            if (body_bytes >= next_progress_bytes) {
                logDownloadProgress(grt, "zig_glib_net_http", round, body_bytes, started);
                while (next_progress_bytes <= body_bytes) next_progress_bytes += 512 * 1024;
            }
        } else if (copy_len < chunk.len) {
            return error.HttpHeaderTooLarge;
        }
    }

    const duration_ns = glib.time.instant.sub(grt.time.instant.now(), started);
    const result: HttpProbeResult = .{
        .status_code = if (body_bytes >= http_download_bytes) 206 else 0,
        .body_bytes = body_bytes,
        .duration_us = @intCast(@divTrunc(duration_ns, glib.time.duration.MicroSecond)),
        .connect_us = @intCast(@divTrunc(connect_duration, glib.time.duration.MicroSecond)),
        .recv_calls = recv_calls,
        .slow_recv_calls = slow_recv_calls,
        .max_recv_us = max_recv_us,
        .max_recv_bytes = max_recv_bytes,
    };
    logProbeResult(grt, "zig_glib_net_http", round, result);
    if (body_bytes < http_download_bytes) return error.ZigHttpDownloadShortRead;
}

fn runEspHttpClientBinding(comptime grt: type, round: usize) !void {
    const log = grt.std.log.scoped(.zux_http_client);
    log.info("esp_http_client binding round={d} start url={s} bytes={d}", .{ round, http_download_url, http_download_bytes });

    var result: HttpProbeResult = .{};
    const rc = gizclaw_esp_http_client_download(http_download_url, http_download_bytes, &result);
    if (rc != 0) {
        log.warn("esp_http_client binding failed rc={d} errno={d} status={d} bytes={d}", .{
            result.rc,
            result.errno_value,
            result.status_code,
            result.body_bytes,
        });
        return error.EspHttpClientBindingFailed;
    }

    logProbeResult(grt, "esp_http_client_binding", round, result);
}

fn runPosixHttpBinding(comptime grt: type) !void {
    const log = grt.std.log.scoped(.zux_http_client);
    var last_err: ?anyerror = null;
    for (http_download_ips) |ip| {
        var result: HttpProbeResult = .{};
        log.info("posix binding start host={s} ip={d}.{d}.{d}.{d} port={d} path={s} bytes={d}", .{
            http_download_host,
            ip[0],
            ip[1],
            ip[2],
            ip[3],
            http_download_port,
            http_download_path,
            http_download_bytes,
        });
        const rc = gizclaw_posix_http_download(http_download_host, &ip, http_download_port, http_download_path, http_download_bytes, &result);
        if (rc != 0) {
            log.warn("posix binding failed rc={d} errno={d} status={d} bytes={d}", .{
                result.rc,
                result.errno_value,
                result.status_code,
                result.body_bytes,
            });
            last_err = error.PosixHttpBindingFailed;
            continue;
        }
        logProbeResult(grt, "posix_http_binding", 1, result);
        return;
    }
    return last_err orelse error.PosixHttpBindingFailed;
}

fn writeAll(comptime grt: type, conn: glib.net.Conn, data: []const u8) !void {
    _ = grt;
    var offset: usize = 0;
    while (offset < data.len) {
        const n = try conn.write(data[offset..]);
        if (n == 0) return error.WriteZero;
        offset += n;
    }
}

fn statusLine(comptime grt: type, header: []const u8) []const u8 {
    if (grt.std.mem.indexOf(u8, header, "\r\n")) |end| return header[0..end];
    return header;
}

fn logDownloadProgress(comptime grt: type, comptime label: []const u8, round: usize, bytes: i64, started: glib.time.instant.Time) void {
    const log = grt.std.log.scoped(.zux_http_client);
    const elapsed = glib.time.instant.sub(grt.time.instant.now(), started);
    const down_mbps_milli = mbpsMilli(grt, bytes, elapsed);
    log.info("{s} round={d} progress bytes={d} elapsed_ms={d} mbps={d}.{d:0>3}", .{
        label,
        round,
        bytes,
        @divTrunc(elapsed, glib.time.duration.MilliSecond),
        @divTrunc(down_mbps_milli, 1000),
        @mod(down_mbps_milli, 1000),
    });
}

fn logProbeResult(comptime grt: type, comptime label: []const u8, round: usize, result: HttpProbeResult) void {
    const log = grt.std.log.scoped(.zux_http_client);
    const duration_ns = result.duration_us * glib.time.duration.MicroSecond;
    const down_mbps_milli = mbpsMilli(grt, result.body_bytes, duration_ns);
    const avg_recv_bytes = if (result.recv_calls == 0) 0 else @divTrunc(@as(u64, @intCast(result.body_bytes)), result.recv_calls);
    log.info("{s} round={d} ok duration_ms={d} duration_ns={d} connect_ms={d} bytes={d} mbps={d}.{d:0>3} status={d} recv_calls={d} avg_recv_bytes={d} slow_recv_calls={d} max_recv_ms={d} max_recv_bytes={d}", .{
        label,
        round,
        @divTrunc(duration_ns, glib.time.duration.MilliSecond),
        duration_ns,
        @divTrunc(result.connect_us * glib.time.duration.MicroSecond, glib.time.duration.MilliSecond),
        result.body_bytes,
        @divTrunc(down_mbps_milli, 1000),
        @mod(down_mbps_milli, 1000),
        result.status_code,
        result.recv_calls,
        avg_recv_bytes,
        result.slow_recv_calls,
        @divTrunc(result.max_recv_us * glib.time.duration.MicroSecond, glib.time.duration.MilliSecond),
        result.max_recv_bytes,
    });
}

fn mbpsMilli(comptime grt: type, bytes: i64, duration_ns: i128) u64 {
    if (bytes <= 0 or duration_ns <= 0) return 0;
    const bits = @as(i128, bytes) * 8;
    const milli_mbps = @divTrunc(bits * glib.time.duration.Second, duration_ns * 1000);
    if (milli_mbps <= 0) return 0;
    if (milli_mbps > grt.std.math.maxInt(u64)) return grt.std.math.maxInt(u64);
    return @intCast(milli_mbps);
}
