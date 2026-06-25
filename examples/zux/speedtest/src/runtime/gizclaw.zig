const consts = @import("../consts.zig");
const embed = @import("embed");
const glib = @import("glib");
const gizclaw_pkg = @import("gizclaw");
const giznet = @import("giznet");
const smoke_status = @import("../reducers/smoke_status.zig");

const default_loop_stack_size = 24 * 1024;
const default_drive_stack_size = 64 * 1024;
const default_read_stack_size = 24 * 1024;
const default_timer_stack_size = 16 * 1024;
const default_rpc_stack_size = 24 * 1024;
const preferences_namespace = "gizclaw";
const preferences_client_key = "client_key";

const SpeedPhase = enum {
    up,
    down,
    duplex,
};

const SpeedDisplayState = struct {
    round: u64 = 0,
    ping_rtt_ms: u32 = 0,
    total_up_bytes: u64 = 0,
    total_down_bytes: u64 = 0,
    up_mbps_milli: u32 = 0,
    down_mbps_milli: u32 = 0,
    duplex_up_mbps_milli: u32 = 0,
    duplex_down_mbps_milli: u32 = 0,
    cpu0_percent: u32 = 0,
    cpu1_percent: u32 = 0,
    mem_internal_free_kib: u32 = 0,
    mem_psram_free_kib: u32 = 0,
};

const SpeedPhaseResult = struct {
    up_bytes: u64,
    down_bytes: u64,
    up_mbps_milli: u32,
    down_mbps_milli: u32,
};

pub const Context = struct {
    platform_ctx: type,
    grt: type,
    Reducers: type,
};

const PeerPolicyState = struct {
    server_key: giznet.Key,

    fn allow(ctx: ?*anyopaque, peer_key: giznet.Key) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx orelse return false));
        return peer_key.eql(self.server_key);
    }
};

pub fn make(comptime context: Context) type {
    const platform_ctx = context.platform_ctx;
    const grt = context.grt;
    const Reducers = context.Reducers;
    const sdk = gizclaw_pkg.make(grt, .{});
    const Client = sdk.Client;
    const GizNetImpl = Client.GizNetImpl;
    const Allocator = grt.std.mem.Allocator;
    const AtomicBool = grt.std.atomic.Value(bool);
    const SpeedTestProgressSnapshot = Client.SpeedTestProgressSnapshot;
    const SmokeStatusUpdate = smoke_status.Update;

    return struct {
        pub const Config = struct {
            loop_task_options: glib.task.Options = .{
                .min_stack_size = default_loop_stack_size,
            },
            drive_task_options: glib.task.Options = .{
                .min_stack_size = default_drive_stack_size,
            },
            read_task_options: glib.task.Options = .{
                .min_stack_size = default_read_stack_size,
            },
            timer_task_options: glib.task.Options = .{
                .min_stack_size = default_timer_stack_size,
            },
            rpc_task_options: glib.task.Options = .{
                .min_stack_size = default_rpc_stack_size,
            },
        };

        allocator: Allocator,
        reducers: *Reducers,
        config: Config = .{},
        stop: AtomicBool = AtomicBool.init(false),
        thread: ?grt.task.Handle = null,

        const Self = @This();

        pub fn init(allocator: Allocator, reducers: *Reducers, config: Config) Self {
            return .{
                .allocator = allocator,
                .reducers = reducers,
                .config = config,
            };
        }

        pub fn start(self: *Self) !void {
            if (self.thread != null) return;
            self.stop.store(false, .release);
            self.thread = try grt.task.go("gizclaw/smoke", self.config.loop_task_options, glib.task.Routine.init(self, loop));
        }

        pub fn deinit(self: *Self) void {
            self.stop.store(true, .release);
            if (self.thread) |thread| {
                thread.join();
                self.thread = null;
            }
            self.* = undefined;
        }

        fn loop(self: *Self) void {
            grt.std.log.info("smoke gizclaw loop start", .{});
            self.run() catch |err| {
                grt.std.log.err("smoke gizclaw loop stopped: {s}", .{@errorName(err)});
                self.emitGizclawDisconnected();
            };
        }

        fn run(self: *Self) !void {
            grt.time.sleep(100 * glib.time.duration.MilliSecond);
            try self.enableNetworkIntent();
            if (!self.waitForWifiReady()) return;
            grt.std.log.info("smoke gizclaw config parse start", .{});
            const key_pair = self.resolveClientKeyPair() catch |err| {
                grt.std.log.err("smoke gizclaw client key unavailable: {s}", .{@errorName(err)});
                return err;
            };
            const gizclaw_config = consts.parseGizclaw(sdk, Client, key_pair) catch |err| {
                grt.std.log.err("smoke gizclaw invalid config: {s}", .{@errorName(err)});
                return err;
            };
            grt.std.log.info("smoke gizclaw config parsed server={s}", .{consts.gizclaw_server_addr});

            var peer_policy_state: PeerPolicyState = .{ .server_key = gizclaw_config.server_key };
            const runtime_allocator = runtimeAllocator(self.allocator);
            grt.std.log.info("smoke gizclaw listen packet start", .{});
            var packet_conn = try grt.net.listenPacket(.{
                .allocator = runtime_allocator,
                .address = giznet.AddrPort.from4(.{ 0, 0, 0, 0 }, 0),
            });
            defer packet_conn.deinit();
            grt.std.log.info("smoke gizclaw listen packet ok", .{});

            var runtime_config = Client.runtimeConfig(gizclaw_config.key_pair, .{
                .ctx = &peer_policy_state,
                .allow = PeerPolicyState.allow,
            });
            runtime_config.on_error = .{ .call = runtimeOnError };
            runtime_config.channel_capacity = 64;
            runtime_config.service.kcp_stream.stream.channel_capacity = 4096;
            runtime_config.service.kcp_stream.stream.kcp_nodelay = 1;
            runtime_config.service.kcp_stream.stream.kcp_interval = 10;
            runtime_config.service.kcp_stream.stream.kcp_resend = 2;
            runtime_config.service.kcp_stream.stream.kcp_no_congestion_control = 0;

            grt.std.log.info("smoke gizclaw runtime init start", .{});
            const impl = try GizNetImpl.init(runtime_allocator, packet_conn, runtime_config);
            grt.std.log.info("smoke gizclaw runtime init ok", .{});
            grt.std.log.info("smoke gizclaw runtime up start", .{});
            const root = try impl.up(.{
                .drive_task_options = self.config.drive_task_options,
                .read_task_options = self.config.read_task_options,
                .timer_task_options = self.config.timer_task_options,
            });
            defer root.deinit();

            grt.std.log.info("smoke gizclaw runtime started server={s}", .{consts.gizclaw_server_addr});
            var attempt: u64 = 0;
            var status: SpeedDisplayState = .{};
            while (!self.stop.load(.acquire)) {
                attempt += 1;
                grt.std.log.info("smoke gizclaw attempt start attempt={d}", .{attempt});
                grt.std.log.info("smoke gizclaw emit connecting start attempt={d}", .{attempt});
                self.emitGizclawConnecting();
                grt.std.log.info("smoke gizclaw emit connecting done attempt={d}", .{attempt});
                grt.std.log.info("smoke gizclaw dial start attempt={d} server={s}", .{ attempt, consts.gizclaw_server_addr });
                root.dial(.{
                    .remote_key = gizclaw_config.server_key,
                    .endpoint = gizclaw_config.server_endpoint,
                    .connect_timeout_ms = consts.gizclaw_connect_timeout_ms,
                    .keepalive_ms = consts.gizclaw_keepalive_ms,
                }) catch |err| {
                    grt.std.log.warn("smoke gizclaw dial failed attempt={d}: {s}", .{ attempt, @errorName(err) });
                    self.emitGizclawDisconnected();
                    continue;
                };
                grt.std.log.info("smoke gizclaw dial requested attempt={d}", .{attempt});

                grt.std.log.info("smoke gizclaw accept wait attempt={d} timeout_ns={d}", .{ attempt, consts.gizclaw_accept_timeout });
                const conn = root.acceptTimeout(consts.gizclaw_accept_timeout) catch |err| {
                    grt.std.log.warn("smoke gizclaw accept failed attempt={d}: {s}", .{ attempt, @errorName(err) });
                    self.emitGizclawDisconnected();
                    continue;
                };
                grt.std.log.info("smoke gizclaw accept ok attempt={d}", .{attempt});
                if (!conn.remoteStatic().eql(gizclaw_config.server_key)) {
                    conn.close() catch {};
                    conn.deinit();
                    grt.std.log.warn("smoke gizclaw ignored non-server peer attempt={d}", .{attempt});
                    self.emitGizclawDisconnected();
                    continue;
                }

                var client = Client.init(runtime_allocator, .{
                    .key_pair = gizclaw_config.key_pair,
                }) catch |err| {
                    conn.close() catch {};
                    conn.deinit();
                    grt.std.log.warn("smoke gizclaw client init failed attempt={d}: {s}", .{ attempt, @errorName(err) });
                    self.emitGizclawDisconnected();
                    continue;
                };
                grt.std.log.info("smoke gizclaw attach start attempt={d}", .{attempt});
                client.attach(gizclaw_config.server_key, conn, self.config.rpc_task_options) catch |err| {
                    conn.close() catch {};
                    conn.deinit();
                    client.deinit();
                    grt.std.log.warn("smoke gizclaw attach failed attempt={d}: {s}", .{ attempt, @errorName(err) });
                    self.emitGizclawDisconnected();
                    continue;
                };
                grt.std.log.info("smoke gizclaw attach ok attempt={d}", .{attempt});

                grt.std.log.info("smoke gizclaw emit connected start attempt={d}", .{attempt});
                self.emitGizclawConnected();
                grt.std.log.info("smoke gizclaw connected attempt={d} server={s}", .{ attempt, consts.gizclaw_server_addr });
                while (!self.stop.load(.acquire)) {
                    status.round += 1;
                    grt.std.log.info("smoke gizclaw cycle start attempt={d} round={d}", .{ attempt, status.round });
                    grt.std.log.info("smoke gizclaw ping start attempt={d} round={d}", .{ attempt, status.round });
                    const ping_send_ms = grt.time.now().unixMilli();
                    const ping_start = grt.time.instant.now();
                    const response = client.ping() catch |err| {
                        grt.std.log.warn("smoke gizclaw ping failed attempt={d} round={d}: {s}", .{ attempt, status.round, @errorName(err) });
                        self.emitGizclawDisconnected();
                        break;
                    };
                    const ping_recv_ms = grt.time.now().unixMilli();
                    const ping_rtt_ns = glib.time.instant.sub(grt.time.instant.now(), ping_start);
                    const ping_rtt_ms = @divTrunc(ping_rtt_ns, glib.time.duration.MilliSecond);
                    const local_midpoint_ms = midpointMilli(ping_send_ms, ping_recv_ms);
                    const clock_diff_ms = response.server_time - local_midpoint_ms;
                    const ntp_time_ms = ping_recv_ms + clock_diff_ms;
                    var server_time_buf: [32]u8 = undefined;
                    var ntp_time_buf: [32]u8 = undefined;
                    var local_recv_time_buf: [32]u8 = undefined;
                    status.ping_rtt_ms = clampU32(ping_rtt_ms);
                    grt.std.log.info("smoke gizclaw ping ok attempt={d} round={d} rtt_ms={d} rtt_ns={d} clock_diff_ms={d} server_time={s} ntp_time={s} local_recv_time={s}", .{
                        attempt,
                        status.round,
                        ping_rtt_ms,
                        ping_rtt_ns,
                        clock_diff_ms,
                        formatUnixMilli(&server_time_buf, response.server_time),
                        formatUnixMilli(&ntp_time_buf, ntp_time_ms),
                        formatUnixMilli(&local_recv_time_buf, ping_recv_ms),
                    });
                    self.emitSmokeStatusFromState(status);

                    const up_result = self.runSpeedPhase(&client, attempt, status, .up) catch |err| {
                        grt.std.log.warn("smoke gizclaw up phase failed attempt={d} round={d}: {s}", .{ attempt, status.round, @errorName(err) });
                        self.emitGizclawDisconnected();
                        break;
                    };
                    status.total_up_bytes +|= up_result.up_bytes;
                    status.total_down_bytes +|= up_result.down_bytes;
                    status.up_mbps_milli = up_result.up_mbps_milli;
                    self.emitSmokeStatusFromState(status);

                    const down_result = self.runSpeedPhase(&client, attempt, status, .down) catch |err| {
                        grt.std.log.warn("smoke gizclaw down phase failed attempt={d} round={d}: {s}", .{ attempt, status.round, @errorName(err) });
                        self.emitGizclawDisconnected();
                        break;
                    };
                    status.total_up_bytes +|= down_result.up_bytes;
                    status.total_down_bytes +|= down_result.down_bytes;
                    status.down_mbps_milli = down_result.down_mbps_milli;
                    self.emitSmokeStatusFromState(status);

                    const duplex_result = self.runSpeedPhase(&client, attempt, status, .duplex) catch |err| {
                        grt.std.log.warn("smoke gizclaw duplex phase failed attempt={d} round={d}: {s}", .{ attempt, status.round, @errorName(err) });
                        self.emitGizclawDisconnected();
                        break;
                    };
                    status.total_up_bytes +|= duplex_result.up_bytes;
                    status.total_down_bytes +|= duplex_result.down_bytes;
                    status.duplex_up_mbps_milli = duplex_result.up_mbps_milli;
                    status.duplex_down_mbps_milli = duplex_result.down_mbps_milli;
                    self.emitSmokeStatusFromState(status);

                    grt.std.log.info("smoke gizclaw cycle done attempt={d} round={d} sleep_ns={d}", .{ attempt, status.round, consts.gizclaw_ping_interval });
                    grt.time.sleep(consts.gizclaw_ping_interval);
                }
                grt.std.log.info("smoke gizclaw client deinit attempt={d}", .{attempt});
                client.deinit();
            }
            self.emitGizclawDisconnected();
        }

        fn enableNetworkIntent(self: *Self) !void {
            const timestamp = grt.time.instant.now();
            grt.std.log.info("smoke auto start app and wifi", .{});
            try self.reducers.emitAutoStart(timestamp);
        }

        fn waitForWifiReady(self: *Self) bool {
            if (comptime @hasDecl(platform_ctx, "smokeManageWifi")) {
                if (!platform_ctx.smokeManageWifi()) {
                    grt.std.log.info("smoke wifi wait skipped by platform", .{});
                    return true;
                }
            }
            var wait_cycle: u64 = 0;
            while (!self.stop.load(.acquire)) {
                if (self.reducers.wifiHasIp()) {
                    grt.std.log.info("smoke wifi ready has_ip=true wait_cycle={d}", .{wait_cycle});
                    return true;
                }
                wait_cycle += 1;
                grt.std.log.info("smoke wifi wait has_ip=false wait_cycle={d}", .{wait_cycle});
                grt.time.sleep(glib.time.duration.Second);
            }
            return false;
        }

        const SpeedTestProgressContext = struct {
            reducers: *Reducers,
            attempt: u64,
            phase: SpeedPhase,
            display: SpeedDisplayState,
        };

        fn runSpeedPhase(self: *Self, client: *Client, attempt: u64, display: SpeedDisplayState, phase: SpeedPhase) !SpeedPhaseResult {
            const request = speedPhaseRequest(phase);
            grt.std.log.info("smoke gizclaw {s} phase start attempt={d} round={d} up_bytes={d} down_bytes={d}", .{
                speedPhaseName(phase),
                attempt,
                display.round,
                request.up_content_length,
                request.down_content_length,
            });
            var progress_context: SpeedTestProgressContext = .{
                .reducers = self.reducers,
                .attempt = attempt,
                .phase = phase,
                .display = display,
            };
            const speed_result = client.speedTestWithProgress(request, consts.gizclaw_speed_test_timeout, .{
                .ctx = &progress_context,
                .interval = consts.gizclaw_speed_test_progress_interval,
                .callback = logSpeedTestProgress,
            }) catch |err| {
                grt.std.log.warn("smoke gizclaw {s} phase failed attempt={d} round={d}: {s}", .{
                    speedPhaseName(phase),
                    attempt,
                    display.round,
                    @errorName(err),
                });
                return err;
            };
            const up_mbps_milli = clampU32(mbpsMilli(speed_result.up_bytes, speed_result.duration_ns));
            const down_mbps_milli = clampU32(mbpsMilli(speed_result.down_bytes, speed_result.duration_ns));
            grt.std.log.info("smoke gizclaw {s} phase ok attempt={d} round={d} duration_ms={d} duration_ns={d} up_bytes={d} down_bytes={d} up_mbps={d}.{d:0>3} down_mbps={d}.{d:0>3}", .{
                speedPhaseName(phase),
                attempt,
                display.round,
                @divTrunc(speed_result.duration_ns, glib.time.duration.MilliSecond),
                speed_result.duration_ns,
                speed_result.up_bytes,
                speed_result.down_bytes,
                @divTrunc(up_mbps_milli, 1000),
                @mod(up_mbps_milli, 1000),
                @divTrunc(down_mbps_milli, 1000),
                @mod(down_mbps_milli, 1000),
            });
            return .{
                .up_bytes = intToU64(speed_result.up_bytes),
                .down_bytes = intToU64(speed_result.down_bytes),
                .up_mbps_milli = up_mbps_milli,
                .down_mbps_milli = down_mbps_milli,
            };
        }

        fn logSpeedTestProgress(ctx: ?*anyopaque, snapshot: SpeedTestProgressSnapshot) void {
            const progress_context: *SpeedTestProgressContext = @ptrCast(@alignCast(ctx orelse return));
            const display = progressDisplay(progress_context.display, progress_context.phase, snapshot);
            progress_context.reducers.emitSmokeStatus(statusUpdate(withSystemStats(display)), grt.time.instant.now()) catch |err| {
                grt.std.log.warn("smoke status progress emit failed: {s}", .{@errorName(err)});
            };
            grt.std.log.info("smoke gizclaw {s} phase progress attempt={d} round={d} elapsed_ms={d} up_bytes={d}/{d} down_bytes={d}/{d} total_up={d} total_down={d} up_pct={d}.{d:0>2} down_pct={d}.{d:0>2} up_mbps={d}.{d:0>3} down_mbps={d}.{d:0>3}", .{
                speedPhaseName(progress_context.phase),
                progress_context.attempt,
                progress_context.display.round,
                @divTrunc(snapshot.elapsed_ns, glib.time.duration.MilliSecond),
                snapshot.up_bytes,
                snapshot.up_total,
                snapshot.down_bytes,
                snapshot.down_total,
                display.total_up_bytes,
                display.total_down_bytes,
                percentWhole(snapshot.up_bytes, snapshot.up_total),
                percentFrac2(snapshot.up_bytes, snapshot.up_total),
                percentWhole(snapshot.down_bytes, snapshot.down_total),
                percentFrac2(snapshot.down_bytes, snapshot.down_total),
                @divTrunc(snapshot.up_mbps_milli, 1000),
                @mod(snapshot.up_mbps_milli, 1000),
                @divTrunc(snapshot.down_mbps_milli, 1000),
                @mod(snapshot.down_mbps_milli, 1000),
            });
        }

        fn progressDisplay(base: SpeedDisplayState, phase: SpeedPhase, snapshot: SpeedTestProgressSnapshot) SpeedDisplayState {
            var display = base;
            display.total_up_bytes = base.total_up_bytes +| intToU64(snapshot.up_bytes);
            display.total_down_bytes = base.total_down_bytes +| intToU64(snapshot.down_bytes);
            switch (phase) {
                .up => display.up_mbps_milli = clampU32(snapshot.up_mbps_milli),
                .down => display.down_mbps_milli = clampU32(snapshot.down_mbps_milli),
                .duplex => {
                    display.duplex_up_mbps_milli = clampU32(snapshot.up_mbps_milli);
                    display.duplex_down_mbps_milli = clampU32(snapshot.down_mbps_milli);
                },
            }
            return display;
        }

        fn emitSmokeStatusFromState(self: *Self, display: SpeedDisplayState) void {
            self.emitSmokeStatus(statusUpdate(withSystemStats(display)));
        }

        fn statusUpdate(display: SpeedDisplayState) SmokeStatusUpdate {
            return .{
                .round = display.round,
                .ping_rtt_ms = display.ping_rtt_ms,
                .up_bytes = display.total_up_bytes,
                .down_bytes = display.total_down_bytes,
                .up_total = display.total_up_bytes,
                .down_total = display.total_down_bytes,
                .up_mbps_milli = display.up_mbps_milli,
                .down_mbps_milli = display.down_mbps_milli,
                .duplex_up_mbps_milli = display.duplex_up_mbps_milli,
                .duplex_down_mbps_milli = display.duplex_down_mbps_milli,
                .cpu0_percent = display.cpu0_percent,
                .cpu1_percent = display.cpu1_percent,
                .mem_internal_free_kib = display.mem_internal_free_kib,
                .mem_psram_free_kib = display.mem_psram_free_kib,
            };
        }

        fn withSystemStats(display: SpeedDisplayState) SpeedDisplayState {
            var next = display;
            var cpu_stats: grt.system.CpuStats = .{};
            if (grt.system.readCpuStats(&cpu_stats)) {
                if (cpu_stats.core_count > 0) next.cpu0_percent = cpu_stats.cores[0].usage_percent;
                if (cpu_stats.core_count > 1) next.cpu1_percent = cpu_stats.cores[1].usage_percent;
            } else |_| {}

            var memory_stats: grt.system.MemoryStats = .{};
            if (grt.system.readMemoryStats(&memory_stats)) {
                next.mem_internal_free_kib = bytesToKiBU32(memory_stats.internal_free);
                next.mem_psram_free_kib = bytesToKiBU32(memory_stats.psram_free);
            } else |_| {}
            return next;
        }

        fn speedPhaseRequest(phase: SpeedPhase) gizclaw_pkg.models.SpeedTestRequest {
            return switch (phase) {
                .up => .{
                    .up_content_length = consts.gizclaw_speed_test_content_length,
                    .down_content_length = 0,
                },
                .down => .{
                    .up_content_length = 0,
                    .down_content_length = consts.gizclaw_speed_test_content_length,
                },
                .duplex => .{
                    .up_content_length = consts.gizclaw_speed_test_content_length,
                    .down_content_length = consts.gizclaw_speed_test_content_length,
                },
            };
        }

        fn speedPhaseName(phase: SpeedPhase) []const u8 {
            return switch (phase) {
                .up => "up",
                .down => "down",
                .duplex => "duplex",
            };
        }

        fn emitSmokeStatus(self: *Self, value: SmokeStatusUpdate) void {
            if (self.stop.load(.acquire)) return;
            self.reducers.emitSmokeStatus(value, grt.time.instant.now()) catch |err| {
                grt.std.log.warn("smoke status emit failed: {s}", .{@errorName(err)});
            };
        }

        fn emitGizclawConnecting(self: *Self) void {
            if (self.stop.load(.acquire)) return;
            self.reducers.emitGizclawConnecting(grt.time.instant.now()) catch |err| {
                grt.std.log.warn("smoke gizclaw emit connecting failed: {s}", .{@errorName(err)});
            };
        }

        fn emitGizclawConnected(self: *Self) void {
            if (self.stop.load(.acquire)) return;
            self.reducers.emitGizclawConnected(grt.time.instant.now()) catch |err| {
                grt.std.log.warn("smoke gizclaw emit connected failed: {s}", .{@errorName(err)});
            };
        }

        fn emitGizclawDisconnected(self: *Self) void {
            if (self.stop.load(.acquire)) return;
            self.reducers.emitGizclawDisconnected(grt.time.instant.now()) catch |err| {
                grt.std.log.warn("smoke gizclaw emit disconnected failed: {s}", .{@errorName(err)});
            };
        }

        fn runtimeOnError(_: ?*anyopaque, err: anyerror) void {
            grt.std.log.err("smoke giznet runtime error: {s}", .{@errorName(err)});
        }

        fn runtimeAllocator(default_allocator: Allocator) Allocator {
            return platform_ctx.gizclawAllocator(default_allocator);
        }

        fn resolveClientKeyPair(self: *Self) !giznet.KeyPair {
            if (consts.gizclaw_client_key.len != 0) {
                grt.std.log.info("smoke gizclaw client key source=build_config", .{});
                return sdk.key.fromPrivate(try sdk.key.parse(consts.gizclaw_client_key));
            }

            if (comptime @hasDecl(platform_ctx, "preferencesProvider")) {
                return try self.resolveClientKeyPairFromPreferences();
            }

            return error.EmptyKey;
        }

        fn resolveClientKeyPairFromPreferences(self: *Self) !giznet.KeyPair {
            var provider_impl = try platform_ctx.preferencesProvider(self.allocator);
            const provider = if (@TypeOf(provider_impl) == embed.system.Preferences.Provider)
                provider_impl
            else
                provider_impl.handle();
            var store = try provider.open(preferences_namespace, .{ .create = true });
            defer store.deinit();

            var key_buf: [64]u8 = undefined;
            const stored_len = store.get(preferences_client_key, &key_buf) catch |err| switch (err) {
                error.NotFound => return try self.generateAndStoreClientKeyPair(store),
                else => return err,
            };
            const stored = key_buf[0..stored_len];
            if (stored.len != 0) {
                const private = sdk.key.parse(stored) catch |err| {
                    grt.std.log.warn("smoke gizclaw stored client key invalid: {s}; regenerating", .{@errorName(err)});
                    return try self.generateAndStoreClientKeyPair(store);
                };
                const key_pair = try sdk.key.fromPrivate(private);
                var public_buf: [52]u8 = undefined;
                grt.std.log.info("smoke gizclaw client key source=preferences public={s}", .{sdk.key.format(key_pair.public, &public_buf)});
                return key_pair;
            }

            return try self.generateAndStoreClientKeyPair(store);
        }

        fn generateAndStoreClientKeyPair(self: *Self, store: embed.system.Preferences.Store) !giznet.KeyPair {
            _ = self;
            const key_pair = sdk.key.randomKeyPair();
            var private_buf: [52]u8 = undefined;
            const private_text = sdk.key.format(key_pair.private, &private_buf);
            try store.put(preferences_client_key, private_text);
            try store.sync();
            var public_buf: [52]u8 = undefined;
            grt.std.log.info("smoke gizclaw client key source=generated public={s}", .{sdk.key.format(key_pair.public, &public_buf)});
            return key_pair;
        }

        fn midpointMilli(start_ms: i64, stop_ms: i64) i64 {
            return @intCast(@divTrunc(@as(i128, start_ms) + @as(i128, stop_ms), 2));
        }

        fn mbpsMilli(bytes: i64, duration_ns: i128) u64 {
            if (bytes <= 0 or duration_ns <= 0) return 0;
            const bits = @as(i128, bytes) * 8;
            const milli_mbps = @divTrunc(bits * glib.time.duration.Second, duration_ns * 1000);
            if (milli_mbps <= 0) return 0;
            if (milli_mbps > grt.std.math.maxInt(u64)) return grt.std.math.maxInt(u64);
            return @intCast(milli_mbps);
        }

        fn percentWhole(done: i64, total: i64) u64 {
            if (done <= 0 or total <= 0) return 0;
            return @intCast(@divTrunc(@divTrunc(@as(i128, done) * 10000, total), 100));
        }

        fn percentFrac2(done: i64, total: i64) u64 {
            if (done <= 0 or total <= 0) return 0;
            return @intCast(@mod(@divTrunc(@as(i128, done) * 10000, total), 100));
        }

        fn intToU64(value: i64) u64 {
            if (value <= 0) return 0;
            return @intCast(value);
        }

        fn clampU32(value: anytype) u32 {
            if (value <= 0) return 0;
            if (value > grt.std.math.maxInt(u32)) return grt.std.math.maxInt(u32);
            return @intCast(value);
        }

        fn bytesToKiBU32(value: usize) u32 {
            const kib = @divTrunc(value, 1024);
            if (kib > grt.std.math.maxInt(u32)) return grt.std.math.maxInt(u32);
            return @intCast(kib);
        }

        fn formatUnixMilli(buf: []u8, millis: i64) []const u8 {
            if (millis < 0) return "invalid";
            const secs = @divTrunc(millis, 1000);
            const ms: u16 = @intCast(@mod(millis, 1000));
            const days = @divTrunc(secs, 86_400);
            const seconds_into_day = @mod(secs, 86_400);
            const date = civilFromUnixDays(days);
            const hour = @divTrunc(seconds_into_day, 3_600);
            const minute = @divTrunc(@mod(seconds_into_day, 3_600), 60);
            const second = @mod(seconds_into_day, 60);
            return grt.std.fmt.bufPrint(
                buf,
                "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z",
                .{
                    date.year,
                    date.month,
                    date.day,
                    hour,
                    minute,
                    second,
                    ms,
                },
            ) catch "invalid";
        }

        fn civilFromUnixDays(unix_days: i64) struct { year: i64, month: u8, day: u8 } {
            const z = unix_days + 719_468;
            const era = @divFloor(z, 146_097);
            const doe: u32 = @intCast(z - era * 146_097);
            const yoe = @divTrunc(doe - @divTrunc(doe, 1_460) + @divTrunc(doe, 36_524) - @divTrunc(doe, 146_096), 365);
            var year = @as(i64, yoe) + era * 400;
            const doy = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100));
            const mp = @divTrunc(5 * doy + 2, 153);
            const day: u8 = @intCast(doy - @divTrunc(153 * mp + 2, 5) + 1);
            const month_i64 = @as(i64, mp) + if (mp < 10) @as(i64, 3) else -9;
            if (month_i64 <= 2) year += 1;
            return .{
                .year = year,
                .month = @intCast(month_i64),
                .day = day,
            };
        }
    };
}
