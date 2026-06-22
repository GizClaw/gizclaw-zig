const consts = @import("../consts.zig");
const glib = @import("glib");
const gizclaw_pkg = @import("gizclaw");
const giznet = @import("giznet");

const default_loop_stack_size = 24 * 1024;
const default_drive_stack_size = 64 * 1024;
const default_read_stack_size = 24 * 1024;
const default_timer_stack_size = 16 * 1024;
const default_rpc_stack_size = 24 * 1024;

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
            grt.std.log.info("smoke gizclaw config parse start", .{});
            const gizclaw_config = consts.parseGizclaw(sdk, Client) catch |err| {
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
            runtime_config.service.kcp_stream.stream.kcp_send_window = 1024;
            runtime_config.service.kcp_stream.stream.kcp_recv_window = 1024;

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
                    grt.std.log.info("smoke gizclaw ping start attempt={d}", .{attempt});
                    const ping_send_ms = grt.time.now().unixMilli();
                    const ping_start = grt.time.instant.now();
                    const response = client.ping() catch |err| {
                        grt.std.log.warn("smoke gizclaw ping failed attempt={d}: {s}", .{ attempt, @errorName(err) });
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
                    grt.std.log.info("smoke gizclaw ping ok attempt={d} rtt_ms={d} rtt_ns={d} clock_diff_ms={d} server_time={s} ntp_time={s} local_recv_time={s}", .{
                        attempt,
                        ping_rtt_ms,
                        ping_rtt_ns,
                        clock_diff_ms,
                        formatUnixMilli(&server_time_buf, response.server_time),
                        formatUnixMilli(&ntp_time_buf, ntp_time_ms),
                        formatUnixMilli(&local_recv_time_buf, ping_recv_ms),
                    });

                    grt.std.log.info("smoke gizclaw speed test start attempt={d} up_bytes={d} down_bytes={d}", .{
                        attempt,
                        consts.gizclaw_speed_test_content_length,
                        consts.gizclaw_speed_test_content_length,
                    });
                    const speed_result = client.speedTest(.{
                        .up_content_length = consts.gizclaw_speed_test_content_length,
                        .down_content_length = consts.gizclaw_speed_test_content_length,
                    }, consts.gizclaw_speed_test_timeout) catch |err| {
                        grt.std.log.warn("smoke gizclaw speed test failed attempt={d}: {s}", .{ attempt, @errorName(err) });
                        self.emitGizclawDisconnected();
                        break;
                    };
                    const up_mbps_milli = mbpsMilli(speed_result.up_bytes, speed_result.duration_ns);
                    const down_mbps_milli = mbpsMilli(speed_result.down_bytes, speed_result.duration_ns);
                    grt.std.log.info("smoke gizclaw speed test ok attempt={d} duration_ms={d} duration_ns={d} up_bytes={d} down_bytes={d} up_mbps={d}.{d:0>3} down_mbps={d}.{d:0>3}", .{
                        attempt,
                        @divTrunc(speed_result.duration_ns, glib.time.duration.MilliSecond),
                        speed_result.duration_ns,
                        speed_result.up_bytes,
                        speed_result.down_bytes,
                        @divTrunc(up_mbps_milli, 1000),
                        @mod(up_mbps_milli, 1000),
                        @divTrunc(down_mbps_milli, 1000),
                        @mod(down_mbps_milli, 1000),
                    });
                    grt.time.sleep(consts.gizclaw_ping_interval);
                }
                grt.std.log.info("smoke gizclaw client deinit attempt={d}", .{attempt});
                client.deinit();
            }
            self.emitGizclawDisconnected();
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
