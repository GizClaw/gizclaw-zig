const dep = @import("dep");
const testing_api = @import("dep").testing;

const config = @import("../../../kcp/config.zig");
const errors = @import("../../../kcp/errors.zig");
const Conn = @import("../../../kcp/Conn.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        fn makeCaseRunner(
            comptime label: []const u8,
            comptime run_case: *const fn (dep.embed.mem.Allocator) anyerror!void,
        ) testing_api.TestRunner {
            const CaseRunner = struct {
                pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
                    _ = self;
                    _ = allocator;
                }

                pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
                    _ = self;
                    run_case(allocator) catch |err| {
                        t.logErrorf("{s} failed: {}", .{ label, err });
                        return false;
                    };
                    return true;
                }

                pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
                    _ = allocator;
                    lib.testing.allocator.destroy(self);
                }
            };

            const value = lib.testing.allocator.create(CaseRunner) catch @panic("OOM");
            value.* = .{};
            return testing_api.TestRunner.make(CaseRunner).new(value);
        }

        fn runConnBehavior(allocator: dep.embed.mem.Allocator) !void {
            const testing = lib.testing;

            var clock = Clock{ .now_ms = 1 };
            var relay = RelayPair{};

            var a = try Conn.init(allocator, 1, .{
                .output = .{
                    .ctx = &relay.a_to_b,
                    .write = Relay.write,
                },
            });
            defer a.deinit();

            var b = try Conn.init(allocator, 1, .{
                .output = .{
                    .ctx = &relay.b_to_a,
                    .write = Relay.write,
                },
            });
            defer b.deinit();

            relay.a_to_b = .{
                .peer = &b,
            };
            relay.b_to_a = .{
                .peer = &a,
            };

            try testing.expectEqual(@as(u32, 1), a.getConv());
            try testing.expectEqual(@as(u32, 1), try Conn.getConvFromPacket(&[_]u8{ 1, 0, 0, 0 }));
            try testing.expectError(errors.Error.InvalidPacket, Conn.getConvFromPacket(&[_]u8{ 1, 0, 0 }));
            try testing.expectEqual(@as(u32, 0), a.waitSnd());
            try testing.expect(!a.isDead());

            var normalized_output = Relay{};
            var normalized_conn = try Conn.init(allocator, 10, .{
                .output = .{
                    .ctx = &normalized_output,
                    .write = Relay.write,
                },
                .idle_timeout_ms = 0,
                .idle_timeout_pure_ms = 0,
                .mtu = 0,
                .snd_wnd = 0,
                .rcv_wnd = 0,
                .nodelay = 0,
                .interval = 0,
                .resend = 0,
                .nc = 0,
            });
            defer normalized_conn.deinit();
            try testing.expectEqual(config.default_idle_timeout_ms, normalized_conn.conn_config.idle_timeout_ms);
            try testing.expectEqual(config.default_idle_timeout_pure_ms, normalized_conn.conn_config.idle_timeout_pure_ms);
            try testing.expectEqual(config.default_mtu, normalized_conn.conn_config.mtu);
            try testing.expectEqual(config.default_snd_wnd, normalized_conn.conn_config.snd_wnd);
            try testing.expectEqual(config.default_rcv_wnd, normalized_conn.conn_config.rcv_wnd);
            try testing.expectEqual(config.default_nodelay, normalized_conn.conn_config.nodelay);
            try testing.expectEqual(config.default_interval, normalized_conn.conn_config.interval);
            try testing.expectEqual(config.default_resend, normalized_conn.conn_config.resend);
            try testing.expectEqual(config.default_nc, normalized_conn.conn_config.nc);
            _ = try normalized_conn.send("normalize", 1);
            try testing.expectError(errors.Error.ConnTimeout, normalized_conn.tick(config.default_idle_timeout_ms + 1));

            var override_output = Relay{};
            var override_conn = try Conn.init(allocator, 11, .{
                .output = .{
                    .ctx = &override_output,
                    .write = Relay.write,
                },
                .idle_timeout_ms = 10,
                .idle_timeout_pure_ms = 20,
                .mtu = 1200,
                .snd_wnd = 8,
                .rcv_wnd = 9,
                .nodelay = 5,
                .interval = 6,
                .resend = 7,
                .nc = 8,
            });
            defer override_conn.deinit();
            try testing.expectEqual(@as(u64, 10), override_conn.conn_config.idle_timeout_ms);
            try testing.expectEqual(@as(u64, 20), override_conn.conn_config.idle_timeout_pure_ms);
            try testing.expectEqual(@as(u32, 1200), override_conn.conn_config.mtu);
            try testing.expectEqual(@as(u32, 8), override_conn.conn_config.snd_wnd);
            try testing.expectEqual(@as(u32, 9), override_conn.conn_config.rcv_wnd);
            try testing.expectEqual(@as(i32, 5), override_conn.conn_config.nodelay);
            try testing.expectEqual(@as(i32, 6), override_conn.conn_config.interval);
            try testing.expectEqual(@as(i32, 7), override_conn.conn_config.resend);
            try testing.expectEqual(@as(i32, 8), override_conn.conn_config.nc);

            clock.now_ms += 1;
            _ = try a.send("hello", clock.now_ms);
            var pump_count: usize = 0;
            while (pump_count < 8) : (pump_count += 1) {
                try relay.pump(clock.now_ms);
                clock.now_ms += 1;
                try a.update(clock.now_ms);
                try b.update(clock.now_ms);
            }
            try relay.pump(clock.now_ms);

            var buf: [32]u8 = undefined;
            const peek_n = try b.peekSize();
            try testing.expectEqual(@as(i32, 5), peek_n);
            const read_n = try b.recv(&buf);
            try testing.expectEqualStrings("hello", buf[0..read_n]);
            try testing.expectError(errors.Error.NoData, b.recv(&buf));

            clock.now_ms += 1;
            _ = try b.send("world", clock.now_ms);
            pump_count = 0;
            while (pump_count < 8) : (pump_count += 1) {
                try relay.pump(clock.now_ms);
                clock.now_ms += 1;
                try a.update(clock.now_ms);
                try b.update(clock.now_ms);
            }
            try relay.pump(clock.now_ms);
            const reply_n = try a.recv(&buf);
            try testing.expectEqualStrings("world", buf[0..reply_n]);

            var read_deadline_output = Relay{};
            var read_deadline_conn = try Conn.init(allocator, 3, .{
                .output = .{
                    .ctx = &read_deadline_output,
                    .write = Relay.write,
                },
            });
            defer read_deadline_conn.deinit();
            read_deadline_conn.setReadDeadline(5);
            try testing.expectError(errors.Error.NoData, read_deadline_conn.read(&buf, 4));
            try testing.expectError(errors.Error.ConnTimeout, read_deadline_conn.read(&buf, 5));

            var write_deadline_output = Relay{};
            var write_deadline_conn = try Conn.init(allocator, 4, .{
                .output = .{
                    .ctx = &write_deadline_output,
                    .write = Relay.write,
                },
            });
            defer write_deadline_conn.deinit();
            write_deadline_conn.setWriteDeadline(7);
            try testing.expectError(errors.Error.ConnTimeout, write_deadline_conn.write("late", 7));

            var close_output = Relay{};
            var close_conn = try Conn.init(allocator, 5, .{
                .output = .{
                    .ctx = &close_output,
                    .write = Relay.write,
                },
            });
            defer close_conn.deinit();
            close_conn.close();
            try testing.expect(close_conn.isClosed());
            try testing.expectError(errors.Error.ConnClosedLocal, close_conn.send("x", 1));
            try testing.expectError(errors.Error.ConnClosedLocal, close_conn.recv(&buf));

            var peer_close_output = Relay{};
            var peer_close_conn = try Conn.init(allocator, 6, .{
                .output = .{
                    .ctx = &peer_close_output,
                    .write = Relay.write,
                },
            });
            defer peer_close_conn.deinit();
            peer_close_conn.closeWithError(errors.Error.ConnClosedByPeer);
            try testing.expectError(errors.Error.ConnClosedByPeer, peer_close_conn.read(&buf, 1));

            var idle_output = Relay{};
            var idle_conn = try Conn.init(allocator, 7, .{
                .output = .{
                    .ctx = &idle_output,
                    .write = Relay.write,
                },
                .idle_timeout_ms = 10,
                .idle_timeout_pure_ms = 20,
            });
            defer idle_conn.deinit();
            try testing.expectError(errors.Error.ConnTimeout, idle_conn.tick(21));

            var pending_idle_output = Relay{};
            var pending_idle_conn = try Conn.init(allocator, 8, .{
                .output = .{
                    .ctx = &pending_idle_output,
                    .write = Relay.write,
                },
                .idle_timeout_ms = 10,
                .idle_timeout_pure_ms = 50,
            });
            defer pending_idle_conn.deinit();
            _ = try pending_idle_conn.send("pending", 1);
            try testing.expect(pending_idle_conn.waitSnd() > 0);
            try testing.expectError(errors.Error.ConnTimeout, pending_idle_conn.tick(12));

            var dead_output = Relay{};
            var dead_conn = try Conn.init(allocator, 9, .{
                .output = .{
                    .ctx = &dead_output,
                    .write = Relay.write,
                },
            });
            defer dead_conn.deinit();
            dead_conn.testMarkEngineDead();
            try testing.expectError(errors.Error.ConnTimeout, dead_conn.tick(1));

            var wrap_clock = Clock{ .now_ms = 0xffff_ffff - 2 };
            var wrap_relay = RelayPair{};

            var wrap_a = try Conn.init(allocator, 2, .{
                .output = .{
                    .ctx = &wrap_relay.a_to_b,
                    .write = Relay.write,
                },
            });
            defer wrap_a.deinit();

            var wrap_b = try Conn.init(allocator, 2, .{
                .output = .{
                    .ctx = &wrap_relay.b_to_a,
                    .write = Relay.write,
                },
            });
            defer wrap_b.deinit();

            wrap_relay.a_to_b = .{ .peer = &wrap_b };
            wrap_relay.b_to_a = .{ .peer = &wrap_a };

            _ = wrap_a.check(wrap_clock.now_ms);
            _ = wrap_b.check(wrap_clock.now_ms);
            _ = try wrap_a.send("wrap", wrap_clock.now_ms);
            pump_count = 0;
            while (pump_count < 8) : (pump_count += 1) {
                try wrap_relay.pump(wrap_clock.now_ms);
                wrap_clock.now_ms += 1;
                try wrap_a.update(wrap_clock.now_ms);
                try wrap_b.update(wrap_clock.now_ms);
            }
            try wrap_relay.pump(wrap_clock.now_ms);
            const wrap_read_n = try wrap_b.recv(&buf);
            try testing.expectEqualStrings("wrap", buf[0..wrap_read_n]);
        }

        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("behavior", makeCaseRunner("kcp/Conn/behavior", runConnBehavior));
            return true;
        }

        pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

const Clock = struct {
    now_ms: u64,
};

const RelayPair = struct {
    a_to_b: Relay = .{},
    b_to_a: Relay = .{},

    fn pump(self: *RelayPair, now_ms: u64) !void {
        try self.a_to_b.drain(now_ms);
        try self.b_to_a.drain(now_ms);
    }
};

const Relay = struct {
    peer: ?*Conn = null,
    packets: [8][1500]u8 = [_][1500]u8{[_]u8{0} ** 1500} ** 8,
    lens: [8]usize = [_]usize{0} ** 8,
    len: usize = 0,

    fn write(ctx: *anyopaque, data: []const u8) !void {
        const self = @as(*Relay, @ptrCast(@alignCast(ctx)));
        if (self.len >= self.packets.len) return error.QueueFull;
        if (data.len > self.packets[self.len].len) return error.BufferTooSmall;
        @memcpy(self.packets[self.len][0..data.len], data);
        self.lens[self.len] = data.len;
        self.len += 1;
    }

    fn drain(self: *Relay, now_ms: u64) !void {
        const peer = self.peer orelse unreachable;
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            try peer.input(self.packets[index][0..self.lens[index]], now_ms);
        }
        self.len = 0;
    }
};
