const dep = @import("dep");
const testing_api = @import("dep").testing;
const cfg = @import("../../../kcp/config.zig");
const errors = @import("../../../kcp/errors.zig");
const Mux = @import("../../../kcp/Mux.zig");

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

        fn runNormalizesDefaultConfig(allocator: dep.embed.mem.Allocator) !void {
            const testing = lib.testing;

            var output = NullOutput{};
            var mux = try Mux.init(allocator, 6, .{
                .is_client = true,
                .output = .{ .ctx = &output, .write = NullOutput.write },
                .close_ack_timeout_ms = 0,
                .idle_stream_timeout_ms = 0,
                .accept_backlog = 0,
                .max_active_streams = 0,
                .mtu = 0,
                .snd_wnd = 0,
                .rcv_wnd = 0,
                .nodelay = 0,
                .interval = 0,
                .resend = 0,
                .nc = 0,
            });
            defer mux.deinit();

            try testing.expectEqual(cfg.default_close_ack_timeout_ms, mux.config.close_ack_timeout_ms);
            try testing.expectEqual(cfg.default_idle_stream_timeout_ms, mux.config.idle_stream_timeout_ms);
            try testing.expectEqual(@as(usize, cfg.default_accept_backlog), mux.accept_queue.slots.len);
            try testing.expectEqual(@as(usize, cfg.default_max_active_streams), mux.config.max_active_streams);
            try testing.expectEqual(cfg.default_mtu, mux.config.mtu);
            try testing.expectEqual(cfg.default_snd_wnd, mux.config.snd_wnd);
            try testing.expectEqual(cfg.default_rcv_wnd, mux.config.rcv_wnd);
            try testing.expectEqual(cfg.default_nodelay, mux.config.nodelay);
            try testing.expectEqual(cfg.default_interval, mux.config.interval);
            try testing.expectEqual(cfg.default_resend, mux.config.resend);
            try testing.expectEqual(cfg.default_nc, mux.config.nc);
            try testing.expectEqual(@as(u64, 1), try mux.open(1));
        }

        fn runBidirectionalStreamExchange(allocator: dep.embed.mem.Allocator) !void {
            const testing = lib.testing;

            var clock = Clock{ .now_ms = 10 };
            var pair = Pair{};

            var client = try Mux.init(allocator, 7, .{
                .is_client = true,
                .output = .{ .ctx = &pair.client_to_server, .write = Relay.write },
            });
            defer client.deinit();

            var server = try Mux.init(allocator, 7, .{
                .is_client = false,
                .output = .{ .ctx = &pair.server_to_client, .write = Relay.write },
            });
            defer server.deinit();

            pair.client_to_server = .{ .peer = &server, .clock = &clock };
            pair.server_to_client = .{ .peer = &client, .clock = &clock };

            const first = try client.open(clock.now_ms);
            try pair.pump();
            try testing.expectEqual(@as(u64, 1), first);
            const accepted = try server.accept();
            try testing.expectEqual(first, accepted);

            var buf: [32]u8 = undefined;
            clock.now_ms += 1;
            _ = try client.send(first, "hello", clock.now_ms);
            try advancePair(&pair, &clock, &client, &server, 8);
            const read_n = try server.recv(accepted, &buf);
            try testing.expectEqualStrings("hello", buf[0..read_n]);

            clock.now_ms += 1;
            _ = try server.send(accepted, "world", clock.now_ms);
            try advancePair(&pair, &clock, &client, &server, 8);
            const reply_n = try client.recv(first, &buf);
            try testing.expectEqualStrings("world", buf[0..reply_n]);

            try testing.expectEqual(@as(usize, 1), client.numStreams());
            try testing.expectEqual(@as(usize, 1), server.numStreams());

            try client.closeStream(first, clock.now_ms);
            try pair.pump();
            try testing.expectEqual(@as(usize, 0), client.numStreams());
            try testing.expectEqual(@as(usize, 0), server.numStreams());
        }

        fn runWrappedConnDeadlines(allocator: dep.embed.mem.Allocator) !void {
            const testing = lib.testing;

            var clock = Clock{ .now_ms = 30 };
            var pair = Pair{};

            var client = try Mux.init(allocator, 70, .{
                .is_client = true,
                .output = .{ .ctx = &pair.client_to_server, .write = Relay.write },
            });
            defer client.deinit();

            var server = try Mux.init(allocator, 70, .{
                .is_client = false,
                .output = .{ .ctx = &pair.server_to_client, .write = Relay.write },
            });
            defer server.deinit();

            pair.client_to_server = .{ .peer = &server, .clock = &clock };
            pair.server_to_client = .{ .peer = &client, .clock = &clock };

            var client_conn = try client.openConn(clock.now_ms);
            try pair.pump();
            var server_conn = try server.acceptConn();
            try testing.expectEqual(client_conn.id(), server_conn.id());

            var buf: [32]u8 = undefined;
            try server_conn.setReadDeadline(clock.now_ms + 1);
            try testing.expectError(errors.Error.NoData, server_conn.read(&buf, clock.now_ms));
            clock.now_ms += 1;
            try testing.expectError(errors.Error.ConnTimeout, server_conn.read(&buf, clock.now_ms));
            try server_conn.setReadDeadline(null);

            clock.now_ms += 1;
            _ = try client_conn.write("wrapped", clock.now_ms);
            try advancePair(&pair, &clock, &client, &server, 8);
            const read_n = try server_conn.read(&buf, clock.now_ms);
            try testing.expectEqualStrings("wrapped", buf[0..read_n]);

            try client_conn.close(clock.now_ms);
            try testing.expectError(errors.Error.ConnClosedLocal, client_conn.write("closed", clock.now_ms));
        }

        fn runServerOpenAndBacklogLimits(allocator: dep.embed.mem.Allocator) !void {
            const testing = lib.testing;

            var clock = Clock{ .now_ms = 50 };
            var server_open_pair = Pair{};

            var server_open_client = try Mux.init(allocator, 17, .{
                .is_client = true,
                .output = .{ .ctx = &server_open_pair.client_to_server, .write = Relay.write },
            });
            defer server_open_client.deinit();

            var server_open_server = try Mux.init(allocator, 17, .{
                .is_client = false,
                .output = .{ .ctx = &server_open_pair.server_to_client, .write = Relay.write },
            });
            defer server_open_server.deinit();

            server_open_pair.client_to_server = .{ .peer = &server_open_server, .clock = &clock };
            server_open_pair.server_to_client = .{ .peer = &server_open_client, .clock = &clock };

            const server_open_stream = try server_open_server.open(clock.now_ms);
            try testing.expectEqual(@as(u64, 0), server_open_stream);
            try server_open_pair.pump();
            const accepted_server_open = try server_open_client.accept();
            try testing.expectEqual(server_open_stream, accepted_server_open);

            var buf: [32]u8 = undefined;
            clock.now_ms += 1;
            _ = try server_open_server.send(server_open_stream, "srv", clock.now_ms);
            try advancePair(&server_open_pair, &clock, &server_open_client, &server_open_server, 8);
            const server_open_read_n = try server_open_client.recv(accepted_server_open, &buf);
            try testing.expectEqualStrings("srv", buf[0..server_open_read_n]);

            var backlog_pair = Pair{};
            var backlog_client = try Mux.init(allocator, 19, .{
                .is_client = true,
                .max_active_streams = 4,
                .output = .{ .ctx = &backlog_pair.client_to_server, .write = Relay.write },
            });
            defer backlog_client.deinit();
            var backlog_server = try Mux.init(allocator, 19, .{
                .is_client = false,
                .accept_backlog = 1,
                .max_active_streams = 4,
                .output = .{ .ctx = &backlog_pair.server_to_client, .write = Relay.write },
            });
            defer backlog_server.deinit();
            backlog_pair.client_to_server = .{ .peer = &backlog_server, .clock = &clock };
            backlog_pair.server_to_client = .{ .peer = &backlog_client, .clock = &clock };

            const backlog_first = try backlog_client.open(clock.now_ms);
            try backlog_pair.pump();
            const backlog_second = try backlog_client.open(clock.now_ms);
            try backlog_pair.pump();
            try testing.expectEqual(@as(usize, 1), backlog_client.numStreams());
            try testing.expectEqual(@as(usize, 1), backlog_server.numStreams());
            try testing.expectEqual(backlog_first, try backlog_server.accept());
            try testing.expectError(errors.Error.AcceptQueueEmpty, backlog_server.accept());
            try testing.expectError(errors.Error.StreamNotFound, backlog_client.send(backlog_second, "drop", clock.now_ms));

            var stopping_pair = Pair{};
            var stopping_client = try Mux.init(allocator, 12, .{
                .is_client = true,
                .output = .{ .ctx = &stopping_pair.client_to_server, .write = Relay.write },
            });
            defer stopping_client.deinit();
            var stopping_server = try Mux.init(allocator, 12, .{
                .is_client = false,
                .output = .{ .ctx = &stopping_pair.server_to_client, .write = Relay.write },
            });
            defer stopping_server.deinit();
            stopping_pair.client_to_server = .{ .peer = &stopping_server, .clock = &clock };
            stopping_pair.server_to_client = .{ .peer = &stopping_client, .clock = &clock };

            _ = try stopping_client.open(clock.now_ms);
            try stopping_pair.pump();
            stopping_server.stopAccepting();
            try stopping_pair.pump();
            try testing.expectEqual(@as(usize, 0), stopping_server.numStreams());
            try testing.expectEqual(@as(usize, 0), stopping_client.numStreams());
        }

        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("normalizes_default_config", makeCaseRunner("kcp/Mux/normalizes_default_config", runNormalizesDefaultConfig));
            t.run("bidirectional_stream_exchange", makeCaseRunner("kcp/Mux/bidirectional_stream_exchange", runBidirectionalStreamExchange));
            t.run("wrapped_conn_deadlines", makeCaseRunner("kcp/Mux/wrapped_conn_deadlines", runWrappedConnDeadlines));
            t.run("server_open_and_backlog_limits", makeCaseRunner("kcp/Mux/server_open_and_backlog_limits", runServerOpenAndBacklogLimits));
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

fn advancePair(pair: *Pair, clock: *Clock, client: *Mux, server: *Mux, rounds: usize) !void {
    var round: usize = 0;
    while (round < rounds) : (round += 1) {
        try pair.pump();
        clock.now_ms += 1;
        try client.tick(clock.now_ms);
        try server.tick(clock.now_ms);
    }
    try pair.pump();
}

const Clock = struct {
    now_ms: u64,
};

const Pair = struct {
    client_to_server: Relay = .{},
    server_to_client: Relay = .{},

    fn pump(self: *Pair) !void {
        try self.client_to_server.drain();
        try self.server_to_client.drain();
    }
};

const Relay = struct {
    peer: ?*Mux = null,
    clock: ?*Clock = null,
    packets: [16][1600]u8 = [_][1600]u8{[_]u8{0} ** 1600} ** 16,
    lens: [16]usize = [_]usize{0} ** 16,
    len: usize = 0,

    fn write(ctx: *anyopaque, data_out: []const u8) !void {
        const self = @as(*Relay, @ptrCast(@alignCast(ctx)));
        if (self.len >= self.packets.len) return error.QueueFull;
        if (data_out.len > self.packets[self.len].len) return error.BufferTooSmall;
        @memcpy(self.packets[self.len][0..data_out.len], data_out);
        self.lens[self.len] = data_out.len;
        self.len += 1;
    }

    fn drain(self: *Relay) !void {
        const peer = self.peer orelse unreachable;
        const clock = self.clock orelse unreachable;
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            try peer.input(self.packets[index][0..self.lens[index]], clock.now_ms);
        }
        self.len = 0;
    }
};

const NullOutput = struct {
    fn write(_: *anyopaque, _: []const u8) !void {}
};
