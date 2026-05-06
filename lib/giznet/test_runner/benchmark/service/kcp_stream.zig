const glib = @import("glib");
const testing_api = glib.testing;

const bench = @import("../test_utils/common.zig");
const Key = @import("../../../noise/Key.zig");
const NoiseMessage = @import("../../../noise/Message.zig");
const packet = @import("../../../packet.zig");
const KcpStreamType = @import("../../../service/KcpStream.zig");

const packet_size_capacity = 64 * 1024;
const total_transfer_bytes: usize = 8 * 1024 * 1024;
const chunk_size: usize = 16 * 1024;
const service_id: u64 = 7;
const stream_id: u32 = 1;
const remote_key = Key{ .bytes = [_]u8{0x57} ** 32 };
const stream_config = KcpStreamType.Config{
    .channel_capacity = 4096,
    .kcp_nodelay = 1,
    .kcp_interval = 10,
    .kcp_resend = 2,
    .kcp_no_congestion_control = 1,
    .kcp_send_window = 1024,
    .kcp_recv_window = 1024,
    .max_pending_segments = 1024,
    .resume_pending_segments = 768,
};

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;

            runOneWay(grt, allocator) catch |err| {
                t.logErrorf("benchmark/service/kcp_stream one_way_transfer failed: {}", .{err});
                return false;
            };
            runBidirectional(grt, allocator) catch |err| {
                t.logErrorf("benchmark/service/kcp_stream bidirectional_transfer failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runOneWay(comptime grt: type, allocator: grt.std.mem.Allocator) !void {
    const Pair = StreamPair(grt);
    var pair: Pair = undefined;
    try pair.init(allocator);
    defer pair.deinit();

    var state = TransferState(Pair){
        .pair = &pair,
        .direction = .client_to_server,
        .target_bytes = total_transfer_bytes,
    };
    const config = bench.Config{ .warmup = 0, .iterations = 1 };
    const elapsed_ns = try bench.runLoop(grt, config, &state, @TypeOf(state).runRound);

    grt.std.mem.doNotOptimizeAway(state.checksum);
    bench.print(grt, "giznet.service.kcp_stream.one_way_transfer", config, elapsed_ns, .{
        .tier = .regular,
        .payload_bytes_per_op = state.received_bytes,
        .copy_bytes_per_op = state.sent_bytes,
        .extra_name = "frames",
        .extra_value = state.frames,
    });
    printObserved(grt, "giznet.service.kcp_stream.one_way_transfer", state);
}

fn runBidirectional(comptime grt: type, allocator: grt.std.mem.Allocator) !void {
    const Pair = StreamPair(grt);
    var pair: Pair = undefined;
    try pair.init(allocator);
    defer pair.deinit();

    var state = TransferState(Pair){
        .pair = &pair,
        .direction = .bidirectional,
        .target_bytes = total_transfer_bytes,
    };
    const config = bench.Config{ .warmup = 0, .iterations = 1 };
    const elapsed_ns = try bench.runLoop(grt, config, &state, @TypeOf(state).runRound);

    grt.std.mem.doNotOptimizeAway(state.checksum);
    bench.print(grt, "giznet.service.kcp_stream.bidirectional_transfer", config, elapsed_ns, .{
        .tier = .regular,
        .payload_bytes_per_op = state.received_bytes,
        .copy_bytes_per_op = state.sent_bytes,
        .extra_name = "frames",
        .extra_value = state.frames,
    });
    printObserved(grt, "giznet.service.kcp_stream.bidirectional_transfer", state);
}

const Direction = enum {
    client_to_server,
    bidirectional,
};

fn TransferState(comptime Pair: type) type {
    return struct {
        pair: *Pair,
        direction: Direction,
        target_bytes: usize,
        sent_bytes: usize = 0,
        received_bytes: usize = 0,
        frames: usize = 0,
        ticks: usize = 0,
        checksum: u64 = 0,

        const Self = @This();

        fn runRound(self: *Self) !void {
            switch (self.direction) {
                .client_to_server => try self.pair.transfer(.client_to_server, self.target_bytes),
                .bidirectional => {
                    try self.pair.transfer(.client_to_server, self.target_bytes / 2);
                    try self.pair.transfer(.server_to_client, self.target_bytes / 2);
                },
            }
            self.sent_bytes = self.pair.sent_bytes;
            self.received_bytes = self.pair.received_bytes;
            self.frames = self.pair.frames;
            self.ticks = self.pair.ticks;
            self.checksum = self.pair.checksum;
        }
    };
}

const TransferDirection = enum {
    client_to_server,
    server_to_client,
};

fn StreamPair(comptime grt: type) type {
    const Stream = KcpStreamType.make(grt);

    return struct {
        allocator: grt.std.mem.Allocator,
        pools: packet.Pools,
        client: Stream,
        server: Stream,
        client_to_server: PacketQueue,
        server_to_client: PacketQueue,
        now: glib.time.instant.Time,
        sent_bytes: usize = 0,
        received_bytes: usize = 0,
        frames: usize = 0,
        ticks: usize = 0,
        checksum: u64 = 0,

        const Self = @This();

        fn init(self: *Self, allocator: grt.std.mem.Allocator) !void {
            self.allocator = allocator;
            self.client_to_server = PacketQueue.init(allocator);
            errdefer self.client_to_server.deinit();

            self.server_to_client = PacketQueue.init(allocator);
            errdefer self.server_to_client.deinit();

            self.now = grt.time.instant.now();
            self.sent_bytes = 0;
            self.received_bytes = 0;
            self.frames = 0;
            self.ticks = 0;
            self.checksum = 0;

            self.pools = packet.Pools{
                .inbound = try packet.Inbound.initPool(grt, allocator, packet_size_capacity),
                .outbound = undefined,
            };
            errdefer self.pools.inbound.deinit();

            self.pools.outbound = try packet.Outbound.initPool(grt, allocator, packet_size_capacity);
            errdefer self.pools.outbound.deinit();

            self.client = try Stream.init(allocator, remote_key, service_id, stream_id, &self.pools, stream_config);
            errdefer self.client.deinit();

            self.server = try Stream.init(allocator, remote_key, service_id, stream_id, &self.pools, stream_config);
        }

        fn deinit(self: *Self) void {
            self.server_to_client.deinit();
            self.client_to_server.deinit();
            self.server.deinit();
            self.client.deinit();
            self.pools.outbound.deinit();
            self.pools.inbound.deinit();
        }

        fn transfer(self: *Self, direction: TransferDirection, bytes: usize) !void {
            const received_start = self.received_bytes;
            const received_target = received_start + bytes;
            var sent: usize = 0;
            while (sent < bytes) {
                var source_port = switch (direction) {
                    .client_to_server => self.client.port(),
                    .server_to_client => self.server.port(),
                };
                const requested_len = @min(chunk_size, bytes - sent);
                var granted_len: usize = 0;
                while (granted_len == 0) {
                    try source_port.setWriteDeadline(glib.time.instant.add(grt.time.instant.now(), glib.time.duration.Second));
                    granted_len = try source_port.waitWritable(@intCast(@min(requested_len, grt.std.math.maxInt(u32))));
                    _ = try self.tick(direction);
                    try self.pump();
                }

                const n = @min(granted_len, requested_len);
                const pkt = try self.makeWritePacket(n, sent);
                switch (direction) {
                    .client_to_server => self.client.drive(.{ .outbound = pkt }, self.clientOutputCallback()) catch |err| {
                        pkt.deinit();
                        return err;
                    },
                    .server_to_client => self.server.drive(.{ .outbound = pkt }, self.serverOutputCallback()) catch |err| {
                        pkt.deinit();
                        return err;
                    },
                }
                sent += n;
                self.sent_bytes += n;
                try self.pump();
                if (self.received_bytes < received_target) {
                    _ = try self.tick(direction);
                    try self.pump();
                }
            }

            var wait_rounds: usize = 0;
            while (self.received_bytes < received_target and wait_rounds < 10_000) : (wait_rounds += 1) {
                _ = try self.tick(direction);
                try self.pump();
            }
            if (self.received_bytes < received_target) return error.KcpStreamBenchmarkIncompleteTransfer;
        }

        fn tick(self: *Self, direction: TransferDirection) !bool {
            _ = direction;
            self.now += 20 * glib.time.duration.MilliSecond;
            try self.client.drive(.{ .tick = self.now }, self.clientOutputCallback());
            try self.server.drive(.{ .tick = self.now }, self.serverOutputCallback());
            self.ticks += 2;
            return false;
        }

        fn pump(self: *Self) !void {
            var rounds: usize = 0;
            while ((self.client_to_server.count() != 0 or self.server_to_client.count() != 0) and rounds < 64) : (rounds += 1) {
                if (self.client_to_server.count() != 0) {
                    try self.deliverQueue(&self.client_to_server, &self.server, self.serverOutputCallback(), .client_to_server);
                    self.client_to_server.clear();
                }
                if (self.server_to_client.count() != 0) {
                    try self.deliverQueue(&self.server_to_client, &self.client, self.clientOutputCallback(), .server_to_client);
                    self.server_to_client.clear();
                }
            }
            if (self.client_to_server.count() != 0 or self.server_to_client.count() != 0) return error.KcpStreamBenchmarkPumpStalled;
        }

        fn deliverQueue(
            self: *Self,
            queue: *PacketQueue,
            target: *Stream,
            callback: Stream.Callback,
            receive_direction: TransferDirection,
        ) !void {
            for (queue.packets.items) |pkt| {
                const write = switch (pkt.service_data orelse return error.PayloadNotParsed) {
                    .write_stream => |data| data,
                    else => return error.UnexpectedServiceData,
                };
                const inbound = try self.makeKcpInbound(write.payload);
                target.drive(.{ .inbound = inbound }, callback) catch |err| {
                    inbound.deinit();
                    return err;
                };
                self.frames += 1;
                _ = try self.drainReceived(receive_direction);
            }
        }

        fn drainReceived(self: *Self, direction: TransferDirection) !usize {
            var port = switch (direction) {
                .client_to_server => self.server.port(),
                .server_to_client => self.client.port(),
            };

            var received: usize = 0;
            try port.setReadDeadline(grt.time.instant.now());
            while (true) {
                const result = port.recv() catch break;
                if (!result.ok) break;
                defer result.value.deinit();
                const data = result.value.bytes();
                received += data.len;
                self.received_bytes += data.len;
                for (data) |byte| self.checksum +%= byte;
            }
            return received;
        }

        fn makeWritePacket(self: *Self, len: usize, offset: usize) !*packet.Outbound {
            const pkt = self.pools.outbound.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();

            const payload_buf = pkt.transportPlaintextBufRef();
            if (payload_buf.len < len) return error.BufferTooSmall;
            fillPayload(payload_buf[0..len], offset);

            pkt.remote_static = remote_key;
            pkt.len = len;
            pkt.service_data = .{ .write_stream = .{
                .service = service_id,
                .stream = stream_id,
                .payload = payload_buf[0..len],
            } };
            return pkt;
        }

        fn makeKcpInbound(self: *Self, frame: []const u8) !*packet.Inbound {
            const pkt = self.pools.inbound.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();

            const payload_buf = pkt.bufRef()[NoiseMessage.TransportHeaderSize..];
            if (payload_buf.len < frame.len) return error.BufferTooSmall;
            @memcpy(payload_buf[0..frame.len], frame);

            pkt.remote_static = remote_key;
            pkt.len = frame.len;
            pkt.kind = .transport;
            pkt.state = .ready_to_consume;
            pkt.service_data = .{ .kcp = .{
                .service = service_id,
                .stream = stream_id,
                .frame = payload_buf[0..frame.len],
            } };
            return pkt;
        }

        fn clientOutputCallback(self: *Self) Stream.Callback {
            return .{ .ctx = self, .call = clientOutput };
        }

        fn serverOutputCallback(self: *Self) Stream.Callback {
            return .{ .ctx = self, .call = serverOutput };
        }

        fn clientOutput(ctx: *anyopaque, output: KcpStreamType.DriveOutput) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.handleOutput(&self.client_to_server, output);
        }

        fn serverOutput(ctx: *anyopaque, output: KcpStreamType.DriveOutput) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.handleOutput(&self.server_to_client, output);
        }

        fn handleOutput(_: *Self, queue: *PacketQueue, output: KcpStreamType.DriveOutput) !void {
            switch (output) {
                .outbound => |pkt| {
                    try queue.push(pkt);
                },
                .next_tick_deadline => {},
            }
        }
    };
}

const PacketQueue = struct {
    allocator: glib.std.mem.Allocator,
    packets: glib.std.ArrayList(*packet.Outbound) = .empty,

    const Self = @This();

    fn init(allocator: glib.std.mem.Allocator) Self {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *Self) void {
        self.clear();
        self.packets.deinit(self.allocator);
    }

    fn count(self: *const Self) usize {
        return self.packets.items.len;
    }

    fn push(self: *Self, pkt: *packet.Outbound) !void {
        try self.packets.append(self.allocator, pkt);
    }

    fn clear(self: *Self) void {
        for (self.packets.items) |pkt| {
            pkt.deinit();
        }
        self.packets.clearRetainingCapacity();
    }
};

fn fillPayload(buf: []u8, offset: usize) void {
    for (buf, 0..) |*byte, index| {
        byte.* = @intCast((offset + index) % 251);
    }
}

fn printObserved(comptime grt: type, label: []const u8, state: anytype) void {
    grt.std.debug.print(
        "bench label={s}.observed sent_bytes={d} received_bytes={d} frames={d} ticks={d} checksum={d}\n",
        .{
            label,
            state.sent_bytes,
            state.received_bytes,
            state.frames,
            state.ticks,
            state.checksum,
        },
    );
}
