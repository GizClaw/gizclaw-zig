const glib = @import("glib");
const testing_api = glib.testing;

const bench = @import("../test_utils/common.zig");
const Key = @import("../../../noise/Key.zig");
const NoiseMessage = @import("../../../noise/Message.zig");
const PacketInbound = @import("../../../packet/Inbound.zig");
const PacketOutbound = @import("../../../packet/Outbound.zig");
const KcpStreamType = @import("../../../service/KcpStream.zig");

const packet_size_capacity = 64 * 1024;
const total_transfer_bytes: usize = 8 * 1024 * 1024;
const chunk_size: usize = 16 * 1024;
const service_id: u64 = 7;
const stream_id: u32 = 2;
const remote_key = Key{ .bytes = [_]u8{0x71} ** 32 };
const stream_config = KcpStreamType.Config{
    .channel_capacity = 4096,
    .kcp_nodelay = 1,
    .kcp_interval = 10,
    .kcp_resend = 2,
    .kcp_no_congestion_control = 0,
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
                t.logErrorf("benchmark/service/kcp_stream_real_udp one_way_transfer failed: {}", .{err});
                return false;
            };
            runBidirectional(grt, allocator) catch |err| {
                t.logErrorf("benchmark/service/kcp_stream_real_udp bidirectional_transfer failed: {}", .{err});
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
    const Pair = UdpStreamPair(grt);
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
    bench.print(grt, "giznet.service.kcp_stream.real_udp.one_way_transfer", config, elapsed_ns, .{
        .tier = .regular,
        .payload_bytes_per_op = state.received_bytes,
        .copy_bytes_per_op = state.sent_bytes,
        .extra_name = "udp_datagrams",
        .extra_value = state.udp_datagrams,
    });
    printObserved(grt, "giznet.service.kcp_stream.real_udp.one_way_transfer", state);
}

fn runBidirectional(comptime grt: type, allocator: grt.std.mem.Allocator) !void {
    const Pair = UdpStreamPair(grt);
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
    bench.print(grt, "giznet.service.kcp_stream.real_udp.bidirectional_transfer", config, elapsed_ns, .{
        .tier = .regular,
        .payload_bytes_per_op = state.received_bytes,
        .copy_bytes_per_op = state.sent_bytes,
        .extra_name = "udp_datagrams",
        .extra_value = state.udp_datagrams,
    });
    printObserved(grt, "giznet.service.kcp_stream.real_udp.bidirectional_transfer", state);
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
        udp_datagrams: usize = 0,
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
            self.udp_datagrams = self.pair.udp_datagrams;
            self.ticks = self.pair.ticks;
            self.checksum = self.pair.checksum;
        }
    };
}

const TransferDirection = enum {
    client_to_server,
    server_to_client,
};

fn UdpStreamPair(comptime grt: type) type {
    const Stream = KcpStreamType.make(grt);
    const AddrPort = glib.net.netip.AddrPort;

    return struct {
        allocator: grt.std.mem.Allocator,
        inbound_pool: PacketInbound.Pool,
        outbound_pool: PacketOutbound.Pool,
        client: Stream,
        server: Stream,
        client_conn: grt.net.PacketConn,
        server_conn: grt.net.PacketConn,
        client_addr: AddrPort,
        server_addr: AddrPort,
        now: glib.time.instant.Time,
        sent_bytes: usize = 0,
        received_bytes: usize = 0,
        udp_datagrams: usize = 0,
        ticks: usize = 0,
        checksum: u64 = 0,

        const Self = @This();

        fn init(self: *Self, allocator: grt.std.mem.Allocator) !void {
            self.allocator = allocator;
            self.now = grt.time.instant.now();
            self.sent_bytes = 0;
            self.received_bytes = 0;
            self.udp_datagrams = 0;
            self.ticks = 0;
            self.checksum = 0;

            self.client_conn = try grt.net.listenPacket(.{
                .allocator = allocator,
                .address = AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
            });
            errdefer self.client_conn.deinit();

            self.server_conn = try grt.net.listenPacket(.{
                .allocator = allocator,
                .address = AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
            });
            errdefer self.server_conn.deinit();

            const client_udp = try self.client_conn.as(grt.net.UdpConn);
            const server_udp = try self.server_conn.as(grt.net.UdpConn);
            self.client_addr = try client_udp.localAddr();
            self.server_addr = try server_udp.localAddr();

            self.inbound_pool = try PacketInbound.initPool(grt, allocator, packet_size_capacity);
            errdefer self.inbound_pool.deinit();

            self.outbound_pool = try PacketOutbound.initPool(grt, allocator, packet_size_capacity);
            errdefer self.outbound_pool.deinit();

            self.client = try Stream.init(allocator, remote_key, service_id, stream_id, &self.inbound_pool, &self.outbound_pool, stream_config);
            errdefer self.client.deinit();

            self.server = try Stream.init(allocator, remote_key, service_id, stream_id, &self.inbound_pool, &self.outbound_pool, stream_config);
        }

        fn deinit(self: *Self) void {
            self.server.deinit();
            self.client.deinit();
            self.outbound_pool.deinit();
            self.inbound_pool.deinit();
            self.server_conn.deinit();
            self.client_conn.deinit();
        }

        fn transfer(self: *Self, direction: TransferDirection, bytes: usize) !void {
            const received_start = self.received_bytes;
            const received_target = received_start + bytes;
            var sent: usize = 0;
            while (sent < bytes) {
                const n = @min(chunk_size, bytes - sent);
                const packet = try self.makeWritePacket(n, sent);
                switch (direction) {
                    .client_to_server => self.client.drive(.{ .outbound = packet }, self.clientOutputCallback()) catch |err| {
                        packet.deinit();
                        return err;
                    },
                    .server_to_client => self.server.drive(.{ .outbound = packet }, self.serverOutputCallback()) catch |err| {
                        packet.deinit();
                        return err;
                    },
                }
                sent += n;
                self.sent_bytes += n;
                try self.pumpUdp();
                if (self.received_bytes < received_start + sent) {
                    try self.tickBoth();
                    try self.pumpUdp();
                }
            }

            var wait_rounds: usize = 0;
            while (self.received_bytes < received_target and wait_rounds < 10_000) : (wait_rounds += 1) {
                try self.tickBoth();
                try self.pumpUdp();
            }
            if (self.received_bytes < received_target) return error.KcpStreamRealUdpBenchmarkIncompleteTransfer;
        }

        fn tickBoth(self: *Self) !void {
            self.now += 20 * glib.time.duration.MilliSecond;
            try self.client.drive(.{ .tick = self.now }, self.clientOutputCallback());
            try self.server.drive(.{ .tick = self.now }, self.serverOutputCallback());
            self.ticks += 2;
        }

        fn pumpUdp(self: *Self) !void {
            var rounds: usize = 0;
            while (rounds < 128) : (rounds += 1) {
                var progressed = false;
                progressed = try self.drainConn(&self.client_conn, &self.client, self.clientOutputCallback(), .server_to_client) or progressed;
                progressed = try self.drainConn(&self.server_conn, &self.server, self.serverOutputCallback(), .client_to_server) or progressed;
                if (!progressed) break;
            }
            if (rounds == 128) return error.KcpStreamRealUdpPumpStalled;
        }

        fn drainConn(
            self: *Self,
            conn: *grt.net.PacketConn,
            target: *Stream,
            callback: Stream.Callback,
            receive_direction: TransferDirection,
        ) !bool {
            var progressed = false;
            while (true) {
                var buf: [packet_size_capacity]u8 = undefined;
                conn.setReadDeadline(grt.time.instant.add(grt.time.instant.now(), 50 * glib.time.duration.MicroSecond));
                const result = conn.readFrom(&buf) catch |err| switch (err) {
                    error.TimedOut => break,
                    else => return err,
                };
                const inbound = try self.makeKcpInbound(buf[0..result.bytes_read]);
                target.drive(.{ .inbound = inbound }, callback) catch |err| {
                    inbound.deinit();
                    return err;
                };
                self.udp_datagrams += 1;
                _ = try self.drainReceived(receive_direction);
                progressed = true;
            }
            return progressed;
        }

        fn drainReceived(self: *Self, direction: TransferDirection) !usize {
            const port = switch (direction) {
                .client_to_server => self.server.port(),
                .server_to_client => self.client.port(),
            };

            var received: usize = 0;
            while (true) {
                const result = port.recvTimeout(0) catch break;
                if (!result.ok) break;
                defer result.value.deinit();
                const data = result.value.bytes();
                received += data.len;
                self.received_bytes += data.len;
                for (data) |byte| self.checksum +%= byte;
            }
            return received;
        }

        fn makeWritePacket(self: *Self, len: usize, offset: usize) !*PacketOutbound {
            const packet = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();

            const payload_buf = packet.transportPlaintextBufRef();
            if (payload_buf.len < len) return error.BufferTooSmall;
            fillPayload(payload_buf[0..len], offset);

            packet.remote_static = remote_key;
            packet.len = len;
            packet.service_data = .{ .write_stream = .{
                .service = service_id,
                .stream = stream_id,
                .payload = payload_buf[0..len],
            } };
            return packet;
        }

        fn makeKcpInbound(self: *Self, frame: []const u8) !*PacketInbound {
            const packet = self.inbound_pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();

            const payload_buf = packet.bufRef()[NoiseMessage.TransportHeaderSize..];
            if (payload_buf.len < frame.len) return error.BufferTooSmall;
            @memcpy(payload_buf[0..frame.len], frame);

            packet.remote_static = remote_key;
            packet.len = frame.len;
            packet.kind = .transport;
            packet.state = .ready_to_consume;
            packet.service_data = .{ .kcp = .{
                .service = service_id,
                .stream = stream_id,
                .frame = payload_buf[0..frame.len],
            } };
            return packet;
        }

        fn clientOutputCallback(self: *Self) Stream.Callback {
            return .{ .ctx = self, .call = clientOutput };
        }

        fn serverOutputCallback(self: *Self) Stream.Callback {
            return .{ .ctx = self, .call = serverOutput };
        }

        fn clientOutput(ctx: *anyopaque, output: KcpStreamType.DriveOutput) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.handleOutput(&self.client_conn, self.server_addr, output);
        }

        fn serverOutput(ctx: *anyopaque, output: KcpStreamType.DriveOutput) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.handleOutput(&self.server_conn, self.client_addr, output);
        }

        fn handleOutput(_: *Self, conn: *grt.net.PacketConn, dest: AddrPort, output: KcpStreamType.DriveOutput) !void {
            switch (output) {
                .outbound => |packet| {
                    defer packet.deinit();
                    const write = switch (packet.service_data orelse return error.PayloadNotParsed) {
                        .write_stream => |data| data,
                        else => return error.UnexpectedServiceData,
                    };
                    const written = try conn.writeTo(write.payload, dest);
                    if (written != write.payload.len) return error.ShortUdpWrite;
                },
                .next_tick_deadline => {},
            }
        }
    };
}

fn fillPayload(buf: []u8, offset: usize) void {
    for (buf, 0..) |*byte, index| {
        byte.* = @intCast((offset + index) % 251);
    }
}

fn printObserved(comptime grt: type, label: []const u8, state: anytype) void {
    grt.std.debug.print(
        "bench label={s}.observed sent_bytes={d} received_bytes={d} udp_datagrams={d} ticks={d} checksum={d}\n",
        .{
            label,
            state.sent_bytes,
            state.received_bytes,
            state.udp_datagrams,
            state.ticks,
            state.checksum,
        },
    );
}
