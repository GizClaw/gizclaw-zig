const glib = @import("glib");
const testing_api = glib.testing;

const Key = @import("../../../noise/Key.zig");
const NoiseMessage = @import("../../../noise/Message.zig");
const PacketInbound = @import("../../../packet/Inbound.zig");
const PacketOutbound = @import("../../../packet/Outbound.zig");
const KcpStreamType = @import("../../../service/KcpStream.zig");

const packet_size_capacity = 4096;
const service_id: u64 = 7;
const stream_id: u32 = 1;
const remote_key = Key{ .bytes = [_]u8{0x63} ** 32 };
const stream_config = KcpStreamType.Config{
    .channel_capacity = 8,
    .kcp_nodelay = 1,
    .kcp_interval = 10,
    .kcp_resend = 2,
    .kcp_no_congestion_control = 1,
};

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Stream = KcpStreamType.make(grt);

    const FrameSink = struct {
        frames: [64][2048]u8 = undefined,
        lens: [64]usize = undefined,
        count: usize = 0,
        next_tick_deadline: ?glib.time.instant.Time = null,

        fn callback(self: *@This()) Stream.Callback {
            return .{ .ctx = self, .call = call };
        }

        fn clear(self: *@This()) void {
            self.count = 0;
            self.next_tick_deadline = null;
        }

        fn frame(self: *const @This(), index: usize) []const u8 {
            return self.frames[index][0..self.lens[index]];
        }

        fn call(ctx: *anyopaque, output_value: KcpStreamType.DriveOutput) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            switch (output_value) {
                .outbound => |packet| {
                    defer packet.deinit();
                    const write = switch (packet.service_data orelse return error.PayloadNotParsed) {
                        .write_stream => |data| data,
                        else => return error.UnexpectedServiceData,
                    };
                    if (self.count >= self.frames.len) return error.FrameSinkFull;
                    if (write.payload.len > self.frames[self.count].len) return error.FrameTooLarge;
                    @memcpy(self.frames[self.count][0..write.payload.len], write.payload);
                    self.lens[self.count] = write.payload.len;
                    self.count += 1;
                },
                .next_tick_deadline => |deadline| {
                    self.next_tick_deadline = deadline;
                },
            }
        }
    };

    const Helpers = struct {
        fn initPools(inbound_pool: *PacketInbound.Pool, outbound_pool: *PacketOutbound.Pool, allocator: glib.std.mem.Allocator) !void {
            inbound_pool.* = try PacketInbound.initPool(grt, allocator, packet_size_capacity);
            errdefer inbound_pool.deinit();
            outbound_pool.* = try PacketOutbound.initPool(grt, allocator, packet_size_capacity);
        }

        fn makeWritePacket(outbound_pool: *PacketOutbound.Pool, payload: []const u8) !*PacketOutbound {
            const packet = outbound_pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();

            const payload_buf = packet.transportPlaintextBufRef();
            if (payload_buf.len < payload.len) return error.BufferTooSmall;
            @memcpy(payload_buf[0..payload.len], payload);

            packet.remote_static = remote_key;
            packet.len = payload.len;
            packet.service_data = .{ .write_stream = .{
                .service = service_id,
                .stream = stream_id,
                .payload = payload_buf[0..payload.len],
            } };
            return packet;
        }

        fn makeKcpInbound(inbound_pool: *PacketInbound.Pool, frame: []const u8) !*PacketInbound {
            const packet = inbound_pool.get() orelse return error.OutOfMemory;
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

        fn deliverFrames(
            inbound_pool: *PacketInbound.Pool,
            target: *Stream,
            sink: *const FrameSink,
            callback: Stream.Callback,
        ) !void {
            for (0..sink.count) |index| {
                const inbound = try makeKcpInbound(inbound_pool, sink.frame(index));
                target.drive(.{ .inbound = inbound }, callback) catch |err| {
                    inbound.deinit();
                    return err;
                };
            }
        }

        fn driveOutbound(stream: *Stream, packet: *PacketOutbound, callback: Stream.Callback) !void {
            errdefer packet.deinit();
            try stream.drive(.{ .outbound = packet }, callback);
        }

        fn expectRecv(port: Stream.Port, expected: []const u8) !void {
            const result = try port.recvTimeout(0);
            try grt.std.testing.expect(result.ok);
            defer result.value.deinit();
            try grt.std.testing.expect(glib.std.mem.eql(u8, result.value.bytes(), expected));
        }
    };

    const Cases = struct {
        fn lostFrameRetransmitByTick(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var inbound_pool: PacketInbound.Pool = undefined;
            var outbound_pool: PacketOutbound.Pool = undefined;
            try Helpers.initPools(&inbound_pool, &outbound_pool, allocator);
            defer outbound_pool.deinit();
            defer inbound_pool.deinit();

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, stream_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, stream_config);
            defer server.deinit();

            var client_sink = FrameSink{};
            const packet = try Helpers.makeWritePacket(&outbound_pool, "retransmit-me");
            try Helpers.driveOutbound(&client, packet, client_sink.callback());
            try grt.std.testing.expect(client_sink.count > 0);

            client_sink.clear();
            var now = grt.time.instant.now();
            for (0..20) |_| {
                now += 200 * glib.time.duration.MilliSecond;
                try client.drive(.{ .tick = now }, client_sink.callback());
                if (client_sink.count > 0) break;
            }
            try grt.std.testing.expect(client_sink.count > 0);

            var server_sink = FrameSink{};
            try Helpers.deliverFrames(&inbound_pool, &server, &client_sink, server_sink.callback());
            try Helpers.expectRecv(server.port(), "retransmit-me");
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("lost_frame_retransmit_by_tick", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.lostFrameRetransmitByTick));
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
