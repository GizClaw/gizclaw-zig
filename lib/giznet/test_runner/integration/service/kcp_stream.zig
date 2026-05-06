const glib = @import("glib");
const testing_api = glib.testing;

const Key = @import("../../../noise/Key.zig");
const NoiseMessage = @import("../../../noise/Message.zig");
const packet = @import("../../../packet.zig");
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
const backpressure_config = KcpStreamType.Config{
    .channel_capacity = 8,
    .kcp_nodelay = 1,
    .kcp_interval = 10,
    .kcp_resend = 2,
    .kcp_no_congestion_control = 1,
    .max_pending_segments = 1,
    .resume_pending_segments = 0,
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
                .outbound => |pkt| {
                    defer pkt.deinit();
                    const write = switch (pkt.service_data orelse return error.PayloadNotParsed) {
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
        fn initPools(allocator: glib.std.mem.Allocator) !packet.Pools {
            var pools = packet.Pools{
                .inbound = try packet.Inbound.initPool(grt, allocator, packet_size_capacity),
                .outbound = undefined,
            };
            errdefer pools.inbound.deinit();

            pools.outbound = try packet.Outbound.initPool(grt, allocator, packet_size_capacity);
            return pools;
        }

        fn deinitPools(pools: *packet.Pools) void {
            pools.outbound.deinit();
            pools.inbound.deinit();
        }

        fn makeWritePacket(pools: *packet.Pools, payload: []const u8) !*packet.Outbound {
            const pkt = pools.outbound.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();

            const payload_buf = pkt.transportPlaintextBufRef();
            if (payload_buf.len < payload.len) return error.BufferTooSmall;
            @memcpy(payload_buf[0..payload.len], payload);

            pkt.remote_static = remote_key;
            pkt.len = payload.len;
            pkt.service_data = .{ .write_stream = .{
                .service = service_id,
                .stream = stream_id,
                .payload = payload_buf[0..payload.len],
            } };
            return pkt;
        }

        fn makeKcpInbound(pools: *packet.Pools, frame: []const u8) !*packet.Inbound {
            const pkt = pools.inbound.get() orelse return error.OutOfMemory;
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

        fn deliverFrames(
            pools: *packet.Pools,
            target: *Stream,
            sink: *const FrameSink,
            callback: Stream.Callback,
        ) !void {
            for (0..sink.count) |index| {
                const inbound = try makeKcpInbound(pools, sink.frame(index));
                target.drive(.{ .inbound = inbound }, callback) catch |err| {
                    inbound.deinit();
                    return err;
                };
            }
        }

        fn driveOutbound(stream: *Stream, outbound: *packet.Outbound, callback: Stream.Callback) !void {
            errdefer outbound.deinit();
            try stream.drive(.{ .outbound = outbound }, callback);
        }

        fn expectRecv(port_value: Stream.Port, expected: []const u8) !void {
            var port = port_value;
            try port.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), glib.time.duration.Second));
            const result = try port.recv();
            try grt.std.testing.expect(result.ok);
            defer result.value.deinit();
            try grt.std.testing.expect(glib.std.mem.eql(u8, result.value.bytes(), expected));
        }
    };

    const Cases = struct {
        fn portReadDeadlineWake(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, stream_config);
            defer stream.deinit();

            var port = stream.port();
            const StartedChannel = grt.sync.Channel(void);
            var started = try StartedChannel.make(allocator, 1);
            defer started.deinit();

            const Task = struct {
                port: *Stream.Port,
                started: *StartedChannel,
                err: ?anyerror = null,

                fn run(task: *@This()) void {
                    _ = task.started.send({}) catch {};
                    const result = task.port.recv() catch |err| {
                        task.err = err;
                        return;
                    };
                    if (result.ok) result.value.deinit();
                    task.err = error.ExpectedReadTimeout;
                }
            };

            var task: Task = .{
                .port = &port,
                .started = &started,
            };
            var thread = try grt.std.Thread.spawn(.{}, Task.run, .{&task});

            const started_result = try started.recvTimeout(2 * glib.time.duration.Second);
            try grt.std.testing.expect(started_result.ok);
            for (0..16) |_| grt.std.Thread.yield() catch {};

            try port.setReadDeadline(grt.time.instant.now());
            thread.join();

            if (task.err) |err| {
                try grt.std.testing.expectEqual(error.Timeout, err);
            } else {
                return error.ExpectedReadTimeout;
            }
        }

        fn lostFrameRetransmitByTick(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, stream_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, stream_config);
            defer server.deinit();

            var client_sink = FrameSink{};
            const pkt = try Helpers.makeWritePacket(&pools, "retransmit-me");
            try Helpers.driveOutbound(&client, pkt, client_sink.callback());
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
            try Helpers.deliverFrames(&pools, &server, &client_sink, server_sink.callback());
            try Helpers.expectRecv(server.port(), "retransmit-me");
        }

        fn writeBackpressureResumesAfterAck(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, backpressure_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, backpressure_config);
            defer server.deinit();

            var client_port = client.port();
            try grt.std.testing.expect((try client_port.waitWritable(16)) > 0);

            var client_sink = FrameSink{};
            var server_sink = FrameSink{};
            const pkt = try Helpers.makeWritePacket(&pools, "ack-opens-writer");
            try Helpers.driveOutbound(&client, pkt, client_sink.callback());

            try client_port.setWriteDeadline(grt.time.instant.now());
            try grt.std.testing.expectEqual(@as(u32, 0), try client_port.waitWritable(16));
            try grt.std.testing.expectError(error.Timeout, client_port.waitWritable(16));

            try Helpers.deliverFrames(&pools, &server, &client_sink, server_sink.callback());
            try Helpers.expectRecv(server.port(), "ack-opens-writer");

            client_sink.clear();
            try Helpers.deliverFrames(&pools, &client, &server_sink, client_sink.callback());

            try client_port.setWriteDeadline(glib.time.instant.add(grt.time.instant.now(), glib.time.duration.Second));
            try grt.std.testing.expect((try client_port.waitWritable(16)) > 0);
        }

        fn writeDeadlineInterruptsBackpressureWait(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, backpressure_config);
            defer stream.deinit();

            var sink = FrameSink{};
            const pkt = try Helpers.makeWritePacket(&pools, "blocked");
            try Helpers.driveOutbound(&stream, pkt, sink.callback());

            var port = stream.port();
            try port.setWriteDeadline(glib.time.instant.add(grt.time.instant.now(), glib.time.duration.Second));

            const WaitTask = struct {
                port: *Stream.Port,
                err: ?anyerror = null,

                fn run(task: *@This()) void {
                    const n = task.port.waitWritable(16) catch |err| {
                        task.err = err;
                        return;
                    };
                    if (n != 0) task.err = error.TestUnexpectedWritable;
                }
            };

            var task = WaitTask{ .port = &port };
            var thread = try grt.std.Thread.spawn(.{}, WaitTask.run, .{&task});
            for (0..16) |_| grt.std.Thread.yield() catch {};

            try port.setWriteDeadline(grt.time.instant.now());
            thread.join();
            if (task.err) |err| return err;
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
            t.run("port_read_deadline_wake", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.portReadDeadlineWake));
            t.run("write_backpressure_resumes_after_ack", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.writeBackpressureResumesAfterAck));
            t.run("write_deadline_interrupts_backpressure_wait", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.writeDeadlineInterruptsBackpressureWait));
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
