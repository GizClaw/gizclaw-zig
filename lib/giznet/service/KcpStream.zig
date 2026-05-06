const glib = @import("glib");
const kcp_ns = @import("kcp");

const Key = @import("../noise/Key.zig");
const NoiseMessage = @import("../noise/Message.zig");
const packet = @import("../packet.zig");

pub const Config = struct {
    channel_capacity: usize = 32,
    kcp_nodelay: i32 = -1,
    kcp_interval: i32 = -1,
    kcp_resend: i32 = -1,
    kcp_no_congestion_control: i32 = -1,
    kcp_send_window: u32 = 0,
    kcp_recv_window: u32 = 0,
    max_pending_segments: u32 = 1024,
    resume_pending_segments: u32 = 768,
};

pub const DriveInput = union(enum) {
    inbound: *packet.Inbound,
    outbound: *packet.Outbound,
    tick: glib.time.instant.Time,
};

pub const DriveOutput = union(enum) {
    outbound: *packet.Outbound,
    next_tick_deadline: glib.time.instant.Time,
};

pub fn make(comptime grt: type) type {
    const ReadEvent = union(enum) {
        data: *packet.Inbound,
        read_interrupt,
    };
    const WritableEvent = enum {
        writable,
        write_interrupt,
    };
    const ReadChannel = grt.sync.Channel(ReadEvent);
    const WritableChannel = grt.sync.Channel(WritableEvent);

    return struct {
        allocator: grt.std.mem.Allocator,
        remote_static: Key,
        service: u64,
        stream: u32,
        kcp: *kcp_ns.Kcp,
        pools: *packet.Pools,
        read_ch: ReadChannel,
        writable_ch: WritableChannel,
        kcp_pending_segments: grt.std.atomic.Value(u32),
        reserved_segments: grt.std.atomic.Value(u32),
        max_pending_segments: u32,
        resume_pending_segments: u32,
        write_segment_bytes: u32,
        now: glib.time.instant.Time,

        const Self = @This();
        pub const ReadChannelType = ReadChannel;
        pub const WritableChannelType = WritableChannel;
        pub const RecvResult = struct {
            value: *packet.Inbound,
            ok: bool,
        };
        pub const Callback = struct {
            ctx: *anyopaque,
            call: *const fn (ctx: *anyopaque, output: DriveOutput) anyerror!void,

            pub fn handle(self: Callback, drive_output: DriveOutput) !void {
                try self.call(self.ctx, drive_output);
            }
        };

        pub const Port = struct {
            remote_static: Key,
            service: u64,
            stream: u32,
            read_ch: *ReadChannel,
            writable_ch: *WritableChannel,
            kcp_pending_segments: *grt.std.atomic.Value(u32),
            reserved_segments: *grt.std.atomic.Value(u32),
            max_pending_segments: u32,
            write_segment_bytes: u32,
            read_deadline: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            write_deadline: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),

            pub fn recv(self: *Port) !RecvResult {
                while (true) {
                    const deadline = self.read_deadline.load(.acquire);
                    const result = if (deadline != 0)
                        try self.read_ch.recvTimeout(durationUntil(@intCast(deadline)))
                    else
                        try self.read_ch.recv();
                    if (!result.ok) return .{ .value = undefined, .ok = false };
                    switch (result.value) {
                        .data => |pkt| return .{ .value = pkt, .ok = true },
                        .read_interrupt => {},
                    }
                }
            }

            pub fn setReadDeadline(self: *Port, deadline: glib.time.instant.Time) !void {
                self.read_deadline.store(@intCast(deadline), .release);
                self.wakeRead();
            }

            pub fn wakeRead(self: *Port) void {
                _ = self.read_ch.sendTimeout(.read_interrupt, 0) catch {};
            }

            pub fn waitWritable(self: *Port, requested_bytes: u32) !u32 {
                if (requested_bytes == 0) return 0;

                while (true) {
                    if (self.reserveWritableBytes(requested_bytes)) |granted| return granted;

                    const deadline = self.write_deadline.load(.acquire);
                    const wait_duration = if (deadline != 0)
                        durationUntil(@intCast(deadline))
                    else
                        10 * glib.time.duration.MilliSecond;
                    const result = self.writable_ch.recvTimeout(wait_duration) catch |err| switch (err) {
                        error.Timeout => {
                            if (deadline != 0) return err;
                            continue;
                        },
                        else => return err,
                    };
                    if (!result.ok) return error.KcpStreamClosed;
                    switch (result.value) {
                        .writable => {},
                        .write_interrupt => return 0,
                    }
                }
            }

            fn reserveWritableBytes(self: *Port, requested_bytes: u32) ?u32 {
                const requested_segments = bytesToSegments(requested_bytes, self.write_segment_bytes);
                while (true) {
                    const kcp_pending = self.kcp_pending_segments.load(.acquire);
                    const reserved = self.reserved_segments.load(.acquire);
                    const effective_pending = kcp_pending +| reserved;
                    if (effective_pending >= self.max_pending_segments) return null;

                    const available_segments = self.max_pending_segments - effective_pending;
                    const granted_segments = @min(requested_segments, available_segments);
                    const next_reserved = reserved +| granted_segments;
                    if (self.reserved_segments.cmpxchgWeak(reserved, next_reserved, .acq_rel, .acquire) == null) {
                        const granted_bytes = granted_segments *| self.write_segment_bytes;
                        return @min(requested_bytes, granted_bytes);
                    }
                }
            }

            pub fn setWriteDeadline(self: *Port, deadline: glib.time.instant.Time) !void {
                self.write_deadline.store(@intCast(deadline), .release);
                self.wakeWrite();
            }

            pub fn wakeWrite(self: *Port) void {
                _ = self.writable_ch.sendTimeout(.write_interrupt, 0) catch {};
            }
        };

        pub fn init(
            allocator: grt.std.mem.Allocator,
            remote_static: Key,
            service: u64,
            stream: u32,
            pools: *packet.Pools,
            config: Config,
        ) !Self {
            const kcp = try kcp_ns.create(allocator, stream, null);
            errdefer kcp_ns.release(kcp);
            kcp_ns.setOutput(kcp, output);
            kcp_ns.setNodelay(kcp, config.kcp_nodelay, config.kcp_interval, config.kcp_resend, config.kcp_no_congestion_control);
            if (config.kcp_send_window != 0 or config.kcp_recv_window != 0) {
                kcp_ns.wndsize(kcp, config.kcp_send_window, config.kcp_recv_window);
            }

            const max_pending_segments = if (config.max_pending_segments == 0) @as(u32, 1) else config.max_pending_segments;
            const resume_pending_segments = @min(config.resume_pending_segments, maxPendingSegmentsMinusOne(max_pending_segments));

            var read_ch = try ReadChannel.make(allocator, config.channel_capacity);
            errdefer read_ch.deinit();

            var writable_ch = try WritableChannel.make(allocator, config.channel_capacity);
            errdefer writable_ch.deinit();

            return .{
                .allocator = allocator,
                .remote_static = remote_static,
                .service = service,
                .stream = stream,
                .kcp = kcp,
                .pools = pools,
                .read_ch = read_ch,
                .writable_ch = writable_ch,
                .kcp_pending_segments = grt.std.atomic.Value(u32).init(0),
                .reserved_segments = grt.std.atomic.Value(u32).init(0),
                .max_pending_segments = max_pending_segments,
                .resume_pending_segments = resume_pending_segments,
                .write_segment_bytes = kcp.mss,
                .now = grt.time.instant.now(),
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.drainPackets();
            self.writable_ch.deinit();
            self.read_ch.deinit();
            kcp_ns.release(self.kcp);
        }

        pub fn port(self: *Self) Port {
            return .{
                .remote_static = self.remote_static,
                .service = self.service,
                .stream = self.stream,
                .read_ch = &self.read_ch,
                .writable_ch = &self.writable_ch,
                .kcp_pending_segments = &self.kcp_pending_segments,
                .reserved_segments = &self.reserved_segments,
                .max_pending_segments = self.max_pending_segments,
                .write_segment_bytes = self.write_segment_bytes,
            };
        }

        pub fn drive(self: *Self, input: DriveInput, callback: Callback) !void {
            var output_ctx = OutputContext{
                .stream = self,
                .callback = callback,
            };
            const previous_user = self.kcp.user;
            self.kcp.user = &output_ctx;
            defer self.kcp.user = previous_user;

            switch (input) {
                .inbound => |pkt| {
                    errdefer self.updateNextTick(callback) catch {};
                    const now = self.observeTime(grt.time.instant.now());
                    const service_data = pkt.service_data orelse return error.PayloadNotParsed;
                    const frame = switch (service_data) {
                        .kcp => |data| blk: {
                            if (data.service != self.service) return error.KcpStreamMismatch;
                            break :blk data.frame;
                        },
                        else => return error.InvalidKcpPacket,
                    };
                    _ = try kcp_ns.input(self.kcp, frame);
                    try self.drainKcpRecv();
                    try self.update(now);
                    try self.flush(callback);
                    self.updateWriteBackpressure();
                    pkt.deinit();
                },
                .outbound => |pkt| {
                    errdefer self.updateNextTick(callback) catch {};
                    const now = self.observeTime(grt.time.instant.now());
                    const service_data = pkt.service_data orelse return error.PayloadNotParsed;
                    const write = switch (service_data) {
                        .write_stream => |data| data,
                        else => return error.InvalidKcpPacket,
                    };
                    if (write.stream > grt.std.math.maxInt(u32)) return error.InvalidKcpStreamId;
                    if (write.service != self.service or @as(u32, @intCast(write.stream)) != self.stream) return error.KcpStreamMismatch;
                    _ = try kcp_ns.send(self.kcp, write.payload);
                    self.releaseReservedBytes(write.payload.len);
                    try self.update(now);
                    try self.flush(callback);
                    self.updateWriteBackpressure();
                    pkt.deinit();
                },
                .tick => |now| {
                    try self.update(self.observeTime(now));
                    try self.flush(callback);
                    self.updateWriteBackpressure();
                },
            }
        }

        fn close(self: *Self) void {
            self.read_ch.close();
            self.writable_ch.close();
        }

        fn drainPackets(self: *Self) void {
            while (true) {
                const result = self.read_ch.recvTimeout(0) catch break;
                if (!result.ok) break;
                switch (result.value) {
                    .data => |pkt| pkt.deinit(),
                    .read_interrupt => {},
                }
            }
        }

        fn update(self: *Self, now: glib.time.instant.Time) !void {
            try kcp_ns.update(self.kcp, kcpTime(now));
        }

        fn flush(self: *Self, callback: Callback) !void {
            try kcp_ns.flush(self.kcp);
            try self.updateNextTick(callback);
        }

        fn observeTime(self: *Self, now: glib.time.instant.Time) glib.time.instant.Time {
            if (now > self.now) self.now = now;
            return self.now;
        }

        fn drainKcpRecv(self: *Self) !void {
            while (true) {
                const peek_size = try kcp_ns.peeksize(self.kcp);
                if (peek_size <= 0) return;

                const pkt = self.pools.inbound.get() orelse return error.OutOfMemory;
                errdefer pkt.deinit();

                const payload_len: usize = @intCast(peek_size);
                const payload_buf = pkt.bufRef()[NoiseMessage.TransportHeaderSize..];
                if (payload_buf.len < payload_len) return error.BufferTooSmall;

                const recv_len = try kcp_ns.recv(self.kcp, payload_buf[0..payload_len]);
                pkt.remote_static = self.remote_static;
                pkt.len = recv_len;
                pkt.kind = .transport;
                pkt.state = .service_delivered;

                const send_result = try self.read_ch.sendTimeout(.{ .data = pkt }, 0);
                if (!send_result.ok) return error.KcpStreamChannelFull;
            }
        }

        fn updateWriteBackpressure(self: *Self) void {
            const pending = kcp_ns.waitsnd(self.kcp);
            self.kcp_pending_segments.store(pending, .release);
            const effective_pending = pending +| self.reserved_segments.load(.acquire);
            if (effective_pending <= self.resume_pending_segments) {
                _ = self.writable_ch.sendTimeout(.writable, 0) catch {};
            }
        }

        fn releaseReservedBytes(self: *Self, bytes: usize) void {
            const segments = bytesToSegments(@intCast(@min(bytes, grt.std.math.maxInt(u32))), self.write_segment_bytes);
            while (true) {
                const reserved = self.reserved_segments.load(.acquire);
                if (reserved == 0) return;
                const next_reserved = if (reserved > segments) reserved - segments else 0;
                if (self.reserved_segments.cmpxchgWeak(reserved, next_reserved, .acq_rel, .acquire) == null) return;
            }
        }

        fn durationUntil(deadline: glib.time.instant.Time) glib.time.duration.Duration {
            const now = grt.time.instant.now();
            if (deadline <= now) return 0;
            return glib.time.instant.sub(deadline, now);
        }

        fn updateNextTick(self: *Self, callback: Callback) !void {
            const next = kcp_ns.check(self.kcp, kcpTime(self.now));
            try callback.handle(.{ .next_tick_deadline = instantFromKcpTime(next) });
        }

        const OutputContext = struct {
            stream: *Self,
            callback: Callback,
        };

        fn output(frame: []const u8, _: *kcp_ns.Kcp, user: ?*anyopaque) !i32 {
            const ctx: *OutputContext = @ptrCast(@alignCast(user orelse return error.KcpStreamMissingOutputContext));
            const self = ctx.stream;
            const pkt = self.pools.outbound.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();

            const payload_buf = pkt.transportPlaintextBufRef();
            if (payload_buf.len < frame.len) return error.BufferTooSmall;
            @memcpy(payload_buf[0..frame.len], frame);

            pkt.remote_static = self.remote_static;
            pkt.len = frame.len;
            pkt.service_data = .{ .write_stream = .{
                .service = self.service,
                .stream = self.stream,
                .payload = payload_buf[0..frame.len],
            } };

            try ctx.callback.handle(.{ .outbound = pkt });
            return @intCast(frame.len);
        }

        fn kcpTime(now: glib.time.instant.Time) u32 {
            return @truncate(@divTrunc(now, glib.time.duration.MilliSecond));
        }

        fn instantFromKcpTime(time_ms: u32) glib.time.instant.Time {
            return @as(glib.time.instant.Time, @intCast(time_ms)) * glib.time.duration.MilliSecond;
        }

        fn maxPendingSegmentsMinusOne(value: u32) u32 {
            return if (value == 0) 0 else value - 1;
        }

        fn bytesToSegments(bytes: u32, segment_bytes: u32) u32 {
            const divisor = if (segment_bytes == 0) @as(u32, 1) else segment_bytes;
            if (bytes == 0) return 0;
            return ((bytes - 1) / divisor) + 1;
        }
    };
}

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    const testing_api = glib.testing;
    const Stream = make(grt);
    const packet_size_capacity = 4096;
    const service_id: u64 = 7;
    const stream_id: u32 = 1;
    const remote_key = Key{ .bytes = [_]u8{0x42} ** 32 };
    const max_test_frames = 4;
    const test_config = Config{
        .channel_capacity = 4,
        .kcp_nodelay = 1,
        .kcp_interval = 10,
        .kcp_resend = 2,
        .kcp_no_congestion_control = 1,
    };
    const backpressure_config = Config{
        .channel_capacity = 4,
        .kcp_nodelay = 1,
        .kcp_interval = 10,
        .kcp_resend = 2,
        .kcp_no_congestion_control = 1,
        .max_pending_segments = 1,
        .resume_pending_segments = 0,
    };
    const delayed_flush_config = Config{
        .channel_capacity = 4,
        .kcp_nodelay = 1,
        .kcp_interval = 60 * 1000,
        .kcp_resend = 2,
        .kcp_no_congestion_control = 1,
    };

    const FrameSink = struct {
        frames: [max_test_frames][2048]u8 = undefined,
        lens: [max_test_frames]usize = undefined,
        services: [max_test_frames]u64 = undefined,
        streams: [max_test_frames]u64 = undefined,
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

        fn call(ctx: *anyopaque, output_value: DriveOutput) anyerror!void {
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
                    self.services[self.count] = write.service;
                    self.streams[self.count] = write.stream;
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
            return makeKcpInboundForService(pools, service_id, frame);
        }

        fn makeKcpInboundForService(pools: *packet.Pools, service: u64, frame: []const u8) !*packet.Inbound {
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
                .service = service,
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

        fn oneWay(
            pools: *packet.Pools,
            from: *Stream,
            to: *Stream,
            payload: []const u8,
        ) !void {
            var outbound_sink = FrameSink{};
            var inbound_sink = FrameSink{};
            const pkt = try makeWritePacket(pools, payload);
            try driveOutbound(from, pkt, outbound_sink.callback());
            var now = grt.time.instant.now();
            for (0..20) |_| {
                if (outbound_sink.count > 0) break;
                now += 20 * glib.time.duration.MilliSecond;
                try from.drive(.{ .tick = now }, outbound_sink.callback());
            }
            if (outbound_sink.count == 0) return error.TestExpectedOutboundFrame;
            try deliverFrames(pools, to, &outbound_sink, inbound_sink.callback());
            try expectRecv(to.port(), payload);
        }
    };

    const Cases = struct {
        fn outboundToFrame(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer stream.deinit();

            var sink = FrameSink{};
            const pkt = try Helpers.makeWritePacket(&pools, "hello");
            try Helpers.driveOutbound(&stream, pkt, sink.callback());

            try grt.std.testing.expect(sink.count > 0);
            try grt.std.testing.expectEqual(service_id, sink.services[0]);
            try grt.std.testing.expectEqual(@as(u64, stream_id), sink.streams[0]);
            try grt.std.testing.expect(sink.frame(0).len > 0);
            try grt.std.testing.expect(sink.next_tick_deadline != null);
        }

        fn inboundServiceMismatchKeepsOwnership(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer stream.deinit();

            var sink = FrameSink{};
            const inbound = try Helpers.makeKcpInboundForService(&pools, service_id + 1, &.{});
            stream.drive(.{ .inbound = inbound }, sink.callback()) catch |err| {
                defer inbound.deinit();
                try grt.std.testing.expectEqual(error.KcpStreamMismatch, err);
                return;
            };
            return error.TestExpectedError;
        }

        fn frameToInboundPayload(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer server.deinit();

            var client_sink = FrameSink{};
            var server_sink = FrameSink{};
            const pkt = try Helpers.makeWritePacket(&pools, "from-client");
            try Helpers.driveOutbound(&client, pkt, client_sink.callback());
            try Helpers.deliverFrames(&pools, &server, &client_sink, server_sink.callback());
            try Helpers.expectRecv(server.port(), "from-client");
        }

        fn inboundFlushesAckWithoutWaitingForTick(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, delayed_flush_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, delayed_flush_config);
            defer server.deinit();

            var client_sink = FrameSink{};
            var server_sink = FrameSink{};

            const first = try Helpers.makeWritePacket(&pools, "first");
            try Helpers.driveOutbound(&client, first, client_sink.callback());
            try Helpers.deliverFrames(&pools, &server, &client_sink, server_sink.callback());
            try grt.std.testing.expect(server_sink.count > 0);
            try Helpers.expectRecv(server.port(), "first");

            client_sink.clear();
            server_sink.clear();

            const second = try Helpers.makeWritePacket(&pools, "second");
            try Helpers.driveOutbound(&client, second, client_sink.callback());
            try Helpers.deliverFrames(&pools, &server, &client_sink, server_sink.callback());
            try grt.std.testing.expect(server_sink.count > 0);
            try Helpers.expectRecv(server.port(), "second");
        }

        fn roundtripBetweenTwoStreams(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer server.deinit();

            try Helpers.oneWay(&pools, &client, &server, "one-way-roundtrip");
        }

        fn bidirectionalRoundtrip(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer server.deinit();

            try Helpers.oneWay(&pools, &client, &server, "client-to-server");
            try Helpers.oneWay(&pools, &server, &client, "server-to-client");
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
            const pkt = try Helpers.makeWritePacket(&pools, "backpressure");
            try Helpers.driveOutbound(&client, pkt, client_sink.callback());

            try client_port.setWriteDeadline(grt.time.instant.now());
            try grt.std.testing.expectEqual(@as(u32, 0), try client_port.waitWritable(16));
            try grt.std.testing.expectError(error.Timeout, client_port.waitWritable(16));

            try Helpers.deliverFrames(&pools, &server, &client_sink, server_sink.callback());
            try Helpers.expectRecv(server.port(), "backpressure");

            client_sink.clear();
            try Helpers.deliverFrames(&pools, &client, &server_sink, client_sink.callback());

            try client_port.setWriteDeadline(glib.time.instant.add(grt.time.instant.now(), glib.time.duration.Second));
            try grt.std.testing.expect((try client_port.waitWritable(16)) > 0);
        }

        fn setWriteDeadlineInterruptsWritableWait(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
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

        fn writeInterruptDoesNotWakeRead(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, backpressure_config);
            defer stream.deinit();

            var port = stream.port();
            try port.setWriteDeadline(grt.time.instant.now());

            try port.setReadDeadline(grt.time.instant.now());
            try grt.std.testing.expectError(error.Timeout, port.recv());
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: glib.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: glib.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("outbound_to_frame", testing_api.TestRunner.fromFn(grt.std, 32 * 1024, Cases.outboundToFrame));
            t.run("inbound_service_mismatch_keeps_ownership", testing_api.TestRunner.fromFn(grt.std, 32 * 1024, Cases.inboundServiceMismatchKeepsOwnership));
            t.run("frame_to_inbound_payload", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.frameToInboundPayload));
            t.run("inbound_flushes_ack_without_waiting_for_tick", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.inboundFlushesAckWithoutWaitingForTick));
            t.run("roundtrip_between_two_streams", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.roundtripBetweenTwoStreams));
            t.run("bidirectional_roundtrip", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.bidirectionalRoundtrip));
            t.run("write_backpressure_resumes_after_ack", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.writeBackpressureResumesAfterAck));
            t.run("set_write_deadline_interrupts_writable_wait", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.setWriteDeadlineInterruptsWritableWait));
            t.run("write_interrupt_does_not_wake_read", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.writeInterruptDoesNotWakeRead));
            return true;
        }

        pub fn deinit(self: *@This(), allocator: glib.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
