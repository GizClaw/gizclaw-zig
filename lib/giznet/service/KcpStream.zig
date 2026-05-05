const glib = @import("glib");
const kcp_ns = @import("kcp");

const Key = @import("../noise/Key.zig");
const NoiseMessage = @import("../noise/Message.zig");
const PacketInbound = @import("../packet/Inbound.zig");
const PacketOutbound = @import("../packet/Outbound.zig");

pub const Config = struct {
    channel_capacity: usize = 32,
    kcp_nodelay: i32 = -1,
    kcp_interval: i32 = -1,
    kcp_resend: i32 = -1,
    kcp_no_congestion_control: i32 = -1,
};

pub const DriveInput = union(enum) {
    inbound: *PacketInbound,
    outbound: *PacketOutbound,
    tick: glib.time.instant.Time,
};

pub const DriveOutput = union(enum) {
    outbound: *PacketOutbound,
    next_tick_deadline: glib.time.instant.Time,
};

pub fn make(comptime grt: type) type {
    const ChannelType = grt.sync.Channel(*PacketInbound);

    return struct {
        allocator: grt.std.mem.Allocator,
        remote_static: Key,
        service: u64,
        stream: u32,
        kcp: *kcp_ns.Kcp,
        inbound_pool: *PacketInbound.Pool,
        outbound_pool: *PacketOutbound.Pool,
        ch: Channel,
        now: glib.time.instant.Time,

        const Self = @This();
        pub const Channel = ChannelType;
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
            ch: *Channel,

            pub fn recv(self: Port) @TypeOf(self.ch.recv()) {
                return self.ch.recv();
            }

            pub fn recvTimeout(self: Port, timeout: glib.time.duration.Duration) @TypeOf(self.ch.recvTimeout(timeout)) {
                return self.ch.recvTimeout(timeout);
            }
        };

        pub fn init(
            allocator: grt.std.mem.Allocator,
            remote_static: Key,
            service: u64,
            stream: u32,
            inbound_pool: *PacketInbound.Pool,
            outbound_pool: *PacketOutbound.Pool,
            config: Config,
        ) !Self {
            const kcp = try kcp_ns.create(allocator, stream, null);
            errdefer kcp_ns.release(kcp);
            kcp_ns.setOutput(kcp, output);
            kcp_ns.setNodelay(kcp, config.kcp_nodelay, config.kcp_interval, config.kcp_resend, config.kcp_no_congestion_control);

            return .{
                .allocator = allocator,
                .remote_static = remote_static,
                .service = service,
                .stream = stream,
                .kcp = kcp,
                .inbound_pool = inbound_pool,
                .outbound_pool = outbound_pool,
                .ch = try Channel.make(allocator, config.channel_capacity),
                .now = grt.time.instant.now(),
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.drainPackets();
            self.ch.deinit();
            kcp_ns.release(self.kcp);
        }

        pub fn port(self: *Self) Port {
            return .{
                .remote_static = self.remote_static,
                .service = self.service,
                .stream = self.stream,
                .ch = &self.ch,
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
                .inbound => |packet| {
                    errdefer self.updateNextTick(callback) catch {};
                    const now = self.observeTime(grt.time.instant.now());
                    const service_data = packet.service_data orelse return error.PayloadNotParsed;
                    const frame = switch (service_data) {
                        .kcp => |data| blk: {
                            if (data.service != self.service) return error.KcpStreamMismatch;
                            break :blk data.frame;
                        },
                        else => return error.InvalidKcpPacket,
                    };
                    _ = try kcp_ns.input(self.kcp, frame);
                    try self.drainKcpRecv();
                    try self.flush(now, callback);
                    packet.deinit();
                },
                .outbound => |packet| {
                    errdefer self.updateNextTick(callback) catch {};
                    const now = self.observeTime(grt.time.instant.now());
                    const service_data = packet.service_data orelse return error.PayloadNotParsed;
                    const write = switch (service_data) {
                        .write_stream => |data| data,
                        else => return error.InvalidKcpPacket,
                    };
                    if (write.stream > grt.std.math.maxInt(u32)) return error.InvalidKcpStreamId;
                    if (write.service != self.service or @as(u32, @intCast(write.stream)) != self.stream) return error.KcpStreamMismatch;
                    _ = try kcp_ns.send(self.kcp, write.payload);
                    try self.flush(now, callback);
                    packet.deinit();
                },
                .tick => |now| {
                    try self.flush(self.observeTime(now), callback);
                },
            }
        }

        fn close(self: *Self) void {
            self.ch.close();
        }

        fn drainPackets(self: *Self) void {
            while (true) {
                const result = self.ch.recvTimeout(0) catch break;
                if (!result.ok) break;
                result.value.deinit();
            }
        }

        fn flush(self: *Self, now: glib.time.instant.Time, callback: Callback) !void {
            try kcp_ns.update(self.kcp, kcpTime(now));
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

                const packet = self.inbound_pool.get() orelse return error.OutOfMemory;
                errdefer packet.deinit();

                const payload_len: usize = @intCast(peek_size);
                const payload_buf = packet.bufRef()[NoiseMessage.TransportHeaderSize..];
                if (payload_buf.len < payload_len) return error.BufferTooSmall;

                const recv_len = try kcp_ns.recv(self.kcp, payload_buf[0..payload_len]);
                packet.remote_static = self.remote_static;
                packet.len = recv_len;
                packet.kind = .transport;
                packet.state = .service_delivered;

                const send_result = try self.ch.sendTimeout(packet, 0);
                if (!send_result.ok) return error.KcpStreamChannelFull;
            }
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
            const packet = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();

            const payload_buf = packet.transportPlaintextBufRef();
            if (payload_buf.len < frame.len) return error.BufferTooSmall;
            @memcpy(payload_buf[0..frame.len], frame);

            packet.remote_static = self.remote_static;
            packet.len = frame.len;
            packet.service_data = .{ .write_stream = .{
                .service = self.service,
                .stream = self.stream,
                .payload = payload_buf[0..frame.len],
            } };

            try ctx.callback.handle(.{ .outbound = packet });
            return @intCast(frame.len);
        }

        fn kcpTime(now: glib.time.instant.Time) u32 {
            return @truncate(@divTrunc(now, glib.time.duration.MilliSecond));
        }

        fn instantFromKcpTime(time_ms: u32) glib.time.instant.Time {
            return @as(glib.time.instant.Time, @intCast(time_ms)) * glib.time.duration.MilliSecond;
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
            return makeKcpInboundForService(inbound_pool, service_id, frame);
        }

        fn makeKcpInboundForService(inbound_pool: *PacketInbound.Pool, service: u64, frame: []const u8) !*PacketInbound {
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
                .service = service,
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

        fn oneWay(
            outbound_pool: *PacketOutbound.Pool,
            inbound_pool: *PacketInbound.Pool,
            from: *Stream,
            to: *Stream,
            payload: []const u8,
        ) !void {
            var outbound_sink = FrameSink{};
            var inbound_sink = FrameSink{};
            const packet = try makeWritePacket(outbound_pool, payload);
            try driveOutbound(from, packet, outbound_sink.callback());
            var now = grt.time.instant.now();
            for (0..20) |_| {
                if (outbound_sink.count > 0) break;
                now += 20 * glib.time.duration.MilliSecond;
                try from.drive(.{ .tick = now }, outbound_sink.callback());
            }
            if (outbound_sink.count == 0) return error.TestExpectedOutboundFrame;
            try deliverFrames(inbound_pool, to, &outbound_sink, inbound_sink.callback());
            try expectRecv(to.port(), payload);
        }
    };

    const Cases = struct {
        fn outboundToFrame(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var inbound_pool: PacketInbound.Pool = undefined;
            var outbound_pool: PacketOutbound.Pool = undefined;
            try Helpers.initPools(&inbound_pool, &outbound_pool, allocator);
            defer outbound_pool.deinit();
            defer inbound_pool.deinit();

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, test_config);
            defer stream.deinit();

            var sink = FrameSink{};
            const packet = try Helpers.makeWritePacket(&outbound_pool, "hello");
            try Helpers.driveOutbound(&stream, packet, sink.callback());

            try grt.std.testing.expect(sink.count > 0);
            try grt.std.testing.expectEqual(service_id, sink.services[0]);
            try grt.std.testing.expectEqual(@as(u64, stream_id), sink.streams[0]);
            try grt.std.testing.expect(sink.frame(0).len > 0);
            try grt.std.testing.expect(sink.next_tick_deadline != null);
        }

        fn inboundServiceMismatchKeepsOwnership(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var inbound_pool: PacketInbound.Pool = undefined;
            var outbound_pool: PacketOutbound.Pool = undefined;
            try Helpers.initPools(&inbound_pool, &outbound_pool, allocator);
            defer outbound_pool.deinit();
            defer inbound_pool.deinit();

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, test_config);
            defer stream.deinit();

            var sink = FrameSink{};
            const inbound = try Helpers.makeKcpInboundForService(&inbound_pool, service_id + 1, &.{});
            stream.drive(.{ .inbound = inbound }, sink.callback()) catch |err| {
                defer inbound.deinit();
                try grt.std.testing.expectEqual(error.KcpStreamMismatch, err);
                return;
            };
            return error.TestExpectedError;
        }

        fn frameToInboundPayload(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var inbound_pool: PacketInbound.Pool = undefined;
            var outbound_pool: PacketOutbound.Pool = undefined;
            try Helpers.initPools(&inbound_pool, &outbound_pool, allocator);
            defer outbound_pool.deinit();
            defer inbound_pool.deinit();

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, test_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, test_config);
            defer server.deinit();

            var client_sink = FrameSink{};
            var server_sink = FrameSink{};
            const packet = try Helpers.makeWritePacket(&outbound_pool, "from-client");
            try Helpers.driveOutbound(&client, packet, client_sink.callback());
            try Helpers.deliverFrames(&inbound_pool, &server, &client_sink, server_sink.callback());
            try Helpers.expectRecv(server.port(), "from-client");
        }

        fn roundtripBetweenTwoStreams(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var inbound_pool: PacketInbound.Pool = undefined;
            var outbound_pool: PacketOutbound.Pool = undefined;
            try Helpers.initPools(&inbound_pool, &outbound_pool, allocator);
            defer outbound_pool.deinit();
            defer inbound_pool.deinit();

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, test_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, test_config);
            defer server.deinit();

            try Helpers.oneWay(&outbound_pool, &inbound_pool, &client, &server, "one-way-roundtrip");
        }

        fn bidirectionalRoundtrip(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var inbound_pool: PacketInbound.Pool = undefined;
            var outbound_pool: PacketOutbound.Pool = undefined;
            try Helpers.initPools(&inbound_pool, &outbound_pool, allocator);
            defer outbound_pool.deinit();
            defer inbound_pool.deinit();

            var client = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, test_config);
            defer client.deinit();
            var server = try Stream.init(allocator, remote_key, service_id, stream_id, &inbound_pool, &outbound_pool, test_config);
            defer server.deinit();

            try Helpers.oneWay(&outbound_pool, &inbound_pool, &client, &server, "client-to-server");
            try Helpers.oneWay(&outbound_pool, &inbound_pool, &server, &client, "server-to-client");
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
            t.run("roundtrip_between_two_streams", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.roundtripBetweenTwoStreams));
            t.run("bidirectional_roundtrip", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.bidirectionalRoundtrip));
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
