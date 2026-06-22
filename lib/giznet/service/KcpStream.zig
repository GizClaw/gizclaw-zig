const glib = @import("glib");
const kcp_ns = @import("kcp");

const Key = @import("../noise/Key.zig");
const NoiseMessage = @import("../noise/Message.zig");
const packet = @import("../packet.zig");

pub const Config = struct {
    channel_capacity: usize = 32,
    kcp_nodelay: i32 = 1,
    kcp_interval: i32 = 10,
    kcp_resend: i32 = 2,
    kcp_no_congestion_control: i32 = 1,
    kcp_send_window: u32 = 32,
    kcp_recv_window: u32 = 32,
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
    const ReadChannelArc = grt.sync.Arc.make(grt.std, ReadChannel);
    const WritableChannelArc = grt.sync.Arc.make(grt.std, WritableChannel);
    const fallback_writable_segment_limit: u32 = 1;
    const Shared = struct {
        read_ch: ReadChannelArc.Arc,
        writable_ch: WritableChannelArc.Arc,
        kcp_pending_segments: grt.std.atomic.Value(u32) = grt.std.atomic.Value(u32).init(0),
        reserved_segments: grt.std.atomic.Value(u32) = grt.std.atomic.Value(u32).init(0),
        writable_segment_limit: grt.std.atomic.Value(u32) = grt.std.atomic.Value(u32).init(fallback_writable_segment_limit),
        closed: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),

        pub fn close(self: *@This()) void {
            self.closed.store(true, .release);
            self.read_ch.ptr().close();
            self.writable_ch.ptr().close();
        }

        pub fn deinit(self: *@This()) void {
            self.close();
            self.writable_ch.deinit();
            self.read_ch.deinit();
        }
    };
    const SharedArc = grt.sync.Arc.make(grt.std, Shared);

    return struct {
        allocator: grt.std.mem.Allocator,
        remote_static: Key,
        service: u64,
        stream: u32,
        kcp: [*c]kcp_ns.Kcp,
        pools: *packet.Pools,
        shared: SharedArc.Arc,
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
            shared: SharedArc.Arc,
            write_segment_bytes: u32,
            read_deadline: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
            write_deadline: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),

            pub fn recv(self: *Port) !RecvResult {
                while (true) {
                    const deadline = self.read_deadline.load(.acquire);
                    const result = if (deadline != 0)
                        try self.shared.ptr().read_ch.ptr().recvTimeout(durationUntil(@intCast(deadline)))
                    else
                        try self.shared.ptr().read_ch.ptr().recv();
                    if (!result.ok) return .{ .value = undefined, .ok = false };
                    switch (result.value) {
                        .data => |pkt| return .{ .value = pkt, .ok = true },
                        .read_interrupt => {},
                    }
                }
            }

            pub fn recvTimeout(self: *Port, timeout: glib.time.duration.Duration) !RecvResult {
                while (true) {
                    const result = try self.shared.ptr().read_ch.ptr().recvTimeout(timeout);
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
                _ = self.shared.ptr().read_ch.ptr().sendTimeout(.read_interrupt, 0) catch {};
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
                    const result = self.shared.ptr().writable_ch.ptr().recvTimeout(wait_duration) catch |err| switch (err) {
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
                const shared = self.shared.ptr();
                while (true) {
                    if (shared.closed.load(.acquire)) return null;
                    const kcp_pending = shared.kcp_pending_segments.load(.acquire);
                    const reserved = shared.reserved_segments.load(.acquire);
                    const writable_limit = shared.writable_segment_limit.load(.acquire);
                    const effective_pending = kcp_pending +| reserved;
                    if (effective_pending >= writable_limit) return null;

                    const available_segments = writable_limit - effective_pending;
                    const granted_segments = @min(requested_segments, available_segments);
                    const next_reserved = reserved +| granted_segments;
                    if (shared.reserved_segments.cmpxchgWeak(reserved, next_reserved, .acq_rel, .acquire) == null) {
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
                _ = self.shared.ptr().writable_ch.ptr().sendTimeout(.write_interrupt, 0) catch {};
            }

            pub fn deinit(self: *Port) void {
                self.shared.deinit();
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
            const kcp = kcp_ns.create(stream, null) orelse return error.KcpCreateFailed;
            errdefer kcp_ns.release(kcp);
            kcp_ns.setOutput(kcp, output);
            try setNodelay(kcp, config.kcp_nodelay, config.kcp_interval, config.kcp_resend, config.kcp_no_congestion_control);
            if (config.kcp_send_window != 0 or config.kcp_recv_window != 0) {
                try wndsize(kcp, config.kcp_send_window, config.kcp_recv_window);
            }

            const read_ch = try makeChannelRef(ReadChannel, ReadChannelArc, allocator, config.channel_capacity);
            errdefer read_ch.deinit();

            const writable_ch = try makeChannelRef(WritableChannel, WritableChannelArc, allocator, config.channel_capacity);
            errdefer writable_ch.deinit();

            const shared_value = try allocator.create(Shared);
            errdefer allocator.destroy(shared_value);
            shared_value.* = .{
                .read_ch = read_ch,
                .writable_ch = writable_ch,
                .writable_segment_limit = grt.std.atomic.Value(u32).init(writableSegmentLimitForKcp(kcp)),
            };

            return .{
                .allocator = allocator,
                .remote_static = remote_static,
                .service = service,
                .stream = stream,
                .kcp = kcp,
                .pools = pools,
                .shared = try SharedArc.adopt(allocator, shared_value),
                .write_segment_bytes = kcp.*.mss,
                .now = grt.time.instant.now(),
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.drainPackets();
            self.shared.deinit();
            kcp_ns.release(self.kcp);
        }

        pub fn port(self: *Self) Port {
            return .{
                .remote_static = self.remote_static,
                .service = self.service,
                .stream = self.stream,
                .shared = self.shared.clone(),
                .write_segment_bytes = self.write_segment_bytes,
            };
        }

        pub fn drive(self: *Self, input: DriveInput, callback: Callback) !void {
            var output_ctx = OutputContext{
                .stream = self,
                .callback = callback,
            };
            const previous_user = self.kcp.*.user;
            self.kcp.*.user = &output_ctx;
            defer self.kcp.*.user = previous_user;

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
                    try self.update(now);
                    _ = try inputKcp(self.kcp, frame);
                    try self.drainKcpRecv();
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
                    _ = try send(self.kcp, write.payload);
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
            self.shared.ptr().close();
        }

        fn drainPackets(self: *Self) void {
            while (true) {
                const result = self.shared.ptr().read_ch.ptr().recvTimeout(0) catch break;
                if (!result.ok) break;
                switch (result.value) {
                    .data => |pkt| pkt.deinit(),
                    .read_interrupt => {},
                }
            }
        }

        fn update(self: *Self, now: glib.time.instant.Time) !void {
            kcp_ns.update(self.kcp, kcpTime(now));
        }

        fn flush(self: *Self, callback: Callback) !void {
            kcp_ns.flush(self.kcp);
            try self.updateNextTick(callback);
        }

        fn observeTime(self: *Self, now: glib.time.instant.Time) glib.time.instant.Time {
            if (now > self.now) self.now = now;
            return self.now;
        }

        fn drainKcpRecv(self: *Self) !void {
            while (true) {
                const peek_size = kcp_ns.peeksize(self.kcp);
                if (peek_size <= 0) return;

                const payload_len: usize = @intCast(peek_size);
                const payload_capacity = self.inboundPayloadCapacity();
                if (payload_capacity == 0) return error.BufferTooSmall;
                if (payload_len > payload_capacity) {
                    const payload = try self.allocator.alloc(u8, payload_len);
                    defer self.allocator.free(payload);

                    const recv_len = try recv(self.kcp, payload);
                    try self.deliverKcpPayload(payload[0..recv_len]);
                    continue;
                }

                const pkt = self.pools.inbound.get() orelse return error.OutOfMemory;
                errdefer pkt.deinit();

                const payload_buf = pkt.bufRef()[NoiseMessage.TransportHeaderSize..];
                if (payload_buf.len < payload_len) return error.BufferTooSmall;

                const recv_len = try recv(self.kcp, payload_buf[0..payload_len]);
                try self.deliverInboundPacket(pkt, recv_len);
            }
        }

        fn inboundPayloadCapacity(self: *Self) usize {
            const pkt = self.pools.inbound.get() orelse return 0;
            defer pkt.deinit();

            const buf = pkt.bufRef();
            if (buf.len <= NoiseMessage.TransportHeaderSize) return 0;
            return buf.len - NoiseMessage.TransportHeaderSize;
        }

        fn deliverKcpPayload(self: *Self, payload: []const u8) !void {
            const capacity = self.inboundPayloadCapacity();
            if (capacity == 0) return error.BufferTooSmall;

            var offset: usize = 0;
            while (offset < payload.len) {
                const chunk_len = @min(capacity, payload.len - offset);
                const pkt = self.pools.inbound.get() orelse return error.OutOfMemory;
                errdefer pkt.deinit();

                const payload_buf = pkt.bufRef()[NoiseMessage.TransportHeaderSize..];
                @memcpy(payload_buf[0..chunk_len], payload[offset..][0..chunk_len]);
                try self.deliverInboundPacket(pkt, chunk_len);
                offset += chunk_len;
            }
        }

        fn deliverInboundPacket(self: *Self, pkt: *packet.Inbound, len: usize) !void {
            pkt.remote_static = self.remote_static;
            pkt.len = len;
            pkt.kind = .transport;
            pkt.state = .service_delivered;

            const send_result = try self.shared.ptr().read_ch.ptr().sendTimeout(.{ .data = pkt }, 0);
            if (!send_result.ok) return error.KcpStreamChannelFull;
        }

        fn updateWriteBackpressure(self: *Self) void {
            const shared = self.shared.ptr();
            const pending_i = kcp_ns.waitsnd(self.kcp);
            const pending: u32 = if (pending_i <= 0) 0 else @intCast(pending_i);
            shared.kcp_pending_segments.store(pending, .release);
            const writable_limit = self.writableSegmentLimit();
            shared.writable_segment_limit.store(writable_limit, .release);
            const effective_pending = pending +| shared.reserved_segments.load(.acquire);
            if (effective_pending < writable_limit) {
                _ = shared.writable_ch.ptr().sendTimeout(.writable, 0) catch {};
            }
        }

        fn writableSegmentLimit(self: *const Self) u32 {
            return writableSegmentLimitForKcp(self.kcp);
        }

        fn writableSegmentLimitForKcp(kcp: [*c]const kcp_ns.Kcp) u32 {
            return if (kcp.*.snd_wnd == 0) fallback_writable_segment_limit else kcp.*.snd_wnd;
        }

        fn makeChannelRef(
            comptime Channel: type,
            comptime ChannelArc: type,
            allocator: grt.std.mem.Allocator,
            capacity: usize,
        ) !ChannelArc.Arc {
            const channel = try allocator.create(Channel);
            errdefer allocator.destroy(channel);
            channel.* = try Channel.make(allocator, capacity);
            errdefer channel.deinit();
            return try ChannelArc.adopt(allocator, channel);
        }

        fn releaseReservedBytes(self: *Self, bytes: usize) void {
            const segments = bytesToSegments(@intCast(@min(bytes, grt.std.math.maxInt(u32))), self.write_segment_bytes);
            const shared = self.shared.ptr();
            while (true) {
                const reserved = shared.reserved_segments.load(.acquire);
                if (reserved == 0) return;
                const next_reserved = if (reserved > segments) reserved - segments else 0;
                if (shared.reserved_segments.cmpxchgWeak(reserved, next_reserved, .acq_rel, .acquire) == null) return;
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

        fn output(raw_frame: [*c]const u8, len: c_int, _: [*c]kcp_ns.Kcp, user: ?*anyopaque) callconv(.c) c_int {
            if (len < 0) return -1;
            const frame = raw_frame[0..@intCast(len)];
            const ctx: *OutputContext = @ptrCast(@alignCast(user orelse return -1));
            const self = ctx.stream;
            const pkt = self.pools.outbound.get() orelse return -1;

            const payload_buf = pkt.transportPlaintextBufRef();
            if (payload_buf.len < frame.len) {
                pkt.deinit();
                return -1;
            }
            @memcpy(payload_buf[0..frame.len], frame);

            pkt.remote_static = self.remote_static;
            pkt.len = frame.len;
            pkt.service_data = .{ .write_stream = .{
                .service = self.service,
                .stream = self.stream,
                .payload = payload_buf[0..frame.len],
            } };

            ctx.callback.handle(.{ .outbound = pkt }) catch {
                pkt.deinit();
                return -1;
            };
            return @intCast(frame.len);
        }

        fn kcpTime(now: glib.time.instant.Time) u32 {
            return @truncate(@divTrunc(now, glib.time.duration.MilliSecond));
        }

        fn instantFromKcpTime(time_ms: u32) glib.time.instant.Time {
            return @as(glib.time.instant.Time, @intCast(time_ms)) * glib.time.duration.MilliSecond;
        }

        fn setNodelay(kcp: [*c]kcp_ns.Kcp, nodelay_value: i32, interval: i32, resend: i32, nc: i32) !void {
            if (kcp_ns.nodelay(kcp, nodelay_value, interval, resend, nc) != 0) return error.KcpNodelayFailed;
        }

        fn wndsize(kcp: [*c]kcp_ns.Kcp, sndwnd: u32, rcvwnd: u32) !void {
            if (kcp_ns.wndsize(kcp, @intCast(sndwnd), @intCast(rcvwnd)) != 0) return error.KcpWndsizeFailed;
        }

        fn send(kcp: [*c]kcp_ns.Kcp, buf: []const u8) !usize {
            const rc = kcp_ns.send(kcp, @ptrCast(buf.ptr), @intCast(buf.len));
            if (rc < 0) return error.KcpSendFailed;
            return @intCast(rc);
        }

        fn recv(kcp: [*c]kcp_ns.Kcp, buf: []u8) !usize {
            const rc = kcp_ns.recv(kcp, @ptrCast(buf.ptr), @intCast(buf.len));
            if (rc < 0) return error.NoData;
            return @intCast(rc);
        }

        fn inputKcp(kcp: [*c]kcp_ns.Kcp, buf: []const u8) !i32 {
            const rc = kcp_ns.input(kcp, @ptrCast(buf.ptr), @intCast(buf.len));
            if (rc < 0) return error.KcpInputFailed;
            return rc;
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
    const max_test_frames = 16;
    const test_stack_size = 128 * 1024;
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
        .kcp_no_congestion_control = 0,
        .kcp_send_window = 1,
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

        fn kcpOutput(raw_frame: [*c]const u8, len: c_int, _: [*c]kcp_ns.Kcp, user: ?*anyopaque) callconv(.c) c_int {
            if (len < 0) return -1;
            const output_frame = raw_frame[0..@intCast(len)];
            const self: *@This() = @ptrCast(@alignCast(user orelse return -1));
            if (self.count >= self.frames.len) return -1;
            if (output_frame.len > self.frames[self.count].len) return -1;
            @memcpy(self.frames[self.count][0..output_frame.len], output_frame);
            self.lens[self.count] = output_frame.len;
            self.services[self.count] = service_id;
            self.streams[self.count] = stream_id;
            self.count += 1;
            return 0;
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

        fn makeKcpAckFrame(buf: *[kcp_ns.OVERHEAD]u8, ts: u32) []const u8 {
            var offset: usize = 0;
            offset = encode32u(buf, offset, stream_id);
            offset = encode8u(buf, offset, 82);
            offset = encode8u(buf, offset, 0);
            offset = encode16u(buf, offset, 128);
            offset = encode32u(buf, offset, ts);
            offset = encode32u(buf, offset, 0);
            offset = encode32u(buf, offset, 0);
            offset = encode32u(buf, offset, 0);
            return buf[0..offset];
        }

        fn encode8u(buf: []u8, offset: usize, value: u8) usize {
            buf[offset] = value;
            return offset + 1;
        }

        fn encode16u(buf: []u8, offset: usize, value: u16) usize {
            buf[offset] = @truncate(value);
            buf[offset + 1] = @truncate(value >> 8);
            return offset + 2;
        }

        fn encode32u(buf: []u8, offset: usize, value: u32) usize {
            buf[offset] = @truncate(value);
            buf[offset + 1] = @truncate(value >> 8);
            buf[offset + 2] = @truncate(value >> 16);
            buf[offset + 3] = @truncate(value >> 24);
            return offset + 4;
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
            defer port.deinit();
            try port.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), glib.time.duration.Second));
            const result = try port.recv();
            try grt.std.testing.expect(result.ok);
            defer result.value.deinit();
            try grt.std.testing.expect(glib.std.mem.eql(u8, result.value.bytes(), expected));
        }

        fn expectRecvBytes(port_value: Stream.Port, expected: []const u8) !void {
            var port = port_value;
            defer port.deinit();
            try port.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), glib.time.duration.Second));

            var read: usize = 0;
            while (read < expected.len) {
                const result = try port.recv();
                try grt.std.testing.expect(result.ok);
                defer result.value.deinit();

                const bytes = result.value.bytes();
                try grt.std.testing.expect(bytes.len <= expected.len - read);
                try grt.std.testing.expect(glib.std.mem.eql(u8, bytes, expected[read..][0..bytes.len]));
                read += bytes.len;
            }
        }

        fn makeRawKcpFrames(sink: *FrameSink, payload: []const u8, allocator: grt.std.mem.Allocator) !void {
            _ = allocator;
            const sender = kcp_ns.create(stream_id, null) orelse return error.KcpCreateFailed;
            defer kcp_ns.release(sender);

            kcp_ns.setOutput(sender, FrameSink.kcpOutput);
            try testSetNodelay(sender, test_config.kcp_nodelay, test_config.kcp_interval, test_config.kcp_resend, test_config.kcp_no_congestion_control);
            const previous_user = sender.*.user;
            sender.*.user = sink;
            defer sender.*.user = previous_user;

            _ = try testSend(sender, payload);
            kcp_ns.update(sender, 0);
        }

        fn testSetNodelay(kcp: [*c]kcp_ns.Kcp, nodelay_value: i32, interval: i32, resend: i32, nc: i32) !void {
            if (kcp_ns.nodelay(kcp, nodelay_value, interval, resend, nc) != 0) return error.KcpNodelayFailed;
        }

        fn testSend(kcp: [*c]kcp_ns.Kcp, buf: []const u8) !usize {
            const rc = kcp_ns.send(kcp, @ptrCast(buf.ptr), @intCast(buf.len));
            if (rc < 0) return error.KcpSendFailed;
            return @intCast(rc);
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

        fn inboundAckUpdatesKcpTimeBeforeInput(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer stream.deinit();

            const now_ms: u32 = @truncate(@divTrunc(grt.time.instant.now(), glib.time.duration.MilliSecond));
            stream.kcp.*.current = now_ms +% 0x60000000;

            var frame_buf: [kcp_ns.OVERHEAD]u8 = undefined;
            const frame = Helpers.makeKcpAckFrame(&frame_buf, now_ms);
            const inbound = try Helpers.makeKcpInbound(&pools, frame);

            var sink = FrameSink{};
            try stream.drive(.{ .inbound = inbound }, sink.callback());
            try grt.std.testing.expect(stream.kcp.*.rx_srtt < 1000);
        }

        fn largeKcpMessageSplitsAcrossReadPackets(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer stream.deinit();

            var payload: [6000]u8 = undefined;
            for (&payload, 0..) |*byte, index| byte.* = @truncate(index);

            var input_frames = FrameSink{};
            var ack_sink = FrameSink{};
            try Helpers.makeRawKcpFrames(&input_frames, &payload, allocator);
            try Helpers.deliverFrames(&pools, &stream, &input_frames, ack_sink.callback());
            try Helpers.expectRecvBytes(stream.port(), &payload);
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

        fn initialWritableLimitUsesKcpSendWindow(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, test_config);
            defer stream.deinit();

            var port = stream.port();
            defer port.deinit();

            const requested = stream.write_segment_bytes * 2;
            try grt.std.testing.expectEqual(requested, try port.waitWritable(requested));
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
            defer client_port.deinit();
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
            defer port.deinit();
            try port.setWriteDeadline(glib.time.instant.add(grt.time.instant.now(), glib.time.duration.Second));

            try port.setWriteDeadline(grt.time.instant.now());
            try grt.std.testing.expectEqual(@as(u32, 0), try port.waitWritable(16));
        }

        fn writeInterruptDoesNotWakeRead(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, backpressure_config);
            defer stream.deinit();

            var port = stream.port();
            defer port.deinit();
            try port.setWriteDeadline(grt.time.instant.now());

            try port.setReadDeadline(grt.time.instant.now());
            try grt.std.testing.expectError(error.Timeout, port.recv());
        }

        fn portOutlivesStreamDeinit(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var stream = try Stream.init(allocator, remote_key, service_id, stream_id, &pools, backpressure_config);
            var port = stream.port();
            defer port.deinit();

            stream.deinit();

            const read_result = try port.recvTimeout(0);
            try grt.std.testing.expect(!read_result.ok);
            try grt.std.testing.expectError(error.KcpStreamClosed, port.waitWritable(16));
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

            t.run("outbound_to_frame", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.outboundToFrame));
            t.run("inbound_service_mismatch_keeps_ownership", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.inboundServiceMismatchKeepsOwnership));
            t.run("frame_to_inbound_payload", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.frameToInboundPayload));
            t.run("inbound_flushes_ack_without_waiting_for_tick", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.inboundFlushesAckWithoutWaitingForTick));
            t.run("inbound_ack_updates_kcp_time_before_input", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.inboundAckUpdatesKcpTimeBeforeInput));
            t.run("large_kcp_message_splits_across_read_packets", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.largeKcpMessageSplitsAcrossReadPackets));
            t.run("roundtrip_between_two_streams", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.roundtripBetweenTwoStreams));
            t.run("initial_writable_limit_uses_kcp_send_window", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.initialWritableLimitUsesKcpSendWindow));
            t.run("bidirectional_roundtrip", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.bidirectionalRoundtrip));
            t.run("write_backpressure_resumes_after_ack", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.writeBackpressureResumesAfterAck));
            t.run("set_write_deadline_interrupts_writable_wait", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.setWriteDeadlineInterruptsWritableWait));
            t.run("write_interrupt_does_not_wake_read", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.writeInterruptDoesNotWakeRead));
            t.run("port_outlives_stream_deinit", testing_api.TestRunner.fromFn(grt.std, test_stack_size, Cases.portOutlivesStreamDeinit));
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
