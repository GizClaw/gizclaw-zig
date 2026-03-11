const std = @import("std");
const runtime = @import("embed").runtime;
const conn_mod = @import("conn.zig");

const PacketWriter = conn_mod.PacketWriter;

pub const KCPMuxError = error{
    KCPMuxClosed,
    AcceptQueueClosed,
    InvalidMuxFrame,
    StreamIDExhausted,
    OutOfMemory,
    OutputFailed,
};

const FrameType = enum(u8) {
    open = 0,
    data = 1,
    close = 2,
    close_ack = 3,
};

const CloseReason = enum(u8) {
    close = 0,
    abort = 1,
    invalid = 2,
};

fn decodeFrameType(byte: u8) KCPMuxError!FrameType {
    return switch (byte) {
        @intFromEnum(FrameType.open) => .open,
        @intFromEnum(FrameType.data) => .data,
        @intFromEnum(FrameType.close) => .close,
        @intFromEnum(FrameType.close_ack) => .close_ack,
        else => KCPMuxError.InvalidMuxFrame,
    };
}

fn encodeUvarint(buf: []u8, value: u64) usize {
    var n: usize = 0;
    var x = value;
    while (x >= 0x80) {
        buf[n] = @intCast((x & 0x7f) | 0x80);
        x >>= 7;
        n += 1;
    }
    buf[n] = @intCast(x);
    return n + 1;
}

fn decodeUvarint(data: []const u8) KCPMuxError!struct { value: u64, bytes_read: usize } {
    var x: u64 = 0;
    var shift: u6 = 0;

    for (data, 0..) |byte, idx| {
        if (idx == 10) return KCPMuxError.InvalidMuxFrame;
        const low = @as(u64, byte & 0x7f);
        if (idx == 9 and byte > 1) return KCPMuxError.InvalidMuxFrame;

        x |= low << shift;
        if ((byte & 0x80) == 0) {
            if (x > std.math.maxInt(u32)) return KCPMuxError.InvalidMuxFrame;
            return .{ .value = x, .bytes_read = idx + 1 };
        }
        shift += 7;
    }

    return KCPMuxError.InvalidMuxFrame;
}

pub fn KCPMux(
    comptime KCPConnType: type,
    comptime MutexImpl: type,
    comptime CondImpl: type,
    comptime TimeImpl: type,
) type {
    comptime {
        _ = runtime.sync.Mutex(MutexImpl);
        _ = runtime.sync.Condition(CondImpl);
        _ = runtime.time.from(TimeImpl);
    }

    return struct {
        const Self = @This();

        pub const Config = struct {
            service_port: u64,
            is_client: bool,
            output_ctx: *anyopaque,
            output: *const fn (ctx: *anyopaque, service_port: u64, data: []const u8) anyerror!void,
            on_output_error: ?*const fn (ctx: *anyopaque, service_port: u64, err: anyerror) void = null,
            accept_backlog: usize = 32,
        };

        pub const Stream = struct {
            mux: *Self,
            stream_id: u64,
            conn: ?*KCPConnType,
            closed_error: ?conn_mod.ConnError = null,

            pub fn read(self: *Stream, buf: []u8) anyerror!usize {
                const conn = self.conn orelse return self.closed_error orelse conn_mod.ConnError.ConnClosedLocal;
                return conn.read(buf);
            }

            pub fn write(self: *Stream, data: []const u8) anyerror!usize {
                const conn = self.conn orelse return self.closed_error orelse conn_mod.ConnError.ConnClosedLocal;
                return conn.write(data);
            }

            pub fn close(self: *Stream) void {
                if (self.conn == null) return;
                self.mux.closeStream(self.stream_id);
            }

            pub fn isClosed(self: *Stream) bool {
                const conn = self.conn orelse return true;
                return conn.isClosed();
            }
        };

        const AcceptQueue = struct {
            items: std.ArrayListUnmanaged(u64) = .{},
            capacity: usize = 0,
            is_closed: bool = false,

            fn push(self: *AcceptQueue, allocator: std.mem.Allocator, item: u64) !bool {
                if (self.items.items.len >= self.capacity) return false;
                try self.items.append(allocator, item);
                return true;
            }

            fn pop(self: *AcceptQueue) ?u64 {
                if (self.items.items.len == 0) return null;
                return self.items.orderedRemove(0);
            }
        };

        const OutputCtx = struct {
            mux: *Self,
            stream_id: u64,
        };

        const StreamEntry = struct {
            conn: *KCPConnType,
            stream: *Stream,
            output_ctx: *OutputCtx,
            queued: bool,
        };

        const StreamCloseOrigin = enum {
            local,
            peer,
        };

        config: Config,
        streams: std.AutoHashMap(u64, StreamEntry),
        stream_resources: std.ArrayListUnmanaged(StreamEntry),
        closed_streams: std.ArrayListUnmanaged(*Stream),
        streams_mu: MutexImpl,

        accept_queue: AcceptQueue,
        accept_mu: MutexImpl,
        accept_cond: CondImpl,

        closed: std.atomic.Value(bool),
        next_local_stream_id: u64,
        output_errors: std.atomic.Value(u64),

        time: TimeImpl,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, time: TimeImpl, config: Config) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            self.* = .{
                .config = config,
                .streams = std.AutoHashMap(u64, StreamEntry).init(allocator),
                .stream_resources = .{},
                .closed_streams = .{},
                .streams_mu = MutexImpl.init(),
                .accept_queue = .{ .capacity = config.accept_backlog },
                .accept_mu = MutexImpl.init(),
                .accept_cond = CondImpl.init(),
                .closed = std.atomic.Value(bool).init(false),
                .next_local_stream_id = if (config.is_client) 1 else 0,
                .output_errors = std.atomic.Value(u64).init(0),
                .time = time,
                .allocator = allocator,
            };

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.close();

            self.streams_mu.lock();
            for (self.closed_streams.items) |stream| {
                self.allocator.destroy(stream);
            }
            self.closed_streams.deinit(self.allocator);
            self.streams_mu.unlock();

            self.accept_cond.deinit();
            self.accept_mu.deinit();
            self.accept_queue.items.deinit(self.allocator);
            self.streams_mu.deinit();
            self.allocator.destroy(self);
        }

        pub fn input(self: *Self, data: []const u8) KCPMuxError!void {
            if (self.closed.load(.acquire)) return KCPMuxError.KCPMuxClosed;

            const stream = try decodeUvarint(data);
            if (data.len <= stream.bytes_read) return KCPMuxError.InvalidMuxFrame;

            const frame_type = try decodeFrameType(data[stream.bytes_read]);
            const payload = data[stream.bytes_read + 1 ..];
            const stream_id = stream.value;

            switch (frame_type) {
                .open => return self.handleOpen(stream_id, payload),
                .data => return self.handleData(stream_id, payload),
                .close => return self.handleClose(stream_id),
                .close_ack => return self.handleCloseAck(stream_id),
            }
        }

        pub fn openStream(self: *Self) KCPMuxError!*Stream {
            if (self.closed.load(.acquire)) return KCPMuxError.KCPMuxClosed;

            self.streams_mu.lock();
            defer self.streams_mu.unlock();

            const stream_id = try self.allocateLocalStreamIDLocked();
            const entry = try self.createStreamLocked(stream_id, false);
            self.sendFrame(stream_id, .open, &.{}) catch |err| {
                self.destroyActiveStreamLocked(stream_id);
                if (self.next_local_stream_id == stream_id + 2) {
                    self.next_local_stream_id = stream_id;
                }
                return err;
            };
            return entry.stream;
        }

        pub fn acceptStream(self: *Self) KCPMuxError!*Stream {
            if (self.closed.load(.acquire)) return KCPMuxError.KCPMuxClosed;

            while (true) {
                self.accept_mu.lock();
                while (self.accept_queue.items.items.len == 0) {
                    if (self.accept_queue.is_closed) {
                        self.accept_mu.unlock();
                        return KCPMuxError.AcceptQueueClosed;
                    }
                    self.accept_cond.wait(&self.accept_mu);
                }
                const stream_id = self.accept_queue.pop() orelse {
                    self.accept_mu.unlock();
                    return KCPMuxError.AcceptQueueClosed;
                };
                self.accept_mu.unlock();

                self.streams_mu.lock();
                if (self.streams.getPtr(stream_id)) |entry| {
                    entry.queued = false;
                    const stream = entry.stream;
                    self.streams_mu.unlock();
                    return stream;
                }
                self.streams_mu.unlock();
            }
        }

        pub fn close(self: *Self) void {
            if (self.closed.swap(true, .acq_rel)) return;

            self.streams_mu.lock();

            self.accept_mu.lock();
            self.accept_queue.is_closed = true;
            self.accept_cond.broadcast();
            self.accept_mu.unlock();

            while (self.streams.count() > 0) {
                var iter = self.streams.iterator();
                const stream_id = iter.next().?.key_ptr.*;
                self.removeStreamLocked(stream_id, .local);
            }

            self.stream_resources.deinit(self.allocator);
            self.streams.deinit();
            self.streams_mu.unlock();
        }

        pub fn numStreams(self: *Self) usize {
            self.streams_mu.lock();
            defer self.streams_mu.unlock();
            return self.streams.count();
        }

        pub fn outputErrorCount(self: *const Self) u64 {
            return self.output_errors.load(.acquire);
        }

        fn handleOpen(self: *Self, stream_id: u64, payload: []const u8) KCPMuxError!void {
            if (payload.len != 0) {
                try self.sendFrame(stream_id, .close, &.{@intFromEnum(CloseReason.invalid)});
                return;
            }
            if (!self.isRemoteStreamID(stream_id)) {
                try self.sendFrame(stream_id, .close, &.{@intFromEnum(CloseReason.invalid)});
                return;
            }

            self.streams_mu.lock();
            defer self.streams_mu.unlock();
            if (self.streams.contains(stream_id)) return;

            const entry = try self.createStreamLocked(stream_id, true);
            _ = entry;
            self.accept_mu.lock();
            if (!(try self.accept_queue.push(self.allocator, stream_id))) {
                self.accept_mu.unlock();
                self.destroyActiveStreamLocked(stream_id);
                try self.sendFrame(stream_id, .close, &.{@intFromEnum(CloseReason.abort)});
                return;
            }
            self.accept_cond.signal();
            self.accept_mu.unlock();
        }

        fn handleData(self: *Self, stream_id: u64, payload: []const u8) KCPMuxError!void {
            self.streams_mu.lock();
            const entry = self.streams.getPtr(stream_id) orelse {
                self.streams_mu.unlock();
                try self.sendFrame(stream_id, .close, &.{@intFromEnum(CloseReason.invalid)});
                return;
            };
            const conn = entry.conn;
            self.streams_mu.unlock();

            conn.input(payload) catch {
                self.closeStream(stream_id);
            };
        }

        fn handleClose(self: *Self, stream_id: u64) KCPMuxError!void {
            self.removeStream(stream_id, .peer);
            try self.sendFrame(stream_id, .close_ack, &.{});
        }

        fn handleCloseAck(self: *Self, stream_id: u64) KCPMuxError!void {
            self.removeStream(stream_id, .peer);
        }

        fn closeStream(self: *Self, stream_id: u64) void {
            self.sendFrame(stream_id, .close, &.{@intFromEnum(CloseReason.close)}) catch {};
            self.removeStream(stream_id, .local);
        }

        fn removeStream(self: *Self, stream_id: u64, reason: StreamCloseOrigin) void {
            self.streams_mu.lock();
            defer self.streams_mu.unlock();
            self.removeStreamLocked(stream_id, reason);
        }

        fn removeStreamLocked(self: *Self, stream_id: u64, reason: StreamCloseOrigin) void {
            if (self.streams.fetchRemove(stream_id)) |kv| {
                const closed_error = switch (reason) {
                    .local => conn_mod.ConnError.ConnClosedLocal,
                    .peer => conn_mod.ConnError.ConnClosedByPeer,
                };

                if (reason == .peer and @hasDecl(KCPConnType, "closeByPeer")) {
                    kv.value.conn.closeByPeer();
                } else {
                    kv.value.conn.close();
                }
                kv.value.stream.conn = null;
                kv.value.stream.closed_error = closed_error;
                kv.value.conn.deinit();
                self.allocator.destroy(kv.value.output_ctx);

                for (self.stream_resources.items, 0..) |entry, idx| {
                    if (entry.stream != kv.value.stream) continue;
                    _ = self.stream_resources.swapRemove(idx);
                    break;
                }

                if (kv.value.queued) {
                    self.allocator.destroy(kv.value.stream);
                } else {
                    self.closed_streams.append(self.allocator, kv.value.stream) catch {};
                }
            }
        }

        fn destroyDetachedStreamResourcesLocked(self: *Self, stream_id: u64) void {
            for (self.stream_resources.items, 0..) |entry, idx| {
                if (entry.stream.stream_id != stream_id) continue;

                entry.conn.close();
                entry.conn.deinit();
                self.allocator.destroy(entry.output_ctx);
                self.allocator.destroy(entry.stream);
                _ = self.stream_resources.swapRemove(idx);
                return;
            }
        }

        fn destroyActiveStreamLocked(self: *Self, stream_id: u64) void {
            if (self.streams.fetchRemove(stream_id)) |kv| {
                for (self.stream_resources.items, 0..) |entry, idx| {
                    if (entry.stream != kv.value.stream) continue;
                    _ = self.stream_resources.swapRemove(idx);
                    break;
                }

                kv.value.conn.close();
                kv.value.conn.deinit();
                self.allocator.destroy(kv.value.output_ctx);
                self.allocator.destroy(kv.value.stream);
            }
        }

        fn allocateLocalStreamIDLocked(self: *Self) KCPMuxError!u64 {
            const start = self.next_local_stream_id;
            var current = start;
            while (true) {
                if (!self.streams.contains(current)) {
                    self.next_local_stream_id = current + 2;
                    return current;
                }
                current += 2;
                if (current == start) return KCPMuxError.StreamIDExhausted;
            }
        }

        fn createStreamLocked(self: *Self, stream_id: u64, queued: bool) KCPMuxError!*StreamEntry {
            const output_ctx = self.allocator.create(OutputCtx) catch return KCPMuxError.OutOfMemory;
            errdefer self.allocator.destroy(output_ctx);
            output_ctx.* = .{ .mux = self, .stream_id = stream_id };

            const packet_writer = PacketWriter{
                .ptr = @ptrCast(output_ctx),
                .writeFn = &streamOutputTrampoline,
            };

            const conn = KCPConnType.init(
                self.allocator,
                self.time,
                @intCast(stream_id),
                packet_writer,
            ) catch return KCPMuxError.OutOfMemory;
            errdefer conn.deinit();

            const stream = self.allocator.create(Stream) catch return KCPMuxError.OutOfMemory;
            errdefer self.allocator.destroy(stream);
            stream.* = .{ .mux = self, .stream_id = stream_id, .conn = conn };

            const entry = StreamEntry{
                .conn = conn,
                .stream = stream,
                .output_ctx = output_ctx,
                .queued = queued,
            };
            self.stream_resources.append(self.allocator, entry) catch return KCPMuxError.OutOfMemory;
            errdefer _ = self.stream_resources.pop();
            self.streams.put(stream_id, entry) catch return KCPMuxError.OutOfMemory;

            return self.streams.getPtr(stream_id).?;
        }

        fn streamOutputTrampoline(ctx: *anyopaque, data: []const u8) anyerror!void {
            const output_ctx: *OutputCtx = @ptrCast(@alignCast(ctx));
            try output_ctx.mux.sendFrame(output_ctx.stream_id, .data, data);
        }

        fn sendFrame(self: *Self, stream_id: u64, frame_type: FrameType, payload: []const u8) KCPMuxError!void {
            var varint_buf: [10]u8 = undefined;
            const varint_len = encodeUvarint(&varint_buf, stream_id);
            const frame = self.allocator.alloc(u8, varint_len + 1 + payload.len) catch return KCPMuxError.OutOfMemory;
            defer self.allocator.free(frame);

            @memcpy(frame[0..varint_len], varint_buf[0..varint_len]);
            frame[varint_len] = @intFromEnum(frame_type);
            @memcpy(frame[varint_len + 1 ..], payload);

            self.config.output(self.config.output_ctx, self.config.service_port, frame) catch |err| {
                _ = self.output_errors.fetchAdd(1, .seq_cst);
                if (self.config.on_output_error) |cb| cb(self.config.output_ctx, self.config.service_port, err);
                return KCPMuxError.OutputFailed;
            };
        }

        fn isRemoteStreamID(self: *Self, stream_id: u64) bool {
            if (self.config.is_client) return stream_id % 2 == 0;
            return stream_id % 2 == 1;
        }
    };
}

pub fn StdKCPMux(comptime KCPConnType: type) type {
    return KCPMux(KCPConnType, runtime.std.Mutex, runtime.std.Condition, runtime.std.Time);
}

const testing = std.testing;
var mock_kcp_conn_init_count: usize = 0;
var mock_kcp_conn_deinit_count: usize = 0;

const MockKCPConn = struct {
    allocator: std.mem.Allocator,
    conv: u32,
    output: PacketWriter,
    inbound: std.ArrayListUnmanaged(u8) = .{},
    closed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        _: runtime.std.Time,
        conv: u32,
        output: PacketWriter,
    ) !*MockKCPConn {
        const self = try allocator.create(MockKCPConn);
        self.* = .{
            .allocator = allocator,
            .conv = conv,
            .output = output,
        };
        mock_kcp_conn_init_count += 1;
        return self;
    }

    pub fn deinit(self: *MockKCPConn) void {
        self.inbound.deinit(self.allocator);
        mock_kcp_conn_deinit_count += 1;
        self.allocator.destroy(self);
    }

    pub fn input(self: *MockKCPConn, data: []const u8) !void {
        try self.inbound.appendSlice(self.allocator, data);
    }

    pub fn read(self: *MockKCPConn, buf: []u8) !usize {
        if (self.closed) return conn_mod.ConnError.ConnClosedLocal;
        const n = @min(buf.len, self.inbound.items.len);
        @memcpy(buf[0..n], self.inbound.items[0..n]);
        self.inbound.clearRetainingCapacity();
        return n;
    }

    pub fn write(self: *MockKCPConn, data: []const u8) !usize {
        if (self.closed) return conn_mod.ConnError.ConnClosedLocal;
        try self.output.write(data);
        return data.len;
    }

    pub fn close(self: *MockKCPConn) void {
        self.closed = true;
    }

    pub fn closeByPeer(self: *MockKCPConn) void {
        self.closed = true;
    }

    pub fn isClosed(self: *const MockKCPConn) bool {
        return self.closed;
    }
};

const TestKCPMux = StdKCPMux(MockKCPConn);

const FrameCollector = struct {
    frames: std.ArrayListUnmanaged([]u8) = .{},
    allocator: std.mem.Allocator,

    fn output(ctx: *anyopaque, _: u64, data: []const u8) !void {
        const self: *FrameCollector = @ptrCast(@alignCast(ctx));
        try self.frames.append(self.allocator, try self.allocator.dupe(u8, data));
    }

    fn deinit(self: *FrameCollector) void {
        for (self.frames.items) |frame| self.allocator.free(frame);
        self.frames.deinit(self.allocator);
    }
};

const OutputFailureRecorder = struct {
    err_count: usize = 0,
    callback_count: usize = 0,

    fn failOutput(_: *anyopaque, _: u64, _: []const u8) anyerror!void {
        return error.TestOutputFailure;
    }

    fn onOutputError(ctx: *anyopaque, _: u64, err: anyerror) void {
        const self: *OutputFailureRecorder = @ptrCast(@alignCast(ctx));
        self.callback_count += 1;
        if (err == error.TestOutputFailure) {
            self.err_count += 1;
        }
    }
};

test "KCPMux openStream emits open frame and data frame" {
    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 9,
        .is_client = true,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
    });
    defer mux.deinit();

    const stream = try mux.openStream();
    try testing.expectEqual(@as(usize, 1), collector.frames.items.len);

    const open_frame = collector.frames.items[0];
    const decoded = try decodeUvarint(open_frame);
    try testing.expectEqual(@as(u64, 1), decoded.value);
    try testing.expectEqual(@intFromEnum(FrameType.open), open_frame[decoded.bytes_read]);

    _ = try stream.write("abc");
    try testing.expectEqual(@as(usize, 2), collector.frames.items.len);

    const data_frame = collector.frames.items[1];
    const decoded_data = try decodeUvarint(data_frame);
    try testing.expectEqual(@as(u64, 1), decoded_data.value);
    try testing.expectEqual(@intFromEnum(FrameType.data), data_frame[decoded_data.bytes_read]);
    try testing.expectEqualStrings("abc", data_frame[decoded_data.bytes_read + 1 ..]);
}

test "KCPMux accepts remote open and routes inbound data by stream id" {
    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 11,
        .is_client = false,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
    });
    defer mux.deinit();

    var open_frame = [_]u8{ 1, @intFromEnum(FrameType.open) };
    try mux.input(&open_frame);

    const stream = try mux.acceptStream();
    try testing.expectEqual(@as(usize, 1), mux.numStreams());

    var data_frame = [_]u8{ 1, @intFromEnum(FrameType.data), 'h', 'i' };
    try mux.input(&data_frame);

    var out: [8]u8 = undefined;
    const n = try stream.read(&out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("hi", out[0..n]);
}

test "KCPMux rejects invalid frame type" {
    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 12,
        .is_client = true,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
    });
    defer mux.deinit();

    const bad_frame = [_]u8{ 1, 99 };
    try testing.expectError(KCPMuxError.InvalidMuxFrame, mux.input(&bad_frame));
    try testing.expectEqual(@as(usize, 0), mux.numStreams());
}

test "KCPMux skips stale queued stream ids during accept" {
    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 13,
        .is_client = false,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
    });
    defer mux.deinit();

    var open1 = [_]u8{ 1, @intFromEnum(FrameType.open) };
    try mux.input(&open1);

    var close1 = [_]u8{ 1, @intFromEnum(FrameType.close) };
    try mux.input(&close1);

    var open3 = [_]u8{ 3, @intFromEnum(FrameType.open) };
    try mux.input(&open3);

    const stream = try mux.acceptStream();
    try testing.expectEqual(@as(u64, 3), stream.stream_id);
}

test "KCPMux openStream surfaces output failures" {
    var recorder = OutputFailureRecorder{};

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 14,
        .is_client = true,
        .output_ctx = @ptrCast(&recorder),
        .output = &OutputFailureRecorder.failOutput,
        .on_output_error = &OutputFailureRecorder.onOutputError,
    });
    defer mux.deinit();

    try testing.expectError(KCPMuxError.OutputFailed, mux.openStream());
    try testing.expectEqual(@as(u64, 1), mux.outputErrorCount());
    try testing.expectEqual(@as(usize, 1), recorder.callback_count);
    try testing.expectEqual(@as(usize, 1), recorder.err_count);
    try testing.expectEqual(@as(usize, 0), mux.numStreams());
}

test "KCPMux openStream failure rolls back resources and stream id" {
    var recorder = OutputFailureRecorder{};
    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 17,
        .is_client = true,
        .output_ctx = @ptrCast(&recorder),
        .output = &OutputFailureRecorder.failOutput,
        .on_output_error = &OutputFailureRecorder.onOutputError,
    });
    defer mux.deinit();

    try testing.expectError(KCPMuxError.OutputFailed, mux.openStream());
    try testing.expectEqual(@as(usize, 0), mux.numStreams());

    mux.config.output_ctx = @ptrCast(&collector);
    mux.config.output = &FrameCollector.output;
    mux.config.on_output_error = null;

    const stream = try mux.openStream();
    try testing.expectEqual(@as(u64, 1), stream.stream_id);
    try testing.expectEqual(@as(usize, 1), mux.numStreams());
    try testing.expectEqual(@as(usize, 1), collector.frames.items.len);
}

test "KCPMux local close keeps stream handle safe" {
    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 15,
        .is_client = true,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
    });
    defer mux.deinit();

    const stream = try mux.openStream();
    stream.close();

    try testing.expect(stream.isClosed());
    try testing.expectEqual(@as(usize, 0), mux.numStreams());
    try testing.expectEqual(@as(usize, 0), mux.stream_resources.items.len);

    var buf: [8]u8 = undefined;
    try testing.expectError(conn_mod.ConnError.ConnClosedLocal, stream.read(&buf));
    try testing.expectError(conn_mod.ConnError.ConnClosedLocal, stream.write("x"));
}

test "KCPMux remote close keeps accepted stream handle safe" {
    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 16,
        .is_client = false,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
    });
    defer mux.deinit();

    var open_frame = [_]u8{ 1, @intFromEnum(FrameType.open) };
    try mux.input(&open_frame);

    const stream = try mux.acceptStream();

    var close_frame = [_]u8{ 1, @intFromEnum(FrameType.close) };
    try mux.input(&close_frame);

    try testing.expect(stream.isClosed());
    try testing.expectEqual(@as(usize, 0), mux.numStreams());
    try testing.expectEqual(@as(usize, 0), mux.stream_resources.items.len);

    var buf: [8]u8 = undefined;
    try testing.expectError(conn_mod.ConnError.ConnClosedByPeer, stream.read(&buf));
    try testing.expectError(conn_mod.ConnError.ConnClosedByPeer, stream.write("x"));
}

test "KCPMux close paths release active conn resources" {
    mock_kcp_conn_init_count = 0;
    mock_kcp_conn_deinit_count = 0;

    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 18,
        .is_client = true,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
    });
    defer mux.deinit();

    const stream = try mux.openStream();
    try testing.expectEqual(@as(usize, 1), mux.stream_resources.items.len);
    try testing.expectEqual(@as(usize, 1), mock_kcp_conn_init_count);

    stream.close();

    try testing.expect(stream.isClosed());
    try testing.expectEqual(@as(usize, 1), mock_kcp_conn_deinit_count);
    try testing.expectEqual(@as(usize, 0), mux.stream_resources.items.len);
}

test "KCPMux close keeps issued stream handle safe" {
    mock_kcp_conn_init_count = 0;
    mock_kcp_conn_deinit_count = 0;

    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 21,
        .is_client = true,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
    });
    defer mux.deinit();

    const stream = try mux.openStream();
    try testing.expectEqual(@as(usize, 1), mock_kcp_conn_init_count);

    mux.close();

    try testing.expect(stream.isClosed());
    try testing.expectEqual(@as(usize, 1), mock_kcp_conn_deinit_count);

    var buf: [8]u8 = undefined;
    try testing.expectError(conn_mod.ConnError.ConnClosedLocal, stream.read(&buf));
    try testing.expectError(conn_mod.ConnError.ConnClosedLocal, stream.write("x"));
}

test "KCPMux concurrent open and close does not deadlock" {
    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 19,
        .is_client = false,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
    });
    defer mux.deinit();

    const opener_thread = try std.Thread.spawn(.{}, struct {
        fn run(m: *TestKCPMux) void {
            for (0..20) |i| {
                const stream_id: u8 = @intCast(i * 2 + 1);
                var open_frame = [_]u8{ stream_id, @intFromEnum(FrameType.open) };
                m.input(&open_frame) catch {};
            }
        }
    }.run, .{mux});

    const closer_thread = try std.Thread.spawn(.{}, struct {
        fn run(m: *TestKCPMux) void {
            var time = runtime.std.Time{};
            time.sleepMs(1);
            m.close();
        }
    }.run, .{mux});

    opener_thread.join();
    closer_thread.join();
}

test "KCPMux accept backlog limits queued inbound streams" {
    var collector = FrameCollector{ .allocator = testing.allocator };
    defer collector.deinit();

    const mux = try TestKCPMux.init(testing.allocator, runtime.std.Time{}, .{
        .service_port = 20,
        .is_client = false,
        .output_ctx = @ptrCast(&collector),
        .output = &FrameCollector.output,
        .accept_backlog = 1,
    });
    defer mux.deinit();

    var open1 = [_]u8{ 1, @intFromEnum(FrameType.open) };
    try mux.input(&open1);
    try testing.expectEqual(@as(usize, 1), mux.accept_queue.items.items.len);

    var open3 = [_]u8{ 3, @intFromEnum(FrameType.open) };
    try mux.input(&open3);

    try testing.expectEqual(@as(usize, 1), mux.accept_queue.items.items.len);
    try testing.expectEqual(@as(usize, 1), mux.numStreams());
    try testing.expectEqual(@as(usize, 1), collector.frames.items.len);

    const abort_frame = collector.frames.items[0];
    const decoded = try decodeUvarint(abort_frame);
    try testing.expectEqual(@as(u64, 3), decoded.value);
    try testing.expectEqual(@intFromEnum(FrameType.close), abort_frame[decoded.bytes_read]);
    try testing.expectEqual(
        @intFromEnum(CloseReason.abort),
        abort_frame[decoded.bytes_read + 1],
    );
}
