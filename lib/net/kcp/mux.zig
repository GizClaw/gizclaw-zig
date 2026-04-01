const embed = @import("embed");

const cfg = @import("config.zig");
const conn_file = @import("conn.zig");
const errors = @import("errors.zig");
const frame = @import("frame.zig");
const map = @import("map.zig");

const mem = embed.mem;

// Single-threaded: callers must serialize all Mux access and drive tick().
allocator: mem.Allocator,
service_id: u64,
config: cfg.Mux,
callback_state: *CallbackState,
streams: map.UIntMap(u64, Stream),
accept_queue: AcceptQueue,
next_local_stream_id: u64,
active_streams: usize = 0,
accepting_remote: bool = true,
closed: bool = false,

const Self = @This();
const Config = cfg.Mux;
const Conn = conn_file;

const CallbackState = struct {
    service_id: u64,
    output: cfg.Output,
    output_errors: u64 = 0,
};

const StreamOutputState = struct {
    allocator: mem.Allocator,
    callback_state: *CallbackState,
    stream_id: u64,
    scratch: []u8,
};

const Stream = struct {
    output_state: *StreamOutputState,
    conn: Conn,
    queued: bool,
    local_close: bool = false,
    close_deadline_ms: u64 = 0,
    last_active_ms: u64,

    fn deinit(self: *Stream, allocator: mem.Allocator) void {
        self.conn.deinit();
        allocator.free(self.output_state.scratch);
        allocator.destroy(self.output_state);
    }
};

const AcceptQueue = struct {
    allocator: mem.Allocator,
    slots: []u64,
    head: usize = 0,
    tail: usize = 0,
    len: usize = 0,

    fn init(allocator: mem.Allocator, capacity: usize) !AcceptQueue {
        return .{
            .allocator = allocator,
            .slots = try allocator.alloc(u64, @max(capacity, 1)),
        };
    }

    fn deinit(self: *AcceptQueue) void {
        self.allocator.free(self.slots);
        self.slots = &.{};
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }

    fn push(self: *AcceptQueue, value: u64) !void {
        if (self.len == self.slots.len) return errors.Error.RemoteRejected;
        self.slots[self.tail] = value;
        self.tail = (self.tail + 1) % self.slots.len;
        self.len += 1;
    }

    fn pop(self: *AcceptQueue) ?u64 {
        if (self.len == 0) return null;
        const value = self.slots[self.head];
        self.head = (self.head + 1) % self.slots.len;
        self.len -= 1;
        return value;
    }

    fn remove(self: *AcceptQueue, value: u64) bool {
        if (self.len == 0) return false;

        var count: usize = 0;
        var removed = false;
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            const slot_index = (self.head + index) % self.slots.len;
            const current = self.slots[slot_index];
            if (!removed and current == value) {
                removed = true;
                continue;
            }
            const write_index = (self.head + count) % self.slots.len;
            self.slots[write_index] = current;
            count += 1;
        }

        self.tail = (self.head + count) % self.slots.len;
        self.len = count;
        return removed;
    }

    fn clear(self: *AcceptQueue) void {
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }
};

pub fn init(allocator: mem.Allocator, service_id: u64, mux_config: Config) !Self {
    const callback_state = try allocator.create(CallbackState);
    errdefer allocator.destroy(callback_state);
    callback_state.* = .{
        .service_id = service_id,
        .output = mux_config.output,
    };

    return .{
        .allocator = allocator,
        .service_id = service_id,
        .config = mux_config,
        .callback_state = callback_state,
        .streams = try map.UIntMap(u64, Stream).init(allocator, 8),
        .accept_queue = try AcceptQueue.init(allocator, mux_config.accept_backlog),
        .next_local_stream_id = if (mux_config.is_client) 1 else 0,
    };
}

pub fn deinit(self: *Self) void {
    self.close();
    self.accept_queue.deinit();
    self.streams.deinit();
    self.allocator.destroy(self.callback_state);
}

pub fn open(self: *Self, now_ms: u64) !u64 {
    if (self.closed) return errors.Error.ServiceMuxClosed;
    if (self.streams.count() >= self.config.max_active_streams) return errors.Error.StreamLimitReached;

    const stream_id = try self.allocateLocalStreamId();
    var stream = try self.createStream(stream_id, false, now_ms);
    errdefer stream.deinit(self.allocator);

    _ = try self.streams.put(stream_id, stream);
    self.active_streams += 1;

    self.sendControlFrame(stream_id, frame.open, &.{}) catch |err| {
        _ = self.removeStream(stream_id);
        return err;
    };
    return stream_id;
}

pub fn accept(self: *Self) !u64 {
    if (self.closed) return errors.Error.ServiceMuxClosed;

    while (self.accept_queue.pop()) |stream_id| {
        const stream = self.streams.getPtr(stream_id) orelse continue;
        if (!stream.queued) continue;
        stream.queued = false;
        self.active_streams += 1;
        return stream_id;
    }

    return errors.Error.AcceptQueueEmpty;
}

pub fn input(self: *Self, data_in: []const u8, now_ms: u64) !void {
    if (self.closed) return errors.Error.ServiceMuxClosed;

    const decoded = try frame.decode(data_in);
    const stream = self.streams.getPtr(decoded.stream_id);
    const invalid_remote_id = !self.isRemoteStreamId(decoded.stream_id);

    switch (decoded.frame_type) {
        frame.close_ack => {
            if (stream) |entry| {
                entry.last_active_ms = now_ms;
                if (entry.local_close) _ = self.removeStream(decoded.stream_id);
            }
            return;
        },
        frame.close => {
            if (stream) |entry| entry.last_active_ms = now_ms;
            try self.notifyAndRemove(decoded.stream_id, frame.close_ack, &.{});
            return;
        },
        else => {},
    }

    if (decoded.frame_type == frame.open) {
        if (decoded.payload.len != 0 or invalid_remote_id or stream != null) {
            try self.notifyAndRemove(decoded.stream_id, frame.close, &[_]u8{frame.close_reason_invalid});
            return;
        }

        if (self.closed or !self.accepting_remote or self.streams.count() >= self.config.max_active_streams or self.accept_queue.len >= self.accept_queue.slots.len) {
            try self.sendControlFrame(decoded.stream_id, frame.close, &[_]u8{frame.close_reason_abort});
            return;
        }

        var new_stream = try self.createStream(decoded.stream_id, true, now_ms);
        errdefer new_stream.deinit(self.allocator);
        _ = try self.streams.put(decoded.stream_id, new_stream);
        self.accept_queue.push(decoded.stream_id) catch {
            try self.notifyAndRemove(decoded.stream_id, frame.close, &[_]u8{frame.close_reason_abort});
            return;
        };
        return;
    }

    if (decoded.frame_type != frame.data or stream == null) {
        try self.notifyAndRemove(decoded.stream_id, frame.close, &[_]u8{frame.close_reason_invalid});
        return;
    }

    const entry = stream.?;
    if (entry.queued) {
        try self.notifyAndRemove(decoded.stream_id, frame.close, &[_]u8{frame.close_reason_abort});
        return;
    }
    entry.last_active_ms = now_ms;
    entry.conn.input(decoded.payload, now_ms) catch {
        try self.notifyAndRemove(decoded.stream_id, frame.close, &[_]u8{frame.close_reason_invalid});
        return;
    };
}

pub fn send(self: *Self, stream_id: u64, payload: []const u8, now_ms: u64) !usize {
    if (self.closed) return errors.Error.ServiceMuxClosed;
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.queued or stream.local_close) return errors.Error.StreamNotFound;
    stream.last_active_ms = now_ms;
    return stream.conn.send(payload, now_ms);
}

pub fn recv(self: *Self, stream_id: u64, out: []u8) !usize {
    if (self.closed) return errors.Error.ServiceMuxClosed;
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.queued) return errors.Error.StreamNotFound;
    return stream.conn.recv(out);
}

pub fn closeStream(self: *Self, stream_id: u64, now_ms: u64) !void {
    if (self.closed) return errors.Error.ServiceMuxClosed;
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.local_close) return;
    try self.sendControlFrame(stream_id, frame.close, &[_]u8{frame.close_reason_close});
    stream.local_close = true;
    stream.close_deadline_ms = now_ms + self.config.close_ack_timeout_ms;
}

pub fn stopAccepting(self: *Self) void {
    if (self.closed or !self.accepting_remote) return;
    self.accepting_remote = false;

    for (self.streams.slots) |slot| {
        if (slot.state != .full) continue;
        if (!slot.value.queued) continue;
        self.sendControlFrame(slot.key, frame.close, &[_]u8{frame.close_reason_abort}) catch |err| self.reportOutputError(err);
        _ = self.removeStream(slot.key);
    }
}

pub fn tick(self: *Self, now_ms: u64) !void {
    if (self.closed) return;
    var first_error: ?anyerror = null;

    for (self.streams.slots) |*slot| {
        if (slot.state != .full) continue;

        const stream = &slot.value;
        if (!stream.queued and !stream.local_close and self.config.idle_stream_timeout_ms > 0 and now_ms -| stream.last_active_ms >= self.config.idle_stream_timeout_ms) {
            self.sendControlFrame(slot.key, frame.close, &[_]u8{frame.close_reason_abort}) catch |err| self.reportOutputError(err);
            _ = self.removeStream(slot.key);
            continue;
        }

        if (stream.local_close and now_ms >= stream.close_deadline_ms) {
            _ = self.removeStream(slot.key);
            continue;
        }

        stream.conn.update(now_ms) catch |err| {
            if (first_error == null) first_error = err;
        };
    }

    if (first_error) |err| return err;
}

pub fn close(self: *Self) void {
    if (self.closed) return;
    self.closed = true;
    self.accepting_remote = false;

    for (self.streams.slots) |*slot| {
        if (slot.state != .full) continue;
        self.sendControlFrame(slot.key, frame.close, &[_]u8{frame.close_reason_close}) catch |err| self.reportOutputError(err);
        slot.value.deinit(self.allocator);
        slot.state = .empty;
    }
    self.streams.count_value = 0;
    self.streams.tombstones = 0;
    self.active_streams = 0;
    self.accept_queue.clear();
}

pub fn numStreams(self: *const Self) usize {
    return self.streams.count();
}

pub fn outputErrorCount(self: *const Self) u64 {
    return self.callback_state.output_errors;
}

pub fn testAll(testing: anytype, allocator: mem.Allocator) !void {
    var queue = try AcceptQueue.init(allocator, 4);
    defer queue.deinit();
    try queue.push(10);
    try queue.push(11);
    try queue.push(12);
    try testing.expectEqual(@as(?u64, 10), queue.pop());
    try queue.push(13);
    try queue.push(14);
    try testing.expect(queue.remove(13));
    try testing.expectEqual(@as(?u64, 11), queue.pop());
    try testing.expectEqual(@as(?u64, 12), queue.pop());
    try testing.expectEqual(@as(?u64, 14), queue.pop());
    try testing.expectEqual(@as(?u64, null), queue.pop());

    var clock = Clock{ .now_ms = 10 };
    var pair = Pair{};

    var client = try Self.init(allocator, 7, .{
        .is_client = true,
        .output = .{ .ctx = &pair.client_to_server, .write = Relay.write },
    });
    defer client.deinit();

    var server = try Self.init(allocator, 7, .{
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
    var pump_count: usize = 0;
    while (pump_count < 8) : (pump_count += 1) {
        try pair.pump();
        clock.now_ms += 1;
        try client.tick(clock.now_ms);
        try server.tick(clock.now_ms);
    }
    try pair.pump();
    const read_n = try server.recv(accepted, &buf);
    try testing.expectEqualStrings("hello", buf[0..read_n]);

    clock.now_ms += 1;
    _ = try server.send(accepted, "world", clock.now_ms);
    pump_count = 0;
    while (pump_count < 8) : (pump_count += 1) {
        try pair.pump();
        clock.now_ms += 1;
        try client.tick(clock.now_ms);
        try server.tick(clock.now_ms);
    }
    try pair.pump();
    const reply_n = try client.recv(first, &buf);
    try testing.expectEqualStrings("world", buf[0..reply_n]);

    try testing.expectEqual(@as(usize, 1), client.numStreams());
    try testing.expectEqual(@as(usize, 1), server.numStreams());

    try client.closeStream(first, clock.now_ms);
    try pair.pump();
    try testing.expectEqual(@as(usize, 0), client.numStreams());
    try testing.expectEqual(@as(usize, 0), server.numStreams());

    var server_open_pair = Pair{};
    var server_open_client = try Self.init(allocator, 17, .{
        .is_client = true,
        .output = .{ .ctx = &server_open_pair.client_to_server, .write = Relay.write },
    });
    defer server_open_client.deinit();
    var server_open_server = try Self.init(allocator, 17, .{
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
    clock.now_ms += 1;
    _ = try server_open_server.send(server_open_stream, "srv", clock.now_ms);
    pump_count = 0;
    while (pump_count < 8) : (pump_count += 1) {
        try server_open_pair.pump();
        clock.now_ms += 1;
        try server_open_client.tick(clock.now_ms);
        try server_open_server.tick(clock.now_ms);
    }
    try server_open_pair.pump();
    const server_open_read_n = try server_open_client.recv(accepted_server_open, &buf);
    try testing.expectEqualStrings("srv", buf[0..server_open_read_n]);

    var isolation_pair = Pair{};
    var isolation_client = try Self.init(allocator, 18, .{
        .is_client = true,
        .output = .{ .ctx = &isolation_pair.client_to_server, .write = Relay.write },
    });
    defer isolation_client.deinit();
    var isolation_server = try Self.init(allocator, 18, .{
        .is_client = false,
        .output = .{ .ctx = &isolation_pair.server_to_client, .write = Relay.write },
    });
    defer isolation_server.deinit();
    isolation_pair.client_to_server = .{ .peer = &isolation_server, .clock = &clock };
    isolation_pair.server_to_client = .{ .peer = &isolation_client, .clock = &clock };

    const isolation_first = try isolation_client.open(clock.now_ms);
    try isolation_pair.pump();
    const accepted_isolation_first = try isolation_server.accept();
    const isolation_second = try isolation_client.open(clock.now_ms);
    try isolation_pair.pump();
    const accepted_isolation_second = try isolation_server.accept();
    try testing.expectEqual(isolation_first, accepted_isolation_first);
    try testing.expectEqual(isolation_second, accepted_isolation_second);
    try isolation_client.closeStream(isolation_first, clock.now_ms);
    try isolation_pair.pump();
    try testing.expectEqual(@as(usize, 1), isolation_client.numStreams());
    try testing.expectEqual(@as(usize, 1), isolation_server.numStreams());
    clock.now_ms += 1;
    _ = try isolation_client.send(isolation_second, "second", clock.now_ms);
    pump_count = 0;
    while (pump_count < 8) : (pump_count += 1) {
        try isolation_pair.pump();
        clock.now_ms += 1;
        try isolation_client.tick(clock.now_ms);
        try isolation_server.tick(clock.now_ms);
    }
    try isolation_pair.pump();
    const isolation_read_n = try isolation_server.recv(accepted_isolation_second, &buf);
    try testing.expectEqualStrings("second", buf[0..isolation_read_n]);

    var backlog_pair = Pair{};
    var backlog_client = try Self.init(allocator, 19, .{
        .is_client = true,
        .max_active_streams = 4,
        .output = .{ .ctx = &backlog_pair.client_to_server, .write = Relay.write },
    });
    defer backlog_client.deinit();
    var backlog_server = try Self.init(allocator, 19, .{
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

    var pending_pair = Pair{};
    var pending_client = try Self.init(allocator, 8, .{
        .is_client = true,
        .max_active_streams = 4,
        .output = .{ .ctx = &pending_pair.client_to_server, .write = Relay.write },
    });
    defer pending_client.deinit();
    var pending_server = try Self.init(allocator, 8, .{
        .is_client = false,
        .max_active_streams = 4,
        .output = .{ .ctx = &pending_pair.server_to_client, .write = Relay.write },
    });
    defer pending_server.deinit();
    pending_pair.client_to_server = .{ .peer = &pending_server, .clock = &clock };
    pending_pair.server_to_client = .{ .peer = &pending_client, .clock = &clock };

    const pending_stream = try pending_client.open(clock.now_ms);
    try pending_pair.pump();
    clock.now_ms += 10;
    try pending_client.tick(clock.now_ms);
    try pending_server.tick(clock.now_ms);
    try pending_pair.pump();
    try testing.expectEqual(@as(usize, 1), pending_server.numStreams());
    const accepted_pending = try pending_server.accept();
    try testing.expectEqual(pending_stream, accepted_pending);

    var early_pair = Pair{};
    var early_client = try Self.init(allocator, 14, .{
        .is_client = true,
        .max_active_streams = 4,
        .output = .{ .ctx = &early_pair.client_to_server, .write = Relay.write },
    });
    defer early_client.deinit();
    var early_server = try Self.init(allocator, 14, .{
        .is_client = false,
        .max_active_streams = 4,
        .output = .{ .ctx = &early_pair.server_to_client, .write = Relay.write },
    });
    defer early_server.deinit();
    early_pair.client_to_server = .{ .peer = &early_server, .clock = &clock };
    early_pair.server_to_client = .{ .peer = &early_client, .clock = &clock };

    const early_stream = try early_client.open(clock.now_ms);
    try early_pair.pump();
    clock.now_ms += 1;
    _ = try early_client.send(early_stream, "early", clock.now_ms);
    var early_pumps: usize = 0;
    while (early_pumps < 8) : (early_pumps += 1) {
        try early_pair.pump();
        clock.now_ms += 1;
        try early_client.tick(clock.now_ms);
        try early_server.tick(clock.now_ms);
    }
    try early_pair.pump();
    try testing.expectEqual(@as(usize, 0), early_client.numStreams());
    try testing.expectEqual(@as(usize, 0), early_server.numStreams());
    try testing.expectError(errors.Error.AcceptQueueEmpty, early_server.accept());
    const retry_stream = try early_client.open(clock.now_ms);
    try early_pair.pump();
    const retry_accept = try early_server.accept();
    try testing.expectEqual(retry_stream, retry_accept);

    var stopping_pair = Pair{};
    var stopping_client = try Self.init(allocator, 12, .{
        .is_client = true,
        .output = .{ .ctx = &stopping_pair.client_to_server, .write = Relay.write },
    });
    defer stopping_client.deinit();
    var stopping_server = try Self.init(allocator, 12, .{
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

    var stopping_fail_pair = Pair{};
    var stopping_fail_client = try Self.init(allocator, 21, .{
        .is_client = true,
        .output = .{ .ctx = &stopping_fail_pair.client_to_server, .write = Relay.write },
    });
    defer stopping_fail_client.deinit();
    var stopping_fail_server = try Self.init(allocator, 21, .{
        .is_client = false,
        .output = .{ .ctx = &stopping_fail_pair.server_to_client, .write = Relay.write },
    });
    defer stopping_fail_server.deinit();
    stopping_fail_pair.client_to_server = .{ .peer = &stopping_fail_server, .clock = &clock };
    stopping_fail_pair.server_to_client = .{ .peer = &stopping_fail_client, .clock = &clock };

    _ = try stopping_fail_client.open(clock.now_ms);
    try stopping_fail_pair.pump();
    stopping_fail_server.callback_state.output = .{ .ctx = undefined, .write = FailingOutput.write };
    stopping_fail_server.stopAccepting();
    try testing.expectEqual(@as(u64, 1), stopping_fail_server.outputErrorCount());
    try testing.expectEqual(@as(usize, 0), stopping_fail_server.numStreams());

    var failing_pair = Pair{};
    var failing_client = try Self.init(allocator, 15, .{
        .is_client = true,
        .max_active_streams = 4,
        .output = .{ .ctx = &failing_pair.client_to_server, .write = Relay.write },
    });
    defer failing_client.deinit();
    var failing_server = try Self.init(allocator, 15, .{
        .is_client = false,
        .max_active_streams = 4,
        .output = .{ .ctx = &failing_pair.server_to_client, .write = Relay.write },
    });
    defer failing_server.deinit();
    failing_pair.client_to_server = .{ .peer = &failing_server, .clock = &clock };
    failing_pair.server_to_client = .{ .peer = &failing_client, .clock = &clock };

    const failing_stream = try failing_client.open(clock.now_ms);
    try failing_pair.pump();
    failing_server.callback_state.output = .{ .ctx = undefined, .write = FailingOutput.write };
    clock.now_ms += 1;
    _ = try failing_client.send(failing_stream, "boom", clock.now_ms);
    var saw_fail_abort = false;
    var fail_pumps: usize = 0;
    while (fail_pumps < 8 and !saw_fail_abort) : (fail_pumps += 1) {
        clock.now_ms += 1;
        try failing_client.tick(clock.now_ms);
        try failing_server.tick(clock.now_ms);
        failing_pair.pump() catch |err| {
            try testing.expectEqual(error.FailWrite, err);
            saw_fail_abort = true;
        };
    }
    try testing.expect(saw_fail_abort);
    try testing.expectEqual(@as(usize, 0), failing_server.numStreams());
    try testing.expectError(errors.Error.AcceptQueueEmpty, failing_server.accept());

    var limited_pair = Pair{};
    var limited_client = try Self.init(allocator, 9, .{
        .is_client = true,
        .max_active_streams = 2,
        .output = .{ .ctx = &limited_pair.client_to_server, .write = Relay.write },
    });
    defer limited_client.deinit();
    var limited_server = try Self.init(allocator, 9, .{
        .is_client = false,
        .max_active_streams = 1,
        .output = .{ .ctx = &limited_pair.server_to_client, .write = Relay.write },
    });
    defer limited_server.deinit();
    limited_pair.client_to_server = .{ .peer = &limited_server, .clock = &clock };
    limited_pair.server_to_client = .{ .peer = &limited_client, .clock = &clock };

    const stream_a = try limited_client.open(clock.now_ms);
    try limited_pair.pump();
    const stream_b = try limited_client.open(clock.now_ms);
    try limited_pair.pump();
    try testing.expectEqual(@as(usize, 1), limited_server.numStreams());
    try testing.expectEqual(@as(usize, 1), limited_client.numStreams());
    try testing.expect(stream_a == 1);
    try testing.expect(stream_b == 3);
    _ = try limited_server.accept();
    try testing.expectEqual(@as(usize, 1), limited_server.numStreams());
    try testing.expectEqual(@as(usize, 1), limited_client.numStreams());

    var local_limit_output = NullOutput{};
    var local_limit_mux = try Self.init(allocator, 11, .{
        .is_client = true,
        .max_active_streams = 1,
        .output = .{ .ctx = &local_limit_output, .write = NullOutput.write },
    });
    defer local_limit_mux.deinit();
    _ = try local_limit_mux.open(clock.now_ms);
    try testing.expectError(errors.Error.StreamLimitReached, local_limit_mux.open(clock.now_ms));

    var timeout_pair = Pair{};
    var timeout_client = try Self.init(allocator, 10, .{
        .is_client = true,
        .idle_stream_timeout_ms = 3,
        .output = .{ .ctx = &timeout_pair.client_to_server, .write = Relay.write },
    });
    defer timeout_client.deinit();
    var timeout_server = try Self.init(allocator, 10, .{
        .is_client = false,
        .idle_stream_timeout_ms = 3,
        .output = .{ .ctx = &timeout_pair.server_to_client, .write = Relay.write },
    });
    defer timeout_server.deinit();
    timeout_pair.client_to_server = .{ .peer = &timeout_server, .clock = &clock };
    timeout_pair.server_to_client = .{ .peer = &timeout_client, .clock = &clock };

    const timeout_stream = try timeout_client.open(clock.now_ms);
    try timeout_pair.pump();
    _ = try timeout_server.accept();
    try testing.expect(timeout_stream == 1);
    clock.now_ms += 5;
    try timeout_client.tick(clock.now_ms);
    try timeout_server.tick(clock.now_ms);
    try timeout_pair.pump();
    try timeout_pair.pump();
    try testing.expectEqual(@as(usize, 0), timeout_client.numStreams());
    try testing.expectEqual(@as(usize, 0), timeout_server.numStreams());

    var close_timeout_output = NullOutput{};
    var close_timeout_mux = try Self.init(allocator, 13, .{
        .is_client = true,
        .close_ack_timeout_ms = 2,
        .output = .{ .ctx = &close_timeout_output, .write = NullOutput.write },
    });
    defer close_timeout_mux.deinit();
    const close_timeout_stream = try close_timeout_mux.open(clock.now_ms);
    try close_timeout_mux.closeStream(close_timeout_stream, clock.now_ms);
    clock.now_ms += 3;
    try close_timeout_mux.tick(clock.now_ms);
    try testing.expectEqual(@as(usize, 0), close_timeout_mux.numStreams());

    var close_fail_output = NullOutput{};
    var close_fail_mux = try Self.init(allocator, 16, .{
        .is_client = true,
        .output = .{ .ctx = &close_fail_output, .write = NullOutput.write },
    });
    defer close_fail_mux.deinit();
    const close_fail_stream = try close_fail_mux.open(clock.now_ms);
    close_fail_mux.callback_state.output = .{ .ctx = undefined, .write = FailingOutput.write };
    try testing.expectError(error.FailWrite, close_fail_mux.closeStream(close_fail_stream, clock.now_ms));
    _ = try close_fail_mux.send(close_fail_stream, "still-open", clock.now_ms);

    var closed_output = NullOutput{};
    var closed_mux = try Self.init(allocator, 20, .{
        .is_client = true,
        .output = .{ .ctx = &closed_output, .write = NullOutput.write },
    });
    defer closed_mux.deinit();
    const closed_stream = try closed_mux.open(clock.now_ms);
    closed_mux.close();
    var closed_raw: [8]u8 = undefined;
    const closed_n = try frame.encode(&closed_raw, 2, frame.open, &.{});
    try testing.expectEqual(@as(usize, 0), closed_mux.numStreams());
    try testing.expectError(errors.Error.ServiceMuxClosed, closed_mux.open(clock.now_ms));
    try testing.expectError(errors.Error.ServiceMuxClosed, closed_mux.accept());
    try testing.expectError(errors.Error.ServiceMuxClosed, closed_mux.input(closed_raw[0..closed_n], clock.now_ms));
    try testing.expectError(errors.Error.ServiceMuxClosed, closed_mux.send(closed_stream, "closed", clock.now_ms));
    try testing.expectError(errors.Error.ServiceMuxClosed, closed_mux.recv(closed_stream, &buf));
    try testing.expectError(errors.Error.ServiceMuxClosed, closed_mux.closeStream(closed_stream, clock.now_ms));

    try testing.expectError(errors.Error.StreamNotFound, timeout_client.closeStream(999, clock.now_ms));

    var raw: [16]u8 = undefined;
    const raw_n = try frame.encode(&raw, 0xffff_ffff + 1, frame.open, &.{});
    try testing.expectError(errors.Error.InvalidServiceFrame, server.input(raw[0..raw_n], clock.now_ms));
}

fn allocateLocalStreamId(self: *Self) !u64 {
    const start = @as(u32, @intCast(self.next_local_stream_id));
    var current = start;

    while (true) {
        if (self.streams.getPtr(current) == null) {
            self.next_local_stream_id = @as(u64, current +% 2);
            return current;
        }

        current +%= 2;
        if (current == start) break;
    }

    return errors.Error.StreamIdExhausted;
}

fn createStream(self: *Self, stream_id: u64, queued: bool, now_ms: u64) !Stream {
    const output_state = try self.allocator.create(StreamOutputState);
    errdefer self.allocator.destroy(output_state);
    const scratch = try self.allocator.alloc(u8, frame.max_varint_len + 1 + self.config.mtu);
    errdefer self.allocator.free(scratch);
    output_state.* = .{
        .allocator = self.allocator,
        .callback_state = self.callback_state,
        .stream_id = stream_id,
        .scratch = scratch,
    };

    var conn = try Conn.init(self.allocator, @intCast(stream_id), .{
        .output = .{
            .ctx = output_state,
            .write = streamOutput,
        },
        .mtu = self.config.mtu,
        .snd_wnd = self.config.snd_wnd,
        .rcv_wnd = self.config.rcv_wnd,
        .nodelay = self.config.nodelay,
        .interval = self.config.interval,
        .resend = self.config.resend,
        .nc = self.config.nc,
    });
    errdefer conn.deinit();

    return .{
        .output_state = output_state,
        .conn = conn,
        .queued = queued,
        .last_active_ms = now_ms,
    };
}

fn removeStream(self: *Self, stream_id: u64) bool {
    var stream = self.streams.remove(stream_id) orelse return false;
    if (stream.queued) {
        _ = self.accept_queue.remove(stream_id);
    } else if (self.active_streams > 0) {
        self.active_streams -= 1;
    }
    stream.deinit(self.allocator);
    return true;
}

fn sendControlFrame(self: *Self, stream_id: u64, frame_type: u8, payload: []const u8) !void {
    var buffer: [frame.max_varint_len + 2]u8 = undefined;
    const written = try frame.encode(&buffer, stream_id, frame_type, payload);
    try self.callback_state.output.write(self.callback_state.output.ctx, buffer[0..written]);
}

fn notifyAndRemove(self: *Self, stream_id: u64, frame_type: u8, payload: []const u8) !void {
    self.sendControlFrame(stream_id, frame_type, payload) catch |err| {
        _ = self.removeStream(stream_id);
        return err;
    };
    _ = self.removeStream(stream_id);
}

fn reportOutputError(self: *Self, _: anyerror) void {
    self.callback_state.output_errors += 1;
}

fn isRemoteStreamId(self: *const Self, stream_id: u64) bool {
    if (stream_id > 0xffff_ffff) return false;
    return if (self.config.is_client) stream_id % 2 == 0 else stream_id % 2 == 1;
}

fn streamOutput(ctx: *anyopaque, packet: []const u8) !void {
    const output_state = @as(*StreamOutputState, @ptrCast(@alignCast(ctx)));
    const written = try frame.encode(output_state.scratch, output_state.stream_id, frame.data, packet);
    output_state.callback_state.output.write(output_state.callback_state.output.ctx, output_state.scratch[0..written]) catch |err| {
        output_state.callback_state.output_errors += 1;
        return err;
    };
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
    peer: ?*Self = null,
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

const FailingOutput = struct {
    fn write(_: *anyopaque, _: []const u8) !void {
        return error.FailWrite;
    }
};
