const dep = @import("dep");

const cfg = @import("config.zig");
const ConnFile = @import("Conn.zig");
const errors = @import("errors.zig");
const frame = @import("frame.zig");
const StreamFile = @import("Stream.zig");
const UIntMap = @import("UIntMap.zig");

const mem = dep.embed.mem;

// Single-threaded: callers must serialize all Mux access and drive tick().
allocator: mem.Allocator,
service_id: u64,
config: cfg.Mux,
callback_state: *CallbackState,
streams: UIntMap.make(u64, StreamState),
accept_queue: AcceptQueue,
next_local_stream_id: u64,
active_streams: usize = 0,
accepting_remote: bool = true,
closed: bool = false,

const Self = @This();
const Config = cfg.Mux;
const Conn = ConnFile;

pub const Stream = StreamFile.make(Self);

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

const StreamState = struct {
    output_state: *StreamOutputState,
    conn: Conn,
    queued: bool,
    local_close: bool = false,
    close_deadline_ms: u64 = 0,
    last_active_ms: u64,

    fn deinit(self: *StreamState, allocator: mem.Allocator) void {
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
    const normalized_config = cfg.normalizeMux(mux_config);
    const callback_state = try allocator.create(CallbackState);
    errdefer allocator.destroy(callback_state);
    callback_state.* = .{
        .service_id = service_id,
        .output = normalized_config.output,
    };

    return .{
        .allocator = allocator,
        .service_id = service_id,
        .config = normalized_config,
        .callback_state = callback_state,
        .streams = try UIntMap.make(u64, StreamState).init(allocator, 8),
        .accept_queue = try AcceptQueue.init(allocator, normalized_config.accept_backlog),
        .next_local_stream_id = if (normalized_config.is_client) 1 else 0,
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
    if (self.active_streams >= self.config.max_active_streams) return errors.Error.StreamLimitReached;

    const stream_id = try self.allocateLocalStreamId();
    var stream = try self.createStream(stream_id, false, now_ms);
    var stream_owned = true;
    errdefer if (stream_owned) stream.deinit(self.allocator);

    _ = try self.streams.put(stream_id, stream);
    stream_owned = false;
    self.active_streams += 1;

    self.sendControlFrame(stream_id, frame.open, &.{}) catch |err| {
        _ = self.removeStream(stream_id);
        return err;
    };
    return stream_id;
}

pub fn openConn(self: *Self, now_ms: u64) !Stream {
    return .{
        .mux = self,
        .stream_id = try self.open(now_ms),
    };
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

pub fn acceptConn(self: *Self) !Stream {
    return .{
        .mux = self,
        .stream_id = try self.accept(),
    };
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
        if (decoded.payload.len != 0 or invalid_remote_id) {
            try self.notifyAndRemove(decoded.stream_id, frame.close, &[_]u8{frame.close_reason_invalid});
            return;
        }

        if (stream) |entry| {
            entry.last_active_ms = now_ms;
            return;
        }

        if (self.closed or !self.accepting_remote or self.active_streams >= self.config.max_active_streams or self.accept_queue.len >= self.accept_queue.slots.len) {
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
    if (stream.queued) return errors.Error.StreamNotFound;
    if (stream.local_close) return errors.Error.ConnClosedLocal;
    stream.last_active_ms = now_ms;
    return stream.conn.send(payload, now_ms);
}

pub fn recv(self: *Self, stream_id: u64, out: []u8) !usize {
    if (self.closed) return errors.Error.ServiceMuxClosed;
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.queued) return errors.Error.StreamNotFound;
    return stream.conn.recv(out);
}

pub fn writeStream(self: *Self, stream_id: u64, payload: []const u8, now_ms: u64) !usize {
    if (self.closed) return errors.Error.ServiceMuxClosed;
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.queued) return errors.Error.StreamNotFound;
    stream.last_active_ms = now_ms;
    return stream.conn.write(payload, now_ms);
}

pub fn readStream(self: *Self, stream_id: u64, out: []u8, now_ms: u64) !usize {
    if (self.closed) return errors.Error.ServiceMuxClosed;
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.queued) return errors.Error.StreamNotFound;
    return stream.conn.read(out, now_ms);
}

pub fn setStreamReadDeadline(self: *Self, stream_id: u64, deadline_ms: ?u64) !void {
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.queued) return errors.Error.StreamNotFound;
    stream.conn.setReadDeadline(deadline_ms);
}

pub fn setStreamWriteDeadline(self: *Self, stream_id: u64, deadline_ms: ?u64) !void {
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.queued) return errors.Error.StreamNotFound;
    stream.conn.setWriteDeadline(deadline_ms);
}

pub fn setStreamDeadline(self: *Self, stream_id: u64, deadline_ms: ?u64) !void {
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.queued) return errors.Error.StreamNotFound;
    stream.conn.setDeadline(deadline_ms);
}

pub fn closeStream(self: *Self, stream_id: u64, now_ms: u64) !void {
    if (self.closed) return errors.Error.ServiceMuxClosed;
    const stream = self.streams.getPtr(stream_id) orelse return errors.Error.StreamNotFound;
    if (stream.local_close) return;
    try self.sendControlFrame(stream_id, frame.close, &[_]u8{frame.close_reason_close});
    stream.local_close = true;
    stream.close_deadline_ms = now_ms + self.config.close_ack_timeout_ms;
    stream.conn.closeWithError(errors.Error.ConnClosedLocal);
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
    var count: usize = 0;
    for (self.streams.slots) |slot| {
        if (slot.state != .full) continue;
        if (slot.value.local_close) continue;
        count += 1;
    }
    return count;
}

pub fn outputErrorCount(self: *const Self) u64 {
    return self.callback_state.output_errors;
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

fn createStream(self: *Self, stream_id: u64, queued: bool, now_ms: u64) !StreamState {
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
    conn.establishIdleBaseline(now_ms);

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
