const dep = @import("dep");
const zig_kcp = @import("dep").kcp;

const config = @import("config.zig");
const errors = @import("errors.zig");

const mem = dep.embed.mem;

// Single-threaded: callers must serialize all Conn access and drive update().
allocator: mem.Allocator,
conn_config: Config,
inner: *zig_kcp.Kcp,
callback_state: *CallbackState,
clock_origin_ms: ?u64 = null,
lifecycle_origin_ms: ?u64 = null,
last_recv_ms: ?u64 = null,
read_deadline_ms: ?u64 = null,
write_deadline_ms: ?u64 = null,
closed: bool = false,
close_err: ?anyerror = null,

const Self = @This();
const Config = config.Conn;

const CallbackState = struct {
    output: config.Output,
};

pub fn init(allocator: mem.Allocator, conv: u32, conn_config: Config) !Self {
    const normalized_config = config.normalizeConn(conn_config);
    const callback_state = try allocator.create(CallbackState);
    errdefer allocator.destroy(callback_state);
    callback_state.* = .{
        .output = normalized_config.output,
    };

    const inner = try zig_kcp.create(allocator, conv, callback_state);
    errdefer zig_kcp.release(inner);

    zig_kcp.setOutput(inner, outputCallback);
    try zig_kcp.setMtu(inner, normalized_config.mtu);
    zig_kcp.wndsize(inner, normalized_config.snd_wnd, normalized_config.rcv_wnd);
    zig_kcp.setNodelay(inner, normalized_config.nodelay, normalized_config.interval, normalized_config.resend, normalized_config.nc);

    return .{
        .allocator = allocator,
        .conn_config = normalized_config,
        .inner = inner,
        .callback_state = callback_state,
        .clock_origin_ms = null,
        .lifecycle_origin_ms = null,
        .last_recv_ms = null,
        .read_deadline_ms = null,
        .write_deadline_ms = null,
        .closed = false,
        .close_err = null,
    };
}

pub fn deinit(self: *Self) void {
    zig_kcp.release(self.inner);
    self.allocator.destroy(self.callback_state);
}

/// Test runner hook: simulates engine death without exposing `inner`.
pub fn testMarkEngineDead(self: *Self) void {
    self.inner.state = zig_kcp.STATE_DEAD;
}

pub fn send(self: *Self, payload: []const u8, now_ms: u64) !usize {
    try self.ensureWritable(now_ms);
    self.touchLifecycleOrigin(now_ms);
    self.touchClockOrigin(now_ms);
    return zig_kcp.send(self.inner, payload) catch |err| return mapEngineError(err);
}

pub fn input(self: *Self, packet: []const u8, now_ms: u64) !void {
    try self.ensureOpen();
    self.touchLifecycleOrigin(now_ms);
    self.touchClockOrigin(now_ms);
    self.last_recv_ms = now_ms;
    _ = zig_kcp.input(self.inner, packet) catch |err| return mapEngineError(err);
}

pub fn recv(self: *Self, out: []u8) !usize {
    try self.ensureReadableNoDeadline();
    return zig_kcp.recv(self.inner, out) catch |err| return mapEngineError(err);
}

pub fn update(self: *Self, now_ms: u64) !void {
    if (self.closed) return;
    try self.enforceLifecycle(now_ms);
    try zig_kcp.update(self.inner, self.engineNowMs(now_ms));
    try self.enforceIdleTimeouts(now_ms);
}

pub fn check(self: *Self, now_ms: u64) u32 {
    if (self.closed) return 0;
    self.touchLifecycleOrigin(now_ms);
    return zig_kcp.check(self.inner, self.engineNowMs(now_ms));
}

pub fn establishIdleBaseline(self: *Self, now_ms: u64) void {
    self.touchLifecycleOrigin(now_ms);
    self.touchClockOrigin(now_ms);
}

pub fn peekSize(self: *Self) !i32 {
    try self.ensureReadableNoDeadline();
    return zig_kcp.peeksize(self.inner) catch |err| return mapEngineError(err);
}

pub fn waitSnd(self: *Self) u32 {
    return zig_kcp.waitsnd(self.inner);
}

pub fn getConv(self: *Self) u32 {
    return self.inner.conv;
}

pub fn getConvFromPacket(packet: []const u8) !u32 {
    if (packet.len < 4) return errors.Error.InvalidPacket;
    return @as(u32, packet[0]) |
        (@as(u32, packet[1]) << 8) |
        (@as(u32, packet[2]) << 16) |
        (@as(u32, packet[3]) << 24);
}

pub fn isDead(self: *Self) bool {
    return self.inner.state == zig_kcp.STATE_DEAD;
}

pub fn isClosed(self: *const Self) bool {
    return self.closed;
}

pub fn close(self: *Self) void {
    self.closeWithError(errors.Error.ConnClosedLocal);
}

pub fn closeWithError(self: *Self, close_err: anyerror) void {
    if (self.closed) return;
    self.closed = true;
    self.close_err = close_err;
}

pub fn setReadDeadline(self: *Self, deadline_ms: ?u64) void {
    self.read_deadline_ms = deadline_ms;
}

pub fn setWriteDeadline(self: *Self, deadline_ms: ?u64) void {
    self.write_deadline_ms = deadline_ms;
}

pub fn setDeadline(self: *Self, deadline_ms: ?u64) void {
    self.read_deadline_ms = deadline_ms;
    self.write_deadline_ms = deadline_ms;
}

pub fn read(self: *Self, out: []u8, now_ms: u64) !usize {
    try self.ensureReadable(now_ms);
    return self.recv(out) catch |err| switch (err) {
        errors.Error.NoData => if (deadlineExpired(self.read_deadline_ms, now_ms))
            errors.Error.ConnTimeout
        else
            err,
        else => err,
    };
}

pub fn write(self: *Self, payload: []const u8, now_ms: u64) !usize {
    const written = try self.send(payload, now_ms);
    try self.update(now_ms);
    return written;
}

pub fn tick(self: *Self, now_ms: u64) !void {
    try self.update(now_ms);
}

fn outputCallback(buf: []const u8, _: *zig_kcp.Kcp, user: ?*anyopaque) anyerror!i32 {
    const callback_state = @as(*CallbackState, @ptrCast(@alignCast(user orelse return 0)));
    callback_state.output.write(callback_state.output.ctx, buf) catch return errors.Error.OutputFailed;
    return @intCast(buf.len);
}

fn mapEngineError(err: anyerror) anyerror {
    return switch (err) {
        zig_kcp.KcpError.NoData => errors.Error.NoData,
        zig_kcp.KcpError.BufferTooSmall => errors.Error.BufferTooSmall,
        zig_kcp.KcpError.FragmentIncomplete => errors.Error.FragmentIncomplete,
        zig_kcp.KcpError.EmptyData => errors.Error.EmptyData,
        zig_kcp.KcpError.FragmentTooLarge => errors.Error.FragmentTooLarge,
        error.OutOfMemory => error.OutOfMemory,
        else => errors.Error.EngineFailure,
    };
}

fn ensureOpen(self: *Self) !void {
    if (!self.closed) return;
    return self.closeError();
}

fn ensureReadableNoDeadline(self: *Self) !void {
    try self.ensureOpen();
}

fn ensureReadable(self: *Self, now_ms: u64) !void {
    try self.ensureOpen();
    if (deadlineExpired(self.read_deadline_ms, now_ms)) return errors.Error.ConnTimeout;
}

fn ensureWritable(self: *Self, now_ms: u64) !void {
    try self.ensureOpen();
    if (deadlineExpired(self.write_deadline_ms, now_ms)) return errors.Error.ConnTimeout;
}

fn touchLifecycleOrigin(self: *Self, now_ms: u64) void {
    if (self.lifecycle_origin_ms == null) self.lifecycle_origin_ms = now_ms;
}

fn touchClockOrigin(self: *Self, now_ms: u64) void {
    if (self.clock_origin_ms == null) self.clock_origin_ms = now_ms;
}

fn enforceLifecycle(self: *Self, now_ms: u64) !void {
    if (self.isDead()) {
        self.closeWithError(errors.Error.ConnTimeout);
        return errors.Error.ConnTimeout;
    }

    try self.enforceIdleTimeouts(now_ms);
}

fn enforceIdleTimeouts(self: *Self, now_ms: u64) !void {
    const last_recv_ms = self.last_recv_ms orelse self.lifecycle_origin_ms orelse self.clock_origin_ms orelse 0;
    if (self.conn_config.idle_timeout_ms > 0 and now_ms -| last_recv_ms >= self.conn_config.idle_timeout_ms) {
        self.closeWithError(errors.Error.ConnTimeout);
        return errors.Error.ConnTimeout;
    }
    if (self.conn_config.idle_timeout_pure_ms > 0 and now_ms -| last_recv_ms >= self.conn_config.idle_timeout_pure_ms) {
        self.closeWithError(errors.Error.ConnTimeout);
        return errors.Error.ConnTimeout;
    }
}

fn closeError(self: *Self) anyerror {
    return self.close_err orelse errors.Error.ConnClosed;
}

fn deadlineExpired(deadline_ms: ?u64, now_ms: u64) bool {
    return if (deadline_ms) |deadline| now_ms >= deadline else false;
}

fn engineNowMs(self: *Self, now_ms: u64) u32 {
    if (self.clock_origin_ms == null) self.clock_origin_ms = now_ms;
    const origin = self.clock_origin_ms.?;
    return @truncate(now_ms -| origin);
}
