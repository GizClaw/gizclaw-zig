const embed = @import("embed");
const zig_kcp = @import("zig_kcp");

const config = @import("config.zig");
const errors = @import("errors.zig");

const mem = embed.mem;

// Single-threaded: callers must serialize all Conn access and drive update().
allocator: mem.Allocator,
inner: *zig_kcp.Kcp,
callback_state: *CallbackState,
clock_origin_ms: ?u64 = null,

const Self = @This();
const Config = config.Conn;

const CallbackState = struct {
    output: config.Output,
};

pub fn init(allocator: mem.Allocator, conv: u32, conn_config: Config) !Self {
    const callback_state = try allocator.create(CallbackState);
    errdefer allocator.destroy(callback_state);
    callback_state.* = .{
        .output = conn_config.output,
    };

    const inner = try zig_kcp.create(allocator, conv, callback_state);
    errdefer zig_kcp.release(inner);

    zig_kcp.setOutput(inner, outputCallback);
    try zig_kcp.setMtu(inner, conn_config.mtu);
    zig_kcp.wndsize(inner, conn_config.snd_wnd, conn_config.rcv_wnd);
    zig_kcp.setNodelay(inner, conn_config.nodelay, conn_config.interval, conn_config.resend, conn_config.nc);

    return .{
        .allocator = allocator,
        .inner = inner,
        .callback_state = callback_state,
        .clock_origin_ms = null,
    };
}

pub fn deinit(self: *Self) void {
    zig_kcp.release(self.inner);
    self.allocator.destroy(self.callback_state);
}

pub fn send(self: *Self, payload: []const u8, now_ms: u64) !usize {
    // The caller-provided clock is consumed by update(), not by queueing send().
    _ = now_ms;
    return zig_kcp.send(self.inner, payload) catch |err| return mapEngineError(err);
}

pub fn input(self: *Self, packet: []const u8, now_ms: u64) !void {
    // Incoming packets are queued immediately; the caller advances protocol time via update().
    _ = now_ms;
    _ = zig_kcp.input(self.inner, packet) catch |err| return mapEngineError(err);
}

pub fn recv(self: *Self, out: []u8) !usize {
    return zig_kcp.recv(self.inner, out) catch |err| return mapEngineError(err);
}

pub fn update(self: *Self, now_ms: u64) !void {
    try zig_kcp.update(self.inner, self.engineNowMs(now_ms));
}

pub fn check(self: *Self, now_ms: u64) u32 {
    return zig_kcp.check(self.inner, self.engineNowMs(now_ms));
}

pub fn peekSize(self: *Self) !i32 {
    return zig_kcp.peeksize(self.inner) catch |err| return mapEngineError(err);
}

pub fn waitSnd(self: *Self) u32 {
    return zig_kcp.waitsnd(self.inner);
}

pub fn getConv(self: *Self) u32 {
    return self.inner.conv;
}

pub fn isDead(self: *Self) bool {
    return self.inner.state == zig_kcp.STATE_DEAD;
}

pub fn testAll(testing: anytype, allocator: mem.Allocator) !void {
    var clock = Clock{ .now_ms = 1 };
    var relay = RelayPair{};

    var a = try Self.init(allocator, 1, .{
        .output = .{
            .ctx = &relay.a_to_b,
            .write = Relay.write,
        },
    });
    defer a.deinit();

    var b = try Self.init(allocator, 1, .{
        .output = .{
            .ctx = &relay.b_to_a,
            .write = Relay.write,
        },
    });
    defer b.deinit();

    relay.a_to_b = .{
        .peer = &b,
    };
    relay.b_to_a = .{
        .peer = &a,
    };

    try testing.expectEqual(@as(u32, 1), a.getConv());
    try testing.expectEqual(@as(u32, 0), a.waitSnd());
    try testing.expect(!a.isDead());

    clock.now_ms += 1;
    _ = try a.send("hello", clock.now_ms);
    var pump_count: usize = 0;
    while (pump_count < 8) : (pump_count += 1) {
        try relay.pump(clock.now_ms);
        clock.now_ms += 1;
        try a.update(clock.now_ms);
        try b.update(clock.now_ms);
    }
    try relay.pump(clock.now_ms);

    var buf: [32]u8 = undefined;
    const peek_n = try b.peekSize();
    try testing.expectEqual(@as(i32, 5), peek_n);
    const read_n = try b.recv(&buf);
    try testing.expectEqualStrings("hello", buf[0..read_n]);
    try testing.expectError(errors.Error.NoData, b.recv(&buf));

    clock.now_ms += 1;
    _ = try b.send("world", clock.now_ms);
    pump_count = 0;
    while (pump_count < 8) : (pump_count += 1) {
        try relay.pump(clock.now_ms);
        clock.now_ms += 1;
        try a.update(clock.now_ms);
        try b.update(clock.now_ms);
    }
    try relay.pump(clock.now_ms);
    const reply_n = try a.recv(&buf);
    try testing.expectEqualStrings("world", buf[0..reply_n]);

    var wrap_clock = Clock{ .now_ms = 0xffff_ffff - 2 };
    var wrap_relay = RelayPair{};

    var wrap_a = try Self.init(allocator, 2, .{
        .output = .{
            .ctx = &wrap_relay.a_to_b,
            .write = Relay.write,
        },
    });
    defer wrap_a.deinit();

    var wrap_b = try Self.init(allocator, 2, .{
        .output = .{
            .ctx = &wrap_relay.b_to_a,
            .write = Relay.write,
        },
    });
    defer wrap_b.deinit();

    wrap_relay.a_to_b = .{ .peer = &wrap_b };
    wrap_relay.b_to_a = .{ .peer = &wrap_a };

    _ = wrap_a.check(wrap_clock.now_ms);
    _ = try wrap_a.send("wrap", wrap_clock.now_ms);
    pump_count = 0;
    while (pump_count < 8) : (pump_count += 1) {
        try wrap_relay.pump(wrap_clock.now_ms);
        wrap_clock.now_ms += 1;
        try wrap_a.update(wrap_clock.now_ms);
        try wrap_b.update(wrap_clock.now_ms);
    }
    try wrap_relay.pump(wrap_clock.now_ms);
    const wrap_read_n = try wrap_b.recv(&buf);
    try testing.expectEqualStrings("wrap", buf[0..wrap_read_n]);
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

fn engineNowMs(self: *Self, now_ms: u64) u32 {
    if (self.clock_origin_ms == null) self.clock_origin_ms = now_ms;
    const origin = self.clock_origin_ms.?;
    return @truncate(now_ms -| origin);
}

const Clock = struct {
    now_ms: u64,
};

const RelayPair = struct {
    a_to_b: Relay = .{},
    b_to_a: Relay = .{},

    fn pump(self: *RelayPair, now_ms: u64) !void {
        try self.a_to_b.drain(now_ms);
        try self.b_to_a.drain(now_ms);
    }
};

const Relay = struct {
    peer: ?*Self = null,
    packets: [8][1500]u8 = [_][1500]u8{[_]u8{0} ** 1500} ** 8,
    lens: [8]usize = [_]usize{0} ** 8,
    len: usize = 0,

    fn write(ctx: *anyopaque, data: []const u8) !void {
        const self = @as(*Relay, @ptrCast(@alignCast(ctx)));
        if (self.len >= self.packets.len) return error.QueueFull;
        if (data.len > self.packets[self.len].len) return error.BufferTooSmall;
        @memcpy(self.packets[self.len][0..data.len], data);
        self.lens[self.len] = data.len;
        self.len += 1;
    }

    fn drain(self: *Relay, now_ms: u64) !void {
        const peer = self.peer orelse unreachable;
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            try peer.input(self.packets[index][0..self.lens[index]], now_ms);
        }
        self.len = 0;
    }
};
