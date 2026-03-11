const std = @import("std");
const runtime = @import("embed").runtime;
const kcp = @import("kcp");
const ring_buffer = @import("ring_buffer.zig");

const RingBuffer = ring_buffer.RingBuffer;

/// Runtime-polymorphic packet output interface (like std.mem.Allocator).
/// KCP calls this when it needs to send a packet over the wire.
pub const PacketWriter = struct {
    ptr: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, data: []const u8) anyerror!void,

    pub fn write(self: PacketWriter, data: []const u8) anyerror!void {
        try self.writeFn(self.ptr, data);
    }
};

pub const ConnError = error{
    ConnClosed,
    ConnClosedLocal,
    ConnClosedByPeer,
    ConnTimeout,
    KcpSendFailed,
    OutOfMemory,
    InputQueueFull,
};

/// KCPConn wraps a KCP instance as a reliable byte stream.
///
/// All KCP operations (send, recv, input, update, flush) execute exclusively
/// in the runLoop thread. This eliminates concurrency issues with the KCP C
/// library. write() and input() communicate with runLoop via the runtime's
/// sync primitives.
///
/// Generic over:
/// - `Kcp`       — KCP protocol implementation
/// - `MutexImpl` — runtime Mutex (contract: init/deinit/lock/unlock)
/// - `CondImpl`  — runtime Condition (contract: init/deinit/wait/signal/broadcast/timedWait)
/// - `ThreadImpl`— runtime Thread (contract: spawn/join/detach)
/// - `TimeImpl`  — runtime Time (contract: nowMs/sleepMs), instance passed at init
pub fn KCPConn(
    comptime Kcp: type,
    comptime MutexImpl: type,
    comptime CondImpl: type,
    comptime ThreadImpl: type,
    comptime TimeImpl: type,
) type {
    comptime {
        _ = runtime.sync.Mutex(MutexImpl);
        _ = runtime.sync.Condition(CondImpl);
        _ = runtime.thread.from(ThreadImpl);
        _ = runtime.time.from(TimeImpl);
    }
    return struct {
        const Self = @This();
        const uses_native_kcp = Kcp == *kcp.Kcp;

        kcp: Kcp,
        output: PacketWriter,

        recv_buf: RingBuffer(u8),
        recv_mutex: MutexImpl,
        recv_cond: CondImpl,

        input_queue: InputQueue,
        input_mutex: MutexImpl,
        input_cond: CondImpl,

        write_queue: WriteQueue,
        write_mutex: MutexImpl,
        write_cond: CondImpl,

        closed: std.atomic.Value(bool),
        close_reason: std.atomic.Value(CloseReason),
        output_failures: std.atomic.Value(u64),

        time: TimeImpl,
        run_thread: ?ThreadImpl,
        allocator: std.mem.Allocator,

        const CloseReason = enum(u8) {
            none = 0,
            local = 1,
            peer = 2,
            timeout = 3,
            oom = 4,
        };

        const InputQueue = struct {
            items: [256]InputItem = undefined,
            head: usize = 0,
            tail: usize = 0,
            len: usize = 0,

            const InputItem = struct {
                data: []u8,
            };

            fn push(self: *InputQueue, item: InputItem) bool {
                if (self.len >= self.items.len) return false;
                self.items[self.tail] = item;
                self.tail = (self.tail + 1) % self.items.len;
                self.len += 1;
                return true;
            }

            fn pop(self: *InputQueue) ?InputItem {
                if (self.len == 0) return null;
                const item = self.items[self.head];
                self.head = (self.head + 1) % self.items.len;
                self.len -= 1;
                return item;
            }
        };

        const WriteQueue = struct {
            items: [64]*WriteItem = undefined,
            head: usize = 0,
            tail: usize = 0,
            len: usize = 0,

            const WriteStatus = enum {
                pending,
                success,
                failed,
                closed,
            };

            const WriteItem = struct {
                data: []u8,
                done: bool,
                status: WriteStatus,
                result_n: usize,
            };

            fn push(self: *WriteQueue, item: *WriteItem) bool {
                if (self.len >= self.items.len) return false;
                self.items[self.tail] = item;
                self.tail = (self.tail + 1) % self.items.len;
                self.len += 1;
                return true;
            }

            fn pop(self: *WriteQueue) ?*WriteItem {
                if (self.len == 0) return null;
                const ptr = self.items[self.head];
                self.head = (self.head + 1) % self.items.len;
                self.len -= 1;
                return ptr;
            }
        };

        const idle_timeout_ms: u64 = 15_000;
        const idle_timeout_pure_ms: u64 = 30_000;
        const max_update_delay_ms: u64 = 50;

        pub fn init(
            allocator: std.mem.Allocator,
            time: TimeImpl,
            conv: u32,
            output: PacketWriter,
        ) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            self.* = Self{
                .kcp = undefined,
                .output = output,
                .recv_buf = RingBuffer(u8).init(allocator),
                .recv_mutex = MutexImpl.init(),
                .recv_cond = CondImpl.init(),
                .input_queue = .{},
                .input_mutex = MutexImpl.init(),
                .input_cond = CondImpl.init(),
                .write_queue = .{},
                .write_mutex = MutexImpl.init(),
                .write_cond = CondImpl.init(),
                .closed = std.atomic.Value(bool).init(false),
                .close_reason = std.atomic.Value(CloseReason).init(.none),
                .output_failures = std.atomic.Value(u64).init(0),
                .time = time,
                .run_thread = null,
                .allocator = allocator,
            };

            if (comptime uses_native_kcp) {
                self.kcp = try kcp.create(allocator, conv, self);
                kcp.setOutput(self.kcp, kcpOutputCallbackNative);
                kcp.setNodelay(self.kcp, 2, 1, 2, 1);
                kcp.wndsize(self.kcp, 4096, 4096);
                kcp.setMtu(self.kcp, 1400) catch {};
            } else {
                self.kcp = try Kcp.init(conv, &kcpOutputTrampoline, self);
                if (@hasDecl(Kcp, "setUserPtr")) self.kcp.setUserPtr();
                if (@hasDecl(Kcp, "setDefaultConfig")) self.kcp.setDefaultConfig();
            }

            self.run_thread = try ThreadImpl.spawn(
                .{ .stack_size = 65536, .name = "kcp-conn" },
                &runLoopTrampoline,
                @ptrCast(self),
            );

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.closeSignal(.local);

            if (self.run_thread) |*t| {
                t.join();
                self.run_thread = null;
            }

            if (comptime uses_native_kcp) {
                kcp.release(self.kcp);
            } else {
                self.kcp.deinit();
            }
            self.recv_buf.deinit();

            self.drainInputQueue();

            self.recv_cond.deinit();
            self.recv_mutex.deinit();
            self.input_cond.deinit();
            self.input_mutex.deinit();
            self.write_cond.deinit();
            self.write_mutex.deinit();

            self.allocator.destroy(self);
        }

        /// Feed an incoming KCP packet from the network layer.
        pub fn input(self: *Self, data: []const u8) ConnError!void {
            if (self.closed.load(.acquire)) return self.closedError();

            const cp = self.allocator.dupe(u8, data) catch return ConnError.OutOfMemory;

            self.input_mutex.lock();
            defer self.input_mutex.unlock();

            if (self.closed.load(.acquire)) {
                self.allocator.free(cp);
                return self.closedError();
            }

            if (!self.input_queue.push(.{ .data = cp })) {
                self.allocator.free(cp);
                return ConnError.InputQueueFull;
            }
            self.input_cond.signal();
        }

        /// Read reassembled data from KCP. Blocks until data is available or closed.
        pub fn read(self: *Self, buf: []u8) ConnError!usize {
            if (buf.len == 0) return 0;

            self.recv_mutex.lock();
            defer self.recv_mutex.unlock();

            while (self.recv_buf.readableLength() == 0) {
                if (self.closed.load(.acquire)) return self.closedError();
                self.recv_cond.wait(&self.recv_mutex);
            }

            return self.recv_buf.read(buf);
        }

        /// Read with timeout (nanoseconds). Returns `ConnError.ConnTimeout` on timeout.
        pub fn readTimeout(self: *Self, buf: []u8, timeout_ns: u64) ConnError!usize {
            if (buf.len == 0) return 0;

            const start_ns = std.time.nanoTimestamp();
            const deadline_ns = start_ns + @as(i128, @intCast(timeout_ns));

            self.recv_mutex.lock();
            defer self.recv_mutex.unlock();

            while (self.recv_buf.readableLength() == 0) {
                if (self.closed.load(.acquire)) return self.closedError();
                const now_ns = std.time.nanoTimestamp();
                if (now_ns >= deadline_ns) return ConnError.ConnTimeout;

                const remaining_ns: u64 = @intCast(deadline_ns - now_ns);
                const result = self.recv_cond.timedWait(&self.recv_mutex, remaining_ns);
                if (result == .timed_out) return ConnError.ConnTimeout;
            }

            return self.recv_buf.read(buf);
        }

        /// Send data through KCP.
        pub fn write(self: *Self, data: []const u8) ConnError!usize {
            if (data.len == 0) return 0;
            if (self.closed.load(.acquire)) return self.closedError();

            const cp = self.allocator.dupe(u8, data) catch return ConnError.KcpSendFailed;

            const item = self.allocator.create(WriteQueue.WriteItem) catch {
                self.allocator.free(cp);
                return ConnError.KcpSendFailed;
            };
            item.* = .{
                .data = cp,
                .done = false,
                .status = .pending,
                .result_n = 0,
            };

            self.write_mutex.lock();
            defer self.write_mutex.unlock();

            if (self.closed.load(.acquire)) {
                self.allocator.destroy(item);
                self.allocator.free(cp);
                return self.closedError();
            }
            if (!self.write_queue.push(item)) {
                self.allocator.destroy(item);
                self.allocator.free(cp);
                return ConnError.KcpSendFailed;
            }
            self.input_cond.signal();

            while (!item.done) {
                self.write_cond.wait(&self.write_mutex);
            }

            const status = item.status;
            const result_n = item.result_n;
            self.allocator.destroy(item);

            return switch (status) {
                .success => result_n,
                .failed => ConnError.KcpSendFailed,
                .closed => self.closedError(),
                .pending => ConnError.KcpSendFailed,
            };
        }

        pub fn close(self: *Self) void {
            self.closeSignal(.local);
        }

        pub fn closeByPeer(self: *Self) void {
            self.closeSignal(.peer);
        }

        pub fn isClosed(self: *const Self) bool {
            return self.closed.load(.acquire);
        }

        fn closeSignal(self: *Self, reason: CloseReason) void {
            if (self.closed.swap(true, .acq_rel)) return;
            self.close_reason.store(reason, .release);
            self.drainWriteQueue(.closed);
            self.recv_cond.broadcast();
            self.input_cond.signal();
            self.write_cond.broadcast();
        }

        fn closedError(self: *const Self) ConnError {
            return switch (self.close_reason.load(.acquire)) {
                .local => ConnError.ConnClosedLocal,
                .peer => ConnError.ConnClosedByPeer,
                .timeout => ConnError.ConnTimeout,
                .oom => ConnError.OutOfMemory,
                .none => ConnError.ConnClosed,
            };
        }

        fn drainInputQueue(self: *Self) void {
            self.input_mutex.lock();
            defer self.input_mutex.unlock();
            while (self.input_queue.pop()) |item| {
                self.allocator.free(item.data);
            }
        }

        fn drainWriteQueue(self: *Self, status: WriteQueue.WriteStatus) void {
            self.write_mutex.lock();
            defer self.write_mutex.unlock();

            while (self.write_queue.pop()) |item| {
                self.allocator.free(item.data);
                item.status = status;
                item.done = true;
            }
        }

        fn kcpOutputTrampoline(data: []const u8, user: ?*anyopaque) void {
            if (user) |u| {
                const self: *Self = @ptrCast(@alignCast(u));
                self.output.write(data) catch {
                    _ = self.output_failures.fetchAdd(1, .seq_cst);
                };
            }
        }

        fn kcpOutputCallbackNative(data: []const u8, _: *kcp.Kcp, user: ?*anyopaque) anyerror!i32 {
            if (user) |u| {
                const self: *Self = @ptrCast(@alignCast(u));
                self.output.write(data) catch {
                    _ = self.output_failures.fetchAdd(1, .seq_cst);
                    return error.OutputFailed;
                };
            }
            return @intCast(data.len);
        }

        fn runLoopTrampoline(ctx: ?*anyopaque) void {
            if (ctx) |c| {
                const self: *Self = @ptrCast(@alignCast(c));
                self.runLoop();
            }
        }

        fn runLoop(self: *Self) void {
            var last_recv_ms = self.time.nowMs();

            while (!self.closed.load(.acquire)) {
                if (self.kcpState() < 0) {
                    self.closeSignal(.timeout);
                    return;
                }

                const now_ms = self.time.nowMs();
                const idle_ms = now_ms -| last_recv_ms;
                if (idle_ms > idle_timeout_ms and self.kcpWaitSnd() > 0) {
                    self.closeSignal(.timeout);
                    return;
                }
                if (idle_ms > idle_timeout_pure_ms) {
                    self.closeSignal(.timeout);
                    return;
                }

                var had_input = false;

                self.input_mutex.lock();
                while (self.input_queue.pop()) |item| {
                    self.input_mutex.unlock();
                    _ = self.kcpInput(item.data);
                    self.allocator.free(item.data);
                    had_input = true;
                    self.input_mutex.lock();
                }
                self.input_mutex.unlock();

                self.write_mutex.lock();
                while (self.write_queue.pop()) |item| {
                    self.write_mutex.unlock();

                    var status: WriteQueue.WriteStatus = .failed;
                    var result_n: usize = 0;
                    const output_failures_before = self.output_failures.load(.acquire);
                    const ret = self.kcpSend(item.data);
                    if (ret >= 0) {
                        self.kcpFlush();
                        const output_failures_after = self.output_failures.load(.acquire);
                        if (output_failures_after == output_failures_before) {
                            result_n = item.data.len;
                            status = .success;
                        }
                    }
                    self.allocator.free(item.data);

                    self.write_mutex.lock();
                    item.result_n = result_n;
                    item.status = status;
                    item.done = true;
                    self.write_cond.broadcast();
                }
                self.write_mutex.unlock();

                if (had_input) {
                    last_recv_ms = self.time.nowMs();
                }

                const current: u32 = @truncate(self.time.nowMs());
                self.kcpUpdate(current);
                self.drainRecv();

                const next = self.kcpCheck(current);
                var delay_ms: u64 = 1;
                if (next > current) {
                    delay_ms = @min(next - current, max_update_delay_ms);
                }

                self.input_mutex.lock();
                if (self.input_queue.len == 0 and !self.closed.load(.acquire)) {
                    _ = self.input_cond.timedWait(&self.input_mutex, delay_ms * 1_000_000);
                }
                self.input_mutex.unlock();
            }
        }

        fn drainRecv(self: *Self) void {
            var stack_buf: [64 * 1024]u8 = undefined;
            var received = false;

            while (true) {
                const size = self.kcpPeekSize();
                if (size <= 0) break;

                const usize_size: usize = @intCast(size);
                if (usize_size > stack_buf.len) break;

                const n = self.kcpRecv(stack_buf[0..usize_size]);
                if (n <= 0) break;

                self.recv_mutex.lock();
                self.recv_buf.write(stack_buf[0..@intCast(n)]) catch {
                    self.recv_mutex.unlock();
                    self.closeSignal(.oom);
                    break;
                };
                self.recv_mutex.unlock();
                received = true;
            }

            if (received) {
                self.recv_cond.broadcast();
            }
        }

        fn kcpInput(self: *Self, data: []const u8) i32 {
            if (comptime uses_native_kcp) {
                return kcp.input(self.kcp, data) catch -1;
            }
            return self.kcp.input(data);
        }

        fn kcpSend(self: *Self, data: []const u8) i32 {
            if (comptime uses_native_kcp) {
                const n = kcp.send(self.kcp, data) catch return -1;
                return @intCast(n);
            }
            return self.kcp.send(data);
        }

        fn kcpRecv(self: *Self, out: []u8) i32 {
            if (comptime uses_native_kcp) {
                const n = kcp.recv(self.kcp, out) catch return -1;
                return @intCast(n);
            }
            return self.kcp.recv(out);
        }

        fn kcpUpdate(self: *Self, current: u32) void {
            if (comptime uses_native_kcp) {
                kcp.update(self.kcp, current) catch {};
                return;
            }
            self.kcp.update(current);
        }

        fn kcpCheck(self: *Self, current: u32) u32 {
            if (comptime uses_native_kcp) {
                return kcp.check(self.kcp, current);
            }
            return self.kcp.check(current);
        }

        fn kcpFlush(self: *Self) void {
            if (comptime uses_native_kcp) {
                kcp.flush(self.kcp) catch {};
                return;
            }
            self.kcp.flush();
        }

        fn kcpWaitSnd(self: *Self) i32 {
            if (comptime uses_native_kcp) {
                return @intCast(kcp.waitsnd(self.kcp));
            }
            return self.kcp.waitSnd();
        }

        fn kcpPeekSize(self: *Self) i32 {
            if (comptime uses_native_kcp) {
                return kcp.peeksize(self.kcp) catch -1;
            }
            return self.kcp.peekSize();
        }

        fn kcpState(self: *Self) i32 {
            if (comptime uses_native_kcp) {
                if (self.kcp.state == kcp.STATE_DEAD) return -1;
                return @intCast(self.kcp.state);
            }
            return self.kcp.state();
        }
    };
}

pub fn StdKCPConn(comptime KcpType: type) type {
    return KCPConn(
        KcpType,
        runtime.std.Mutex,
        runtime.std.Condition,
        runtime.std.Thread,
        runtime.std.Time,
    );
}

pub const DefaultConn = StdKCPConn(*@import("kcp").Kcp);

// ── Tests ────────────────────────────────────────────────────────────

const testing = std.testing;
const rt = @import("embed").runtime;

test "PacketWriter dispatch" {
    const Ctx = struct {
        var received: [256]u8 = undefined;
        var received_len: usize = 0;

        fn writeFn(ctx: *anyopaque, data: []const u8) !void {
            _ = ctx;
            @memcpy(received[received_len..][0..data.len], data);
            received_len += data.len;
        }
    };
    Ctx.received_len = 0;

    var dummy: u8 = 0;
    const pw = PacketWriter{
        .ptr = @ptrCast(&dummy),
        .writeFn = &Ctx.writeFn,
    };

    try pw.write("hello");
    try pw.write(" world");
    try testing.expectEqual(@as(usize, 11), Ctx.received_len);
    try testing.expectEqualStrings("hello world", Ctx.received[0..11]);
}

test "KCPConn loopback via in-memory bridge" {
    const Mutex = rt.std.Mutex;
    const Condition = rt.std.Condition;
    const Thread = rt.std.Thread;
    const Time = rt.std.Time;
    const Conn = KCPConn(*kcp.Kcp, Mutex, Condition, Thread, Time);

    // In-memory "network": A's output goes to B's input and vice versa.
    // We use two Conn instances with conv=1.
    // The bridge is a pair of atomic packet queues.
    const Bridge = struct {
        const max_pkts = 256;
        const PktSlot = struct { data: [2048]u8 = undefined, len: usize = 0 };

        a_to_b: [max_pkts]PktSlot = [_]PktSlot{.{}} ** max_pkts,
        a_to_b_len: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        b_to_a: [max_pkts]PktSlot = [_]PktSlot{.{}} ** max_pkts,
        b_to_a_len: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

        conn_a: ?*Conn = null,
        conn_b: ?*Conn = null,

        fn pushA2B(self: *@This(), data: []const u8) void {
            const idx = self.a_to_b_len.load(.acquire);
            if (idx >= max_pkts) return;
            @memcpy(self.a_to_b[idx].data[0..data.len], data);
            self.a_to_b[idx].len = data.len;
            self.a_to_b_len.store(idx + 1, .release);
        }

        fn pushB2A(self: *@This(), data: []const u8) void {
            const idx = self.b_to_a_len.load(.acquire);
            if (idx >= max_pkts) return;
            @memcpy(self.b_to_a[idx].data[0..data.len], data);
            self.b_to_a[idx].len = data.len;
            self.b_to_a_len.store(idx + 1, .release);
        }

        fn outputA(ctx: *anyopaque, data: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.pushA2B(data);
            // Immediately deliver to B
            if (self.conn_b) |b| {
                try b.input(data);
            }
        }

        fn outputB(ctx: *anyopaque, data: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.pushB2A(data);
            // Immediately deliver to A
            if (self.conn_a) |a| {
                try a.input(data);
            }
        }
    };

    var bridge = Bridge{};

    const time = Time{};
    const alloc = testing.allocator;

    const pw_a = PacketWriter{ .ptr = @ptrCast(&bridge), .writeFn = &Bridge.outputA };
    const pw_b = PacketWriter{ .ptr = @ptrCast(&bridge), .writeFn = &Bridge.outputB };

    const conn_a = try Conn.init(alloc, time, 1, pw_a);
    const conn_b = try Conn.init(alloc, time, 1, pw_b);
    defer {
        conn_a.close();
        conn_b.close();
        bridge.conn_a = null;
        bridge.conn_b = null;
        conn_b.deinit();
        conn_a.deinit();
    }

    bridge.conn_a = conn_a;
    bridge.conn_b = conn_b;

    // Send from A
    const msg = "hello from KCPConn A!";
    const written = try conn_a.write(msg);
    try testing.expectEqual(msg.len, written);

    // Read on B (with timeout to avoid hanging)
    var buf: [256]u8 = undefined;
    const n = try conn_b.readTimeout(&buf, 2_000_000_000); // 2s timeout
    try testing.expect(n > 0);
    try testing.expectEqualStrings(msg, buf[0..n]);

    // Send from B back to A
    const reply = "reply from B";
    _ = try conn_b.write(reply);

    var buf2: [256]u8 = undefined;
    const n2 = try conn_a.readTimeout(&buf2, 2_000_000_000);
    try testing.expect(n2 > 0);
    try testing.expectEqualStrings(reply, buf2[0..n2]);
}

test "KCPConn close" {
    const Mutex = rt.std.Mutex;
    const Condition = rt.std.Condition;
    const Thread = rt.std.Thread;
    const Time = rt.std.Time;
    const Conn = KCPConn(*kcp.Kcp, Mutex, Condition, Thread, Time);

    const NullWriter = struct {
        fn writeFn(_: *anyopaque, _: []const u8) !void {}
    };
    var dummy: u8 = 0;
    const pw = PacketWriter{ .ptr = @ptrCast(&dummy), .writeFn = &NullWriter.writeFn };

    const conn_inst = try Conn.init(testing.allocator, Time{}, 99, pw);
    try testing.expect(!conn_inst.isClosed());

    conn_inst.close();
    try testing.expect(conn_inst.isClosed());

    // Read after close should return error
    var buf: [16]u8 = undefined;
    const result = conn_inst.read(&buf);
    try testing.expectError(ConnError.ConnClosedLocal, result);

    conn_inst.deinit();
}

test "KCPConn input reports queue full" {
    const ManualThread = struct {
        pub fn spawn(_: runtime.thread.SpawnConfig, _: runtime.thread.types.TaskFn, _: ?*anyopaque) !@This() {
            return .{};
        }

        pub fn join(_: *@This()) void {}

        pub fn detach(_: *@This()) void {}
    };
    const Conn = KCPConn(*kcp.Kcp, rt.std.Mutex, rt.std.Condition, ManualThread, rt.std.Time);
    const NullWriter = struct {
        fn writeFn(_: *anyopaque, _: []const u8) !void {}
    };

    var dummy: u8 = 0;
    const pw = PacketWriter{ .ptr = @ptrCast(&dummy), .writeFn = &NullWriter.writeFn };
    const conn = try Conn.init(testing.allocator, rt.std.Time{}, 7, pw);
    defer conn.deinit();

    const pkt = [_]u8{0xAB} ** 8;
    for (0..256) |_| {
        try conn.input(&pkt);
    }
    try testing.expectError(ConnError.InputQueueFull, conn.input(&pkt));
}

test "KCPConn input reports out of memory" {
    const ManualThread = struct {
        pub fn spawn(_: runtime.thread.SpawnConfig, _: runtime.thread.types.TaskFn, _: ?*anyopaque) !@This() {
            return .{};
        }

        pub fn join(_: *@This()) void {}

        pub fn detach(_: *@This()) void {}
    };
    const Conn = KCPConn(*kcp.Kcp, rt.std.Mutex, rt.std.Condition, ManualThread, rt.std.Time);
    const NullWriter = struct {
        fn writeFn(_: *anyopaque, _: []const u8) !void {}
    };

    var dummy: u8 = 0;
    const pw = PacketWriter{ .ptr = @ptrCast(&dummy), .writeFn = &NullWriter.writeFn };
    const conn = try Conn.init(testing.allocator, rt.std.Time{}, 8, pw);
    defer {
        conn.allocator = testing.allocator;
        conn.deinit();
    }

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    conn.allocator = failing.allocator();

    const pkt = [_]u8{0xCD} ** 8;
    try testing.expectError(ConnError.OutOfMemory, conn.input(&pkt));
}

test "KCPConn drainRecv closes and reports out of memory on recv buffer allocation failure" {
    const ManualThread = struct {
        pub fn spawn(_: runtime.thread.SpawnConfig, _: runtime.thread.types.TaskFn, _: ?*anyopaque) !@This() {
            return .{};
        }

        pub fn join(_: *@This()) void {}

        pub fn detach(_: *@This()) void {}
    };
    const MockRecvKcp = struct {
        payload: []const u8 = "",
        consumed: bool = false,

        pub fn init(_: u32, _: anytype, _: anytype) !@This() {
            return .{};
        }

        pub fn deinit(_: *@This()) void {}

        pub fn setUserPtr(_: *@This()) void {}

        pub fn setDefaultConfig(_: *@This()) void {}

        pub fn input(_: *@This(), _: []const u8) i32 {
            return 0;
        }

        pub fn send(_: *@This(), data: []const u8) i32 {
            return @intCast(data.len);
        }

        pub fn update(_: *@This(), _: u32) void {}

        pub fn check(_: *@This(), current: u32) u32 {
            return current;
        }

        pub fn state(_: *@This()) i32 {
            return 0;
        }

        pub fn waitSnd(_: *@This()) i32 {
            return 0;
        }

        pub fn flush(_: *@This()) void {}

        pub fn peekSize(self: *@This()) i32 {
            if (self.consumed or self.payload.len == 0) return -1;
            return @intCast(self.payload.len);
        }

        pub fn recv(self: *@This(), out: []u8) i32 {
            if (self.consumed or out.len < self.payload.len) return -1;
            @memcpy(out[0..self.payload.len], self.payload);
            self.consumed = true;
            return @intCast(self.payload.len);
        }
    };
    const Conn = KCPConn(MockRecvKcp, rt.std.Mutex, rt.std.Condition, ManualThread, rt.std.Time);
    const NullWriter = struct {
        fn writeFn(_: *anyopaque, _: []const u8) !void {}
    };

    var dummy: u8 = 0;
    const pw = PacketWriter{ .ptr = @ptrCast(&dummy), .writeFn = &NullWriter.writeFn };
    const conn = try Conn.init(testing.allocator, rt.std.Time{}, 9, pw);
    defer {
        conn.recv_buf.allocator = testing.allocator;
        conn.deinit();
    }

    conn.kcp.payload = "payload dropped on oom";

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    conn.recv_buf.allocator = failing.allocator();

    conn.drainRecv();

    try testing.expect(conn.isClosed());

    var buf: [32]u8 = undefined;
    try testing.expectError(ConnError.OutOfMemory, conn.read(&buf));
}

test "KCPConn write reports output failure" {
    const Conn = KCPConn(*kcp.Kcp, rt.std.Mutex, rt.std.Condition, rt.std.Thread, rt.std.Time);
    const FailingWriter = struct {
        fn writeFn(_: *anyopaque, _: []const u8) anyerror!void {
            return error.TestOutputFailure;
        }
    };

    var dummy: u8 = 0;
    const pw = PacketWriter{ .ptr = @ptrCast(&dummy), .writeFn = &FailingWriter.writeFn };
    const conn = try Conn.init(testing.allocator, rt.std.Time{}, 9, pw);
    defer conn.deinit();

    try testing.expectError(ConnError.KcpSendFailed, conn.write("hello"));
}

// ── Concurrency & edge-case helpers ──────────────────────────────────

const TestBridge = struct {
    const Mutex = rt.std.Mutex;
    const Condition = rt.std.Condition;
    const Thread = rt.std.Thread;
    const Time = rt.std.Time;
    const Conn = KCPConn(*kcp.Kcp, Mutex, Condition, Thread, Time);

    conn_a: ?*Conn = null,
    conn_b: ?*Conn = null,

    fn outputA(ctx: *anyopaque, data: []const u8) !void {
        const self: *TestBridge = @ptrCast(@alignCast(ctx));
        if (self.conn_b) |b| try b.input(data);
    }

    fn outputB(ctx: *anyopaque, data: []const u8) !void {
        const self: *TestBridge = @ptrCast(@alignCast(ctx));
        if (self.conn_a) |a| try a.input(data);
    }

    fn create(alloc: std.mem.Allocator) !struct { bridge: *TestBridge, a: *Conn, b: *Conn } {
        const bridge = try alloc.create(TestBridge);
        bridge.* = .{};

        const time = Time{};
        const pw_a = PacketWriter{ .ptr = @ptrCast(bridge), .writeFn = &outputA };
        const pw_b = PacketWriter{ .ptr = @ptrCast(bridge), .writeFn = &outputB };

        const a = try Conn.init(alloc, time, 1, pw_a);
        const b = try Conn.init(alloc, time, 1, pw_b);
        bridge.conn_a = a;
        bridge.conn_b = b;
        return .{ .bridge = bridge, .a = a, .b = b };
    }

    fn destroy(self: *TestBridge, alloc: std.mem.Allocator) void {
        const conn_a = self.conn_a;
        const conn_b = self.conn_b;
        if (conn_a) |a| a.close();
        if (conn_b) |b| b.close();
        self.conn_a = null;
        self.conn_b = null;
        if (conn_a) |a| a.deinit();
        if (conn_b) |b| b.deinit();
        alloc.destroy(self);
    }
};

// ── Concurrency tests ────────────────────────────────────────────────

test "concurrent: multiple writers on same conn" {
    const alloc = testing.allocator;
    const r = try TestBridge.create(alloc);
    defer r.bridge.destroy(alloc);

    const num_writers = 4;
    const msgs_per_writer = 20;
    const msg = "CONCURRENT_WRITE_PAYLOAD!";

    var threads: [num_writers]TestBridge.Thread = undefined;
    for (&threads) |*t| {
        t.* = try TestBridge.Thread.spawn(
            .{ .stack_size = 65536, .name = "writer" },
            &struct {
                fn run(ctx: ?*anyopaque) void {
                    const conn: *TestBridge.Conn = @ptrCast(@alignCast(ctx.?));
                    for (0..msgs_per_writer) |_| {
                        _ = conn.write(msg) catch break;
                    }
                }
            }.run,
            @ptrCast(r.a),
        );
    }

    // Reader on B: collect all messages
    var total_bytes: usize = 0;
    const expected_total = num_writers * msgs_per_writer * msg.len;
    var read_buf: [4096]u8 = undefined;

    while (total_bytes < expected_total) {
        const n = r.b.readTimeout(&read_buf, 3_000_000_000) catch |err| {
            if (err == ConnError.ConnTimeout) break;
            break;
        };
        if (n == 0) break;
        total_bytes += n;
    }

    for (&threads) |*t| t.join();

    try testing.expectEqual(expected_total, total_bytes);
}

test "concurrent: reader blocks until data arrives" {
    const alloc = testing.allocator;
    const r = try TestBridge.create(alloc);
    defer r.bridge.destroy(alloc);

    var read_result: usize = 0;
    var read_buf: [64]u8 = undefined;
    var read_done = std.atomic.Value(bool).init(false);

    var reader = try TestBridge.Thread.spawn(
        .{ .stack_size = 65536, .name = "reader" },
        &struct {
            fn run(ctx: ?*anyopaque) void {
                const args: *struct { conn: *TestBridge.Conn, result: *usize, buf: *[64]u8, done: *std.atomic.Value(bool) } = @ptrCast(@alignCast(ctx.?));
                const n = args.conn.readTimeout(args.buf, 5_000_000_000) catch 0;
                args.result.* = n;
                args.done.store(true, .release);
            }
        }.run,
        @ptrCast(@constCast(&struct { conn: *TestBridge.Conn, result: *usize, buf: *[64]u8, done: *std.atomic.Value(bool) }{
            .conn = r.b,
            .result = &read_result,
            .buf = &read_buf,
            .done = &read_done,
        })),
    );

    // Wait a bit, then write — reader should be blocking
    TestBridge.Time.sleepMs(.{}, 50);
    try testing.expect(!read_done.load(.acquire));

    const msg = "delayed data";
    _ = try r.a.write(msg);

    reader.join();
    try testing.expect(read_done.load(.acquire));
    try testing.expect(read_result > 0);
    try testing.expectEqualStrings(msg, read_buf[0..read_result]);
}

test "concurrent: close unblocks reader" {
    const alloc = testing.allocator;
    const r = try TestBridge.create(alloc);

    var read_err: ?ConnError = null;
    var reader_done = std.atomic.Value(bool).init(false);

    var reader = try TestBridge.Thread.spawn(
        .{ .stack_size = 65536, .name = "reader" },
        &struct {
            fn run(ctx: ?*anyopaque) void {
                const args: *struct { conn: *TestBridge.Conn, err: *?ConnError, done: *std.atomic.Value(bool) } = @ptrCast(@alignCast(ctx.?));
                var buf: [16]u8 = undefined;
                _ = args.conn.read(&buf) catch |e| {
                    args.err.* = e;
                };
                args.done.store(true, .release);
            }
        }.run,
        @ptrCast(@constCast(&struct { conn: *TestBridge.Conn, err: *?ConnError, done: *std.atomic.Value(bool) }{
            .conn = r.b,
            .err = &read_err,
            .done = &reader_done,
        })),
    );

    TestBridge.Time.sleepMs(.{}, 50);
    try testing.expect(!reader_done.load(.acquire));

    r.b.close();

    reader.join();
    try testing.expect(reader_done.load(.acquire));
    try testing.expect(read_err != null);

    // Clean up (close A, then destroy bridge)
    r.a.deinit();
    r.b.deinit();
    alloc.destroy(r.bridge);
}

test "concurrent: write after close returns error" {
    const alloc = testing.allocator;
    const r = try TestBridge.create(alloc);
    defer r.bridge.destroy(alloc);

    r.a.close();

    const result = r.a.write("should fail");
    try testing.expectError(ConnError.ConnClosedLocal, result);
}

test "concurrent: input after close is rejected" {
    const alloc = testing.allocator;
    const r = try TestBridge.create(alloc);
    defer r.bridge.destroy(alloc);

    r.a.close();

    const result = r.a.input("some data");
    try testing.expectError(ConnError.ConnClosedLocal, result);
}

test "KCPConn input rechecks closed after locking queue" {
    const ManualThread = struct {
        pub fn spawn(_: runtime.thread.SpawnConfig, _: runtime.thread.types.TaskFn, _: ?*anyopaque) !@This() {
            return .{};
        }

        pub fn join(_: *@This()) void {}

        pub fn detach(_: *@This()) void {}
    };
    const Conn = KCPConn(*kcp.Kcp, rt.std.Mutex, rt.std.Condition, ManualThread, rt.std.Time);
    const NullWriter = struct {
        fn writeFn(_: *anyopaque, _: []const u8) !void {}
    };
    const Result = struct {
        err: ?ConnError = null,
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    };

    var dummy: u8 = 0;
    const pw = PacketWriter{ .ptr = @ptrCast(&dummy), .writeFn = &NullWriter.writeFn };
    const conn = try Conn.init(testing.allocator, rt.std.Time{}, 10, pw);
    defer conn.deinit();

    var result = Result{};
    conn.input_mutex.lock();
    defer conn.input_mutex.unlock();

    const worker = try std.Thread.spawn(.{}, struct {
        fn run(conn_ptr: *Conn, res: *Result) void {
            conn_ptr.input("queued while closing") catch |err| {
                res.err = err;
            };
            res.done.store(true, .release);
        }
    }.run, .{ conn, &result });

    rt.std.Time.sleepMs(.{}, 20);
    conn.close();
    conn.input_mutex.unlock();
    worker.join();
    conn.input_mutex.lock();

    try testing.expect(result.done.load(.acquire));
    try testing.expectEqual(ConnError.ConnClosedLocal, result.err.?);
    try testing.expectEqual(@as(usize, 0), conn.input_queue.len);
}

test "concurrent: readTimeout returns timeout" {
    const alloc = testing.allocator;
    const r = try TestBridge.create(alloc);
    defer r.bridge.destroy(alloc);

    // No one writes — should timeout
    var buf: [16]u8 = undefined;
    const result = r.b.readTimeout(&buf, 50_000_000); // 50ms
    try testing.expectError(ConnError.ConnTimeout, result);
}

test "readTimeout shrinks remaining wait across wakeups" {
    const FakeMutex = struct {
        pub fn init() @This() {
            return .{};
        }

        pub fn deinit(_: *@This()) void {}
        pub fn lock(_: *@This()) void {}
        pub fn unlock(_: *@This()) void {}
    };

    const RecordingCondition = struct {
        pub const MutexType = FakeMutex;

        var next_id: usize = 0;
        var recv_waits: [3]u64 = [_]u64{0} ** 3;
        var recv_wait_count: usize = 0;

        id: usize,

        pub fn init() @This() {
            const id = next_id;
            next_id += 1;
            return .{ .id = id };
        }

        pub fn deinit(_: *@This()) void {}
        pub fn wait(_: *@This(), _: *FakeMutex) void {}
        pub fn signal(_: *@This()) void {}
        pub fn broadcast(_: *@This()) void {}

        pub fn timedWait(self: *@This(), _: *FakeMutex, timeout_ns: u64) runtime.sync.types.TimedWaitResult {
            if (self.id == 0 and recv_wait_count < recv_waits.len) {
                recv_waits[recv_wait_count] = timeout_ns;
                recv_wait_count += 1;
                if (recv_wait_count < recv_waits.len) {
                    rt.std.Time.sleepMs(.{}, 1);
                    return .signaled;
                }
            }
            return .timed_out;
        }
    };

    const ManualThread = struct {
        pub fn spawn(_: runtime.thread.SpawnConfig, _: runtime.thread.types.TaskFn, _: ?*anyopaque) !@This() {
            return .{};
        }

        pub fn join(_: *@This()) void {}
        pub fn detach(_: *@This()) void {}
    };

    RecordingCondition.next_id = 0;
    RecordingCondition.recv_wait_count = 0;
    RecordingCondition.recv_waits = [_]u64{0} ** 3;

    const Conn = KCPConn(*kcp.Kcp, FakeMutex, RecordingCondition, ManualThread, rt.std.Time);
    const NullWriter = struct {
        fn writeFn(_: *anyopaque, _: []const u8) !void {}
    };

    var dummy: u8 = 0;
    const pw = PacketWriter{ .ptr = @ptrCast(&dummy), .writeFn = &NullWriter.writeFn };
    const conn = try Conn.init(testing.allocator, rt.std.Time{}, 55, pw);
    defer conn.deinit();

    var buf: [8]u8 = undefined;
    try testing.expectError(ConnError.ConnTimeout, conn.readTimeout(&buf, 5_000_000));
    try testing.expectEqual(@as(usize, 3), RecordingCondition.recv_wait_count);
    try testing.expect(RecordingCondition.recv_waits[1] < RecordingCondition.recv_waits[0]);
    try testing.expect(RecordingCondition.recv_waits[2] < RecordingCondition.recv_waits[1]);
}

test "concurrent: bidirectional ping-pong" {
    const alloc = testing.allocator;
    const r = try TestBridge.create(alloc);
    defer r.bridge.destroy(alloc);

    const rounds = 10;

    // Thread A: send "ping-N", expect "pong-N"
    var thread_a = try TestBridge.Thread.spawn(
        .{ .stack_size = 65536, .name = "ping" },
        &struct {
            fn run(ctx: ?*anyopaque) void {
                const args: *struct { a: *TestBridge.Conn, b: *TestBridge.Conn } = @ptrCast(@alignCast(ctx.?));
                var send_buf: [32]u8 = undefined;
                var recv_buf: [32]u8 = undefined;
                for (0..rounds) |i| {
                    const msg = std.fmt.bufPrint(&send_buf, "ping-{d}", .{i}) catch return;
                    _ = args.a.write(msg) catch return;
                    const n = args.a.readTimeout(&recv_buf, 3_000_000_000) catch return;
                    const expected = std.fmt.bufPrint(&send_buf, "pong-{d}", .{i}) catch return;
                    if (!std.mem.eql(u8, expected, recv_buf[0..n])) return;
                }
            }
        }.run,
        @ptrCast(@constCast(&struct { a: *TestBridge.Conn, b: *TestBridge.Conn }{ .a = r.a, .b = r.b })),
    );

    var thread_b = try TestBridge.Thread.spawn(
        .{ .stack_size = 65536, .name = "pong" },
        &struct {
            fn run(ctx: ?*anyopaque) void {
                const args: *struct { a: *TestBridge.Conn, b: *TestBridge.Conn } = @ptrCast(@alignCast(ctx.?));
                var recv_buf: [32]u8 = undefined;
                var send_buf: [32]u8 = undefined;
                for (0..rounds) |i| {
                    const n = args.b.readTimeout(&recv_buf, 3_000_000_000) catch return;
                    const expected = std.fmt.bufPrint(&send_buf, "ping-{d}", .{i}) catch return;
                    if (!std.mem.eql(u8, expected, recv_buf[0..n])) return;
                    const reply = std.fmt.bufPrint(&send_buf, "pong-{d}", .{i}) catch return;
                    _ = args.b.write(reply) catch return;
                }
            }
        }.run,
        @ptrCast(@constCast(&struct { a: *TestBridge.Conn, b: *TestBridge.Conn }{ .a = r.a, .b = r.b })),
    );

    thread_a.join();
    thread_b.join();

    // If we got here without hanging, the ping-pong completed
}

test "concurrent: large message fragmentation" {
    const alloc = testing.allocator;
    const r = try TestBridge.create(alloc);
    defer r.bridge.destroy(alloc);

    // Send a message larger than KCP MSS (~1400 bytes) to exercise fragmentation
    var big_msg: [8000]u8 = undefined;
    for (&big_msg, 0..) |*b, i| b.* = @truncate(i);

    _ = try r.a.write(&big_msg);

    // Read all fragments on B
    var received: [8000]u8 = undefined;
    var total: usize = 0;
    while (total < big_msg.len) {
        const n = r.b.readTimeout(received[total..], 3_000_000_000) catch break;
        if (n == 0) break;
        total += n;
    }

    try testing.expectEqual(big_msg.len, total);
    try testing.expectEqualSlices(u8, &big_msg, received[0..total]);
}

test "concurrent: rapid open/close cycles" {
    const alloc = testing.allocator;
    const NullWriter = struct {
        fn writeFn(_: *anyopaque, _: []const u8) !void {}
    };
    var dummy: u8 = 0;
    const pw = PacketWriter{ .ptr = @ptrCast(&dummy), .writeFn = &NullWriter.writeFn };

    for (0..20) |_| {
        const c = try TestBridge.Conn.init(alloc, TestBridge.Time{}, 1, pw);
        try testing.expect(!c.isClosed());
        c.close();
        try testing.expect(c.isClosed());
        c.deinit();
    }
}

test "concurrent: zero-length read and write" {
    const alloc = testing.allocator;
    const r = try TestBridge.create(alloc);
    defer r.bridge.destroy(alloc);

    // Zero-length write returns 0 immediately
    const wn = try r.a.write("");
    try testing.expectEqual(@as(usize, 0), wn);

    // Zero-length read returns 0 immediately
    var empty: [0]u8 = .{};
    const rn = try r.b.read(&empty);
    try testing.expectEqual(@as(usize, 0), rn);
}

test "concurrent: double close is safe" {
    const alloc = testing.allocator;
    const NullWriter = struct {
        fn writeFn(_: *anyopaque, _: []const u8) !void {}
    };
    var dummy: u8 = 0;
    const pw = PacketWriter{ .ptr = @ptrCast(&dummy), .writeFn = &NullWriter.writeFn };

    const c = try TestBridge.Conn.init(alloc, TestBridge.Time{}, 1, pw);
    c.close();
    c.close(); // second close should be a no-op
    try testing.expect(c.isClosed());
    c.deinit();
}
