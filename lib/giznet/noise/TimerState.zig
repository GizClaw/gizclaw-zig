const embed = @import("embed");
const std = embed.std;

const TimerState = @This();

pub const Kind = enum {
    keepalive,
    rekey,
    handshake_retry,
    handshake_timeout,
    cleanup,
};

keepalive_ms: ?u64 = null,
rekey_ms: ?u64 = null,
handshake_retry_ms: ?u64 = null,
handshake_timeout_ms: ?u64 = null,
cleanup_ms: ?u64 = null,

pub fn clear(self: *TimerState) void {
    self.* = .{};
}

pub fn set(self: *TimerState, kind: Kind, due_ms: ?u64) void {
    switch (kind) {
        .keepalive => self.keepalive_ms = due_ms,
        .rekey => self.rekey_ms = due_ms,
        .handshake_retry => self.handshake_retry_ms = due_ms,
        .handshake_timeout => self.handshake_timeout_ms = due_ms,
        .cleanup => self.cleanup_ms = due_ms,
    }
}

pub fn get(self: TimerState, kind: Kind) ?u64 {
    return switch (kind) {
        .keepalive => self.keepalive_ms,
        .rekey => self.rekey_ms,
        .handshake_retry => self.handshake_retry_ms,
        .handshake_timeout => self.handshake_timeout_ms,
        .cleanup => self.cleanup_ms,
    };
}

pub fn nextDue(self: TimerState, now_ms: u64) ?Kind {
    var best_kind: ?Kind = null;
    var best_due: ?u64 = null;
    self.considerDue(.keepalive, now_ms, &best_kind, &best_due);
    self.considerDue(.rekey, now_ms, &best_kind, &best_due);
    self.considerDue(.handshake_retry, now_ms, &best_kind, &best_due);
    self.considerDue(.handshake_timeout, now_ms, &best_kind, &best_due);
    self.considerDue(.cleanup, now_ms, &best_kind, &best_due);

    return best_kind;
}

pub fn earliest(self: TimerState) ?u64 {
    var best_due: ?u64 = null;
    self.considerEarliest(.keepalive, &best_due);
    self.considerEarliest(.rekey, &best_due);
    self.considerEarliest(.handshake_retry, &best_due);
    self.considerEarliest(.handshake_timeout, &best_due);
    self.considerEarliest(.cleanup, &best_due);

    return best_due;
}

fn considerDue(
    self: TimerState,
    kind: Kind,
    now_ms: u64,
    best_kind: *?Kind,
    best_due: *?u64,
) void {
    const due = self.get(kind) orelse return;
    if (due > now_ms) return;
    if (best_due.* == null or due < best_due.*.?) {
        best_due.* = due;
        best_kind.* = kind;
    }
}

fn considerEarliest(self: TimerState, kind: Kind, best_due: *?u64) void {
    const due = self.get(kind) orelse return;
    if (best_due.* == null or due < best_due.*.?) best_due.* = due;
}

pub fn testRunner(comptime lib: type) embed.testing.TestRunner {
    const testing_api = embed.testing;

    const Runner = struct {
        pub fn init(self: *@This(), allocator: std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase(lib) catch |err| {
                t.logErrorf("giznet/noise TimerState unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }

        fn tryCase(comptime any_lib: type) !void {
            var timers: TimerState = .{};
            try any_lib.testing.expectEqual(@as(?u64, null), timers.earliest());
            try any_lib.testing.expectEqual(@as(?TimerState.Kind, null), timers.nextDue(0));

            timers.set(.rekey, 20);
            timers.set(.cleanup, 30);
            timers.set(.keepalive, 10);
            timers.set(.handshake_retry, 12);
            timers.set(.handshake_timeout, 18);

            try any_lib.testing.expectEqual(@as(?u64, 20), timers.get(.rekey));
            try any_lib.testing.expectEqual(@as(?u64, 10), timers.earliest());
            try any_lib.testing.expectEqual(@as(?TimerState.Kind, null), timers.nextDue(9));
            try any_lib.testing.expectEqual(@as(?TimerState.Kind, .keepalive), timers.nextDue(10));

            timers.set(.keepalive, null);
            try any_lib.testing.expectEqual(@as(?u64, 12), timers.earliest());
            try any_lib.testing.expectEqual(@as(?TimerState.Kind, .handshake_retry), timers.nextDue(12));

            timers.clear();
            try any_lib.testing.expectEqual(@as(?u64, null), timers.earliest());
            try any_lib.testing.expectEqual(@as(?TimerState.Kind, null), timers.nextDue(100));
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
