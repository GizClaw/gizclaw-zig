const glib = @import("glib");

const TimerState = @This();

pub const Kind = enum {
    keepalive_deadline,
    persistent_keepalive_deadline,
    rekey_deadline,
    handshake_retry_deadline,
    handshake_deadline,
    offline_deadline,
    cleanup_deadline,
};

keepalive_deadline: ?glib.time.instant.Time = null,
persistent_keepalive_deadline: ?glib.time.instant.Time = null,
rekey_deadline: ?glib.time.instant.Time = null,
handshake_retry_deadline: ?glib.time.instant.Time = null,
handshake_deadline: ?glib.time.instant.Time = null,
offline_deadline: ?glib.time.instant.Time = null,
cleanup_deadline: ?glib.time.instant.Time = null,

pub fn clear(self: *TimerState) void {
    self.* = .{};
}

pub fn set(self: *TimerState, kind: Kind, due: ?glib.time.instant.Time) void {
    switch (kind) {
        .keepalive_deadline => self.keepalive_deadline = due,
        .persistent_keepalive_deadline => self.persistent_keepalive_deadline = due,
        .rekey_deadline => self.rekey_deadline = due,
        .handshake_retry_deadline => self.handshake_retry_deadline = due,
        .handshake_deadline => self.handshake_deadline = due,
        .offline_deadline => self.offline_deadline = due,
        .cleanup_deadline => self.cleanup_deadline = due,
    }
}

pub fn get(self: TimerState, kind: Kind) ?glib.time.instant.Time {
    return switch (kind) {
        .keepalive_deadline => self.keepalive_deadline,
        .persistent_keepalive_deadline => self.persistent_keepalive_deadline,
        .rekey_deadline => self.rekey_deadline,
        .handshake_retry_deadline => self.handshake_retry_deadline,
        .handshake_deadline => self.handshake_deadline,
        .offline_deadline => self.offline_deadline,
        .cleanup_deadline => self.cleanup_deadline,
    };
}

pub fn nextDue(self: TimerState, now: glib.time.instant.Time) ?Kind {
    var best_kind: ?Kind = null;
    var best_due: ?glib.time.instant.Time = null;
    self.considerDue(.keepalive_deadline, now, &best_kind, &best_due);
    self.considerDue(.persistent_keepalive_deadline, now, &best_kind, &best_due);
    self.considerDue(.rekey_deadline, now, &best_kind, &best_due);
    self.considerDue(.handshake_retry_deadline, now, &best_kind, &best_due);
    self.considerDue(.handshake_deadline, now, &best_kind, &best_due);
    self.considerDue(.offline_deadline, now, &best_kind, &best_due);
    self.considerDue(.cleanup_deadline, now, &best_kind, &best_due);

    return best_kind;
}

pub fn earliest(self: TimerState) ?glib.time.instant.Time {
    var best_due: ?glib.time.instant.Time = null;
    self.considerEarliest(.keepalive_deadline, &best_due);
    self.considerEarliest(.persistent_keepalive_deadline, &best_due);
    self.considerEarliest(.rekey_deadline, &best_due);
    self.considerEarliest(.handshake_retry_deadline, &best_due);
    self.considerEarliest(.handshake_deadline, &best_due);
    self.considerEarliest(.offline_deadline, &best_due);
    self.considerEarliest(.cleanup_deadline, &best_due);

    return best_due;
}

fn considerDue(
    self: TimerState,
    kind: Kind,
    now: glib.time.instant.Time,
    best_kind: *?Kind,
    best_due: *?glib.time.instant.Time,
) void {
    const due = self.get(kind) orelse return;
    if (due > now) return;
    if (best_due.* == null or due < best_due.*.?) {
        best_due.* = due;
        best_kind.* = kind;
    }
}

fn considerEarliest(self: TimerState, kind: Kind, best_due: *?glib.time.instant.Time) void {
    const due = self.get(kind) orelse return;
    if (best_due.* == null or due < best_due.*.?) best_due.* = due;
}

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    const testing_api = glib.testing;

    const Runner = struct {
        pub fn init(self: *@This(), allocator: glib.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: glib.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase(grt) catch |err| {
                t.logErrorf("giznet/noise TimerState unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: glib.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryCase(comptime any_lib: type) !void {
            _ = any_lib;
            var timers: TimerState = .{};
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), timers.earliest());
            try grt.std.testing.expectEqual(@as(?TimerState.Kind, null), timers.nextDue(0));

            timers.set(.rekey_deadline, 20);
            timers.set(.cleanup_deadline, 30);
            timers.set(.keepalive_deadline, 10);
            timers.set(.persistent_keepalive_deadline, 11);
            timers.set(.handshake_retry_deadline, 12);
            timers.set(.handshake_deadline, 18);
            timers.set(.offline_deadline, 25);

            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 20), timers.get(.rekey_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 10), timers.earliest());
            try grt.std.testing.expectEqual(@as(?TimerState.Kind, null), timers.nextDue(9));
            try grt.std.testing.expectEqual(@as(?TimerState.Kind, .keepalive_deadline), timers.nextDue(10));

            timers.set(.keepalive_deadline, null);
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 11), timers.earliest());
            try grt.std.testing.expectEqual(@as(?TimerState.Kind, .persistent_keepalive_deadline), timers.nextDue(11));

            timers.clear();
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), timers.earliest());
            try grt.std.testing.expectEqual(@as(?TimerState.Kind, null), timers.nextDue(100));
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
