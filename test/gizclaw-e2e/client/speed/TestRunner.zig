const common = @import("common");

const grt = common.grt;
const mem = grt.std.mem;
const duration = grt.time.duration;

pub const default_bytes: i64 = 10 * 1024 * 1024;
pub const default_timeout_ms: i64 = 180_000;

pub const Config = struct {
    base: common.BaseOptions = .{},
    up_bytes: i64 = default_bytes,
    down_bytes: i64 = default_bytes,
    timeout_ms: i64 = default_timeout_ms,
};

pub const Summary = struct {
    passed: usize = 0,
    skipped: usize = 0,
    failed: usize = 0,
    ping_rtt_ns: u64 = 0,
    up_bytes: i64 = 0,
    down_bytes: i64 = 0,
    duration_ns: u64 = 0,
    up_mbps: f64 = 0,
    down_mbps: f64 = 0,

    pub fn pass(self: *Summary) void {
        self.passed += 1;
    }

    pub fn fail(self: *Summary) void {
        self.failed += 1;
    }
};

pub fn run(comptime sdk: type, allocator: mem.Allocator, config: Config, reporter: anytype) !Summary {
    var ctx = common.loadContext(allocator, config.base) catch |err| {
        var summary = Summary{};
        try recordFail(&summary, reporter, "Connect", err);
        return summary;
    };
    defer ctx.deinit();
    return runWithContext(sdk, allocator, ctx, config, reporter);
}

pub fn runWithContext(comptime sdk: type, allocator: mem.Allocator, ctx: common.Context, config: Config, reporter: anytype) !Summary {
    var summary = Summary{};
    var client = common.connectClient(sdk, allocator, &ctx) catch |err| {
        try recordFail(&summary, reporter, "Connect", err);
        return summary;
    };
    defer client.deinit();
    try recordPass(&summary, reporter, "Connect");

    const ping_start = grt.time.instant.now();
    if (client.ping()) |response| {
        _ = response;
        summary.ping_rtt_ns = @intCast(grt.time.instant.since(ping_start));
        try reporter.metric("ping_rtt_ms", @intCast(@divTrunc(summary.ping_rtt_ns, duration.MilliSecond)), "ms");
        try reporter.metric("ping_rtt_ns", summary.ping_rtt_ns, "ns");
        try recordPass(&summary, reporter, "Ping");
    } else |err| {
        try recordFail(&summary, reporter, "Ping", err);
    }

    const timeout = @as(duration.Duration, @intCast(@max(config.timeout_ms, 1))) * duration.MilliSecond;
    const result = client.speedTest(.{
        .up_content_length = config.up_bytes,
        .down_content_length = config.down_bytes,
    }, timeout) catch |err| {
        try recordFail(&summary, reporter, "SpeedTest", err);
        return summary;
    };
    summary.up_bytes = result.up_bytes;
    summary.down_bytes = result.down_bytes;
    summary.duration_ns = @intCast(result.duration_ns);
    summary.up_mbps = result.upMbps();
    summary.down_mbps = result.downMbps();
    try reporter.speed(summary);
    try recordPass(&summary, reporter, "SpeedTest");
    return summary;
}

fn recordPass(summary: *Summary, reporter: anytype, name: []const u8) !void {
    summary.pass();
    try reporter.pass(name);
}

fn recordFail(summary: *Summary, reporter: anytype, name: []const u8, err: anyerror) !void {
    summary.fail();
    try reporter.fail(name, err);
}
