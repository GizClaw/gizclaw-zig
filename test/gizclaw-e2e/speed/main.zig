const std = @import("std");
const common = @import("common");

const default_bytes: i64 = 10 * 1024 * 1024;
const default_timeout_ms: i64 = 180_000;

const SpeedOptions = struct {
    base: common.BaseOptions = .{},
    up_bytes: i64 = default_bytes,
    down_bytes: i64 = default_bytes,
    timeout_ms: i64 = default_timeout_ms,

    fn parse(allocator: std.mem.Allocator) !SpeedOptions {
        const args = try std.process.argsAlloc(allocator);
        var out = SpeedOptions{};
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (try out.base.applyArg(args, &i)) continue;
            const arg = args[i];
            if (std.mem.eql(u8, arg, "--help")) {
                try printUsage();
                std.process.exit(0);
            } else if (std.mem.eql(u8, arg, "--bytes")) {
                i += 1;
                const value = try parseBytes(try common.needValue(args, i, arg));
                out.up_bytes = value;
                out.down_bytes = value;
            } else if (std.mem.eql(u8, arg, "--up-bytes")) {
                i += 1;
                out.up_bytes = try parseBytes(try common.needValue(args, i, arg));
            } else if (std.mem.eql(u8, arg, "--down-bytes")) {
                i += 1;
                out.down_bytes = try parseBytes(try common.needValue(args, i, arg));
            } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
                i += 1;
                out.timeout_ms = try parsePositiveInt(try common.needValue(args, i, arg), arg);
            } else {
                return error.UnknownArgument;
            }
        }
        return out;
    }
};

fn printUsage() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\usage: gizclaw-e2e-speed [options]
        \\
        \\Connection:
        \\  --context DIR          GizClaw context dir with config.yaml and identity.key
        \\                         Default: test/gizclaw-e2e/testdata/client-context
        \\  --no-context           Use explicit --server-* and --client-key values
        \\  --server-addr ADDR     Remote GizClaw server address
        \\  --server-key KEY       Remote GizClaw server public key
        \\  --client-key KEY       Client private key
        \\  --cipher-mode MODE     chacha_poly, aes_256_gcm, or plaintext
        \\  --connect-timeout-ms N Milliseconds to wait for the GizNet handshake
        \\
        \\Speed test:
        \\  --bytes N              Set both upload and download byte counts; default 10485760
        \\  --up-bytes N           Upload byte count
        \\  --down-bytes N         Download byte count
        \\  --timeout-ms N         Speed-test stream deadline in milliseconds
        \\
        \\The speed-test RPC runs upload and download concurrently.
        \\
    );
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    const options = try SpeedOptions.parse(allocator);
    var ctx = try common.loadContext(allocator, options.base);
    defer ctx.deinit();

    switch (ctx.cipher_mode) {
        .chacha_poly => try runWithSdk(common.chacha_sdk, allocator, &ctx, options),
        .aes_256_gcm => try runWithSdk(common.aes_256_gcm_sdk, allocator, &ctx, options),
        .plaintext => try runWithSdk(common.plaintext_sdk, allocator, &ctx, options),
    }
}

fn runWithSdk(comptime sdk: type, allocator: std.mem.Allocator, ctx: *const common.Context, options: SpeedOptions) !void {
    var summary = common.Summary.init();
    var client = common.connectClient(sdk, allocator, ctx) catch |err| {
        try summary.fail("Connect", err);
        return summary.finish();
    };
    defer client.deinit();
    try summary.pass("Connect");

    const ping_start = common.grt.time.instant.now();
    if (client.ping()) |_| {
        const ping_duration_ns = common.grt.time.instant.sub(common.grt.time.instant.now(), ping_start);
        try summary.pass("Ping");
        var out = std.fs.File.stdout().deprecatedWriter();
        try out.print("PING rtt_ms={d} rtt_ns={d}\n", .{
            @divTrunc(ping_duration_ns, common.grt.time.duration.MilliSecond),
            ping_duration_ns,
        });
    } else |err| try summary.fail("Ping", err);

    const timeout = @as(common.grt.time.duration.Duration, @intCast(@max(options.timeout_ms, 1))) *
        common.grt.time.duration.MilliSecond;
    const result = client.speedTest(.{
        .up_content_length = options.up_bytes,
        .down_content_length = options.down_bytes,
    }, timeout) catch |err| {
        try summary.fail("SpeedTest", err);
        return summary.finish();
    };
    try summary.pass("SpeedTest");

    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print(
        "SPEED up_bytes={d} down_bytes={d} duration_ms={d} up_mbps={d:.3} down_mbps={d:.3}\n",
        .{
            result.up_bytes,
            result.down_bytes,
            @divTrunc(result.duration_ns, common.grt.time.duration.MilliSecond),
            result.upMbps(),
            result.downMbps(),
        },
    );
    try summary.finish();
}

fn parseBytes(raw: []const u8) !i64 {
    return parsePositiveInt(raw, "bytes");
}

fn parsePositiveInt(raw: []const u8, flag: []const u8) !i64 {
    const value = std.fmt.parseInt(i64, raw, 10) catch |err| {
        var stderr = std.fs.File.stderr().deprecatedWriter();
        try stderr.print("invalid integer for {s}: {s}\n", .{ flag, raw });
        return err;
    };
    if (value < 0) return error.InvalidArgument;
    return value;
}
