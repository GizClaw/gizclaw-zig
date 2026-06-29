const std = @import("std");
const common = @import("common");
const TestRunner = @import("TestRunner.zig");

const Options = struct {
    config: TestRunner.Config = .{},
    host: common.HostOptions = .{},

    fn parse(allocator: std.mem.Allocator) !Options {
        const args = try std.process.argsAlloc(allocator);
        var out = Options{};
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (try out.host.applyArg(args, &i)) continue;
            if (try out.config.base.applyArg(args, &i)) continue;
            const arg = args[i];
            if (std.mem.eql(u8, arg, "--help")) {
                try printUsage();
                std.process.exit(0);
            } else if (std.mem.eql(u8, arg, "--bytes")) {
                i += 1;
                const value = try parseBytes(try common.needValue(args, i, arg));
                out.config.up_bytes = value;
                out.config.down_bytes = value;
            } else if (std.mem.eql(u8, arg, "--up-bytes")) {
                i += 1;
                out.config.up_bytes = try parseBytes(try common.needValue(args, i, arg));
            } else if (std.mem.eql(u8, arg, "--down-bytes")) {
                i += 1;
                out.config.down_bytes = try parseBytes(try common.needValue(args, i, arg));
            } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
                i += 1;
                out.config.timeout_ms = try parsePositiveInt(try common.needValue(args, i, arg), arg);
            } else {
                return error.UnknownArgument;
            }
        }
        return out;
    }
};

const StdoutReporter = struct {
    out: @TypeOf(std.fs.File.stdout().deprecatedWriter()) = std.fs.File.stdout().deprecatedWriter(),

    pub fn pass(self: *StdoutReporter, name: []const u8) !void {
        try self.out.print("PASS {s}\n", .{name});
    }

    pub fn fail(self: *StdoutReporter, name: []const u8, err: anyerror) !void {
        try self.out.print("FAIL {s}: {s}\n", .{ name, @errorName(err) });
    }

    pub fn metric(self: *StdoutReporter, name: []const u8, value: u64, unit: []const u8) !void {
        try self.out.print("METRIC {s}={d}{s}\n", .{ name, value, unit });
    }

    pub fn speed(self: *StdoutReporter, summary: TestRunner.Summary) !void {
        try self.out.print(
            "SPEED up_bytes={d} down_bytes={d} duration_ms={d} up_mbps={d:.3} down_mbps={d:.3}\n",
            .{
                summary.up_bytes,
                summary.down_bytes,
                @divTrunc(summary.duration_ns, common.grt.time.duration.MilliSecond),
                summary.up_mbps,
                summary.down_mbps,
            },
        );
    }

    pub fn finish(self: *StdoutReporter, summary: TestRunner.Summary) !void {
        try self.out.print("SUMMARY pass={d} skip={d} fail={d}\n", .{ summary.passed, summary.skipped, summary.failed });
        if (summary.failed != 0) return error.E2EFailed;
    }
};

fn printUsage() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\usage: gizclaw-e2e-speed [options]
        \\
        \\Connection:
        \\  --context DIR
        \\  --no-context
        \\  --server-addr ADDR
        \\  --server-pub-key KEY
        \\  --client-pri-key KEY
        \\  --cipher-mode MODE
        \\  --connect-timeout-ms N
        \\
        \\Speed test:
        \\  --bytes N
        \\  --up-bytes N
        \\  --down-bytes N
        \\  --timeout-ms N
        \\
        \\Build defaults:
        \\  -Dserver_addr=ADDR
        \\  -Dserver_pub_key=KEY
        \\  -Dclient_pri_key=KEY
        \\
    );
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();

    const options = try Options.parse(arena.allocator());
    var reporter = StdoutReporter{};
    const summary = try runSelectedSdk(gpa.allocator(), options.config, options.host, &reporter);
    try reporter.finish(summary);
}

fn runSelectedSdk(allocator: std.mem.Allocator, config: TestRunner.Config, host: common.HostOptions, reporter: *StdoutReporter) !TestRunner.Summary {
    var ctx = try common.loadHostContext(allocator, config.base, host);
    defer ctx.deinit();
    return switch (ctx.cipher_mode) {
        .chacha_poly => try TestRunner.runWithContext(common.chacha_sdk, allocator, ctx, config, reporter),
        .aes_256_gcm => try TestRunner.runWithContext(common.aes_256_gcm_sdk, allocator, ctx, config, reporter),
        .plaintext => try TestRunner.runWithContext(common.plaintext_sdk, allocator, ctx, config, reporter),
    };
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
