const std = @import("std");

const client_lib = @import("../../lib/client.zig");
const flags_mod = @import("../../lib/flags.zig");
const fmt = @import("../../lib/format.zig");

const default_content_length: i64 = 10 * 1024 * 1024;
const default_timeout: i64 = 30 * std.time.ns_per_s;

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0 or flags_mod.isHelp(args[0])) return printHelp();
    if (std.mem.eql(u8, args[0], "ping")) {
        if (args.len > 1 and flags_mod.isHelp(args[1])) return printPingHelp();
        return runPing(allocator, args[1..]);
    }
    if (std.mem.eql(u8, args[0], "server-info")) {
        if (args.len > 1 and flags_mod.isHelp(args[1])) return printServerInfoHelp();
        return runServerInfo(allocator, args[1..]);
    }
    if (std.mem.eql(u8, args[0], "set-name")) {
        if (args.len > 1 and flags_mod.isHelp(args[1])) return printSetNameHelp();
        return runSetName(allocator, args[1..]);
    }
    if (std.mem.eql(u8, args[0], "test-speed")) {
        if (args.len > 1 and flags_mod.isHelp(args[1])) return printTestSpeedHelp();
        return runTestSpeed(allocator, args[1..]);
    }
    return error.UnknownCommand;
}

fn runPing(allocator: std.mem.Allocator, args: []const []const u8) !void {
    client_lib.armNetworkWatchdog();
    const flags = try flags_mod.parse(args);
    if (flags.positionals().len != 0) return error.InvalidArguments;
    var ctx = try client_lib.loadSelectedContext(allocator, flags.value("context"));
    defer ctx.deinit();
    var client = try client_lib.initFromContext(allocator, &ctx);
    defer client.deinit();
    try client_lib.connect(&client, &ctx);

    const start = std.time.nanoTimestamp();
    const ping = try client.ping();
    const stop = std.time.nanoTimestamp();
    const rtt_ns = stop - start;
    const mid_ms = @divTrunc(@divTrunc(start, std.time.ns_per_ms) + @divTrunc(stop, std.time.ns_per_ms), 2);
    const clock_diff_ms = ping.server_time - mid_ms;

    var time_buf: [64]u8 = undefined;
    var rtt_buf: [64]u8 = undefined;
    var diff_buf: [64]u8 = undefined;
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print(
        "Server Time: {s}\nRTT:         {s}\nClock Diff:  {s}\n",
        .{
            try fmt.unixMilli(&time_buf, ping.server_time),
            try fmt.duration(&rtt_buf, rtt_ns),
            try fmt.duration(&diff_buf, clock_diff_ms * std.time.ns_per_ms),
        },
    );
}

fn runServerInfo(allocator: std.mem.Allocator, args: []const []const u8) !void {
    client_lib.armNetworkWatchdog();
    const flags = try flags_mod.parse(args);
    if (flags.positionals().len != 0) return error.InvalidArguments;
    var ctx = try client_lib.loadSelectedContext(allocator, flags.value("context"));
    defer ctx.deinit();
    var client = try client_lib.initFromContext(allocator, &ctx);
    defer client.deinit();
    try client_lib.connect(&client, &ctx);
    var info = try client.serverInfo();
    defer client_lib.Client.deinitServerInfo(allocator, &info);

    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print(
        "{{\"public_key\":{f},\"server_time\":{d},\"build_commit\":{f}}}\n",
        .{ std.json.fmt(info.public_key, .{}), info.server_time, std.json.fmt(info.build_commit, .{}) },
    );
}

fn runSetName(allocator: std.mem.Allocator, args: []const []const u8) !void {
    client_lib.armNetworkWatchdog();
    const flags = try flags_mod.parse(args);
    const positionals = flags.positionals();
    if (positionals.len != 1) return error.InvalidArguments;
    if (std.mem.trim(u8, positionals[0], " \t\r\n").len == 0) return error.EmptyDeviceName;

    var ctx = try client_lib.loadSelectedContext(allocator, flags.value("context"));
    defer ctx.deinit();
    var client = try client_lib.initFromContext(allocator, &ctx);
    defer client.deinit();
    try client_lib.connect(&client, &ctx);

    var info = try client.setPeerName(positionals[0]);
    defer client_lib.Client.deinitDeviceInfo(allocator, &info);
    try printDeviceInfo(allocator, info);
}

fn runTestSpeed(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const flags = try flags_mod.parse(args);
    if (flags.positionals().len != 0) return error.InvalidArguments;

    const up_content_length = try parseI64Flag(flags, "up-content-length", default_content_length);
    const down_content_length = try parseI64Flag(flags, "down-content-length", default_content_length);
    const timeout_ns = try parseDurationFlag(flags, "timeout", default_timeout);

    client_lib.armNetworkWatchdogAfter(@intCast(timeout_ns + 5 * std.time.ns_per_s));
    var ctx = try client_lib.loadSelectedContext(allocator, flags.value("context"));
    defer ctx.deinit();
    var client = try client_lib.initFromContext(allocator, &ctx);
    defer client.deinit();
    try client_lib.connect(&client, &ctx);

    const result = try client.speedTest(.{
        .up_content_length = up_content_length,
        .down_content_length = down_content_length,
    }, timeout_ns);

    var duration_buf: [64]u8 = undefined;
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print(
        "Up Bytes:     {d}\nDown Bytes:   {d}\nDuration:     {s}\nUp Speed:     {d:.2} Mbps\nDown Speed:   {d:.2} Mbps\n",
        .{
            result.up_bytes,
            result.down_bytes,
            try fmt.duration(&duration_buf, result.duration_ns),
            result.upMbps(),
            result.downMbps(),
        },
    );
}

fn printDeviceInfo(allocator: std.mem.Allocator, info: anytype) !void {
    const data = try client_lib.models.toJson(allocator, info);
    defer allocator.free(data);
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{s}\n", .{data});
}

fn parseI64Flag(flags: flags_mod.Parsed, name: []const u8, default: i64) !i64 {
    const value = flags.value(name) orelse return default;
    return try std.fmt.parseInt(i64, value, 10);
}

fn parseDurationFlag(flags: flags_mod.Parsed, name: []const u8, default: i64) !i64 {
    const value = flags.value(name) orelse return default;
    return parseDuration(value) catch error.InvalidArguments;
}

fn parseDuration(value: []const u8) !i64 {
    if (value.len == 0) return error.InvalidArguments;
    var number_len: usize = 0;
    while (number_len < value.len and std.ascii.isDigit(value[number_len])) : (number_len += 1) {}
    if (number_len == 0) return error.InvalidArguments;
    const amount = try std.fmt.parseInt(i64, value[0..number_len], 10);
    if (amount < 0) return error.InvalidArguments;
    const unit = value[number_len..];
    const multiplier: i64 = if (unit.len == 0 or std.mem.eql(u8, unit, "s"))
        std.time.ns_per_s
    else if (std.mem.eql(u8, unit, "ms"))
        std.time.ns_per_ms
    else if (std.mem.eql(u8, unit, "us"))
        std.time.ns_per_us
    else if (std.mem.eql(u8, unit, "ns"))
        1
    else if (std.mem.eql(u8, unit, "m"))
        60 * std.time.ns_per_s
    else if (std.mem.eql(u8, unit, "h"))
        60 * 60 * std.time.ns_per_s
    else
        return error.InvalidArguments;
    return std.math.mul(i64, amount, multiplier) catch error.InvalidArguments;
}

fn printHelp() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\Usage:
        \\  gizclaw peer ping [--context name]
        \\  gizclaw peer server-info [--context name]
        \\  gizclaw peer set-name <name> [--context name]
        \\  gizclaw peer test-speed [--up-content-length bytes] [--down-content-length bytes] [--timeout duration] [--context name]
        \\
    );
}

fn printSetNameHelp() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\Usage:
        \\  gizclaw peer set-name <name> [--context name]
        \\
    );
}

fn printPingHelp() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\Usage:
        \\  gizclaw peer ping [--context name]
        \\
    );
}

fn printServerInfoHelp() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\Usage:
        \\  gizclaw peer server-info [--context name]
        \\
    );
}

fn printTestSpeedHelp() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\Usage:
        \\  gizclaw peer test-speed [--up-content-length bytes] [--down-content-length bytes] [--timeout duration] [--context name]
        \\
    );
}
