const std = @import("std");

const client_lib = @import("../../lib/client.zig");
const flags_mod = @import("../../lib/flags.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0 or flags_mod.isHelp(args[0])) return printHelp();
    if (std.mem.eql(u8, args[0], "info")) return runInfo(allocator, args[1..]);
    if (std.mem.eql(u8, args[0], "set-name")) return runSetName(allocator, args[1..]);
    return error.UnknownCommand;
}

fn runInfo(allocator: std.mem.Allocator, args: []const []const u8) !void {
    client_lib.armNetworkWatchdog();
    const flags = try flags_mod.parse(args);
    if (flags.positionals().len != 0) return error.InvalidArguments;
    var ctx = try client_lib.loadSelectedContext(allocator, flags.value("context"));
    defer ctx.deinit();
    var client = try client_lib.connectFromContext(allocator, &ctx);
    defer client.deinit();

    var info = try client.deviceInfo();
    defer client_lib.Client.deinitDeviceInfo(allocator, &info);
    try printDeviceInfo(info);
}

fn runSetName(allocator: std.mem.Allocator, args: []const []const u8) !void {
    client_lib.armNetworkWatchdog();
    const flags = try flags_mod.parse(args);
    const positionals = flags.positionals();
    if (positionals.len != 1) return error.InvalidArguments;
    var ctx = try client_lib.loadSelectedContext(allocator, flags.value("context"));
    defer ctx.deinit();
    var client = try client_lib.connectFromContext(allocator, &ctx);
    defer client.deinit();

    var info = try client.setDeviceName(positionals[0]);
    defer client_lib.Client.deinitDeviceInfo(allocator, &info);
    try printDeviceInfo(info);
}

fn printDeviceInfo(info: anytype) !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{f}\n", .{std.json.fmt(info, .{})});
}

fn printHelp() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\Usage:
        \\  gizclaw device info [--context name]
        \\  gizclaw device set-name <name> [--context name]
        \\
    );
}
