const std = @import("std");

const client_lib = @import("../../lib/client.zig");
const flags_mod = @import("../../lib/flags.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
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

    var info = try client.setDeviceName(positionals[0]);
    defer client_lib.Client.deinitDeviceInfo(allocator, &info);
    try printDeviceInfo(allocator, info);
}

fn printDeviceInfo(allocator: std.mem.Allocator, info: anytype) !void {
    const data = try client_lib.models.toJson(allocator, info);
    defer allocator.free(data);
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{s}\n", .{data});
}

pub fn printHelp() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\Usage:
        \\  gizclaw set-name <name> [--context name]
        \\
    );
}
