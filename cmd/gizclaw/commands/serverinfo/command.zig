const std = @import("std");
const gizclaw = @import("gizclaw");

const client_lib = @import("../../lib/client.zig");
const flags_mod = @import("../../lib/flags.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
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
