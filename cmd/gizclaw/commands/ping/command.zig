const std = @import("std");

const client_lib = @import("../../lib/client.zig");
const flags_mod = @import("../../lib/flags.zig");
const fmt = @import("../../lib/format.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    client_lib.armNetworkWatchdog();
    const flags = try flags_mod.parse(args);
    if (flags.positionals().len != 0) return error.InvalidArguments;
    var ctx = try client_lib.loadSelectedContext(allocator, flags.value("context"));
    defer ctx.deinit();
    var client = try client_lib.connectFromContext(allocator, &ctx);
    defer client.deinit();

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
