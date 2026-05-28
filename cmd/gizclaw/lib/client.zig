const std = @import("std");
const gstd = @import("gstd");
const gizclaw = @import("gizclaw");

const cli_context = @import("context.zig");

const grt = gstd.runtime;
const sdk = gizclaw.make(grt, .{});
pub const Client = sdk.Client;
pub const models = sdk.models;

pub fn initFromContext(allocator: std.mem.Allocator, ctx: *const cli_context.Context) !Client {
    return try Client.init(allocator, .{
        .key_pair = ctx.key_pair,
    });
}

pub fn connect(client: *Client, ctx: *const cli_context.Context) !void {
    try client.connect(.{
        .server_key = ctx.config.server.public_key,
        .server_addr = ctx.config.server.address,
    });
}

pub fn loadSelectedContext(allocator: std.mem.Allocator, name: ?[]const u8) !cli_context.Context {
    var store = try cli_context.Store.default(allocator);
    defer store.deinit();
    if (name) |ctx_name| return try store.loadByName(ctx_name);
    return (try store.current()) orelse error.NoActiveContext;
}

pub fn armNetworkWatchdog() void {
    const thread = std.Thread.spawn(.{}, networkWatchdog, .{}) catch return;
    thread.detach();
}

fn networkWatchdog() void {
    std.Thread.sleep(10 * std.time.ns_per_s);
    var stderr = std.fs.File.stderr().deprecatedWriter();
    stderr.writeAll("Error: network operation timed out\n") catch {};
    std.process.exit(124);
}
