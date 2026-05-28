const std = @import("std");
const gizclaw = @import("gizclaw");
const gstd = @import("gstd");

const flags_mod = @import("../../lib/flags.zig");
const cli_context = @import("../../lib/context.zig");

const key = gizclaw.make(gstd.runtime, .{}).key;

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0 or flags_mod.isHelp(args[0])) return printHelp();
    var store = try cli_context.Store.default(allocator);
    defer store.deinit();

    if (std.mem.eql(u8, args[0], "create")) return runCreate(store, args[1..]);
    if (std.mem.eql(u8, args[0], "use")) return runUse(store, args[1..]);
    if (std.mem.eql(u8, args[0], "list")) return runList(store, args[1..]);
    if (std.mem.eql(u8, args[0], "info")) return runInfo(store, args[1..]);
    if (std.mem.eql(u8, args[0], "show")) return runShow(store, args[1..]);
    return error.UnknownCommand;
}

fn runCreate(store: cli_context.Store, args: []const []const u8) !void {
    var flags = try flags_mod.parse(args);
    if (flags.positionals().len != 1) return error.InvalidArguments;
    const server = flags.value("server") orelse return error.MissingServerFlag;
    const pubkey = flags.value("pubkey") orelse return error.MissingPubkeyFlag;
    try store.create(flags.positionals()[0], server, pubkey);
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print("Context \"{s}\" created.\n", .{flags.positionals()[0]});
}

fn runUse(store: cli_context.Store, args: []const []const u8) !void {
    if (args.len != 1) return error.InvalidArguments;
    try store.use(args[0]);
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print("Switched to context \"{s}\".\n", .{args[0]});
}

fn runList(store: cli_context.Store, args: []const []const u8) !void {
    if (args.len != 0) return error.InvalidArguments;
    var result = try store.list();
    defer result.deinit();
    var out = std.fs.File.stdout().deprecatedWriter();
    if (result.names.len == 0) {
        try out.writeAll("No contexts found.\n");
        return;
    }
    for (result.names) |name| {
        const current = result.current != null and std.mem.eql(u8, name, result.current.?);
        try out.print("{s}{s}\n", .{ if (current) "* " else "  ", name });
    }
}

fn runInfo(store: cli_context.Store, args: []const []const u8) !void {
    if (args.len != 0) return error.InvalidArguments;
    var ctx = (try store.current()) orelse return error.NoActiveContext;
    defer ctx.deinit();
    var result = try store.list();
    defer result.deinit();
    try printContextInfo(cli_context.info(&ctx, result.current orelse ""));
}

fn runShow(store: cli_context.Store, args: []const []const u8) !void {
    if (args.len != 1) return error.InvalidArguments;
    var ctx = try store.loadByName(args[0]);
    defer ctx.deinit();
    var result = try store.list();
    defer result.deinit();
    try printContextInfo(cli_context.info(&ctx, result.current orelse ""));
}

fn printContextInfo(info: cli_context.Info) !void {
    var server_key: [52]u8 = undefined;
    var identity_key: [52]u8 = undefined;
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.print(
        "{{\"name\":\"{s}\",\"current\":{},\"server_address\":\"{s}\",\"server_public_key\":\"{s}\",\"identity_public\":\"{s}\"}}\n",
        .{
            info.name,
            info.current,
            info.server_address,
            key.format(info.server_public_key, &server_key),
            key.format(info.identity_public, &identity_key),
        },
    );
}

fn printHelp() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\Usage:
        \\  gizclaw context create <name> --server <addr> --pubkey <key>
        \\  gizclaw context use <name>
        \\  gizclaw context list
        \\  gizclaw context info
        \\  gizclaw context show <name>
        \\
    );
}
