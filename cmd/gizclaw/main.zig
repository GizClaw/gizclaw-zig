const std = @import("std");

const context_cmd = @import("commands/context/command.zig");
const device_cmd = @import("commands/device/command.zig");
const ping_cmd = @import("commands/ping/command.zig");
const serverinfo_cmd = @import("commands/serverinfo/command.zig");
const flags_mod = @import("lib/flags.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const raw_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw_args);
    const args = try flags_mod.normalizeLegacyLongFlags(allocator, raw_args[1..]);
    defer {
        for (args) |arg| allocator.free(arg);
        allocator.free(args);
    }

    run(allocator, args) catch |err| {
        var stderr = std.fs.File.stderr().deprecatedWriter();
        try stderr.print("Error: {s}\n", .{errorMessage(err)});
        std.process.exit(1);
    };
}

fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0 or flags_mod.isHelp(args[0])) return printRootHelp();
    if (std.mem.eql(u8, args[0], "context")) return context_cmd.run(allocator, args[1..]);
    if (std.mem.eql(u8, args[0], "device")) return device_cmd.run(allocator, args[1..]);
    if (std.mem.eql(u8, args[0], "ping")) return ping_cmd.run(allocator, args[1..]);
    if (std.mem.eql(u8, args[0], "server-info")) return serverinfo_cmd.run(allocator, args[1..]);
    if (std.mem.eql(u8, args[0], "help")) return printRootHelp();
    return error.UnknownCommand;
}

fn printRootHelp() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\Usage:
        \\  gizclaw context
        \\  gizclaw device
        \\  gizclaw ping [--context name]
        \\  gizclaw server-info [--context name]
        \\
    );
}

fn errorMessage(err: anyerror) []const u8 {
    return switch (err) {
        error.NoActiveContext => "no active context; run 'gizclaw context create' first",
        error.ContextAlreadyExists => "context already exists",
        error.ContextDoesNotExist => "context does not exist",
        error.InvalidContextName => "invalid context name",
        error.InvalidServerPublicKey => "invalid server public key",
        error.MissingServerFlag => "required flag not set: --server",
        error.MissingPubkeyFlag => "required flag not set: --pubkey",
        error.RpcMethodNotFound => "server does not support this RPC method; restart an updated gizclaw-go service",
        error.RpcInvalidRequest => "server rejected RPC request",
        error.RpcInvalidParams => "server rejected RPC params",
        error.RpcInternalError => "server RPC internal error",
        error.RpcError => "server returned an RPC error",
        error.GearNotFound => "gear not found",
        error.GearAlreadyExists => "gear already exists",
        error.BadRequest => "bad request",
        error.UnknownCommand => "unknown command",
        error.InvalidArguments => "invalid arguments",
        else => @errorName(err),
    };
}
