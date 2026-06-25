const std = @import("std");
const common = @import("common");

pub fn main(comptime Runner: type) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();

    const options = try Options(Runner).parse(arena.allocator());
    var reporter = StdoutReporter(Runner){};
    const summary = try runSelectedSdk(Runner, arena.allocator(), options.config, options.host, &reporter);
    try reporter.finish(summary);
}

fn Options(comptime Runner: type) type {
    return struct {
        config: Runner.Config = .{},
        host: common.HostOptions = .{},

        fn parse(allocator: std.mem.Allocator) !@This() {
            const args = try std.process.argsAlloc(allocator);
            var out = @This(){};
            var i: usize = 1;
            while (i < args.len) : (i += 1) {
                if (try out.host.applyArg(args, &i)) continue;
                if (try out.config.base.applyArg(args, &i)) continue;
                const arg = args[i];
                if (std.mem.eql(u8, arg, "--help")) {
                    try printUsage();
                    std.process.exit(0);
                } else if (std.mem.eql(u8, arg, "--allow-mutations")) {
                    out.config.allow_mutations = true;
                } else if (std.mem.eql(u8, arg, "--workspace")) {
                    i += 1;
                    out.config.fixtures.workspace = try common.needValue(args, i, arg);
                } else if (std.mem.eql(u8, arg, "--run-workspace")) {
                    i += 1;
                    out.config.fixtures.run_workspace = try common.needValue(args, i, arg);
                } else if (std.mem.eql(u8, arg, "--credential-name")) {
                    i += 1;
                    out.config.fixtures.credential_name = try common.needValue(args, i, arg);
                } else if (std.mem.eql(u8, arg, "--voice-id")) {
                    i += 1;
                    out.config.fixtures.voice_id = try common.needValue(args, i, arg);
                } else if (std.mem.eql(u8, arg, "--firmware-id")) {
                    i += 1;
                    out.config.fixtures.firmware_id = try common.needValue(args, i, arg);
                } else {
                    return error.UnknownArgument;
                }
            }
            return out;
        }
    };
}

fn StdoutReporter(comptime Runner: type) type {
    return struct {
        out: @TypeOf(std.fs.File.stdout().deprecatedWriter()) = std.fs.File.stdout().deprecatedWriter(),

        pub fn pass(self: *@This(), name: []const u8) !void {
            try self.out.print("PASS {s}\n", .{name});
        }

        pub fn fail(self: *@This(), name: []const u8, err: anyerror) !void {
            try self.out.print("FAIL {s}: {s}\n", .{ name, @errorName(err) });
        }

        pub fn finish(self: *@This(), summary: Runner.Summary) !void {
            try self.out.print("SUMMARY pass={d} skip={d} fail={d}\n", .{ summary.passed, summary.skipped, summary.failed });
            if (summary.failed != 0) return error.E2EFailed;
        }
    };
}

fn printUsage() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\usage: gizclaw-e2e-rpc [options]
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
        \\RPC fixtures:
        \\  --workspace NAME
        \\  --run-workspace NAME
        \\  --credential-name NAME
        \\  --voice-id ID
        \\  --firmware-id ID
        \\  --allow-mutations
        \\
        \\Build defaults:
        \\  -Dserver_addr=ADDR
        \\  -Dserver_pub_key=KEY
        \\  -Dclient_pri_key=KEY
        \\
    );
}

fn runSelectedSdk(
    comptime Runner: type,
    allocator: std.mem.Allocator,
    config: Runner.Config,
    host: common.HostOptions,
    reporter: anytype,
) !Runner.Summary {
    var ctx = try common.loadHostContext(allocator, config.base, host);
    defer ctx.deinit();
    return switch (ctx.cipher_mode) {
        .chacha_poly => try Runner.runWithContext(common.chacha_sdk, allocator, ctx, config, reporter),
        .aes_256_gcm => try Runner.runWithContext(common.aes_256_gcm_sdk, allocator, ctx, config, reporter),
        .plaintext => try Runner.runWithContext(common.plaintext_sdk, allocator, ctx, config, reporter),
    };
}
