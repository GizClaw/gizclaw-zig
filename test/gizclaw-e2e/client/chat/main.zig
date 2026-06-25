const std = @import("std");
const common = @import("common");
const TestRunner = @import("TestRunner.zig");

const Options = struct {
    config: TestRunner.Config = .{},
    host: common.HostOptions = .{},
    audio_manifest_file: ?[]const u8 = "test/gizclaw-e2e/testdata/chat/roundtrip/manifest.json",

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
            } else if (std.mem.eql(u8, arg, "--workspace-config")) {
                i += 1;
                out.config.workspace_config = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--workspace")) {
                i += 1;
                out.config.workspace_name = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--mode")) {
                i += 1;
                out.config.mode = try parseMode(try common.needValue(args, i, arg));
            } else if (std.mem.eql(u8, arg, "--audio-manifest")) {
                i += 1;
                out.audio_manifest_file = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--rounds")) {
                i += 1;
                out.config.rounds = try std.fmt.parseInt(u32, try common.needValue(args, i, arg), 10);
            } else if (std.mem.eql(u8, arg, "--run-timeout-ms")) {
                i += 1;
                out.config.run_timeout_ms = try std.fmt.parseInt(u32, try common.needValue(args, i, arg), 10);
            } else if (std.mem.eql(u8, arg, "--conversation-timeout-ms")) {
                i += 1;
                out.config.conversation_timeout_ms = try std.fmt.parseInt(u32, try common.needValue(args, i, arg), 10);
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

    pub fn finish(self: *StdoutReporter, summary: TestRunner.Summary) !void {
        try self.out.print(
            "SUMMARY pass={d} skip={d} fail={d} rounds={d} input_bytes={d} output_bytes={d}\n",
            .{ summary.passed, summary.skipped, summary.failed, summary.rounds, summary.input_bytes, summary.output_bytes },
        );
        if (summary.failed != 0) return error.E2EFailed;
    }
};

fn printUsage() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\usage: gizclaw-e2e-chat [options]
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
        \\Chat:
        \\  --workspace-config FILE
        \\  --workspace NAME
        \\  --mode push_to_talk|realtime
        \\  --audio-manifest FILE
        \\  --rounds N
        \\  --run-timeout-ms N
        \\  --conversation-timeout-ms N
        \\
        \\Build defaults:
        \\  -Dserver_addr=ADDR
        \\  -Dserver_pub_key=KEY
        \\  -Dclient_pri_key=KEY
        \\
    );
}

fn parseMode(raw: []const u8) !TestRunner.Mode {
    if (std.mem.eql(u8, raw, "push_to_talk")) return .push_to_talk;
    if (std.mem.eql(u8, raw, "realtime")) return .realtime;
    return error.InvalidChatMode;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();

    const options = try Options.parse(arena.allocator());
    var config = options.config;
    try loadWorkspaceConfig(arena.allocator(), &config);
    if (options.audio_manifest_file) |path| {
        try loadAudioManifest(arena.allocator(), path, &config);
    }
    var reporter = StdoutReporter{};
    const summary = try runSelectedSdk(arena.allocator(), config, options.host, &reporter);
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

const Manifest = struct {
    rounds: []const Round,

    const Round = struct {
        index: u32,
        audio: []const u8,
        text: []const u8,
    };
};

const WorkspaceConfig = struct {
    workspace: ?[]const u8 = null,
    workflow: ?Workflow = null,
    rounds: ?u32 = null,
    conversation_timeout_ms: ?u32 = null,

    const Workflow = struct {
        name: ?[]const u8 = null,
    };
};

fn loadWorkspaceConfig(allocator: std.mem.Allocator, config: *TestRunner.Config) !void {
    if (config.workspace_config.len == 0) return;
    const data = std.fs.cwd().readFileAlloc(allocator, config.workspace_config, 512 * 1024) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    config.workspace_config_json = data;
    var parsed = try std.json.parseFromSlice(WorkspaceConfig, allocator, data, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    if (config.workspace_name == null) {
        if (parsed.value.workspace) |workspace| {
            if (workspace.len != 0) config.workspace_name = try allocator.dupe(u8, workspace);
        } else if (parsed.value.workflow) |workflow| {
            if (workflow.name) |name| {
                if (name.len != 0) config.workspace_name = try allocator.dupe(u8, name);
            }
        }
    }
}

fn loadAudioManifest(allocator: std.mem.Allocator, path: []const u8, config: *TestRunner.Config) !void {
    const manifest_data = try std.fs.cwd().readFileAlloc(allocator, path, 256 * 1024);
    config.audio_manifest = manifest_data;

    var parsed = try std.json.parseFromSlice(Manifest, allocator, manifest_data, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const base_dir = std.fs.path.dirname(path) orelse ".";
    const assets = try allocator.alloc(TestRunner.ChatAudioAsset, parsed.value.rounds.len);
    for (parsed.value.rounds, 0..) |round, i| {
        if (round.index == 0 or round.audio.len == 0 or round.text.len == 0) return error.InvalidAudioManifest;
        const audio_path = try std.fs.path.join(allocator, &.{ base_dir, round.audio });
        const audio = try std.fs.cwd().readFileAlloc(allocator, audio_path, 4 * 1024 * 1024);
        assets[i] = .{
            .name = try allocator.dupe(u8, round.audio),
            .expected_text = try allocator.dupe(u8, round.text),
            .ogg_opus = audio,
        };
    }
    config.embedded_audio = assets;
}
