const std = @import("std");
const common = @import("common");

const WorkspaceOptions = struct {
    base: common.BaseOptions = .{},
    config: []const u8 = "test/gizclaw-e2e/workspace/config/doubao-realtime.example.json",
    skip_run_control: bool = false,
    conversation_smoke: bool = false,
    run_timeout_ms: ?i64 = null,
    conversation_timeout_ms: ?i64 = null,
    opus_packets_base64_file: ?[]const u8 = null,

    fn parse(allocator: std.mem.Allocator) !WorkspaceOptions {
        const args = try std.process.argsAlloc(allocator);
        var out = WorkspaceOptions{};
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (try out.base.applyArg(args, &i)) continue;
            const arg = args[i];
            if (std.mem.eql(u8, arg, "--help")) {
                try printUsage();
                std.process.exit(0);
            } else if (std.mem.eql(u8, arg, "--config")) {
                i += 1;
                out.config = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--skip-run-control")) {
                out.skip_run_control = true;
            } else if (std.mem.eql(u8, arg, "--conversation-smoke")) {
                out.conversation_smoke = true;
            } else if (std.mem.eql(u8, arg, "--run-timeout-ms")) {
                i += 1;
                out.run_timeout_ms = try std.fmt.parseInt(i64, try common.needValue(args, i, arg), 10);
            } else if (std.mem.eql(u8, arg, "--conversation-timeout-ms")) {
                i += 1;
                out.conversation_timeout_ms = try std.fmt.parseInt(i64, try common.needValue(args, i, arg), 10);
            } else if (std.mem.eql(u8, arg, "--opus-packets-base64-file")) {
                i += 1;
                out.opus_packets_base64_file = try common.needValue(args, i, arg);
            } else {
                return error.UnknownArgument;
            }
        }
        return out;
    }
};

fn printUsage() !void {
    var out = std.fs.File.stdout().deprecatedWriter();
    try out.writeAll(
        \\usage: gizclaw-e2e-workspace [options]
        \\
        \\Connection:
        \\  --context DIR          Go setup context dir with config.yaml and identity.key
        \\  --no-context           Use explicit --server-* and --client-key values
        \\  --server-addr ADDR     Remote GizClaw server address
        \\  --server-key KEY       Remote GizClaw server public key
        \\  --client-key KEY       Client private key
        \\  --cipher-mode MODE     chacha_poly, aes_256_gcm, or plaintext
        \\  --connect-timeout-ms N Milliseconds to wait for the GizNet handshake
        \\
        \\Workspace:
        \\  --config FILE          doubao-realtime workspace config JSON
        \\  --skip-run-control     Only create/update workflow and workspace
        \\  --conversation-smoke   Send real speech Opus packets and observe event/audio output
        \\  --opus-packets-base64-file FILE
        \\                         Base64 encoded Opus packets, one packet per line
        \\  --run-timeout-ms N     Milliseconds to wait for the workspace to report running
        \\  --conversation-timeout-ms N
        \\                         Milliseconds to observe the optional conversation smoke
        \\
    );
}

const WorkspaceConfig = struct {
    parsed: std.json.Parsed(std.json.Value),

    pub fn deinit(self: *WorkspaceConfig) void {
        self.parsed.deinit();
        self.* = undefined;
    }

    fn root(self: *const WorkspaceConfig) std.json.Value {
        return self.parsed.value;
    }

    fn string(self: *const WorkspaceConfig, path: []const []const u8) ![]const u8 {
        var value = self.root();
        for (path) |name| {
            value = value.object.get(name) orelse return error.MissingConfigField;
        }
        return switch (value) {
            .string => |text| text,
            else => error.InvalidConfigField,
        };
    }

    fn optionalObject(self: *const WorkspaceConfig, path: []const []const u8) ?std.json.ObjectMap {
        var value = self.root();
        for (path) |name| value = value.object.get(name) orelse return null;
        return switch (value) {
            .object => |object| object,
            else => null,
        };
    }

    fn optionalInteger(self: *const WorkspaceConfig, path: []const []const u8, default: i64) i64 {
        var value = self.root();
        for (path) |name| value = value.object.get(name) orelse return default;
        return switch (value) {
            .integer => |integer| integer,
            else => default,
        };
    }

    fn optionalString(self: *const WorkspaceConfig, path: []const []const u8) ?[]const u8 {
        var value = self.root();
        for (path) |name| value = value.object.get(name) orelse return null;
        return switch (value) {
            .string => |text| if (text.len == 0) null else text,
            else => null,
        };
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    const options = try WorkspaceOptions.parse(allocator);
    var ctx = try common.loadContext(allocator, options.base);
    defer ctx.deinit();
    var cfg = try loadWorkspaceConfig(allocator, options.config);
    defer cfg.deinit();

    switch (ctx.cipher_mode) {
        .chacha_poly => try runWithSdk(common.chacha_sdk, allocator, &ctx, &cfg, options),
        .aes_256_gcm => try runWithSdk(common.aes_256_gcm_sdk, allocator, &ctx, &cfg, options),
        .plaintext => try runWithSdk(common.plaintext_sdk, allocator, &ctx, &cfg, options),
    }
}

fn runWithSdk(comptime sdk: type, allocator: std.mem.Allocator, ctx: *const common.Context, cfg: *const WorkspaceConfig, options: WorkspaceOptions) !void {
    var summary = common.Summary.init();
    var client = common.connectClient(sdk, allocator, ctx) catch |err| {
        try summary.fail("Connect", err);
        return summary.finish();
    };
    defer client.deinit();
    try summary.pass("Connect");

    try ensureWorkflow(sdk, allocator, &client, cfg, &summary);
    try ensureWorkspace(sdk, allocator, &client, cfg, &summary);
    if (!options.skip_run_control) {
        try runControl(sdk, &client, cfg, &summary, options.run_timeout_ms);
        try checkPeerEventStream(sdk, &client, &summary);
        try checkServerRunSay(sdk, &client, cfg, &summary);
        if (options.conversation_smoke) {
            try runConversationSmoke(sdk, allocator, &client, cfg, &summary, options);
        } else {
            try summary.skip("StampedOpusConversation", "enable with --conversation-smoke");
        }
    } else {
        try summary.skip("SetServerRunAgent", "disabled by --skip-run-control");
        try summary.skip("ReloadServerRun", "disabled by --skip-run-control");
        try summary.skip("WaitServerRunStatus", "disabled by --skip-run-control");
        try summary.skip("OpenPeerEventStream", "disabled by --skip-run-control");
        try summary.skip("ServerRunSay", "disabled by --skip-run-control");
        try summary.skip("StampedOpusConversation", "disabled by --skip-run-control");
    }
    try summary.finish();
}

fn loadWorkspaceConfig(allocator: std.mem.Allocator, path: []const u8) !WorkspaceConfig {
    const data = try std.fs.cwd().readFileAlloc(allocator, path, 256 * 1024);
    defer allocator.free(data);
    return .{
        .parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{}),
    };
}

fn ensureWorkflow(comptime sdk: type, allocator: std.mem.Allocator, client: *sdk.Client, cfg: *const WorkspaceConfig, summary: *common.Summary) !void {
    const name = try cfg.string(&.{ "workflow", "name" });
    var workflow = try workflowDocument(sdk, allocator, cfg);
    defer workflow.deinit();

    if (client.createWorkflow(workflow.value)) |created| {
        var parsed = created;
        defer parsed.deinit();
        try summary.pass("CreateWorkflow");
    } else |err| switch (err) {
        error.GearAlreadyExists => {
            if (client.putWorkflow(.{ .name = name, .body = workflow.value })) |updated| {
                var parsed = updated;
                defer parsed.deinit();
                try summary.pass("PutWorkflow");
            } else |put_err| try summary.fail("PutWorkflow", put_err);
        },
        else => try summary.fail("CreateWorkflow", err),
    }
}

fn ensureWorkspace(comptime sdk: type, allocator: std.mem.Allocator, client: *sdk.Client, cfg: *const WorkspaceConfig, summary: *common.Summary) !void {
    const name = try cfg.string(&.{"workspace"});
    var workspace = try workspaceDocument(sdk, allocator, cfg);
    defer workspace.deinit();

    if (client.createWorkspace(workspace.value)) |created| {
        var parsed = created;
        defer parsed.deinit();
        try summary.pass("CreateWorkspace");
    } else |err| switch (err) {
        error.GearAlreadyExists => {
            if (client.putWorkspace(.{ .name = name, .body = workspace.value })) |updated| {
                var parsed = updated;
                defer parsed.deinit();
                try summary.pass("PutWorkspace");
            } else |put_err| try summary.fail("PutWorkspace", put_err);
        },
        else => try summary.fail("CreateWorkspace", err),
    }
}

fn runControl(comptime sdk: type, client: *sdk.Client, cfg: *const WorkspaceConfig, summary: *common.Summary, timeout_ms_override: ?i64) !void {
    const workspace = try cfg.string(&.{"workspace"});
    if (client.setServerRunAgent(.{ .workspace_name = workspace })) |selected| {
        var parsed = selected;
        defer parsed.deinit();
        try summary.pass("SetServerRunAgent");
    } else |err| try summary.fail("SetServerRunAgent", err);

    if (client.reloadServerRun()) |reloaded| {
        var parsed = reloaded;
        defer parsed.deinit();
        try summary.pass("ReloadServerRun");
    } else |err| {
        if (try isWorkspaceRunning(sdk, client, workspace)) {
            try summary.pass("ReloadServerRun");
        } else {
            try summary.fail("ReloadServerRun", err);
        }
    }

    try waitForRunStatus(sdk, client, cfg, summary, workspace, timeout_ms_override);
}

fn isWorkspaceRunning(comptime sdk: type, client: *sdk.Client, workspace: []const u8) !bool {
    var status = client.getServerRunStatus(.{}) catch return false;
    defer status.deinit();
    const workspace_matches = if (status.value.workspace_name) |name|
        std.mem.eql(u8, name, workspace)
    else
        false;
    return std.mem.eql(u8, status.value.state, "running") and workspace_matches;
}

fn waitForRunStatus(
    comptime sdk: type,
    client: *sdk.Client,
    cfg: *const WorkspaceConfig,
    summary: *common.Summary,
    workspace: []const u8,
    timeout_ms_override: ?i64,
) !void {
    const timeout_ms = timeout_ms_override orelse cfg.optionalInteger(&.{"run_timeout_ms"}, 30_000);
    const deadline = std.time.milliTimestamp() + @max(timeout_ms, 1);
    while (std.time.milliTimestamp() <= deadline) {
        var status = client.getServerRunStatus(.{}) catch |err| return summary.fail("WaitServerRunStatus", err);
        defer status.deinit();
        const workspace_matches = if (status.value.workspace_name) |name|
            std.mem.eql(u8, name, workspace)
        else
            false;
        if (std.mem.eql(u8, status.value.state, "running") and workspace_matches) {
            return summary.pass("WaitServerRunStatus");
        }
        if (std.mem.eql(u8, status.value.state, "error")) {
            return summary.fail("WaitServerRunStatus", error.WorkspaceRunError);
        }
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }
    try summary.fail("WaitServerRunStatus", error.WorkspaceRunTimeout);
}

fn checkPeerEventStream(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    if (client.openPeerEventStream()) |stream| {
        var peer_events = stream;
        peer_events.deinit();
        try summary.pass("OpenPeerEventStream");
    } else |err| try summary.fail("OpenPeerEventStream", err);
}

fn checkServerRunSay(comptime sdk: type, client: *sdk.Client, cfg: *const WorkspaceConfig, summary: *common.Summary) !void {
    const voice = cfg.string(&.{"voice"}) catch {
        return summary.skip("ServerRunSay", "workspace config has no voice fixture");
    };
    if (client.serverRunSay(.{
        .text = "hello from gizclaw-zig workspace e2e",
        .voice_id = voice,
    })) |response| {
        var parsed = response;
        defer parsed.deinit();
        try summary.pass("ServerRunSay");
    } else |err| try summary.fail("ServerRunSay", err);
}

const ConversationStats = struct {
    events: usize = 0,
    transcript_events: usize = 0,
    assistant_events: usize = 0,
    eos_events: usize = 0,
    audio_packets: usize = 0,
    audio_bytes: usize = 0,
    text_bytes: usize = 0,
    first_event_ms: ?i64 = null,
    first_transcript_ms: ?i64 = null,
    first_assistant_text_ms: ?i64 = null,
    first_assistant_done_ms: ?i64 = null,
    first_audio_ms: ?i64 = null,
    first_eos_ms: ?i64 = null,
    last_event_ms: ?i64 = null,
    last_audio_ms: ?i64 = null,
};

fn runConversationSmoke(
    comptime sdk: type,
    allocator: std.mem.Allocator,
    client: *sdk.Client,
    cfg: *const WorkspaceConfig,
    summary: *common.Summary,
    options: WorkspaceOptions,
) !void {
    const packet_file = options.opus_packets_base64_file orelse cfg.optionalString(&.{"opus_packets_base64_file"}) orelse {
        return summary.skip("StampedOpusConversation", "requires --opus-packets-base64-file with real speech Opus packets");
    };
    var packets = try loadBase64Packets(allocator, packet_file);
    defer deinitPackets(allocator, &packets);
    if (packets.items.len == 0) return summary.fail("StampedOpusConversation", error.EmptyOpusFixture);

    const timeout_ms = options.conversation_timeout_ms orelse cfg.optionalInteger(&.{"conversation_timeout_ms"}, 10_000);
    const timeout = durationFromMillis(timeout_ms);
    var stream = client.openPeerStream(.{ .read_timeout = timeout }) catch |err| return summary.fail("StampedOpusConversation", err);
    defer stream.deinit();

    const send_started_at = std.time.milliTimestamp();
    client.beginPeerAudio(&stream, .{
        .stream_id = "audio",
        .label = "workspacetest",
        .timestamp = send_started_at,
    }) catch |err| return summary.fail("StampedOpusConversation", err);
    for (packets.items, 0..) |packet, i| {
        client.writePeerAudio(&stream, .{
            .timestamp = @intCast(@as(i64, @intCast(send_started_at)) + @as(i64, @intCast(i)) * 20),
            .frame = packet,
        }) catch |err| return summary.fail("StampedOpusConversation", err);
        if (i + 1 < packets.items.len) std.Thread.sleep(20 * std.time.ns_per_ms);
    }
    client.endPeerAudio(&stream, .{
        .stream_id = "audio",
        .label = "workspacetest",
        .timestamp = send_started_at + @as(i64, @intCast(packets.items.len)) * 20,
    }) catch |err| return summary.fail("StampedOpusConversation", err);
    const send_finished_at = std.time.milliTimestamp();

    try summary.out.print(
        "INFO ConversationTurn input_packets={d} input_audio_ms={d} send_elapsed_ms={d}\n",
        .{ packets.items.len, packets.items.len * 20, send_finished_at - send_started_at },
    );

    var stats = ConversationStats{};
    var opus_buf: [16 * 1024]u8 = undefined;
    const deadline = std.time.milliTimestamp() + @max(timeout_ms, 1);
    while (std.time.milliTimestamp() <= deadline and (stats.audio_packets == 0 or stats.eos_events == 0)) {
        if (client.readPeerStreamChunk(&stream, &opus_buf)) |chunk_result| {
            var result = chunk_result;
            defer result.deinit();
            switch (result.chunk()) {
                .event => |event| {
                    const now = std.time.milliTimestamp();
                    const elapsed_ms = now - send_started_at;
                    stats.events += 1;
                    if (stats.first_event_ms == null) stats.first_event_ms = elapsed_ms;
                    stats.last_event_ms = elapsed_ms;
                    if (event.label) |label| {
                        if (std.mem.eql(u8, label, "transcript")) {
                            stats.transcript_events += 1;
                            if (stats.first_transcript_ms == null) stats.first_transcript_ms = elapsed_ms;
                        }
                        if (std.mem.eql(u8, label, "assistant")) {
                            stats.assistant_events += 1;
                            if (event.text != null and stats.first_assistant_text_ms == null) stats.first_assistant_text_ms = elapsed_ms;
                            if (event.type == .text_done and stats.first_assistant_done_ms == null) stats.first_assistant_done_ms = elapsed_ms;
                        }
                    }
                    if (event.type == .eos) {
                        stats.eos_events += 1;
                        if (stats.first_eos_ms == null) stats.first_eos_ms = elapsed_ms;
                    }
                    if (event.text) |value| stats.text_bytes += value.len;
                    try printConversationEvent(&summary.out, elapsed_ms, event);
                },
                .stamped_opus => |frame| {
                    const now = std.time.milliTimestamp();
                    const elapsed_ms = now - send_started_at;
                    stats.audio_packets += 1;
                    stats.audio_bytes += frame.frame.len;
                    if (stats.first_audio_ms == null) stats.first_audio_ms = elapsed_ms;
                    stats.last_audio_ms = elapsed_ms;
                    try summary.out.print(
                        "AUDIO ConversationTurn +{d}ms timestamp={d} bytes={d} packet={d}\n",
                        .{ elapsed_ms, frame.timestamp, frame.frame.len, stats.audio_packets },
                    );
                },
            }
        } else |err| switch (err) {
            error.Timeout, error.EndOfStream => {},
            else => return summary.fail("StampedOpusConversation", err),
        }
    }

    if (stats.events == 0) {
        return summary.fail("StampedOpusConversation", error.MissingConversationEvents);
    }
    if (stats.audio_packets == 0) {
        return summary.fail("StampedOpusConversation", error.MissingConversationAudio);
    }
    try summary.pass("StampedOpusConversation");
    try summary.out.print(
        "INFO StampedOpusConversation input_packets={d} events={d} transcript_events={d} assistant_events={d} eos_events={d} text_bytes={d} audio_packets={d} audio_bytes={d}",
        .{
            packets.items.len,
            stats.events,
            stats.transcript_events,
            stats.assistant_events,
            stats.eos_events,
            stats.text_bytes,
            stats.audio_packets,
            stats.audio_bytes,
        },
    );
    try printOptionalMs(&summary.out, "first_event_ms", stats.first_event_ms);
    try printOptionalMs(&summary.out, "first_transcript_ms", stats.first_transcript_ms);
    try printOptionalMs(&summary.out, "first_assistant_text_ms", stats.first_assistant_text_ms);
    try printOptionalMs(&summary.out, "first_assistant_done_ms", stats.first_assistant_done_ms);
    try printOptionalMs(&summary.out, "first_audio_ms", stats.first_audio_ms);
    try printOptionalMs(&summary.out, "first_eos_ms", stats.first_eos_ms);
    try printOptionalMs(&summary.out, "last_event_ms", stats.last_event_ms);
    try printOptionalMs(&summary.out, "last_audio_ms", stats.last_audio_ms);
    try summary.out.writeAll("\n");
}

fn printConversationEvent(out: anytype, elapsed_ms: i64, event: anytype) !void {
    try out.print("EVENT ConversationTurn +{d}ms type={s}", .{ elapsed_ms, peerStreamEventTypeName(event.type) });
    if (event.kind) |kind| try out.print(" kind={s}", .{peerStreamKindName(kind)});
    if (event.label) |label| try out.print(" label={s}", .{label});
    if (event.stream_id) |stream_id| try out.print(" stream_id={s}", .{stream_id});
    if (event.seq) |seq| try out.print(" seq={d}", .{seq});
    if (event.timestamp) |timestamp| try out.print(" timestamp={d}", .{timestamp});
    if (event.text) |text| {
        try out.writeAll(" text=");
        try printJsonString(out, text);
    }
    if (event.@"error") |message| {
        try out.writeAll(" error=");
        try printJsonString(out, message);
    }
    try out.writeAll("\n");
}

fn printJsonString(out: anytype, text: []const u8) !void {
    try out.writeAll("\"");
    for (text) |byte| switch (byte) {
        '\\' => try out.writeAll("\\\\"),
        '"' => try out.writeAll("\\\""),
        '\n' => try out.writeAll("\\n"),
        '\r' => try out.writeAll("\\r"),
        '\t' => try out.writeAll("\\t"),
        else => {
            if (byte < 0x20) {
                try out.print("\\u{x:0>4}", .{byte});
            } else {
                try out.writeByte(byte);
            }
        },
    };
    try out.writeAll("\"");
}

fn peerStreamEventTypeName(value: anytype) []const u8 {
    return switch (value) {
        .bos => "bos",
        .eos => "eos",
        .text_delta => "text.delta",
        .text_done => "text.done",
    };
}

fn peerStreamKindName(value: anytype) []const u8 {
    return switch (value) {
        .audio => "audio",
        .mixed => "mixed",
        .text => "text",
        .video => "video",
    };
}

fn printOptionalMs(out: anytype, name: []const u8, value: ?i64) !void {
    try out.print(" {s}=", .{name});
    if (value) |ms| {
        try out.print("{d}", .{ms});
    } else {
        try out.writeAll("null");
    }
}

fn loadBase64Packets(allocator: std.mem.Allocator, path: []const u8) !std.ArrayList([]u8) {
    const data = try std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024 * 1024);
    defer allocator.free(data);

    var packets = std.ArrayList([]u8){};
    errdefer deinitPackets(allocator, &packets);
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        const packet = try decodeBase64Alloc(allocator, trimmed);
        if (packet.len == 0) {
            allocator.free(packet);
            continue;
        }
        try packets.append(allocator, packet);
    }
    return packets;
}

fn deinitPackets(allocator: std.mem.Allocator, packets: *std.ArrayList([]u8)) void {
    for (packets.items) |packet| allocator.free(packet);
    packets.deinit(allocator);
    packets.* = .{};
}

fn decodeBase64Alloc(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    if (decoder.calcSizeForSlice(encoded)) |size| {
        const out = try allocator.alloc(u8, size);
        errdefer allocator.free(out);
        try decoder.decode(out, encoded);
        return out;
    } else |_| {
        const no_pad = std.base64.standard_no_pad.Decoder;
        const size = try no_pad.calcSizeForSlice(encoded);
        const out = try allocator.alloc(u8, size);
        errdefer allocator.free(out);
        try no_pad.decode(out, encoded);
        return out;
    }
}

fn durationFromMillis(timeout_ms: i64) common.grt.time.duration.Duration {
    return @as(common.grt.time.duration.Duration, @intCast(@max(timeout_ms, 1))) * common.grt.time.duration.MilliSecond;
}

fn workflowDocument(comptime sdk: type, allocator: std.mem.Allocator, cfg: *const WorkspaceConfig) !std.json.Parsed(sdk.models.WorkflowCreateRequest) {
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"apiVersion\":\"gizclaw.flowcraft/v1alpha1\",\"kind\":\"FlowcraftWorkflow\",\"metadata\":{\"name\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "name" }), .{}, w);
    try w.writeAll(",\"description\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "description" }), .{}, w);
    try w.writeAll("},\"spec\":{\"realtime_model\":");
    try std.json.Stringify.value(try cfg.string(&.{ "models", "realtime" }), .{}, w);
    try w.writeAll(",\"realtime\":{\"session\":{\"auth_mode\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "session", "auth_mode" }), .{}, w);
    try w.writeAll(",\"bot_name\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "session", "bot_name" }), .{}, w);
    try w.writeAll(",\"model\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "session", "model" }), .{}, w);
    try w.writeAll(",\"resource_id\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "session", "resource_id" }), .{}, w);
    try w.writeAll(",\"system_role\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "session", "system_role" }), .{}, w);
    try w.print(",\"vad_window_ms\":{d}", .{cfg.optionalInteger(&.{ "workflow", "session", "vad_window_ms" }, 200)});
    try w.writeAll("},\"output\":{\"speaker\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "output", "speaker" }), .{}, w);
    try w.writeAll("}}}}");
    const json = try out.toOwnedSlice();
    defer allocator.free(json);
    return try sdk.models.fromJson(sdk.models.WorkflowCreateRequest, allocator, json);
}

fn workspaceDocument(comptime sdk: type, allocator: std.mem.Allocator, cfg: *const WorkspaceConfig) !std.json.Parsed(sdk.models.WorkspaceCreateRequest) {
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"name\":");
    try std.json.Stringify.value(try cfg.string(&.{"workspace"}), .{}, w);
    try w.writeAll(",\"workflow_name\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "name" }), .{}, w);
    try w.writeAll(",\"created_at\":\"1970-01-01T00:00:00Z\",\"updated_at\":\"1970-01-01T00:00:00Z\"");
    try w.writeAll(",\"parameters\":{\"agent_type\":");
    try std.json.Stringify.value(try cfg.string(&.{"agent"}), .{}, w);
    try w.writeAll(",\"realtime_model\":");
    try std.json.Stringify.value(try cfg.string(&.{ "models", "realtime" }), .{}, w);
    if (cfg.optionalObject(&.{ "workflow", "parameters" })) |params| {
        var iter = params.iterator();
        while (iter.next()) |entry| {
            try w.writeAll(",");
            try std.json.Stringify.value(entry.key_ptr.*, .{}, w);
            try w.writeAll(":");
            try std.json.Stringify.value(entry.value_ptr.*, .{}, w);
        }
    }
    try w.writeAll("}}");
    const json = try out.toOwnedSlice();
    defer allocator.free(json);
    return try sdk.models.fromJson(sdk.models.WorkspaceCreateRequest, allocator, json);
}
