const std = @import("std");
const common = @import("common");

const WorkspaceOptions = struct {
    base: common.BaseOptions = .{},
    config: []const u8 = "../gizclaw-go/test/gizclaw-e2e/workspace/config/doubao-realtime.json",
    workspace: ?[]const u8 = null,
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
            } else if (std.mem.eql(u8, arg, "--workspace")) {
                i += 1;
                out.workspace = try common.needValue(args, i, arg);
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
        \\  --config FILE          Go workspace e2e config JSON
        \\  --workspace NAME       Workspace name to delete/create/select for this run
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

    fn optionalIntegerValue(self: *const WorkspaceConfig, path: []const []const u8) ?i64 {
        var value = self.root();
        for (path) |name| value = value.object.get(name) orelse return null;
        return switch (value) {
            .integer => |integer| integer,
            else => null,
        };
    }

    fn optionalBool(self: *const WorkspaceConfig, path: []const []const u8) ?bool {
        var value = self.root();
        for (path) |name| value = value.object.get(name) orelse return null;
        return switch (value) {
            .bool => |boolean| boolean,
            else => null,
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

    fn workspaceName(self: *const WorkspaceConfig) ![]const u8 {
        return self.optionalString(&.{"workspace"}) orelse try self.string(&.{ "workflow", "name" });
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
    const workspace_name = options.workspace orelse try cfg.workspaceName();
    try ensureWorkspace(sdk, allocator, &client, cfg, workspace_name, &summary);
    if (!options.skip_run_control) {
        try runControl(sdk, &client, cfg, workspace_name, &summary, options.run_timeout_ms);
        try checkPeerEventStream(sdk, &client, &summary);
        try checkServerRunSay(sdk, &client, cfg, &summary);
        if (options.conversation_smoke) {
            try runConversationSmoke(sdk, allocator, &client, cfg, &summary, options);
        } else {
            try summary.skip("StampedOpusConversation", "enable with --conversation-smoke");
        }
    } else {
        try summary.skip("SetServerRunWorkspace", "disabled by --skip-run-control");
        try summary.skip("ReloadServerRunWorkspace", "disabled by --skip-run-control");
        try summary.skip("WaitServerRunWorkspace", "disabled by --skip-run-control");
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
    const workflow_json = try sdk.models.toJson(allocator, workflow.value);
    defer allocator.free(workflow_json);
    std.debug.print("INFO WorkflowRequest {s}\n", .{workflow_json});

    if (client.getWorkflow(.{ .name = name })) |existing| {
        var parsed = existing;
        defer parsed.deinit();
        try summary.pass("GetWorkflow");
        return;
    } else |_| {}

    if (client.createWorkflow(workflow.value)) |created| {
        var parsed = created;
        defer parsed.deinit();
        try summary.pass("CreateWorkflow");
    } else |err| {
        try summary.fail("CreateWorkflow", err);
    }
}

fn ensureWorkspace(comptime sdk: type, allocator: std.mem.Allocator, client: *sdk.Client, cfg: *const WorkspaceConfig, name: []const u8, summary: *common.Summary) !void {
    var workspace = try workspaceDocument(sdk, allocator, cfg, name);
    defer workspace.deinit();
    const workspace_json = try sdk.models.toJson(allocator, workspace.value);
    defer allocator.free(workspace_json);
    std.debug.print("INFO WorkspaceRequest {s}\n", .{workspace_json});

    if (client.stopServerRun()) |stopped| {
        var parsed = stopped;
        defer parsed.deinit();
        try summary.pass("StopServerRunBeforeWorkspaceRecreate");
    } else |_| {}
    if (client.deleteWorkspace(.{ .name = name })) |deleted| {
        var parsed = deleted;
        defer parsed.deinit();
        try summary.pass("DeleteWorkspaceBeforeCreate");
    } else |err| switch (err) {
        error.GearNotFound => try summary.skip("DeleteWorkspaceBeforeCreate", "workspace did not exist"),
        else => try summary.fail("DeleteWorkspace", err),
    }

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

fn runControl(comptime sdk: type, client: *sdk.Client, cfg: *const WorkspaceConfig, workspace: []const u8, summary: *common.Summary, timeout_ms_override: ?i64) !void {
    if (client.setServerRunWorkspace(.{ .workspace_name = workspace })) |selected| {
        var parsed = selected;
        defer parsed.deinit();
        try summary.pass("SetServerRunWorkspace");
    } else |err| try summary.fail("SetServerRunWorkspace", err);

    if (client.reloadServerRunWorkspace()) |reloaded| {
        var parsed = reloaded;
        defer parsed.deinit();
        try summary.pass("ReloadServerRunWorkspace");
    } else |err| {
        if (try isWorkspaceRunning(sdk, client, workspace)) {
            try summary.pass("ReloadServerRunWorkspace");
        } else {
            try summary.fail("ReloadServerRunWorkspace", err);
        }
    }

    try waitForRunStatus(sdk, client, cfg, summary, workspace, timeout_ms_override);
}

fn isWorkspaceRunning(comptime sdk: type, client: *sdk.Client, workspace: []const u8) !bool {
    var status = client.getServerRunWorkspace() catch return false;
    defer status.deinit();
    return std.mem.eql(u8, status.value.runtime_state, "running") and workspaceStateMatches(status.value, workspace);
}

fn workspaceStateMatches(status: anytype, workspace: []const u8) bool {
    if (std.mem.eql(u8, status.workspace_name, workspace)) return true;
    if (status.active_workspace_name) |name| {
        if (std.mem.eql(u8, name, workspace)) return true;
    }
    if (status.selected_workspace_name) |name| {
        if (std.mem.eql(u8, name, workspace)) return true;
    }
    return false;
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
        var status = client.getServerRunWorkspace() catch |err| return summary.fail("WaitServerRunWorkspace", err);
        defer status.deinit();
        if (std.mem.eql(u8, status.value.runtime_state, "running") and workspaceStateMatches(status.value, workspace)) {
            return summary.pass("WaitServerRunWorkspace");
        }
        if (std.mem.eql(u8, status.value.runtime_state, "error")) {
            return summary.fail("WaitServerRunWorkspace", error.WorkspaceRunError);
        }
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }
    try summary.fail("WaitServerRunWorkspace", error.WorkspaceRunTimeout);
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
    history_events: usize = 0,
    eos_events: usize = 0,
    audio_packets: usize = 0,
    audio_bytes: usize = 0,
    text_bytes: usize = 0,
    after_eos_first_event_ms: ?i64 = null,
    after_eos_transcript_start_ms: ?i64 = null,
    after_eos_transcript_done_ms: ?i64 = null,
    after_eos_text_first_ms: ?i64 = null,
    assistant_text_done_ms: ?i64 = null,
    text_first_after_transcript_done_ms: ?i64 = null,
    after_eos_audio_first_ms: ?i64 = null,
    first_eos_ms: ?i64 = null,
    last_event_ms: ?i64 = null,
    last_audio_ms: ?i64 = null,
    after_eos_complete_ms: ?i64 = null,
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
    const response_started_at = send_finished_at;

    try summary.out.print(
        "INFO ConversationTurn input_packets={d} input_audio_ms={d} send_elapsed_ms={d}\n",
        .{ packets.items.len, packets.items.len * 20, send_finished_at - send_started_at },
    );

    var stats = ConversationStats{};
    var opus_buf: [16 * 1024]u8 = undefined;
    const deadline = std.time.milliTimestamp() + @max(timeout_ms, 1);
    var eos_seen_at: ?i64 = null;
    while (std.time.milliTimestamp() <= deadline) {
        if (eos_seen_at) |seen_at| {
            if (stats.audio_packets > 0 and std.time.milliTimestamp() - seen_at >= 700) break;
        }
        if (client.readPeerStreamChunk(&stream, &opus_buf)) |chunk_result| {
            var result = chunk_result;
            defer result.deinit();
            switch (result.chunk()) {
                .event => |event| {
                    const now = std.time.milliTimestamp();
                    const elapsed_ms = now - response_started_at;
                    stats.events += 1;
                    if (stats.after_eos_first_event_ms == null) stats.after_eos_first_event_ms = elapsed_ms;
                    stats.last_event_ms = elapsed_ms;
                    if (event.type == .workspace_history_updated) stats.history_events += 1;
                    if (event.label) |label| {
                        if (std.mem.eql(u8, label, "transcript")) {
                            stats.transcript_events += 1;
                            if (event.type == .text_done and stats.after_eos_transcript_done_ms == null) {
                                stats.after_eos_transcript_done_ms = elapsed_ms;
                            }
                            if (event.text) |text| {
                                if (std.mem.trim(u8, text, " \t\r\n").len != 0 and stats.after_eos_transcript_start_ms == null) {
                                    stats.after_eos_transcript_start_ms = elapsed_ms;
                                }
                            }
                        }
                        if (std.mem.eql(u8, label, "assistant")) {
                            stats.assistant_events += 1;
                            if (event.type == .text_done and stats.assistant_text_done_ms == null) {
                                stats.assistant_text_done_ms = elapsed_ms;
                            }
                            if (event.text) |text| {
                                if (std.mem.trim(u8, text, " \t\r\n").len != 0 and stats.after_eos_text_first_ms == null) {
                                    stats.after_eos_text_first_ms = elapsed_ms;
                                    if (stats.after_eos_transcript_done_ms) |done_ms| {
                                        if (elapsed_ms > done_ms) stats.text_first_after_transcript_done_ms = elapsed_ms - done_ms;
                                    }
                                }
                            }
                        }
                    }
                    if (event.type == .eos) {
                        stats.eos_events += 1;
                        if (stats.first_eos_ms == null) stats.first_eos_ms = elapsed_ms;
                        if (event.label) |label| {
                            if (std.mem.eql(u8, label, "assistant") and eos_seen_at == null) {
                                eos_seen_at = now;
                            }
                        }
                    }
                    if (event.text) |value| stats.text_bytes += value.len;
                    try printConversationEvent(&summary.out, elapsed_ms, event);
                },
                .stamped_opus => |frame| {
                    const now = std.time.milliTimestamp();
                    const elapsed_ms = now - response_started_at;
                    stats.audio_packets += 1;
                    stats.audio_bytes += frame.frame.len;
                    if (stats.after_eos_audio_first_ms == null) stats.after_eos_audio_first_ms = elapsed_ms;
                    stats.last_audio_ms = elapsed_ms;
                    try summary.out.print(
                        "AUDIO ConversationTurn after_eos={d}ms timestamp={d} bytes={d} packet={d}\n",
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
    stats.after_eos_complete_ms = stats.first_eos_ms orelse stats.last_audio_ms orelse stats.last_event_ms;
    try summary.pass("StampedOpusConversation");
    try summary.out.print(
        "INFO StampedOpusConversation input_packets={d} events={d} transcript_events={d} assistant_events={d} history_events={d} eos_events={d} text_bytes={d} audio_packets={d} audio_bytes={d} workspace_uplink_send_ms={d}",
        .{
            packets.items.len,
            stats.events,
            stats.transcript_events,
            stats.assistant_events,
            stats.history_events,
            stats.eos_events,
            stats.text_bytes,
            stats.audio_packets,
            stats.audio_bytes,
            send_finished_at - send_started_at,
        },
    );
    try printOptionalMs(&summary.out, "after_eos_first_event_ms", stats.after_eos_first_event_ms);
    try printOptionalMs(&summary.out, "after_eos_transcript_start_ms", stats.after_eos_transcript_start_ms);
    try printOptionalMs(&summary.out, "after_eos_transcript_done_ms", stats.after_eos_transcript_done_ms);
    try printOptionalMs(&summary.out, "after_eos_text_first_ms", stats.after_eos_text_first_ms);
    try printOptionalMs(&summary.out, "assistant_text_done_ms", stats.assistant_text_done_ms);
    try printOptionalMs(&summary.out, "text_first_after_transcript_done_ms", stats.text_first_after_transcript_done_ms);
    try printOptionalMs(&summary.out, "after_eos_audio_first_ms", stats.after_eos_audio_first_ms);
    try printOptionalMs(&summary.out, "first_eos_ms", stats.first_eos_ms);
    try printOptionalMs(&summary.out, "last_event_ms", stats.last_event_ms);
    try printOptionalMs(&summary.out, "last_audio_ms", stats.last_audio_ms);
    try printOptionalMs(&summary.out, "after_eos_complete_ms", stats.after_eos_complete_ms);
    try summary.out.writeAll("\n");
}

fn printConversationEvent(out: anytype, elapsed_ms: i64, event: anytype) !void {
    try out.print("EVENT ConversationTurn after_eos={d}ms type={s}", .{ elapsed_ms, peerStreamEventTypeName(event.type) });
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
        .workspace_history_updated => "workspace.history.updated",
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
    if (std.mem.eql(u8, try cfg.string(&.{"agent"}), "ast-translate")) {
        return astTranslateWorkflowDocument(sdk, allocator, cfg);
    }
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    const w = &out.writer;
    const realtime_model = cfg.optionalString(&.{ "workflow", "realtime_model" }) orelse try cfg.string(&.{ "models", "realtime" });
    try w.writeAll("{\"metadata\":{\"name\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "name" }), .{}, w);
    try w.writeAll(",\"description\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "description" }), .{}, w);
    try w.writeAll("},\"spec\":{\"driver\":\"doubao-realtime\",\"doubao_realtime\":{\"realtime_model\":");
    try std.json.Stringify.value(realtime_model, .{}, w);
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
    try w.writeAll("}}}}}");
    const json = try out.toOwnedSlice();
    defer allocator.free(json);
    return try sdk.models.fromJson(sdk.models.WorkflowCreateRequest, allocator, json);
}

fn astTranslateWorkflowDocument(comptime sdk: type, allocator: std.mem.Allocator, cfg: *const WorkspaceConfig) !std.json.Parsed(sdk.models.WorkflowCreateRequest) {
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    const w = &out.writer;
    const translation_model = cfg.optionalString(&.{ "workflow", "translation_model" }) orelse try cfg.string(&.{ "models", "translation" });
    try w.writeAll("{\"metadata\":{\"name\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "name" }), .{}, w);
    try w.writeAll(",\"description\":");
    try std.json.Stringify.value(cfg.optionalString(&.{ "workflow", "description" }) orelse "Workspace e2e workflow", .{}, w);
    try w.writeAll("},\"spec\":{\"driver\":\"ast-translate\",\"ast_translate\":{\"translation_model\":");
    try std.json.Stringify.value(translation_model, .{}, w);
    try appendOptionalStringField(w, "mode", cfg.optionalString(&.{ "workflow", "ast_translate", "mode" }));
    try appendOptionalObjectField(w, "voice", cfg.optionalObject(&.{ "workflow", "ast_translate", "voice" }));
    try appendOptionalStringField(w, "speaker_id", cfg.optionalString(&.{ "workflow", "ast_translate", "speaker_id" }));
    try appendOptionalBoolField(w, "is_custom_speaker", cfg.optionalBool(&.{ "workflow", "ast_translate", "is_custom_speaker" }));
    try appendOptionalStringField(w, "tts_resource_id", cfg.optionalString(&.{ "workflow", "ast_translate", "tts_resource_id" }));
    try appendOptionalIntegerField(w, "speech_rate", cfg.optionalIntegerValue(&.{ "workflow", "ast_translate", "speech_rate" }));
    try appendOptionalBoolField(w, "enable_source_language_detect", cfg.optionalBool(&.{ "workflow", "ast_translate", "enable_source_language_detect" }));
    try appendOptionalBoolField(w, "denoise", cfg.optionalBool(&.{ "workflow", "ast_translate", "denoise" }));
    try appendOptionalStringField(w, "resource_id", cfg.optionalString(&.{ "workflow", "ast_translate", "resource_id" }));
    try appendOptionalStringField(w, "auth_mode", cfg.optionalString(&.{ "workflow", "ast_translate", "auth_mode" }));
    try w.writeAll("}}}");
    const json = try out.toOwnedSlice();
    defer allocator.free(json);
    return try sdk.models.fromJson(sdk.models.WorkflowCreateRequest, allocator, json);
}

fn workspaceDocument(comptime sdk: type, allocator: std.mem.Allocator, cfg: *const WorkspaceConfig, workspace_name: []const u8) !std.json.Parsed(sdk.models.WorkspaceCreateRequest) {
    if (std.mem.eql(u8, try cfg.string(&.{"agent"}), "ast-translate")) {
        return astTranslateWorkspaceDocument(sdk, allocator, cfg, workspace_name);
    }
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    const w = &out.writer;
    const realtime_model = cfg.optionalString(&.{ "workflow", "realtime_model" }) orelse try cfg.string(&.{ "models", "realtime" });
    try w.writeAll("{\"name\":");
    try std.json.Stringify.value(workspace_name, .{}, w);
    try w.writeAll(",\"workflow_name\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "name" }), .{}, w);
    try w.writeAll(",\"parameters\":{\"agent_type\":");
    try std.json.Stringify.value(try cfg.string(&.{"agent"}), .{}, w);
    try w.writeAll(",\"realtime_model\":");
    try std.json.Stringify.value(realtime_model, .{}, w);
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

fn astTranslateWorkspaceDocument(comptime sdk: type, allocator: std.mem.Allocator, cfg: *const WorkspaceConfig, workspace_name: []const u8) !std.json.Parsed(sdk.models.WorkspaceCreateRequest) {
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"name\":");
    try std.json.Stringify.value(workspace_name, .{}, w);
    try w.writeAll(",\"workflow_name\":");
    try std.json.Stringify.value(try cfg.string(&.{ "workflow", "name" }), .{}, w);
    try w.writeAll(",\"parameters\":{\"agent_type\":\"ast-translate\"");
    try appendOptionalStringField(w, "translation_model", cfg.optionalString(&.{ "workflow", "parameters", "translation_model" }));
    try appendOptionalStringField(w, "input", cfg.optionalString(&.{ "workflow", "parameters", "input" }));
    try appendOptionalStringField(w, "mode", cfg.optionalString(&.{ "workflow", "parameters", "mode" }));
    try appendOptionalStringField(w, "lang_pair", cfg.optionalString(&.{ "workflow", "parameters", "lang_pair" }));
    try appendOptionalObjectField(w, "voice", cfg.optionalObject(&.{ "workflow", "parameters", "voice" }));
    try appendOptionalStringField(w, "speaker_id", cfg.optionalString(&.{ "workflow", "parameters", "speaker_id" }));
    try appendOptionalBoolField(w, "is_custom_speaker", cfg.optionalBool(&.{ "workflow", "parameters", "is_custom_speaker" }));
    try appendOptionalStringField(w, "tts_resource_id", cfg.optionalString(&.{ "workflow", "parameters", "tts_resource_id" }));
    try appendOptionalIntegerField(w, "speech_rate", cfg.optionalIntegerValue(&.{ "workflow", "parameters", "speech_rate" }));
    try appendOptionalBoolField(w, "enable_source_language_detect", cfg.optionalBool(&.{ "workflow", "parameters", "enable_source_language_detect" }));
    try appendOptionalBoolField(w, "denoise", cfg.optionalBool(&.{ "workflow", "parameters", "denoise" }));
    try w.writeAll("}}");
    const json = try out.toOwnedSlice();
    defer allocator.free(json);
    return try sdk.models.fromJson(sdk.models.WorkspaceCreateRequest, allocator, json);
}

fn appendOptionalStringField(w: anytype, comptime name: []const u8, value: ?[]const u8) !void {
    if (value) |text| {
        try w.writeAll(",\"" ++ name ++ "\":");
        try std.json.Stringify.value(text, .{}, w);
    }
}

fn appendOptionalBoolField(w: anytype, comptime name: []const u8, value: ?bool) !void {
    if (value) |boolean| {
        try w.writeAll(",\"" ++ name ++ "\":");
        try std.json.Stringify.value(boolean, .{}, w);
    }
}

fn appendOptionalIntegerField(w: anytype, comptime name: []const u8, value: ?i64) !void {
    if (value) |integer| {
        try w.writeAll(",\"" ++ name ++ "\":");
        try std.json.Stringify.value(integer, .{}, w);
    }
}

fn appendOptionalObjectField(w: anytype, comptime name: []const u8, value: ?std.json.ObjectMap) !void {
    if (value) |object| {
        try w.writeAll(",\"" ++ name ++ "\":");
        try std.json.Stringify.value(std.json.Value{ .object = object }, .{}, w);
    }
}
