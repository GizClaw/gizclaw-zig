const gstd = @import("gstd");
const common = @import("common");

const grt = gstd.runtime;
const mem = grt.std.mem;
const json = grt.std.json;
const duration = grt.time.duration;
const audio_label = "workspacetest";
const audio_frame_ms: u64 = 20;
const stream_poll_timeout = 100 * duration.MilliSecond;
const response_settle_timeout = 700 * duration.MilliSecond;

pub const Mode = enum {
    push_to_talk,
    realtime,
};

pub const ChatAudioAsset = struct {
    name: []const u8,
    expected_text: []const u8,
    ogg_opus: []const u8,
};

pub const Config = struct {
    base: common.BaseOptions = .{},
    workspace_config: []const u8 = "../gizclaw-go/test/gizclaw-e2e/testdata/workspaces/doubao-realtime.json",
    workspace_config_json: ?[]const u8 = null,
    workspace_name: ?[]const u8 = null,
    mode: Mode = .push_to_talk,

    audio_manifest: ?[]const u8 = null,
    embedded_audio: ?[]const ChatAudioAsset = null,
    rounds: u32 = 3,
    min_rounds: u32 = 3,

    run_timeout_ms: u32 = 30_000,
    conversation_timeout_ms: u32 = 10_000,
    stream_smoke_timeout_ms: u32 = 250,
};

pub const Summary = struct {
    passed: usize = 0,
    skipped: usize = 0,
    failed: usize = 0,
    rounds: usize = 0,
    input_bytes: usize = 0,
    output_bytes: usize = 0,
    input_packets: usize = 0,
    output_packets: usize = 0,
    events: usize = 0,
    total_response_ns: u64 = 0,
    worst_response_ns: u64 = 0,

    pub fn pass(self: *Summary) void {
        self.passed += 1;
    }

    pub fn fail(self: *Summary) void {
        self.failed += 1;
    }
};

pub fn run(comptime sdk: type, allocator: mem.Allocator, config: Config, reporter: anytype) !Summary {
    var ctx = common.loadContext(allocator, config.base) catch |err| {
        var summary = Summary{};
        try recordFail(&summary, reporter, "Connect", err);
        return summary;
    };
    defer ctx.deinit();
    return runWithContext(sdk, allocator, ctx, config, reporter);
}

pub fn runWithContext(comptime sdk: type, allocator: mem.Allocator, ctx: common.Context, config: Config, reporter: anytype) !Summary {
    var summary = Summary{};
    if (config.rounds < config.min_rounds) {
        try recordFail(&summary, reporter, "ChatConfig", error.NotEnoughRounds);
        return summary;
    }

    const client = common.connectClient(sdk, ctx.allocator, &ctx) catch |err| {
        try recordFail(&summary, reporter, "Connect", err);
        return summary;
    };
    defer common.disconnectClient(sdk, ctx.allocator, client);

    try recordPass(&summary, reporter, "Connect");
    const ping_started = grt.time.instant.now();
    if (client.ping()) |response| {
        _ = response;
        try reporter.metric("ping_rtt", @intCast(@divTrunc(grt.time.instant.since(ping_started), duration.MilliSecond)), "ms");
        try recordPass(&summary, reporter, "Ping");
    } else |err| {
        try recordFail(&summary, reporter, "Ping", err);
    }

    try ensureWorkspace(sdk, allocator, client, &summary, reporter, config);

    var workspace_ready = false;
    if (config.workspace_name) |workspace| {
        workspace_ready = try selectWorkspace(sdk, client, &summary, reporter, workspace, config.run_timeout_ms);
    } else {
        try recordFail(&summary, reporter, "WorkspaceRun", error.MissingWorkspaceName);
    }
    try peerStreamSmoke(sdk, client, &summary, reporter, config.stream_smoke_timeout_ms);

    switch (config.mode) {
        .push_to_talk => try runAudioRoundtrip(sdk, allocator, client, &summary, reporter, config, workspace_ready, .push_to_talk),
        .realtime => try runAudioRoundtrip(sdk, allocator, client, &summary, reporter, config, workspace_ready, .realtime),
    }

    return summary;
}

fn ensureWorkspace(comptime sdk: type, allocator: mem.Allocator, client: *sdk.Client, summary: *Summary, reporter: anytype, config: Config) !void {
    const raw = config.workspace_config_json orelse {
        try recordFail(summary, reporter, "EnsureWorkspace", error.MissingWorkspaceConfig);
        return;
    };
    const workspace_name = config.workspace_name orelse {
        try recordFail(summary, reporter, "EnsureWorkspace", error.MissingWorkspaceName);
        return;
    };

    const cfg = loadWorkspaceConfig(allocator, raw) catch |err| {
        try recordFail(summary, reporter, "LoadWorkspaceConfig", err);
        return;
    };
    if (!isDoubaoRealtimeConfig(cfg)) {
        try recordFail(summary, reporter, "EnsureWorkspace", error.UnsupportedWorkspaceConfig);
        return;
    }

    const workflow_name = workflowName(cfg) orelse {
        try recordFail(summary, reporter, "EnsureWorkflow", error.MissingWorkflowName);
        return;
    };

    const workflow = buildWorkflowDocument(sdk.models, cfg, workflow_name);
    try parsed(summary, reporter, "EnsureWorkflow", client.putWorkflow(.{
        .name = workflow_name,
        .body = workflow,
    }));

    const workspace = buildWorkspaceDocument(sdk.models, cfg, config.mode, workspace_name, workflow_name);
    try parsed(summary, reporter, "EnsureWorkspace", client.putWorkspace(.{
        .name = workspace_name,
        .body = workspace,
    }));
}

const WorkspaceConfig = struct {
    workspace: ?[]const u8 = null,
    agent: ?[]const u8 = null,
    workflow: Workflow = .{},

    const Workflow = struct {
        name: ?[]const u8 = null,
        description: ?[]const u8 = null,
        realtime_model: ?[]const u8 = null,
        parameters: Parameters = .{},
        session: Session = .{},
        output: Output = .{},
    };

    const Parameters = struct {
        input: ?[]const u8 = null,
        voice: Voice = .{},
        search: Search = .{},
        music: Music = .{},
    };

    const Voice = struct {
        realtime_speaker_id: ?[]const u8 = null,
        speaker_id: ?[]const u8 = null,
    };

    const Search = struct {
        enabled: ?bool = null,
        type: ?[]const u8 = null,
        result_count: ?i64 = null,
        no_result_message: ?[]const u8 = null,
    };

    const Music = struct {
        enabled: ?bool = null,
    };

    const Session = struct {
        auth_mode: ?[]const u8 = null,
        bot_name: ?[]const u8 = null,
        model: ?[]const u8 = null,
        resource_id: ?[]const u8 = null,
        system_role: ?[]const u8 = null,
        vad_window_ms: ?i64 = null,
    };

    const Output = struct {
        speaker: ?[]const u8 = null,
    };
};

fn loadWorkspaceConfig(allocator: mem.Allocator, raw: []const u8) !WorkspaceConfig {
    var parsed_doc = try json.parseFromSlice(WorkspaceConfig, allocator, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed_doc.deinit();
    const parsed_value = parsed_doc.value;
    return .{
        .workspace = try dupeOptional(allocator, parsed_value.workspace),
        .agent = try dupeOptional(allocator, parsed_value.agent),
        .workflow = .{
            .name = try dupeOptional(allocator, parsed_value.workflow.name),
            .description = try dupeOptional(allocator, parsed_value.workflow.description),
            .realtime_model = try dupeOptional(allocator, parsed_value.workflow.realtime_model),
            .parameters = .{
                .input = try dupeOptional(allocator, parsed_value.workflow.parameters.input),
                .voice = .{
                    .realtime_speaker_id = try dupeOptional(allocator, parsed_value.workflow.parameters.voice.realtime_speaker_id),
                    .speaker_id = try dupeOptional(allocator, parsed_value.workflow.parameters.voice.speaker_id),
                },
                .search = .{
                    .enabled = parsed_value.workflow.parameters.search.enabled,
                    .type = try dupeOptional(allocator, parsed_value.workflow.parameters.search.type),
                    .result_count = parsed_value.workflow.parameters.search.result_count,
                    .no_result_message = try dupeOptional(allocator, parsed_value.workflow.parameters.search.no_result_message),
                },
                .music = .{
                    .enabled = parsed_value.workflow.parameters.music.enabled,
                },
            },
            .session = .{
                .auth_mode = try dupeOptional(allocator, parsed_value.workflow.session.auth_mode),
                .bot_name = try dupeOptional(allocator, parsed_value.workflow.session.bot_name),
                .model = try dupeOptional(allocator, parsed_value.workflow.session.model),
                .resource_id = try dupeOptional(allocator, parsed_value.workflow.session.resource_id),
                .system_role = try dupeOptional(allocator, parsed_value.workflow.session.system_role),
                .vad_window_ms = parsed_value.workflow.session.vad_window_ms,
            },
            .output = .{
                .speaker = try dupeOptional(allocator, parsed_value.workflow.output.speaker),
            },
        },
    };
}

fn dupeOptional(allocator: mem.Allocator, value: ?[]const u8) !?[]const u8 {
    if (value) |text| return try allocator.dupe(u8, text);
    return null;
}

fn isDoubaoRealtimeConfig(config: WorkspaceConfig) bool {
    if (config.agent) |agent| return mem.eql(u8, agent, "doubao-realtime");
    return true;
}

fn workflowName(config: WorkspaceConfig) ?[]const u8 {
    if (config.workflow.name) |name| {
        if (name.len != 0) return name;
    }
    return config.workspace;
}

fn buildWorkflowDocument(comptime models: type, config: WorkspaceConfig, name: []const u8) models.WorkflowCreateRequest {
    return .{
        .metadata = .{
            .name = name,
            .description = config.workflow.description,
        },
        .spec = .{
            .driver = "doubao-realtime",
            .doubao_realtime = .{
                .realtime_model = config.workflow.realtime_model,
                .realtime = .{
                    .session = .{
                        .auth_mode = config.workflow.session.auth_mode orelse "v2",
                        .bot_name = config.workflow.session.bot_name orelse "豆包",
                        .model = config.workflow.session.model orelse "1.2.1.1",
                        .resource_id = config.workflow.session.resource_id orelse "volc.speech.dialog",
                        .system_role = config.workflow.session.system_role orelse "你是一个简短、自然的中文语音聊天助手。",
                        .vad_window_ms = config.workflow.session.vad_window_ms orelse 200,
                    },
                    .output = .{
                        .speaker = config.workflow.output.speaker orelse "zh_female_vv_jupiter_bigtts",
                    },
                },
            },
        },
    };
}

fn buildWorkspaceDocument(comptime models: type, config: WorkspaceConfig, mode: Mode, name: []const u8, workflow_name: []const u8) models.WorkspaceCreateRequest {
    return .{
        .name = name,
        .workflow_name = workflow_name,
        .parameters = .{
            .agent_type = "doubao-realtime",
            .realtime_model = config.workflow.realtime_model,
            .input = workspaceInputMode(config, mode),
            .voice = .{
                .realtime_speaker_id = config.workflow.parameters.voice.realtime_speaker_id,
                .speaker_id = config.workflow.parameters.voice.speaker_id,
            },
            .search = .{
                .enabled = config.workflow.parameters.search.enabled,
                .type = config.workflow.parameters.search.type,
                .result_count = config.workflow.parameters.search.result_count,
                .no_result_message = config.workflow.parameters.search.no_result_message,
            },
            .music = .{
                .enabled = config.workflow.parameters.music.enabled,
            },
            .e2e = true,
        },
    };
}

fn workspaceInputMode(config: WorkspaceConfig, mode: Mode) []const u8 {
    return switch (mode) {
        .push_to_talk => config.workflow.parameters.input orelse "push-to-talk",
        .realtime => "realtime",
    };
}

fn selectWorkspace(comptime sdk: type, client: *sdk.Client, summary: *Summary, reporter: anytype, workspace: []const u8, timeout_ms: u32) !bool {
    const log = grt.std.log.scoped(.gizclaw_e2e_chat);
    log.info("select workspace target={s}", .{workspace});

    if (client.setServerRunWorkspace(.{ .workspace_name = workspace })) |set_result| {
        var set_state = set_result;
        defer set_state.deinit();
        logWorkspaceState("after_set_workspace", set_state.value);
        try recordPass(summary, reporter, "SetServerRunWorkspace");
    } else |err| {
        try recordFail(summary, reporter, "SetServerRunWorkspace", err);
    }

    if (client.reloadServerRunWorkspace()) |reload_result| {
        var reload_state = reload_result;
        defer reload_state.deinit();
        logWorkspaceState("after_reload_workspace", reload_state.value);
        try recordPass(summary, reporter, "ReloadServerRunWorkspace");
    } else |err| {
        log.err("reload workspace failed target={s} err={s}", .{ workspace, @errorName(err) });
        try recordFail(summary, reporter, "ReloadServerRunWorkspace", err);
    }

    const started = grt.time.instant.now();
    const timeout: duration.Duration = @as(duration.Duration, @intCast(@max(timeout_ms, 1))) * duration.MilliSecond;
    while (grt.time.instant.since(started) < timeout) {
        if (client.getServerRunWorkspace()) |status_result| {
            var status = status_result;
            defer status.deinit();
            if (mem.eql(u8, status.value.runtime_state, "running") and workspaceStateMatches(status.value, workspace)) {
                try reporter.metric("workspace_ready", @intCast(@divTrunc(grt.time.instant.since(started), duration.MilliSecond)), "ms");
                try recordPass(summary, reporter, "WaitServerRunWorkspace");
                return true;
            }
            if (mem.eql(u8, status.value.runtime_state, "error")) {
                try recordFail(summary, reporter, "WaitServerRunWorkspace", error.WorkspaceRunError);
                return false;
            }
        } else |err| {
            try recordFail(summary, reporter, "WaitServerRunWorkspace", err);
            return false;
        }
        grt.time.sleepMillis(200);
    }
    try recordFail(summary, reporter, "WaitServerRunWorkspace", error.WorkspaceRunTimeout);
    return false;
}

fn logWorkspaceState(stage: []const u8, state: anytype) void {
    const log = grt.std.log.scoped(.gizclaw_e2e_chat);
    log.info("{s} runtime_state={s} workspace={s} active={s} selected={s}", .{
        stage,
        state.runtime_state,
        state.workspace_name,
        state.active_workspace_name orelse "",
        state.selected_workspace_name orelse "",
    });
}

fn peerStreamSmoke(comptime sdk: type, client: *sdk.Client, summary: *Summary, reporter: anytype, timeout_ms: u32) !void {
    var stream = client.openPeerStream(.{
        .read_timeout = @as(duration.Duration, @intCast(@max(timeout_ms, 1))) * duration.MilliSecond,
    }) catch |err| {
        try recordFail(summary, reporter, "OpenPeerStream", err);
        return;
    };
    defer stream.deinit();
    try recordPass(summary, reporter, "OpenPeerStream");
}

fn workspaceStateMatches(status: anytype, workspace: []const u8) bool {
    if (mem.eql(u8, status.workspace_name, workspace)) return true;
    if (status.active_workspace_name) |name| {
        if (mem.eql(u8, name, workspace)) return true;
    }
    if (status.selected_workspace_name) |name| {
        if (mem.eql(u8, name, workspace)) return true;
    }
    return false;
}

fn runAudioRoundtrip(comptime sdk: type, allocator: mem.Allocator, client: *sdk.Client, summary: *Summary, reporter: anytype, config: Config, workspace_ready: bool, mode: Mode) !void {
    const names = audioRoundtripNames(mode);
    if (config.workspace_name == null) {
        try recordFail(summary, reporter, names.roundtrip, error.MissingWorkspaceName);
        return;
    }
    if (!workspace_ready) {
        try recordFail(summary, reporter, names.roundtrip, error.WorkspaceNotRunning);
        return;
    }
    if (config.embedded_audio) |assets| {
        if (assets.len < config.min_rounds) {
            try recordFail(summary, reporter, names.roundtrip, error.NotEnoughAudioFixtures);
            return;
        }
        const round_count = @min(assets.len, @as(usize, config.rounds));
        var stream = client.openPeerStream(.{
            .read_timeout = stream_poll_timeout,
        }) catch |err| {
            try recordFail(summary, reporter, names.open_stream, err);
            return;
        };
        defer stream.deinit();
        try recordPass(summary, reporter, names.open_stream);

        for (assets[0..round_count], 1..) |asset, round_index| {
            const round = runAudioRound(allocator, client, &stream, asset, @intCast(round_index), config.conversation_timeout_ms, mode) catch |err| {
                try recordFail(summary, reporter, names.roundtrip, err);
                return;
            };
            summary.rounds += 1;
            summary.input_bytes += round.input_bytes;
            summary.output_bytes += round.output_bytes;
            summary.input_packets += round.input_packets;
            summary.output_packets += round.output_packets;
            summary.events += round.events;
            summary.total_response_ns += round.response_ns;
            summary.worst_response_ns = @max(summary.worst_response_ns, round.response_ns);
            try reportRound(reporter, round);
        }
        try reporter.metric(names.rounds_metric, @intCast(summary.rounds), "");
        try reporter.metric(names.input_packets_metric, @intCast(summary.input_packets), "");
        try reporter.metric(names.output_packets_metric, @intCast(summary.output_packets), "");
        try reporter.metric(names.events_metric, @intCast(summary.events), "");
        if (summary.rounds > 0) {
            try reporter.metric(names.avg_response_metric, @divTrunc(nsToMs(summary.total_response_ns), @as(u64, @intCast(summary.rounds))), "ms");
            try reporter.metric(names.worst_response_metric, nsToMs(summary.worst_response_ns), "ms");
        }
        try recordPass(summary, reporter, names.roundtrip);
        return;
    }

    if (config.audio_manifest) |manifest| {
        const manifest_info = loadManifest(allocator, manifest) catch |err| {
            try recordFail(summary, reporter, "LoadAudioManifest", err);
            return;
        };
        if (manifest_info.rounds < config.min_rounds) {
            try recordFail(summary, reporter, "LoadAudioManifest", error.NotEnoughAudioFixtures);
            return;
        }
        summary.rounds = @min(manifest_info.rounds, config.rounds);
        try reporter.metric("audio_manifest_rounds", @intCast(manifest_info.rounds), "");
        try recordPass(summary, reporter, "LoadAudioManifest");
        try recordFail(summary, reporter, names.roundtrip, error.MissingEmbeddedAudioFixtures);
        return;
    }

    try recordFail(summary, reporter, names.roundtrip, error.MissingAudioFixtures);
}

const AudioRoundtripNames = struct {
    open_stream: []const u8,
    roundtrip: []const u8,
    rounds_metric: []const u8,
    input_packets_metric: []const u8,
    output_packets_metric: []const u8,
    events_metric: []const u8,
    avg_response_metric: []const u8,
    worst_response_metric: []const u8,
};

fn audioRoundtripNames(mode: Mode) AudioRoundtripNames {
    return switch (mode) {
        .push_to_talk => .{
            .open_stream = "OpenPushToTalkStream",
            .roundtrip = "PushToTalkRoundtrip",
            .rounds_metric = "ptt_rounds",
            .input_packets_metric = "ptt_input_packets",
            .output_packets_metric = "ptt_output_packets",
            .events_metric = "ptt_events",
            .avg_response_metric = "ptt_avg_response_ms",
            .worst_response_metric = "ptt_worst_response_ms",
        },
        .realtime => .{
            .open_stream = "OpenRealtimeStream",
            .roundtrip = "RealtimeRoundtrip",
            .rounds_metric = "realtime_rounds",
            .input_packets_metric = "realtime_input_packets",
            .output_packets_metric = "realtime_output_packets",
            .events_metric = "realtime_events",
            .avg_response_metric = "realtime_avg_response_ms",
            .worst_response_metric = "realtime_worst_response_ms",
        },
    };
}

const RoundSummary = struct {
    index: u32,
    input_bytes: usize = 0,
    input_packets: usize = 0,
    output_bytes: usize = 0,
    output_packets: usize = 0,
    events: usize = 0,
    uplink_ns: u64 = 0,
    response_ns: u64 = 0,
    first_transcript_ns: u64 = 0,
    transcript_done_ns: u64 = 0,
    first_assistant_text_ns: u64 = 0,
    assistant_text_done_ns: u64 = 0,
    first_audio_ns: u64 = 0,
};

fn runAudioRound(
    allocator: mem.Allocator,
    client: anytype,
    stream: anytype,
    asset: ChatAudioAsset,
    round_index: u32,
    timeout_ms: u32,
    mode: Mode,
) !RoundSummary {
    var packets = try parseOggOpusPackets(allocator, asset.ogg_opus);
    defer packets.deinit(allocator);
    if (packets.items.len == 0) return error.EmptyOpusAudio;

    var round = RoundSummary{ .index = round_index };
    round.input_packets = packets.items.len;
    for (packets.items) |packet| round.input_bytes += packet.len;

    const stream_id = try makeStreamID(allocator, round_index);
    defer allocator.free(stream_id);

    const uplink_started = grt.time.instant.now();
    var timestamp: u64 = @intCast(@divTrunc(uplink_started, duration.MilliSecond));
    try client.beginPeerAudio(stream, .{
        .stream_id = stream_id,
        .label = audio_label,
        .timestamp = @intCast(timestamp),
    });
    for (packets.items, 0..) |packet, packet_index| {
        try client.writePeerAudio(stream, .{
            .timestamp = timestamp,
            .frame = packet,
        });
        timestamp += audio_frame_ms;
        if (mode == .realtime and packet_index + 1 < packets.items.len) {
            grt.time.sleepMillis(audio_frame_ms);
        }
    }
    try client.endPeerAudio(stream, .{
        .stream_id = stream_id,
        .label = audio_label,
        .timestamp = @intCast(timestamp),
    });
    round.uplink_ns = @intCast(grt.time.instant.since(uplink_started));

    const response_started = grt.time.instant.now();
    const deadline = grt.time.instant.add(response_started, @as(duration.Duration, @intCast(@max(timeout_ms, 1))) * duration.MilliSecond);
    var transcript_seen = false;
    var transcript_done = false;
    var assistant_text_seen = false;
    var assistant_text_done = false;
    var assistant_audio_eos_seen = false;
    var assistant_audio_done = false;
    var settle_deadline: ?grt.time.instant.Time = null;
    var buf: [8192]u8 = undefined;
    var transcript_stream_id: ?[]const u8 = null;
    var assistant_stream_id: ?[]const u8 = null;

    while (true) {
        const now = grt.time.instant.now();
        if (transcript_seen and transcript_done and assistant_text_seen and assistant_text_done and round.output_packets > 0 and assistant_audio_done) {
            if (settle_deadline == null or now >= settle_deadline.?) {
                round.response_ns = @intCast(grt.time.instant.sub(now, response_started));
                return round;
            }
        }
        if (now >= deadline) return error.AudioRoundResponseTimeout;

        try stream.event_stream.stream.setReadDeadline(grt.time.instant.add(now, stream_poll_timeout));
        var read = client.readPeerStreamChunk(stream, &buf) catch |err| switch (err) {
            error.Timeout, error.EndOfStream => {
                if (settle_deadline) |settle| {
                    if (grt.time.instant.now() >= settle and assistant_audio_done) {
                        if (!transcript_seen) return error.MissingTranscript;
                        if (!transcript_done) return error.MissingTranscriptDone;
                        if (!assistant_text_seen) return error.MissingAssistantText;
                        if (!assistant_text_done) return error.MissingAssistantTextDone;
                        if (round.output_packets == 0) return error.MissingAssistantAudio;
                    }
                }
                continue;
            },
            else => return err,
        };
        defer read.deinit();

        if (read.event) |parsed_event| {
            const event = parsed_event.value;
            if (event.@"error") |message| {
                if (message.len != 0) return error.PeerStreamError;
            }
            const label = eventLabel(event);
            if (mem.eql(u8, label, "transcript")) {
                if (!acceptRoundEventStream(event.stream_id, stream_id, &transcript_stream_id)) continue;
                round.events += 1;
                if (event.text) |text| {
                    if (textHasContent(text) and !transcript_seen) {
                        transcript_seen = true;
                        round.first_transcript_ns = @intCast(grt.time.instant.since(response_started));
                    }
                }
                if (isTranscriptDoneEvent(event) and !transcript_done) {
                    transcript_done = true;
                    round.transcript_done_ns = @intCast(grt.time.instant.since(response_started));
                }
            } else if (mem.eql(u8, label, "assistant")) {
                if (!acceptRoundEventStream(event.stream_id, stream_id, &assistant_stream_id)) continue;
                round.events += 1;
                if (event.type == .eos) {
                    assistant_audio_eos_seen = true;
                    if (assistant_text_done) {
                        assistant_audio_done = true;
                        settle_deadline = grt.time.instant.add(grt.time.instant.now(), response_settle_timeout);
                    }
                    continue;
                }
                if (event.text) |text| {
                    if (textHasContent(text) and !assistant_text_seen) {
                        assistant_text_seen = true;
                        round.first_assistant_text_ns = @intCast(grt.time.instant.since(response_started));
                    }
                }
                if (event.type == .text_done and !assistant_text_done) {
                    assistant_text_done = true;
                    round.assistant_text_done_ns = @intCast(grt.time.instant.since(response_started));
                    if (assistant_audio_eos_seen) {
                        assistant_audio_done = true;
                        settle_deadline = grt.time.instant.add(grt.time.instant.now(), response_settle_timeout);
                    }
                }
            } else {
                if (event.stream_id) |actual| {
                    if (!streamIDMatches(actual, stream_id)) continue;
                }
                round.events += 1;
            }
        } else if (read.stamped_opus) |frame| {
            if (round.output_packets == 0) {
                round.first_audio_ns = @intCast(grt.time.instant.since(response_started));
            }
            round.output_packets += 1;
            round.output_bytes += frame.frame.len;
        }
    }
}

fn reportRound(reporter: anytype, round: RoundSummary) !void {
    try reporter.metric("round_index", round.index, "");
    try reporter.metric("round_input_packets", @intCast(round.input_packets), "");
    try reporter.metric("round_input_bytes", @intCast(round.input_bytes), "B");
    try reporter.metric("round_output_packets", @intCast(round.output_packets), "");
    try reporter.metric("round_output_bytes", @intCast(round.output_bytes), "B");
    try reporter.metric("round_events", @intCast(round.events), "");
    try reporter.metric("round_uplink_ms", nsToMs(round.uplink_ns), "ms");
    try reporter.metric("round_response_ms", nsToMs(round.response_ns), "ms");
    try reporter.metric("round_first_transcript_ms", nsToMs(round.first_transcript_ns), "ms");
    try reporter.metric("round_transcript_done_ms", nsToMs(round.transcript_done_ns), "ms");
    try reporter.metric("round_first_assistant_text_ms", nsToMs(round.first_assistant_text_ns), "ms");
    try reporter.metric("round_assistant_text_done_ms", nsToMs(round.assistant_text_done_ns), "ms");
    try reporter.metric("round_first_audio_ms", nsToMs(round.first_audio_ns), "ms");
}

fn nsToMs(ns: u64) u64 {
    return @divTrunc(ns, @as(u64, @intCast(duration.MilliSecond)));
}

const OpusPackets = struct {
    items: [][]const u8,
    payloads: []u8,

    fn deinit(self: *OpusPackets, allocator: mem.Allocator) void {
        allocator.free(self.items);
        allocator.free(self.payloads);
        self.* = undefined;
    }
};

fn parseOggOpusPackets(allocator: mem.Allocator, data: []const u8) !OpusPackets {
    var packets = grt.std.ArrayList([]const u8){};
    defer packets.deinit(allocator);
    const payloads = try allocator.alloc(u8, data.len);
    errdefer allocator.free(payloads);

    var offset: usize = 0;
    var pending_start: usize = 0;
    var pending_len: usize = 0;
    while (offset < data.len) {
        if (offset + 27 > data.len) return error.InvalidOggPage;
        if (!mem.eql(u8, data[offset .. offset + 4], "OggS")) return error.InvalidOggPage;
        const segment_count: usize = data[offset + 26];
        const lacing_start = offset + 27;
        const lacing_end = lacing_start + segment_count;
        if (lacing_end > data.len) return error.TruncatedOggPage;
        var body_len: usize = 0;
        for (data[lacing_start..lacing_end]) |size| body_len += size;
        const body_start = lacing_end;
        const body_end = body_start + body_len;
        if (body_end > data.len) return error.TruncatedOggPage;

        var cursor = body_start;
        for (data[lacing_start..lacing_end]) |size| {
            if (pending_len == 0) pending_start = pending_start + pending_len;
            if (pending_start + pending_len + size > payloads.len) return error.OggPacketTooLarge;
            @memcpy(payloads[pending_start + pending_len .. pending_start + pending_len + size], data[cursor .. cursor + size]);
            pending_len += size;
            cursor += size;
            if (size < 255) {
                const packet = payloads[pending_start .. pending_start + pending_len];
                if (packet.len != 0 and !mem.startsWith(u8, packet, "OpusHead") and !mem.startsWith(u8, packet, "OpusTags")) {
                    try packets.append(allocator, packet);
                }
                pending_start += pending_len;
                pending_len = 0;
            }
        }
        offset = body_end;
    }
    if (pending_len != 0) return error.UnterminatedOggPacket;
    if (packets.items.len == 0) return error.EmptyOpusAudio;
    return .{
        .items = try packets.toOwnedSlice(allocator),
        .payloads = payloads,
    };
}

fn makeStreamID(allocator: mem.Allocator, round_index: u32) ![]u8 {
    var out = grt.std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    try out.writer.print("audio-zig-e2e-{d}-{d}", .{
        @as(u64, @intCast(@divTrunc(grt.time.instant.now(), duration.MilliSecond))),
        round_index,
    });
    return try allocator.dupe(u8, out.written());
}

fn eventLabel(event: anytype) []const u8 {
    if (event.label) |label| return label;
    return "";
}

fn textHasContent(text: []const u8) bool {
    return mem.trim(u8, text, " \t\r\n").len != 0;
}

fn isTranscriptDoneEvent(event: anytype) bool {
    return event.type == .text_done or event.type == .eos;
}

fn acceptRoundEventStream(actual: ?[]const u8, expected: []const u8, bound: *?[]const u8) bool {
    const value = actual orelse return true;
    if (mem.trim(u8, value, " \t\r\n").len == 0) return true;
    if (streamIDMatches(value, expected)) return true;
    if (bound.*) |existing| return streamIDMatches(value, existing);
    bound.* = value;
    return true;
}

fn streamIDMatches(actual_raw: []const u8, expected_raw: []const u8) bool {
    const actual = mem.trim(u8, actual_raw, " \t\r\n");
    const expected = mem.trim(u8, expected_raw, " \t\r\n");
    return mem.eql(u8, actual, expected) or (expected.len != 0 and mem.startsWith(u8, actual, expected) and actual.len > expected.len and actual[expected.len] == ':');
}

const Manifest = struct {
    rounds: []const Round,

    const Round = struct {
        index: u32,
        audio: []const u8,
        text: []const u8,
    };
};

const ManifestInfo = struct {
    rounds: usize,
};

fn loadManifest(allocator: mem.Allocator, data: []const u8) !ManifestInfo {
    var manifest_doc = try json.parseFromSlice(Manifest, allocator, data, .{});
    defer manifest_doc.deinit();
    if (manifest_doc.value.rounds.len == 0) return error.EmptyAudioManifest;
    for (manifest_doc.value.rounds) |round| {
        if (round.index == 0) return error.InvalidAudioManifest;
        if (round.audio.len == 0) return error.InvalidAudioManifest;
        if (round.text.len == 0) return error.InvalidAudioManifest;
    }
    return .{ .rounds = manifest_doc.value.rounds.len };
}

fn parsed(summary: *Summary, reporter: anytype, name: []const u8, result: anytype) !void {
    if (result) |value| {
        var parsed_value = value;
        defer parsed_value.deinit();
        try recordPass(summary, reporter, name);
    } else |err| {
        try recordFail(summary, reporter, name, err);
    }
}

fn recordPass(summary: *Summary, reporter: anytype, name: []const u8) !void {
    summary.pass();
    try reporter.pass(name);
}

fn recordFail(summary: *Summary, reporter: anytype, name: []const u8, err: anyerror) !void {
    summary.fail();
    try reporter.fail(name, err);
}
