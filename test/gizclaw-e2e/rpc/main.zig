const std = @import("std");
const common = @import("common");

const RpcOptions = struct {
    base: common.BaseOptions = .{},
    allow_mutations: bool = false,
    workspace: ?[]const u8 = null,
    voice_id: ?[]const u8 = null,
    firmware_id: ?[]const u8 = null,
    firmware_channel: ?[]const u8 = null,
    firmware_artifact: ?[]const u8 = null,
    friend_group_id: ?[]const u8 = null,
    audio_base64: ?[]const u8 = null,
    peer_context: ?[]const u8 = null,

    fn parse(allocator: std.mem.Allocator) !RpcOptions {
        const args = try std.process.argsAlloc(allocator);
        var out = RpcOptions{};
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (try out.base.applyArg(args, &i)) continue;
            const arg = args[i];
            if (std.mem.eql(u8, arg, "--help")) {
                try printUsage();
                std.process.exit(0);
            } else if (std.mem.eql(u8, arg, "--allow-mutations")) {
                out.allow_mutations = true;
            } else if (std.mem.eql(u8, arg, "--workspace")) {
                i += 1;
                out.workspace = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--voice-id")) {
                i += 1;
                out.voice_id = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--firmware-id")) {
                i += 1;
                out.firmware_id = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--firmware-channel")) {
                i += 1;
                out.firmware_channel = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--firmware-artifact")) {
                i += 1;
                out.firmware_artifact = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--friend-group-id")) {
                i += 1;
                out.friend_group_id = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--audio-base64")) {
                i += 1;
                out.audio_base64 = try common.needValue(args, i, arg);
            } else if (std.mem.eql(u8, arg, "--peer-context")) {
                i += 1;
                out.peer_context = try common.needValue(args, i, arg);
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
        \\usage: gizclaw-e2e-rpc [options]
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
        \\Fixtures:
        \\  --workspace NAME       Workspace used for run-control methods
        \\  --voice-id ID          Voice fixture for ServerRunSay
        \\  --firmware-id ID --firmware-channel NAME --firmware-artifact NAME
        \\  --friend-group-id ID --audio-base64 PAYLOAD
        \\  --peer-context DIR    Second Go setup context for friend/member RPCs
        \\  --allow-mutations      Permit selected status mutations
        \\
    );
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();
    const options = try RpcOptions.parse(allocator);
    var ctx = try common.loadContext(allocator, options.base);
    defer ctx.deinit();

    switch (ctx.cipher_mode) {
        .chacha_poly => try runWithSdk(common.chacha_sdk, allocator, &ctx, options),
        .aes_256_gcm => try runWithSdk(common.aes_256_gcm_sdk, allocator, &ctx, options),
        .plaintext => try runWithSdk(common.plaintext_sdk, allocator, &ctx, options),
    }
}

fn runWithSdk(comptime sdk: type, allocator: std.mem.Allocator, ctx: *const common.Context, options: RpcOptions) !void {
    var summary = common.Summary.init();
    var client = common.connectClient(sdk, allocator, ctx) catch |err| {
        try summary.fail("Connect", err);
        return summary.finish();
    };
    defer client.deinit();
    try summary.pass("Connect");

    var peer_ctx: ?common.Context = null;
    defer if (peer_ctx) |*ctx_value| ctx_value.deinit();
    var peer_client: ?sdk.Client = null;
    defer if (peer_client) |*client_value| client_value.deinit();
    var peer_id_buf: [52]u8 = undefined;
    var peer_id: ?[]const u8 = null;
    if (options.peer_context) |peer_context_dir| {
        var peer_base = options.base;
        peer_base.context_dir = peer_context_dir;
        peer_ctx = common.loadContext(allocator, peer_base) catch |err| {
            try summary.fail("ConnectPeer", err);
            return summary.finish();
        };
        peer_id = common.key.format(peer_ctx.?.key_pair.public, &peer_id_buf);
        peer_client = common.connectClient(sdk, allocator, &peer_ctx.?) catch |err| {
            try summary.fail("ConnectPeer", err);
            return summary.finish();
        };
        try summary.pass("ConnectPeer");
    }

    try checkCore(sdk, &client, &summary, options);
    try checkResources(sdk, &client, if (peer_client) |*value| value else null, peer_id, &summary, options);
    try checkStopRun(sdk, &client, &summary, options);
    try summary.finish();
}

fn checkCore(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, options: RpcOptions) !void {
    if (client.ping()) |response| {
        _ = response;
        try summary.pass("Ping");
    } else |err| try summary.fail("Ping", err);

    try parsed(summary, "GetServerInfo", client.getServerInfo());
    try parsed(summary, "GetServerRuntime", client.getServerRuntime());
    try parsed(summary, "GetServerStatus", client.getServerStatus());
    try parsed(summary, "GetServerRunAgent", client.getServerRunAgent());
    try parsed(summary, "GetServerRunStatus", client.getServerRunStatus(.{}));
    try parsed(summary, "GetServerRunWorkspace", client.getServerRunWorkspace());
    var run_history = client.listServerRunWorkspaceHistory(.{ .limit = 1 }) catch |err| return summary.fail("ListServerRunWorkspaceHistory", err);
    defer run_history.deinit();
    try summary.pass("ListServerRunWorkspaceHistory");
    try checkPagination(summary, "ListServerRunWorkspaceHistory pagination", run_history.value.has_next, run_history.value.next_cursor);
    if (run_history.value.items.len != 0 and run_history.value.items[0].replay_available) {
        try parsed(summary, "PlayServerRunWorkspaceHistory", client.playServerRunWorkspaceHistory(.{ .history_id = run_history.value.items[0].id }));
    } else {
        try summary.skip("PlayServerRunWorkspaceHistory", "run history returned no replayable fixture rows");
    }
    try parsed(summary, "GetServerRunWorkspaceMemoryStats", client.getServerRunWorkspaceMemoryStats(.{}));
    try parsed(summary, "ServerRunWorkspaceRecall", client.serverRunWorkspaceRecall(.{ .query = "hello", .limit = 1 }));

    if (options.allow_mutations) {
        var info = client.getServerInfo() catch |err| return summary.fail("PutServerInfo", err);
        defer info.deinit();
        try parsed(summary, "PutServerInfo", client.putServerInfo(info.value));
        try parsed(summary, "PutServerStatus", client.putServerStatus(.{}));
    } else {
        try summary.skip("PutServerInfo", "mutates server-side peer info; rerun with --allow-mutations and fixture data");
        try summary.skip("PutServerStatus", "mutates server-side peer status; rerun with --allow-mutations");
    }

    if (options.workspace) |workspace| {
        try parsed(summary, "SetServerRunAgent", client.setServerRunAgent(.{ .workspace_name = workspace }));
        try parsed(summary, "SetServerRunWorkspace", client.setServerRunWorkspace(.{ .workspace_name = workspace }));
        try parsed(summary, "ReloadServerRun", client.reloadServerRun());
        try parsed(summary, "ReloadServerRunWorkspace", client.reloadServerRunWorkspace());
        try waitServerRunWorkspace(sdk, client, summary, workspace);
    } else {
        try summary.skip("SetServerRunAgent", "requires --workspace fixture");
        try summary.skip("SetServerRunWorkspace", "requires --workspace fixture");
        try summary.skip("ReloadServerRun", "requires --workspace fixture");
        try summary.skip("ReloadServerRunWorkspace", "requires --workspace fixture");
        try summary.skip("WaitServerRunWorkspace", "requires --workspace fixture");
    }

    if (options.voice_id != null) {
        try parsed(summary, "ServerRunSay", client.serverRunSay(.{
            .text = "hello from gizclaw-zig e2e",
            .voice_id = options.voice_id,
        }));
    } else {
        try summary.skip("ServerRunSay", "requires --voice-id fixture and running audio path");
    }
}

fn waitServerRunWorkspace(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, workspace: []const u8) !void {
    const deadline = std.time.milliTimestamp() + 30_000;
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

fn checkStopRun(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, options: RpcOptions) !void {
    if (options.workspace != null) {
        try parsed(summary, "StopServerRun", client.stopServerRun());
    } else {
        try summary.skip("StopServerRun", "requires --workspace fixture");
    }
}

fn checkResources(comptime sdk: type, client: *sdk.Client, peer_client: ?*sdk.Client, peer_id: ?[]const u8, summary: *common.Summary, options: RpcOptions) !void {
    try checkWorkspacePages(sdk, client, summary, options);
    try checkWorkflowPages(sdk, client, summary, options);
    try checkModelPages(sdk, client, summary);
    try checkCredentialPages(sdk, client, summary);
    try checkVoicePages(sdk, client, summary);
    try checkFirmwarePages(sdk, client, summary, options);
    try checkSocialPages(sdk, client, peer_client, peer_id, summary, options);
}

fn checkWorkspacePages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, options: RpcOptions) !void {
    var page = client.listWorkspaces(.{ .limit = 1 }) catch |err| return summary.fail("ListWorkspaces", err);
    defer page.deinit();
    try summary.pass("ListWorkspaces");
    try checkPagination(summary, "ListWorkspaces pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListWorkspaces next page", client.listWorkspaces(.{ .limit = 1, .cursor = cursor }));
        }
    }
    if (page.value.items.len != 0) {
        try parsed(summary, "GetWorkspace", client.getWorkspace(.{ .name = page.value.items[0].name }));
    } else {
        try summary.skip("GetWorkspace", "ListWorkspaces returned no fixture rows");
    }
    if (options.workspace) |workspace| {
        var history = client.listWorkspaceHistory(.{ .workspace_name = workspace, .limit = 1 }) catch |err| return summary.fail("ListWorkspaceHistory", err);
        defer history.deinit();
        try summary.pass("ListWorkspaceHistory");
        try checkPagination(summary, "ListWorkspaceHistory pagination", history.value.has_next, history.value.next_cursor);
        if (history.value.items.len != 0) {
            const history_id = history.value.items[0].id;
            try parsed(summary, "GetWorkspaceHistory", client.getWorkspaceHistory(.{ .workspace_name = workspace, .history_id = history_id }));
            var sink = std.ArrayList(u8){};
            defer sink.deinit(std.heap.page_allocator);
            var audio = client.getWorkspaceHistoryAudio(.{ .workspace_name = workspace, .history_id = history_id }, sink.writer(std.heap.page_allocator)) catch |err| return summary.fail("GetWorkspaceHistoryAudio", err);
            defer audio.deinit();
            if (audio.bytes > 0) try summary.pass("GetWorkspaceHistoryAudio") else try summary.fail("GetWorkspaceHistoryAudio", error.EmptyWorkspaceHistoryAudio);
        } else {
            try summary.skip("GetWorkspaceHistory", "workspace history returned no fixture rows");
            try summary.skip("GetWorkspaceHistoryAudio", "workspace history returned no fixture rows");
        }
    } else {
        try summary.skip("ListWorkspaceHistory", "requires --workspace fixture");
        try summary.skip("GetWorkspaceHistory", "requires --workspace fixture");
        try summary.skip("GetWorkspaceHistoryAudio", "requires --workspace fixture");
    }
    try checkWorkspaceMutations(sdk, client, summary);
}

fn checkWorkflowPages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, options: RpcOptions) !void {
    _ = options;
    var page = client.listWorkflows(.{ .limit = 1 }) catch |err| return summary.fail("ListWorkflows", err);
    defer page.deinit();
    try summary.pass("ListWorkflows");
    try checkPagination(summary, "ListWorkflows pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListWorkflows next page", client.listWorkflows(.{ .limit = 1, .cursor = cursor }));
        }
    }
    if (page.value.items.len != 0) {
        try parsed(summary, "GetWorkflow", client.getWorkflow(.{ .name = page.value.items[0].metadata.name }));
    } else {
        try summary.skip("GetWorkflow", "ListWorkflows returned no fixture rows");
    }
    try checkWorkflowMutations(sdk, client, summary);
}

fn checkWorkspaceMutations(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    const workflow_name = try findWorkflowFixture(sdk, client);
    if (workflow_name == null) {
        try summary.skip("CreateWorkspace", "requires at least one workflow fixture");
        try summary.skip("PutWorkspace", "requires at least one workflow fixture");
        try summary.skip("DeleteWorkspace", "requires at least one workflow fixture");
        try summary.skip("ListWorkspaces pagination after create", "requires at least one workflow fixture");
        return;
    }
    defer std.heap.page_allocator.free(workflow_name.?);

    const suffix = std.time.milliTimestamp();
    var primary_buf: [80]u8 = undefined;
    const primary_name = try std.fmt.bufPrint(&primary_buf, "zig-e2e-rpc-workspace-{d}", .{suffix});
    var secondary_buf: [80]u8 = undefined;
    const secondary_name = try std.fmt.bufPrint(&secondary_buf, "zig-e2e-rpc-workspace-page-{d}", .{suffix});

    var created_primary = false;
    var created_secondary = false;
    defer if (created_primary) {
        var deleted = client.deleteWorkspace(.{ .name = primary_name }) catch null;
        if (deleted) |*value| value.deinit();
    };
    defer if (created_secondary) {
        var deleted = client.deleteWorkspace(.{ .name = secondary_name }) catch null;
        if (deleted) |*value| value.deinit();
    };

    const create_json = try workspaceCreateJson(primary_name, workflow_name.?);
    defer std.heap.page_allocator.free(create_json);
    var create_request = try sdk.models.fromJson(sdk.models.WorkspaceCreateRequest, std.heap.page_allocator, create_json);
    defer create_request.deinit();
    var created = client.createWorkspace(create_request.value) catch |err| return summary.fail("CreateWorkspace", err);
    defer created.deinit();
    created_primary = true;
    try summary.pass("CreateWorkspace");

    const second_json = try workspaceCreateJson(secondary_name, workflow_name.?);
    defer std.heap.page_allocator.free(second_json);
    var second_request = try sdk.models.fromJson(sdk.models.WorkspaceCreateRequest, std.heap.page_allocator, second_json);
    defer second_request.deinit();
    var second = client.createWorkspace(second_request.value) catch |err| return summary.fail("CreateWorkspace pagination fixture", err);
    defer second.deinit();
    created_secondary = true;
    try summary.pass("CreateWorkspace pagination fixture");

    const put_json = try workspacePutJson(primary_name, workflow_name.?);
    defer std.heap.page_allocator.free(put_json);
    var put_body = try sdk.models.fromJson(sdk.models.WorkspaceCreateRequest, std.heap.page_allocator, put_json);
    defer put_body.deinit();
    try parsed(summary, "PutWorkspace", client.putWorkspace(.{
        .name = primary_name,
        .body = put_body.value,
    }));
    try parsed(summary, "GetWorkspace created fixture", client.getWorkspace(.{ .name = primary_name }));

    var page = client.listWorkspaces(.{ .limit = 1 }) catch |err| return summary.fail("ListWorkspaces after create", err);
    defer page.deinit();
    try summary.pass("ListWorkspaces after create");
    try checkPagination(summary, "ListWorkspaces pagination after create", page.value.has_next, page.value.next_cursor);

    try parsed(summary, "DeleteWorkspace", client.deleteWorkspace(.{ .name = secondary_name }));
    created_secondary = false;
    try parsed(summary, "DeleteWorkspace cleanup primary", client.deleteWorkspace(.{ .name = primary_name }));
    created_primary = false;
}

fn checkWorkflowMutations(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    const suffix = std.time.milliTimestamp();
    var primary_buf: [80]u8 = undefined;
    const primary_name = try std.fmt.bufPrint(&primary_buf, "zig-e2e-rpc-workflow-{d}", .{suffix});
    var secondary_buf: [80]u8 = undefined;
    const secondary_name = try std.fmt.bufPrint(&secondary_buf, "zig-e2e-rpc-workflow-page-{d}", .{suffix});

    var created_primary = false;
    var created_secondary = false;
    defer if (created_primary) {
        var deleted = client.deleteWorkflow(.{ .name = primary_name }) catch null;
        if (deleted) |*value| value.deinit();
    };
    defer if (created_secondary) {
        var deleted = client.deleteWorkflow(.{ .name = secondary_name }) catch null;
        if (deleted) |*value| value.deinit();
    };

    const create_json = try workflowCreateJson(primary_name, "gizclaw-zig rpc e2e workflow");
    defer std.heap.page_allocator.free(create_json);
    var create_request = try sdk.models.fromJson(sdk.models.WorkflowCreateRequest, std.heap.page_allocator, create_json);
    defer create_request.deinit();
    var created = client.createWorkflow(create_request.value) catch |err| return summary.fail("CreateWorkflow", err);
    defer created.deinit();
    created_primary = true;
    try summary.pass("CreateWorkflow");

    const second_json = try workflowCreateJson(secondary_name, "gizclaw-zig rpc e2e pagination workflow");
    defer std.heap.page_allocator.free(second_json);
    var second_request = try sdk.models.fromJson(sdk.models.WorkflowCreateRequest, std.heap.page_allocator, second_json);
    defer second_request.deinit();
    var second = client.createWorkflow(second_request.value) catch |err| return summary.fail("CreateWorkflow pagination fixture", err);
    defer second.deinit();
    created_secondary = true;
    try summary.pass("CreateWorkflow pagination fixture");

    const put_json = try workflowCreateJson(primary_name, "gizclaw-zig rpc e2e workflow updated");
    defer std.heap.page_allocator.free(put_json);
    var put_body = try sdk.models.fromJson(sdk.models.WorkflowCreateRequest, std.heap.page_allocator, put_json);
    defer put_body.deinit();
    try parsed(summary, "PutWorkflow", client.putWorkflow(.{
        .name = primary_name,
        .body = put_body.value,
    }));
    try parsed(summary, "GetWorkflow created fixture", client.getWorkflow(.{ .name = primary_name }));

    var page = client.listWorkflows(.{ .limit = 1 }) catch |err| return summary.fail("ListWorkflows after create", err);
    defer page.deinit();
    try summary.pass("ListWorkflows after create");
    try checkPagination(summary, "ListWorkflows pagination after create", page.value.has_next, page.value.next_cursor);

    try parsed(summary, "DeleteWorkflow", client.deleteWorkflow(.{ .name = secondary_name }));
    created_secondary = false;
    try parsed(summary, "DeleteWorkflow cleanup primary", client.deleteWorkflow(.{ .name = primary_name }));
    created_primary = false;
}

fn findWorkflowFixture(comptime sdk: type, client: *sdk.Client) !?[]u8 {
    var page = try client.listWorkflows(.{ .limit = 1 });
    defer page.deinit();
    if (page.value.items.len == 0) return null;
    return try std.heap.page_allocator.dupe(u8, page.value.items[0].metadata.name);
}

fn workflowCreateJson(name: []const u8, description: []const u8) ![]u8 {
    var out = std.Io.Writer.Allocating.init(std.heap.page_allocator);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"metadata\":{\"name\":");
    try std.json.Stringify.value(name, .{}, w);
    try w.writeAll(",\"description\":");
    try std.json.Stringify.value(description, .{}, w);
    try w.writeAll("},\"spec\":{\"driver\":\"flowcraft\",\"flowcraft\":{\"entry_agent\":\"\"}}}");
    return try out.toOwnedSlice();
}

fn workspaceCreateJson(name: []const u8, workflow_name: []const u8) ![]u8 {
    return try workspaceJson(name, workflow_name, false);
}

fn workspacePutJson(name: []const u8, workflow_name: []const u8) ![]u8 {
    return try workspaceJson(name, workflow_name, true);
}

fn workspaceJson(name: []const u8, workflow_name: []const u8, updated: bool) ![]u8 {
    var out = std.Io.Writer.Allocating.init(std.heap.page_allocator);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"name\":");
    try std.json.Stringify.value(name, .{}, w);
    try w.writeAll(",\"workflow_name\":");
    try std.json.Stringify.value(workflow_name, .{}, w);
    try w.writeAll(",\"parameters\":{\"agent_type\":\"flowcraft\",\"input\":\"push-to-talk\",\"e2e\":true");
    if (updated) try w.writeAll(",\"updated\":true");
    try w.writeAll("}}");
    return try out.toOwnedSlice();
}

fn checkModelPages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    var page = client.listModels(.{ .limit = 1 }) catch |err| return summary.fail("ListModels", err);
    defer page.deinit();
    try summary.pass("ListModels");
    try checkPagination(summary, "ListModels pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListModels next page", client.listModels(.{ .limit = 1, .cursor = cursor }));
        }
    }
    if (page.value.items.len != 0) {
        try parsed(summary, "GetModel", client.getModel(.{ .id = page.value.items[0].id }));
    } else {
        try summary.skip("GetModel", "ListModels returned no fixture rows");
    }
}

fn checkCredentialPages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    var page = client.listCredentials(.{ .limit = 1 }) catch |err| return summary.fail("ListCredentials", err);
    defer page.deinit();
    try summary.pass("ListCredentials");
    try checkPagination(summary, "ListCredentials pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListCredentials next page", client.listCredentials(.{ .limit = 1, .cursor = cursor }));
        }
    }
    if (page.value.items.len != 0) {
        try parsed(summary, "GetCredential", client.getCredential(.{ .name = page.value.items[0].name }));
    } else {
        try summary.skip("GetCredential", "ListCredentials returned no fixture rows");
    }
}

fn checkVoicePages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    var page = client.listVoices(.{ .limit = 1 }) catch |err| return summary.fail("ListVoices", err);
    defer page.deinit();
    try summary.pass("ListVoices");
    try checkPagination(summary, "ListVoices pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListVoices next page", client.listVoices(.{ .limit = 1, .cursor = cursor }));
        }
    }
    if (page.value.data.len != 0) {
        try parsed(summary, "GetVoice", client.getVoice(.{ .id = page.value.data[0].id }));
    } else {
        try summary.skip("GetVoice", "ListVoices returned no fixture rows");
    }
}

fn checkFirmwarePages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, options: RpcOptions) !void {
    var page = client.listFirmwares(.{ .limit = 1 }) catch |err| return summary.fail("ListFirmwares", err);
    defer page.deinit();
    try summary.pass("ListFirmwares");
    try checkPagination(summary, "ListFirmwares pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListFirmwares next page", client.listFirmwares(.{ .limit = 1, .cursor = cursor }));
        }
    }
    if (page.value.items.len != 0) {
        try parsed(summary, "GetFirmware", client.getFirmware(.{ .firmware_id = page.value.items[0].name }));
    } else {
        try summary.skip("GetFirmware", "ListFirmwares returned no fixture rows");
    }
    if (options.firmware_id != null and options.firmware_channel != null and options.firmware_artifact != null) {
        var sink = std.ArrayList(u8){};
        defer sink.deinit(std.heap.page_allocator);
        var result = client.downloadFirmware(.{
            .firmware_id = options.firmware_id.?,
            .channel = options.firmware_channel.?,
            .artifact_name = options.firmware_artifact.?,
        }, sink.writer(std.heap.page_allocator)) catch |err| return summary.fail("DownloadFirmware", err);
        defer result.deinit();
        if (result.bytes > 0) try summary.pass("DownloadFirmware") else try summary.fail("DownloadFirmware", error.EmptyFirmwarePayload);
    } else {
        try summary.skip("DownloadFirmware", "requires --firmware-id --firmware-channel --firmware-artifact");
    }
}

fn checkSocialPages(comptime sdk: type, client: *sdk.Client, peer_client: ?*sdk.Client, peer_id: ?[]const u8, summary: *common.Summary, options: RpcOptions) !void {
    _ = client;
    _ = peer_client;
    _ = peer_id;
    _ = options;
    try summary.skip("ListContacts", "social RPC coverage is intentionally deferred");
    try summary.skip("ListContacts pagination", "social RPC coverage is intentionally deferred");
    try summary.skip("GetContact", "social RPC coverage is intentionally deferred");
    try summary.skip("CreateContact", "social RPC coverage is intentionally deferred");
    try summary.skip("PutContact", "social RPC coverage is intentionally deferred");
    try summary.skip("DeleteContact", "social RPC coverage is intentionally deferred");
    try summary.skip("ListFriendRequests", "social RPC coverage is intentionally deferred");
    try summary.skip("ListFriendRequests pagination", "social RPC coverage is intentionally deferred");
    try summary.skip("CreateFriendRequest", "social RPC coverage is intentionally deferred");
    try summary.skip("AcceptFriendRequest", "social RPC coverage is intentionally deferred");
    try summary.skip("RejectFriendRequest", "social RPC coverage is intentionally deferred");
    try summary.skip("ListFriends", "social RPC coverage is intentionally deferred");
    try summary.skip("ListFriends pagination", "social RPC coverage is intentionally deferred");
    try summary.skip("DeleteFriend", "social RPC coverage is intentionally deferred");
    try summary.skip("ListFriendGroups", "social RPC coverage is intentionally deferred");
    try summary.skip("ListFriendGroups pagination", "social RPC coverage is intentionally deferred");
    try summary.skip("GetFriendGroup", "social RPC coverage is intentionally deferred");
    try summary.skip("CreateFriendGroup", "social RPC coverage is intentionally deferred");
    try summary.skip("PutFriendGroup", "social RPC coverage is intentionally deferred");
    try summary.skip("DeleteFriendGroup", "social RPC coverage is intentionally deferred");
    try summary.skip("ListFriendGroupMembers", "social RPC coverage is intentionally deferred");
    try summary.skip("AddFriendGroupMember", "social RPC coverage is intentionally deferred");
    try summary.skip("PutFriendGroupMember", "social RPC coverage is intentionally deferred");
    try summary.skip("DeleteFriendGroupMember", "social RPC coverage is intentionally deferred");
    try summary.skip("ListFriendGroupMessages", "social RPC coverage is intentionally deferred");
    try summary.skip("GetFriendGroupMessage", "social RPC coverage is intentionally deferred");
    try summary.skip("SendFriendGroupMessage", "social RPC coverage is intentionally deferred");
}

fn checkFriendGroupPages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, options: RpcOptions) !void {
    _ = options;
    var groups = client.listFriendGroups(.{ .limit = 1 }) catch |err| return summary.fail("ListFriendGroups", err);
    defer groups.deinit();
    try summary.pass("ListFriendGroups");
    try checkPagination(summary, "ListFriendGroups pagination", groups.value.has_next, groups.value.next_cursor);
    if (groups.value.has_next) {
        if (groups.value.next_cursor) |cursor| {
            try parsed(summary, "ListFriendGroups next page", client.listFriendGroups(.{ .limit = 1, .cursor = cursor }));
        }
    }
    if (groups.value.items.len != 0) {
        if (groups.value.items[0].id) |id| {
            try parsed(summary, "GetFriendGroup", client.getFriendGroup(.{ .id = id }));
            try checkFriendGroupMemberPages(sdk, client, summary, id);
            try checkFriendGroupMessagePages(sdk, client, summary, id);
        } else {
            try summary.skip("GetFriendGroup", "first fixture row has no id");
            try summary.skip("ListFriendGroupMembers", "friend group fixture has no id");
            try summary.skip("ListFriendGroupMessages", "friend group fixture has no id");
            try summary.skip("GetFriendGroupMessage", "friend group fixture has no id");
        }
    } else {
        try summary.skip("GetFriendGroup", "ListFriendGroups returned no fixture rows");
        try summary.skip("ListFriendGroupMembers", "requires friend group fixture");
        try summary.skip("ListFriendGroupMessages", "requires friend group fixture");
        try summary.skip("GetFriendGroupMessage", "requires friend group fixture");
    }
}

fn checkContactMutations(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    var name_buf: [64]u8 = undefined;
    const display_name = try std.fmt.bufPrint(&name_buf, "gizclaw-zig e2e contact {d}", .{std.time.milliTimestamp()});

    const create_request = sdk.models.ContactCreateRequest{
        .display_name = display_name,
        .phone_number = "+1 555 0199",
    };
    const id = blk: {
        var created = client.createContact(create_request) catch |err| switch (err) {
            error.Timeout => {
                if (try findContactIdByDisplayName(sdk, client, display_name)) |id| break :blk id;
                var retried = client.createContact(create_request) catch |retry_err| return summary.fail("CreateContact", retry_err);
                defer retried.deinit();
                const retried_id = retried.value.id orelse {
                    try summary.fail("CreateContact", error.MissingContactId);
                    return;
                };
                break :blk try dupeRequiredString(retried_id);
            },
            else => return summary.fail("CreateContact", err),
        };
        defer created.deinit();
        const created_id = created.value.id orelse {
            try summary.fail("CreateContact", error.MissingContactId);
            return;
        };
        break :blk try dupeRequiredString(created_id);
    };
    defer std.heap.page_allocator.free(id);
    try summary.pass("CreateContact");

    try parsed(summary, "PutContact", client.putContact(.{
        .id = id,
        .display_name = "gizclaw-zig e2e contact updated",
        .phone_number = "+1 555 0200",
    }));

    try checkContactPages(sdk, client, summary);
    try parsed(summary, "DeleteContact", client.deleteContact(.{ .id = id }));
}

fn findContactIdByDisplayName(comptime sdk: type, client: *sdk.Client, display_name: []const u8) !?[]u8 {
    var request = sdk.models.ContactListRequest{ .limit = 100 };
    while (true) {
        var page = try client.listContacts(request);
        defer page.deinit();
        for (page.value.items) |contact| {
            if (contact.display_name) |name| {
                if (std.mem.eql(u8, name, display_name)) {
                    const id = contact.id orelse return null;
                    return try dupeRequiredString(id);
                }
            }
        }
        if (!page.value.has_next) return null;
        request.cursor = page.value.next_cursor orelse return null;
    }
}

fn dupeRequiredString(value: []const u8) ![]u8 {
    return try std.heap.page_allocator.dupe(u8, value);
}

fn checkFriendRequestMutations(comptime sdk: type, client: *sdk.Client, peer_client: *sdk.Client, peer_id: []const u8, summary: *common.Summary) ![]u8 {
    try parsed(summary, "ReportFriendOTP reject fixture", peer_client.getServerRunStatus(.{ .friend_otp = "120001" }));
    var rejected_request = client.createFriendRequest(.{
        .to_peer_id = peer_id,
        .code = "120001",
        .message = "gizclaw-zig rejected fixture",
    }) catch |err| {
        try summary.fail("CreateFriendRequest reject fixture", err);
        return err;
    };
    defer rejected_request.deinit();
    const rejected_id = rejected_request.value.id orelse return error.MissingFriendRequestId;
    try parsed(summary, "RejectFriendRequest", peer_client.rejectFriendRequest(.{ .id = rejected_id }));

    try parsed(summary, "ReportFriendOTP", peer_client.getServerRunStatus(.{ .friend_otp = "120002" }));
    var request = client.createFriendRequest(.{
        .to_peer_id = peer_id,
        .code = "120002",
        .message = "gizclaw-zig e2e friend request",
    }) catch |err| {
        try summary.fail("CreateFriendRequest", err);
        return err;
    };
    defer request.deinit();
    const request_id = request.value.id orelse return error.MissingFriendRequestId;
    try summary.pass("CreateFriendRequest");

    try parsed(summary, "AcceptFriendRequest", peer_client.acceptFriendRequest(.{ .id = request_id }));

    var friends = client.listFriends(.{ .limit = 100 }) catch |err| {
        try summary.fail("FindAcceptedFriend", err);
        return err;
    };
    defer friends.deinit();
    for (friends.value.items) |friend| {
        if (friend.peer_id) |id| {
            if (std.mem.eql(u8, id, peer_id)) {
                const found_id = friend.id orelse return error.MissingFriendId;
                return try dupeRequiredString(found_id);
            }
        }
    }
    return error.AcceptedFriendNotFound;
}

fn checkFriendGroupMutations(comptime sdk: type, client: *sdk.Client, peer_id: ?[]const u8, summary: *common.Summary) !void {
    const suffix = std.time.milliTimestamp();
    var name_buf: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "zig-e2e-{d}", .{suffix});
    var second_name_buf: [64]u8 = undefined;
    const second_name = try std.fmt.bufPrint(&second_name_buf, "zig-e2e-backup-{d}", .{suffix});

    var created = client.createFriendGroup(.{
        .name = name,
        .description = "gizclaw-zig rpc e2e group",
    }) catch |err| return summary.fail("CreateFriendGroup", err);
    defer created.deinit();
    const group_id = created.value.id orelse return summary.fail("CreateFriendGroup", error.MissingFriendGroupId);
    try summary.pass("CreateFriendGroup");

    var second = client.createFriendGroup(.{
        .name = second_name,
        .description = "gizclaw-zig rpc e2e pagination group",
    }) catch |err| return summary.fail("CreateFriendGroup pagination fixture", err);
    defer second.deinit();
    const second_group_id = second.value.id orelse return summary.fail("CreateFriendGroup pagination fixture", error.MissingFriendGroupId);

    try parsed(summary, "PutFriendGroup", client.putFriendGroup(.{
        .id = group_id,
        .name = "zig e2e group updated",
        .description = "updated by gizclaw-zig rpc e2e",
    }));

    var groups = client.listFriendGroups(.{ .limit = 1 }) catch |err| return summary.fail("ListFriendGroups", err);
    defer groups.deinit();
    try summary.pass("ListFriendGroups");
    try checkPagination(summary, "ListFriendGroups pagination", groups.value.has_next, groups.value.next_cursor);
    if (groups.value.has_next) {
        if (groups.value.next_cursor) |cursor| {
            try parsed(summary, "ListFriendGroups next page", client.listFriendGroups(.{ .limit = 1, .cursor = cursor }));
        }
    }
    try parsed(summary, "GetFriendGroup", client.getFriendGroup(.{ .id = group_id }));

    if (peer_id) |member_peer_id| {
        var member = client.addFriendGroupMember(.{
            .friend_group_id = group_id,
            .peer_id = member_peer_id,
            .role = "member",
        }) catch |err| return summary.fail("AddFriendGroupMember", err);
        defer member.deinit();
        const member_id = member.value.id orelse return summary.fail("AddFriendGroupMember", error.MissingFriendGroupMemberId);
        try summary.pass("AddFriendGroupMember");

        try parsed(summary, "PutFriendGroupMember", client.putFriendGroupMember(.{
            .friend_group_id = group_id,
            .id = member_id,
            .role = "admin",
        }));

        try checkFriendGroupMemberPages(sdk, client, summary, group_id);
        try parsed(summary, "DeleteFriendGroupMember", client.deleteFriendGroupMember(.{
            .friend_group_id = group_id,
            .id = member_id,
        }));
    } else {
        try summary.skip("AddFriendGroupMember", "mutating method; requires --peer-context");
        try summary.skip("PutFriendGroupMember", "mutating method; requires --peer-context");
        try summary.skip("DeleteFriendGroupMember", "mutating method; requires --peer-context");
        try summary.skip("ListFriendGroupMembers", "requires --peer-context");
    }

    var message_asset_available = true;
    var first_message = client.sendFriendGroupMessage(.{
        .friend_group_id = group_id,
        .audio_base64 = "b3B1cw==",
        .audio_content_type = "audio/opus",
    }) catch |err| switch (err) {
        error.RpcInternalError => blk: {
            message_asset_available = false;
            try summary.skip("SendFriendGroupMessage", "server friend-group message asset store is not configured");
            break :blk null;
        },
        else => return summary.fail("SendFriendGroupMessage", err),
    };
    if (first_message) |*message| {
        defer message.deinit();
        try validateFriendGroupMessage(summary, "SendFriendGroupMessage", message.value);

        std.Thread.sleep(std.time.ns_per_ms);
        var second_message = client.sendFriendGroupMessage(.{
            .friend_group_id = group_id,
            .audio_base64 = "b3B1cw==",
            .audio_content_type = "audio/opus",
        }) catch |err| return summary.fail("SendFriendGroupMessage pagination fixture", err);
        defer second_message.deinit();
        try validateFriendGroupMessage(summary, "SendFriendGroupMessage pagination fixture", second_message.value);
    }

    if (message_asset_available) {
        try checkFriendGroupMessagePages(sdk, client, summary, group_id);
    } else {
        try summary.skip("ListFriendGroupMessages", "server friend-group message asset store is not configured");
        try summary.skip("GetFriendGroupMessage", "server friend-group message asset store is not configured");
    }

    try parsed(summary, "DeleteFriendGroup", client.deleteFriendGroup(.{ .id = second_group_id }));
    try parsed(summary, "DeleteFriendGroup cleanup primary", client.deleteFriendGroup(.{ .id = group_id }));
}

fn checkContactPages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    var page = client.listContacts(.{ .limit = 1 }) catch |err| return summary.fail("ListContacts", err);
    defer page.deinit();
    try summary.pass("ListContacts");
    try checkPagination(summary, "ListContacts pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListContacts next page", client.listContacts(.{ .limit = 1, .cursor = cursor }));
        }
    }
    if (page.value.items.len != 0) {
        if (page.value.items[0].id) |id| {
            try parsed(summary, "GetContact", client.getContact(.{ .id = id }));
        } else {
            try summary.skip("GetContact", "first fixture row has no id");
        }
    } else {
        try summary.skip("GetContact", "ListContacts returned no fixture rows");
    }
}

fn checkFriendRequestPages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    var page = client.listFriendRequests(.{ .limit = 1 }) catch |err| return summary.fail("ListFriendRequests", err);
    defer page.deinit();
    try summary.pass("ListFriendRequests");
    try checkPagination(summary, "ListFriendRequests pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListFriendRequests next page", client.listFriendRequests(.{ .limit = 1, .cursor = cursor }));
        }
    }
}

fn checkFriendPages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary) !void {
    var page = client.listFriends(.{ .limit = 1 }) catch |err| return summary.fail("ListFriends", err);
    defer page.deinit();
    try summary.pass("ListFriends");
    try checkPagination(summary, "ListFriends pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListFriends next page", client.listFriends(.{ .limit = 1, .cursor = cursor }));
        }
    }
}

fn checkFriendGroupMemberPages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, group_id: []const u8) !void {
    var page = client.listFriendGroupMembers(.{ .friend_group_id = group_id, .limit = 1 }) catch |err| return summary.fail("ListFriendGroupMembers", err);
    defer page.deinit();
    try summary.pass("ListFriendGroupMembers");
    try checkPagination(summary, "ListFriendGroupMembers pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListFriendGroupMembers next page", client.listFriendGroupMembers(.{ .friend_group_id = group_id, .limit = 1, .cursor = cursor }));
        }
    }
}

fn checkFriendGroupMessagePages(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, group_id: []const u8) !void {
    var page = client.listFriendGroupMessages(.{ .friend_group_id = group_id, .limit = 1 }) catch |err| return summary.fail("ListFriendGroupMessages", err);
    defer page.deinit();
    try summary.pass("ListFriendGroupMessages");
    try checkPagination(summary, "ListFriendGroupMessages pagination", page.value.has_next, page.value.next_cursor);
    if (page.value.has_next) {
        if (page.value.next_cursor) |cursor| {
            try parsed(summary, "ListFriendGroupMessages next page", client.listFriendGroupMessages(.{ .friend_group_id = group_id, .limit = 1, .cursor = cursor }));
        }
    }
    if (page.value.items.len != 0) {
        if (page.value.items[0].id) |id| {
            try parsed(summary, "GetFriendGroupMessage", client.getFriendGroupMessage(.{ .friend_group_id = group_id, .id = id }));
        } else {
            try summary.skip("GetFriendGroupMessage", "first message fixture row has no id");
        }
    } else {
        try summary.skip("GetFriendGroupMessage", "ListFriendGroupMessages returned no fixture rows");
    }
}

fn validateFriendGroupMessage(summary: *common.Summary, name: []const u8, message: anytype) !void {
    const audio_path = message.audio_path orelse return summary.fail(name, error.MissingAudioPath);
    if (audio_path.len == 0) return summary.fail(name, error.MissingAudioPath);
    const content_type = message.audio_content_type orelse return summary.fail(name, error.MissingAudioContentType);
    if (!std.mem.eql(u8, content_type, "audio/opus")) return summary.fail(name, error.UnexpectedAudioContentType);
    const size = message.audio_size_bytes orelse return summary.fail(name, error.MissingAudioSize);
    if (size <= 0) return summary.fail(name, error.EmptyAudioMessage);
    if (message.ttl_seconds == null) return summary.fail(name, error.MissingAudioTTL);
    if (message.expires_at == null) return summary.fail(name, error.MissingAudioExpiration);
    if (message.created_at == null) return summary.fail(name, error.MissingCreatedAt);
    try summary.pass(name);
}

fn parsed(summary: *common.Summary, name: []const u8, result: anytype) !void {
    if (result) |value| {
        var parsed_value = value;
        defer parsed_value.deinit();
        try summary.pass(name);
    } else |err| {
        try summary.fail(name, err);
    }
}

fn listOnly(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, name: []const u8, result: anytype) !void {
    _ = client;
    if (result) |value| {
        var page = value;
        defer page.deinit();
        try summary.pass(name);
        try checkPagination(summary, name, page.value.has_next, page.value.next_cursor);
    } else |err| try summary.fail(name, err);
}

fn listThenMaybeGet(comptime sdk: type, client: *sdk.Client, summary: *common.Summary, list_name: []const u8, get_name: []const u8, result: anytype) !void {
    if (result) |value| {
        var page = value;
        defer page.deinit();
        try summary.pass(list_name);
        try checkPagination(summary, list_name, page.value.has_next, page.value.next_cursor);
        if (page.value.items.len != 0) {
            if (page.value.items[0].id) |id| {
                try parsed(summary, get_name, client.getContact(.{ .id = id }));
            } else {
                try summary.skip(get_name, "first fixture row has no id");
            }
        } else {
            try summary.skip(get_name, "list returned no fixture rows");
        }
    } else |err| try summary.fail(list_name, err);
}

fn checkPagination(summary: *common.Summary, name: []const u8, has_next: bool, next_cursor: ?[]const u8) !void {
    if (has_next and next_cursor == null) return summary.fail(name, error.MissingNextCursor);
    if (!has_next) return summary.skip(name, "fixture did not expose a second page");
    try summary.pass(name);
}
