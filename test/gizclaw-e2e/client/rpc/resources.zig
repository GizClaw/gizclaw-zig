const TestRunner = @import("TestRunner.zig");

pub fn run(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype, config: TestRunner.Config) !void {
    try workspaceChecks(sdk, client, summary, reporter, config);
    try workflowChecks(sdk, client, summary, reporter);
    try modelChecks(sdk, client, summary, reporter);
    try credentialChecks(sdk, client, summary, reporter, config);
    try voiceChecks(sdk, client, summary, reporter, config);
    try firmwareChecks(sdk, client, summary, reporter, config);

    if (config.allow_mutations) try TestRunner.recordFail(summary, reporter, "ResourceMutations", error.ResourceMutationsNotImplemented);
}

fn workspaceChecks(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype, config: TestRunner.Config) !void {
    var page = client.listWorkspaces(.{ .limit = 1 }) catch |err| return TestRunner.recordFail(summary, reporter, "ListWorkspaces", err);
    defer page.deinit();
    try TestRunner.recordPass(summary, reporter, "ListWorkspaces");
    if (config.fixtures.workspace) |workspace| {
        try TestRunner.parsed(summary, reporter, "GetWorkspace", client.getWorkspace(.{ .name = workspace }));
        try TestRunner.parsed(summary, reporter, "ListWorkspaceHistory", client.listWorkspaceHistory(.{ .workspace_name = workspace, .limit = 1 }));
    } else if (page.value.items.len != 0) {
        try TestRunner.parsed(summary, reporter, "GetWorkspace", client.getWorkspace(.{ .name = page.value.items[0].name }));
        try TestRunner.parsed(summary, reporter, "ListWorkspaceHistory", client.listWorkspaceHistory(.{ .workspace_name = page.value.items[0].name, .limit = 1 }));
    } else {
        try TestRunner.recordFail(summary, reporter, "GetWorkspace", error.MissingWorkspaceFixture);
        try TestRunner.recordFail(summary, reporter, "ListWorkspaceHistory", error.MissingWorkspaceFixture);
    }
}

fn workflowChecks(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype) !void {
    var page = client.listWorkflows(.{ .limit = 1 }) catch |err| return TestRunner.recordFail(summary, reporter, "ListWorkflows", err);
    defer page.deinit();
    try TestRunner.recordPass(summary, reporter, "ListWorkflows");
    if (page.value.items.len != 0) {
        try TestRunner.parsed(summary, reporter, "GetWorkflow", client.getWorkflow(.{ .name = page.value.items[0].metadata.name }));
    } else {
        try TestRunner.recordFail(summary, reporter, "GetWorkflow", error.MissingWorkflowFixture);
    }
}

fn modelChecks(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype) !void {
    var page = client.listModels(.{ .limit = 1 }) catch |err| return TestRunner.recordFail(summary, reporter, "ListModels", err);
    defer page.deinit();
    try TestRunner.recordPass(summary, reporter, "ListModels");
    if (page.value.items.len != 0) {
        try TestRunner.parsed(summary, reporter, "GetModel", client.getModel(.{ .id = page.value.items[0].id }));
    } else {
        try TestRunner.recordFail(summary, reporter, "GetModel", error.MissingModelFixture);
    }
}

fn credentialChecks(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype, config: TestRunner.Config) !void {
    var page = client.listCredentials(.{ .limit = 1 }) catch |err| return TestRunner.recordFail(summary, reporter, "ListCredentials", err);
    defer page.deinit();
    try TestRunner.recordPass(summary, reporter, "ListCredentials");
    if (config.fixtures.credential_name) |credential_name| {
        try TestRunner.parsed(summary, reporter, "GetCredential", client.getCredential(.{ .name = credential_name }));
    } else if (page.value.items.len != 0) {
        try TestRunner.parsed(summary, reporter, "GetCredential", client.getCredential(.{ .name = page.value.items[0].name }));
    } else {
        try TestRunner.recordFail(summary, reporter, "GetCredential", error.MissingCredentialFixture);
    }
}

fn voiceChecks(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype, config: TestRunner.Config) !void {
    var page = client.listVoices(.{ .limit = 1 }) catch |err| return TestRunner.recordFail(summary, reporter, "ListVoices", err);
    defer page.deinit();
    try TestRunner.recordPass(summary, reporter, "ListVoices");
    if (config.fixtures.voice_id) |voice_id| {
        try TestRunner.parsed(summary, reporter, "GetVoice", client.getVoice(.{ .id = voice_id }));
    } else if (page.value.data.len != 0) {
        try TestRunner.parsed(summary, reporter, "GetVoice", client.getVoice(.{ .id = page.value.data[0].id }));
    } else {
        try TestRunner.recordFail(summary, reporter, "GetVoice", error.MissingVoiceFixture);
    }
}

fn firmwareChecks(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype, config: TestRunner.Config) !void {
    var page = client.listFirmwares(.{ .limit = 1 }) catch |err| return TestRunner.recordFail(summary, reporter, "ListFirmwares", err);
    defer page.deinit();
    try TestRunner.recordPass(summary, reporter, "ListFirmwares");
    if (config.fixtures.firmware_id) |firmware_id| {
        try TestRunner.parsed(summary, reporter, "GetFirmware", client.getFirmware(.{ .firmware_id = firmware_id }));
    } else if (page.value.items.len != 0) {
        try TestRunner.parsed(summary, reporter, "GetFirmware", client.getFirmware(.{ .firmware_id = page.value.items[0].name }));
    } else {
        try TestRunner.recordFail(summary, reporter, "GetFirmware", error.MissingFirmwareFixture);
    }
}
