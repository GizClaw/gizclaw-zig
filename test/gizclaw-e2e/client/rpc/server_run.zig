const TestRunner = @import("TestRunner.zig");

pub fn run(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype, config: TestRunner.Config) !void {
    try TestRunner.parsed(summary, reporter, "GetServerRunAgent", client.getServerRunAgent());
    try TestRunner.parsed(summary, reporter, "GetServerRunStatus", client.getServerRunStatus(.{}));
    try TestRunner.parsed(summary, reporter, "GetServerRunWorkspace", client.getServerRunWorkspace());
    try TestRunner.parsed(summary, reporter, "GetServerRunWorkspaceMemoryStats", client.getServerRunWorkspaceMemoryStats(.{}));
    try TestRunner.parsed(summary, reporter, "ServerRunWorkspaceRecall", client.serverRunWorkspaceRecall(.{ .query = "hello", .limit = 1 }));

    if (config.fixtures.run_workspace) |workspace| {
        try TestRunner.parsed(summary, reporter, "SetServerRunWorkspace", client.setServerRunWorkspace(.{ .workspace_name = workspace }));
        try TestRunner.parsed(summary, reporter, "ReloadServerRunWorkspace", client.reloadServerRunWorkspace());
    } else {
        try TestRunner.recordFail(summary, reporter, "SetServerRunWorkspace", error.MissingRunWorkspaceFixture);
        try TestRunner.recordFail(summary, reporter, "ReloadServerRunWorkspace", error.MissingRunWorkspaceFixture);
    }

    var history = client.listServerRunWorkspaceHistory(.{ .limit = 1 }) catch |err| {
        try TestRunner.recordFail(summary, reporter, "ListServerRunWorkspaceHistory", err);
        return;
    };
    defer history.deinit();
    try TestRunner.recordPass(summary, reporter, "ListServerRunWorkspaceHistory");
    if (history.value.items.len != 0 and history.value.items[0].replay_available) {
        try TestRunner.parsed(
            summary,
            reporter,
            "PlayServerRunWorkspaceHistory",
            client.playServerRunWorkspaceHistory(.{ .history_id = history.value.items[0].id }),
        );
    }

    if (config.allow_mutations) {
        try TestRunner.parsed(summary, reporter, "ReloadServerRun", client.reloadServerRun());
        try TestRunner.parsed(summary, reporter, "StopServerRun", client.stopServerRun());
    }
}
