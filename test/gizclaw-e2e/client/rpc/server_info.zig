const TestRunner = @import("TestRunner.zig");

pub fn run(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype) !void {
    try TestRunner.parsed(summary, reporter, "GetServerInfo", client.getServerInfo());
    try TestRunner.parsed(summary, reporter, "GetServerRuntime", client.getServerRuntime());
    try TestRunner.parsed(summary, reporter, "GetServerStatus", client.getServerStatus());
}
