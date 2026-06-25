const TestRunner = @import("TestRunner.zig");

pub fn run(comptime sdk: type, client: *sdk.Client, summary: *TestRunner.Summary, reporter: anytype) !void {
    if (client.ping()) |response| {
        _ = response;
        try TestRunner.recordPass(summary, reporter, "Ping");
    } else |err| {
        try TestRunner.recordFail(summary, reporter, "Ping", err);
    }
}
