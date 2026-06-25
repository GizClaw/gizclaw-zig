const gstd = @import("gstd");
const common = @import("common");

const client_case = @import("client.zig");
const server_run = @import("server_run.zig");
const smoke = @import("TestRunner.zig");

const grt = gstd.runtime;
const mem = grt.std.mem;

pub const Config = smoke.Config;
pub const Fixtures = smoke.Fixtures;
pub const Summary = smoke.Summary;

pub fn run(comptime sdk: type, allocator: mem.Allocator, config: Config, reporter: anytype) !Summary {
    var ctx = common.loadContext(allocator, config.base) catch |err| {
        var summary = Summary{};
        try smoke.recordFail(&summary, reporter, "Connect", err);
        return summary;
    };
    defer ctx.deinit();
    return runWithContext(sdk, allocator, ctx, config, reporter);
}

pub fn runWithContext(comptime sdk: type, allocator: mem.Allocator, ctx: common.Context, config: Config, reporter: anytype) !Summary {
    _ = allocator;
    var summary = Summary{};
    var client = common.connectClient(sdk, ctx.allocator, &ctx) catch |err| {
        try smoke.recordFail(&summary, reporter, "Connect", err);
        return summary;
    };
    defer client.deinit();

    try smoke.recordPass(&summary, reporter, "Connect");
    try client_case.run(sdk, &client, &summary, reporter);
    try server_run.run(sdk, &client, &summary, reporter, config);
    return summary;
}
