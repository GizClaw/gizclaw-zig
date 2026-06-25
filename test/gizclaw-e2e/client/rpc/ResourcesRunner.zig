const gstd = @import("gstd");
const common = @import("common");

const client_case = @import("client.zig");
const resources = @import("resources.zig");
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
    const client = common.connectClient(sdk, ctx.allocator, &ctx) catch |err| {
        try smoke.recordFail(&summary, reporter, "Connect", err);
        return summary;
    };
    defer common.disconnectClient(sdk, ctx.allocator, client);

    try smoke.recordPass(&summary, reporter, "Connect");
    try client_case.run(sdk, client, &summary, reporter);
    try resources.run(sdk, client, &summary, reporter, config);
    return summary;
}
