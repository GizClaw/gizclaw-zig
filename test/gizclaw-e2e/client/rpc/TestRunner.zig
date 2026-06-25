const gstd = @import("gstd");
const common = @import("common");

const client_case = @import("client.zig");
const server_info = @import("server_info.zig");

const grt = gstd.runtime;
const mem = grt.std.mem;

pub const Config = struct {
    base: common.BaseOptions = .{},
    fixtures: Fixtures = .{},
    allow_mutations: bool = false,
};

pub const Fixtures = struct {
    workspace: ?[]const u8 = "e2e-rpc-history-workspace",
    run_workspace: ?[]const u8 = "e2e-rpc-run-workspace",
    voice_id: ?[]const u8 = "e2e-rpc-voice",
    firmware_id: ?[]const u8 = "e2e-rpc-firmware",
};

pub const Summary = struct {
    passed: usize = 0,
    skipped: usize = 0,
    failed: usize = 0,

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
    _ = allocator;
    var summary = Summary{};
    var client = common.connectClient(sdk, ctx.allocator, &ctx) catch |err| {
        try recordFail(&summary, reporter, "Connect", err);
        return summary;
    };
    defer client.deinit();

    try recordPass(&summary, reporter, "Connect");
    try client_case.run(sdk, &client, &summary, reporter);
    try server_info.run(sdk, &client, &summary, reporter);
    _ = config;
    return summary;
}

pub fn parsed(summary: *Summary, reporter: anytype, name: []const u8, result: anytype) !void {
    if (result) |value| {
        var parsed_value = value;
        defer parsed_value.deinit();
        try recordPass(summary, reporter, name);
    } else |err| {
        try recordFail(summary, reporter, name, err);
    }
}

pub fn recordPass(summary: *Summary, reporter: anytype, name: []const u8) !void {
    summary.pass();
    try reporter.pass(name);
}

pub fn recordFail(summary: *Summary, reporter: anytype, name: []const u8, err: anyerror) !void {
    summary.fail();
    try reporter.fail(name, err);
}
