const std = @import("std");

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const integration = b.createModule(.{
        .root_source_file = b.path("lib/integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("integration", integration) catch @panic("OOM");
}

pub fn link(b: *std.Build) void {
    const dep = b.modules.get("dep") orelse @panic("missing module: dep");
    const net = b.modules.get("net") orelse @panic("missing module: net");
    const integration = b.modules.get("integration") orelse @panic("missing module: integration");

    integration.addImport("dep", dep);
    integration.addImport("net", net);
}
