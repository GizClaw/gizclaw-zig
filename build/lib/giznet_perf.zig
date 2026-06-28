const std = @import("std");

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const giznet_perf = b.createModule(.{
        .root_source_file = b.path("lib/giznet_perf.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("giznet_perf", giznet_perf) catch @panic("OOM");
}

pub fn link(b: *std.Build) void {
    const glib = b.modules.get("glib") orelse @panic("missing module: glib");
    const giznet = b.modules.get("giznet") orelse @panic("missing module: giznet");
    const giznet_perf = b.modules.get("giznet_perf") orelse @panic("missing module: giznet_perf");

    giznet_perf.addImport("glib", glib);
    giznet_perf.addImport("giznet", giznet);
}
