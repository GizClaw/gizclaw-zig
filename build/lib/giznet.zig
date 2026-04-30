const std = @import("std");

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const giznet = b.createModule(.{
        .root_source_file = b.path("lib/giznet.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("giznet", giznet) catch @panic("OOM");
}

pub fn link(b: *std.Build) void {
    const glib = b.modules.get("glib") orelse @panic("missing module: glib");
    const kcp = b.modules.get("kcp") orelse @panic("missing module: kcp");
    const giznet = b.modules.get("giznet") orelse @panic("missing module: giznet");

    giznet.addImport("glib", glib);
    giznet.addImport("kcp", kcp);
}
