const std = @import("std");

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const giznoise = b.createModule(.{
        .root_source_file = b.path("lib/giznoise.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("giznoise", giznoise) catch @panic("OOM");
}

pub fn link(b: *std.Build) void {
    const glib = b.modules.get("glib") orelse @panic("missing module: glib");
    const kcp = b.modules.get("kcp") orelse @panic("missing module: kcp");
    const giznet = b.modules.get("giznet") orelse @panic("missing module: giznet");
    const giznoise = b.modules.get("giznoise") orelse @panic("missing module: giznoise");

    giznoise.addImport("glib", glib);
    giznoise.addImport("kcp", kcp);
    giznoise.addImport("giznet", giznet);
}
