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
    const embed = b.modules.get("embed") orelse @panic("missing module: embed");
    const embed_std = b.modules.get("embed_std") orelse @panic("missing module: embed_std");
    const kcp = b.modules.get("kcp") orelse @panic("missing module: kcp");
    const giznet = b.modules.get("giznet") orelse @panic("missing module: giznet");

    giznet.addImport("embed", embed);
    giznet.addImport("embed_std", embed_std);
    giznet.addImport("kcp", kcp);
}
