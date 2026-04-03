const std = @import("std");

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const net = b.createModule(.{
        .root_source_file = b.path("lib/net.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("net", net) catch @panic("OOM");
}

pub fn link(b: *std.Build) void {
    const dep = b.modules.get("dep") orelse @panic("missing module: dep");
    const net = b.modules.get("net") orelse @panic("missing module: net");

    net.addImport("dep", dep);
}
