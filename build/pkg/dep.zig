const std = @import("std");

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const embed_dep = b.dependency("embed", .{
        .target = target,
        .optimize = optimize,
    });
    const zig_kcp_dep = b.dependency("zig_kcp", .{
        .target = target,
        .optimize = optimize,
    });

    const mod = b.createModule(.{
        .root_source_file = b.path("pkg/dep.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("embed", embed_dep.module("embed"));
    mod.addImport("context", embed_dep.module("context"));
    mod.addImport("net", embed_dep.module("net"));
    mod.addImport("sync", embed_dep.module("sync"));
    mod.addImport("testing", embed_dep.module("testing"));
    mod.addImport("embed_std", embed_dep.module("embed_std"));
    mod.addImport("kcp", zig_kcp_dep.module("kcp"));

    b.modules.put("dep", mod) catch @panic("OOM");
}

pub fn link(_: *std.Build) void {}
