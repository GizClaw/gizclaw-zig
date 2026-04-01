const std = @import("std");

pub const Modules = struct {
    noise: *std.Build.Module,
    zig_kcp: *std.Build.Module,
    giztoy: *std.Build.Module,
};

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Modules {
    const zig_kcp_dep = b.dependency("zig_kcp", .{
        .target = target,
        .optimize = optimize,
    });
    const noise = b.createModule(.{
        .root_source_file = b.path("lib/net/noise.zig"),
        .target = target,
        .optimize = optimize,
    });
    const giztoy = b.addModule("giztoy", .{
        .root_source_file = b.path("lib/net.zig"),
        .target = target,
        .optimize = optimize,
    });
    return .{
        .noise = noise,
        .zig_kcp = zig_kcp_dep.module("kcp"),
        .giztoy = giztoy,
    };
}

pub fn link(embed: *std.Build.Module, modules: Modules) void {
    modules.noise.addImport("embed", embed);

    modules.giztoy.addImport("embed", embed);
    modules.giztoy.addImport("noise", modules.noise);
    modules.giztoy.addImport("zig_kcp", modules.zig_kcp);
}
