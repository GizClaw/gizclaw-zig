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

    b.modules.put("embed", embed_dep.module("embed")) catch @panic("OOM");
    b.modules.put("zig_kcp", zig_kcp_dep.module("kcp")) catch @panic("OOM");

    const noise = b.createModule(.{
        .root_source_file = b.path("lib/net/noise.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("noise", noise) catch @panic("OOM");

    const net = b.createModule(.{
        .root_source_file = b.path("lib/net.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("net", net) catch @panic("OOM");
}

pub fn link(b: *std.Build) void {
    const embed = b.modules.get("embed") orelse @panic("missing module: embed");
    const zig_kcp = b.modules.get("zig_kcp") orelse @panic("missing module: zig_kcp");
    const noise = b.modules.get("noise") orelse @panic("missing module: noise");
    const net = b.modules.get("net") orelse @panic("missing module: net");

    noise.addImport("embed", embed);

    net.addImport("embed", embed);
    net.addImport("noise", noise);
    net.addImport("zig_kcp", zig_kcp);
}
