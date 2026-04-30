const std = @import("std");
const build_test = @import("build/test.zig");

const lib_giznet = @import("build/lib/giznet.zig");

const Libraries = struct {
    pub const giznet = lib_giznet;
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const embed_dep = b.dependency("embed", .{
        .target = target,
        .optimize = optimize,
    });
    const zig_kcp_dep = b.dependency("zig_kcp", .{
        .target = target,
        .optimize = optimize,
    });

    b.modules.put("glib", embed_dep.module("glib")) catch @panic("OOM");
    b.modules.put("gstd", embed_dep.module("gstd")) catch @panic("OOM");
    b.modules.put("kcp", zig_kcp_dep.module("kcp")) catch @panic("OOM");

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).create(b, target, optimize);
    }

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).link(b);
    }

    build_test.createTestModule(b, target, optimize, Libraries);
}
