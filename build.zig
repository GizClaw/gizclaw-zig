const std = @import("std");
const build_test = @import("build/test.zig");

const pkg_dep = @import("build/pkg/dep.zig");

const Libraries = struct {
};

const Packages = struct {
    pub const dep = pkg_dep;
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).create(b, target, optimize);
    }
    inline for (@typeInfo(Packages).@"struct".decls) |decl| {
        @field(Packages, decl.name).create(b, target, optimize);
    }

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).link(b);
    }
    inline for (@typeInfo(Packages).@"struct".decls) |decl| {
        if (b.modules.get(decl.name) != null) {
            @field(Packages, decl.name).link(b);
        }
    }

    build_test.createTestModule(b, target, optimize, Libraries, Packages);
}