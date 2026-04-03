const std = @import("std");
const Tests = @import("build/Tests.zig");

const lib_integration = @import("build/lib/integration.zig");
const lib_net = @import("build/lib/net.zig");
const pkg_dep = @import("build/pkg/dep.zig");

const Libraries = struct {
    pub const integration = lib_integration;
    pub const net = lib_net;
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

    const tests = Tests.create(b);
    tests.addTest(b, "integration", null, .integration_only);
    tests.addTest(b, "net", null, .unit_only);
}
