const std = @import("std");
const Tests = @import("build/Tests.zig");

const lib_net = @import("build/lib/net.zig");

const Libraries = struct {
    pub const net = lib_net;
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).create(b, target, optimize);
    }

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).link(b);
    }

    const tests = Tests.create(b);
    tests.addTest(b, "net", null);
}
