const std = @import("std");
const Tests = @import("build/Tests.zig");
const lib_net = @import("build/lib/net.zig");

const EmbedModules = struct {
    embed: *std.Build.Module,
    embed_std: *std.Build.Module,
    testing: *std.Build.Module,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const embed_modules = resolveEmbedModules(b, target, optimize);
    const net_modules = lib_net.create(b, target, optimize);
    lib_net.link(embed_modules.embed, net_modules);

    const tests = Tests.init(b, .{
        .embed = embed_modules.embed,
        .noise = net_modules.noise,
        .embed_std = embed_modules.embed_std,
        .testing = embed_modules.testing,
    });
    const giztoy_mod = net_modules.giztoy;

    const check_step = b.step("check", "Compile-check the giztoy module");
    check_step.dependOn(&b.addObject(.{
        .name = "giztoy_check",
        .root_module = giztoy_mod,
    }).step);

    const run_root_tests = tests.addRun(giztoy_mod);

    const noise_test_mod = tests.createModule(
        b.path("lib/net/noise_test.zig"),
        target,
        optimize,
        .{
            .embed_std = true,
            .testing = true,
        },
    );
    const run_noise_tests = tests.addNamedTest(
        "test-noise",
        "Run noise package tests",
        noise_test_mod,
    );

    const core_test_mod = tests.createModule(
        b.path("lib/net/core_test.zig"),
        target,
        optimize,
        .{
            .noise = true,
            .embed_std = true,
            .testing = true,
        },
    );
    const run_core_tests = tests.addNamedTest(
        "test-core",
        "Run core package tests",
        core_test_mod,
    );

    const test_step = b.step("test", "Run configured test suites");
    test_step.dependOn(&run_root_tests.step);
    test_step.dependOn(&run_noise_tests.step);
    test_step.dependOn(&run_core_tests.step);
}

fn resolveEmbedModules(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) EmbedModules {
    const embed_dep = b.dependency("embed", .{
        .target = target,
        .optimize = optimize,
    });
    return .{
        .embed = embed_dep.module("embed"),
        .embed_std = embed_dep.module("embed_std"),
        .testing = embed_dep.module("testing"),
    };
}
