const std = @import("std");

fn addCommonImports(module: *std.Build.Module, embed_mod: *std.Build.Module) void {
    module.addImport("embed", embed_mod);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const embed_dep = b.dependency("embed", .{
        .target = target,
        .optimize = optimize,
    });
    const embed_mod = embed_dep.module("embed");
    const embed_std_mod = embed_dep.module("embed_std");
    const testing_mod = embed_dep.module("testing");

    const project_mod = b.addModule("giztoy", .{
        .root_source_file = b.path("lib/net.zig"),
        .target = target,
        .optimize = optimize,
    });
    addCommonImports(project_mod, embed_mod);

    const check_mod = b.createModule(.{
        .root_source_file = b.path("lib/net.zig"),
        .target = target,
        .optimize = optimize,
    });
    addCommonImports(check_mod, embed_mod);
    const check_step = b.step("check", "Compile-check the giztoy module");
    check_step.dependOn(&b.addObject(.{
        .name = "giztoy_check",
        .root_module = check_mod,
    }).step);

    const root_test_mod = b.createModule(.{
        .root_source_file = b.path("lib/net.zig"),
        .target = target,
        .optimize = optimize,
    });
    addCommonImports(root_test_mod, embed_mod);
    const root_tests = b.addTest(.{
        .root_module = root_test_mod,
    });
    const run_root_tests = b.addRunArtifact(root_tests);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("lib/net/noise_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    addCommonImports(test_mod, embed_mod);
    test_mod.addImport("embed_std", embed_std_mod);
    test_mod.addImport("testing", testing_mod);

    const noise_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_noise_tests = b.addRunArtifact(noise_tests);

    const test_noise_step = b.step("test-noise", "Run noise package tests");
    test_noise_step.dependOn(&run_noise_tests.step);

    const test_step = b.step("test", "Run configured test suites");
    test_step.dependOn(&run_root_tests.step);
    test_step.dependOn(&run_noise_tests.step);
}
