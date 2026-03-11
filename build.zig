const std = @import("std");

fn addProjectImports(
    module: *std.Build.Module,
    embed_mod: *std.Build.Module,
    kcp_mod: *std.Build.Module,
) void {
    module.addImport("embed", embed_mod);
    module.addImport("kcp", kcp_mod);
}

fn addPackageTestStep(
    b: *std.Build,
    name: []const u8,
    description: []const u8,
    root_source: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    embed_mod: *std.Build.Module,
    kcp_mod: *std.Build.Module,
) *std.Build.Step {
    const mod = b.createModule(.{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addProjectImports(mod, embed_mod, kcp_mod);
    const tests = b.addTest(.{
        .root_module = mod,
    });
    const run = b.addRunArtifact(tests);
    const step = b.step(name, description);
    step.dependOn(&run.step);
    return step;
}

fn addPackageCoverageStep(
    b: *std.Build,
    name: []const u8,
    description: []const u8,
    root_source: []const u8,
    include_root: []const u8,
    out_dir: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    embed_mod: *std.Build.Module,
    kcp_mod: *std.Build.Module,
    kcov_path: []const u8,
) *std.Build.Step {
    const mod = b.createModule(.{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addProjectImports(mod, embed_mod, kcp_mod);
    const tests = b.addTest(.{
        .root_module = mod,
        .use_llvm = true,
    });
    const include_pattern = b.fmt("--include-pattern={s}", .{b.pathFromRoot(include_root)});
    const cov_out = b.pathFromRoot(out_dir);
    tests.setExecCmd(&.{ kcov_path, "--clean", include_pattern, cov_out, null });
    const run = b.addRunArtifact(tests);
    const step = b.step(name, description);
    step.dependOn(&run.step);
    return step;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const embed_dep = b.dependency("embed", .{
        .target = target,
        .optimize = optimize,
    });
    const embed_mod = embed_dep.module("embed");
    const kcp_dep = b.dependency("kcp", .{
        .target = target,
        .optimize = optimize,
    });
    const kcp_mod = kcp_dep.module("kcp");

    const project_mod = b.addModule("giztoy", .{
        .root_source_file = b.path("src/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addProjectImports(project_mod, embed_mod, kcp_mod);

    const project_test_mod = b.createModule(.{
        .root_source_file = b.path("src/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addProjectImports(project_test_mod, embed_mod, kcp_mod);

    const project_tests = b.addTest(.{
        .root_module = project_test_mod,
    });
    const run_project_tests = b.addRunArtifact(project_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_project_tests.step);

    const test_net_step = b.step("test-net", "Run all net tests");
    test_net_step.dependOn(addPackageTestStep(
        b,
        "test-core",
        "Run core package tests",
        "src/net/core/test_root.zig",
        target,
        optimize,
        embed_mod,
        kcp_mod,
    ));
    test_net_step.dependOn(addPackageTestStep(
        b,
        "test-kcp",
        "Run KCP package tests",
        "src/net/kcp/test_root.zig",
        target,
        optimize,
        embed_mod,
        kcp_mod,
    ));
    test_net_step.dependOn(addPackageTestStep(
        b,
        "test-noise",
        "Run noise package tests",
        "src/net/noise/test_root.zig",
        target,
        optimize,
        embed_mod,
        kcp_mod,
    ));

    const cov_step = b.step("test-cov", "Run tests with kcov coverage (output: kcov-out/)");
    if (b.findProgram(&.{"kcov"}, &.{})) |kcov_path| {
        const cov_test_mod = b.createModule(.{
            .root_source_file = b.path("src/mod.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        addProjectImports(cov_test_mod, embed_mod, kcp_mod);
        const cov_tests = b.addTest(.{
            .root_module = cov_test_mod,
            .use_llvm = true,
        });
        const src_root = b.pathFromRoot("src");
        const include_pattern = b.fmt("--include-pattern={s}", .{src_root});
        const cov_out = b.pathFromRoot("kcov-out");
        cov_tests.setExecCmd(&.{ kcov_path, "--clean", include_pattern, cov_out, null });
        const run_cov_tests = b.addRunArtifact(cov_tests);
        cov_step.dependOn(&run_cov_tests.step);
        cov_step.dependOn(addPackageCoverageStep(
            b,
            "test-cov-core",
            "Run core package coverage (output: kcov-out-core/)",
            "src/net/core/test_root.zig",
            "src/net/core",
            "kcov-out-core",
            target,
            optimize,
            embed_mod,
            kcp_mod,
            kcov_path,
        ));
        cov_step.dependOn(addPackageCoverageStep(
            b,
            "test-cov-kcp",
            "Run KCP package coverage (output: kcov-out-kcp/)",
            "src/net/kcp/test_root.zig",
            "src/net/kcp",
            "kcov-out-kcp",
            target,
            optimize,
            embed_mod,
            kcp_mod,
            kcov_path,
        ));
        cov_step.dependOn(addPackageCoverageStep(
            b,
            "test-cov-noise",
            "Run noise package coverage (output: kcov-out-noise/)",
            "src/net/noise/test_root.zig",
            "src/net/noise",
            "kcov-out-noise",
            target,
            optimize,
            embed_mod,
            kcp_mod,
            kcov_path,
        ));
    } else |_| {
        const missing = b.addFail("kcov coverage steps require `kcov` to be installed and available on PATH");
        cov_step.dependOn(&missing.step);
    }

    const project_check_mod = b.createModule(.{
        .root_source_file = b.path("src/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addProjectImports(project_check_mod, embed_mod, kcp_mod);

    const check_step = b.step("check", "Compile-check the project module");
    check_step.dependOn(&b.addObject(.{
        .name = "giztoy_check",
        .root_module = project_check_mod,
    }).step);
}
