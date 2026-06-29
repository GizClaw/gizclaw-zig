const std = @import("std");

pub fn createTestModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    comptime Libraries: type,
) void {
    const test_step = b.step("test", "Run all tests");

    const unit_step = b.step("test-unit", "Run unit tests");
    const integration_step = b.step("test-integration", "Run integration tests");
    const benchmark_step = b.step("test-benchmark", "Run benchmark tests");
    const cork_step = b.step("test-cork", "Run cork tests");
    test_step.dependOn(unit_step);
    test_step.dependOn(integration_step);
    test_step.dependOn(benchmark_step);
    test_step.dependOn(cork_step);
    benchmark_step.dependOn(integration_step);

    const TestType = struct {
        label: []const u8,
        parent_step: *std.Build.Step,
    };
    const test_types = [_]TestType{
        .{ .label = "unit", .parent_step = unit_step },
        .{ .label = "integration", .parent_step = integration_step },
        .{ .label = "benchmark", .parent_step = benchmark_step },
        .{ .label = "cork", .parent_step = cork_step },
    };

    const test_mod = b.createModule(.{
        .root_source_file = b.path("lib/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("test", test_mod) catch @panic("OOM");

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        const mod = b.modules.get(decl.name) orelse @panic("test dependency missing");
        test_mod.addImport(decl.name, mod);
    }
    for ([_][]const u8{ "glib", "gstd", "kcp" }) |name| {
        const mod = b.modules.get(name) orelse @panic("test dependency missing");
        test_mod.addImport(name, mod);
    }

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        for (test_types) |test_type| {
            const module_step = b.step(
                b.fmt("test-{s}-{s}", .{ test_type.label, decl.name }),
                b.fmt("Run {s} {s} tests", .{ test_type.label, decl.name }),
            );
            const compile_test = b.addTest(.{
                .root_module = test_mod,
                .filters = &.{b.fmt("{s}/{s}", .{ decl.name, test_type.label })},
            });
            const run_test = b.addRunArtifact(compile_test);
            run_test.setName(b.fmt("{s}:{s}", .{ decl.name, test_type.label }));
            if (std.mem.eql(u8, test_type.label, "benchmark")) {
                run_test.step.dependOn(integration_step);
            }
            test_type.parent_step.dependOn(&run_test.step);
            module_step.dependOn(&run_test.step);
        }
    }

    const kcp_integration_step = b.step(
        "test-integration-kcp",
        "Run integration kcp tests",
    );
    const kcp_integration_compile = b.addTest(.{
        .root_module = test_mod,
        .filters = &.{"kcp/integration"},
    });
    const kcp_integration_run = b.addRunArtifact(kcp_integration_compile);
    kcp_integration_run.setName("kcp:integration");
    kcp_integration_step.dependOn(&kcp_integration_run.step);

    const kcp_unit_step = b.step(
        "test-unit-kcp",
        "Run unit kcp tests",
    );
    const kcp_unit_compile = b.addTest(.{
        .root_module = test_mod,
        .filters = &.{"kcp/unit"},
    });
    const kcp_unit_run = b.addRunArtifact(kcp_unit_compile);
    kcp_unit_run.setName("kcp:unit");
    kcp_unit_step.dependOn(&kcp_unit_run.step);
}

pub fn createZuxSpeedTest(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    embed_dep: *std.Build.Dependency,
    glib: *std.Build.Module,
    gstd: *std.Build.Module,
    embed: *std.Build.Module,
) void {
    const speedtest_config = zuxSpeedTestBuildConfigOptions(b);
    const launcher = b.createModule(.{
        .root_source_file = embed_dep.path("apps/src/Launcher.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "glib", .module = glib },
        },
    });
    const selected_app = b.createModule(.{
        .root_source_file = b.path("examples/zux/speedtest/src/app.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "embed", .module = embed },
            .{ .name = "glib", .module = glib },
            .{ .name = "lvgl", .module = embed_dep.module("thirdparty/lvgl") },
            .{ .name = "launcher", .module = launcher },
        },
    });
    selected_app.addOptions("build_config", speedtest_config);

    const test_mod = b.createModule(.{
        .root_source_file = createZuxSpeedTestSource(b),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "glib", .module = glib },
            .{ .name = "gstd", .module = gstd },
            .{ .name = "selected_app", .module = selected_app },
        },
    });
    const compile_test = b.addTest(.{
        .root_module = test_mod,
    });
    const run_test = b.addRunArtifact(compile_test);
    run_test.setName("zux-speedtest:stories");

    const test_step = b.step("test-zux-speedtest", "Run zux speedtest user stories");
    test_step.dependOn(&run_test.step);
}

pub fn createGizClawE2E(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const e2e_build_config = b.addOptions();
    e2e_build_config.addOption(
        []const u8,
        "server_addr",
        b.option([]const u8, "gizclaw_e2e_server_addr", "Override GizClaw e2e server address") orelse "",
    );
    e2e_build_config.addOption(
        []const u8,
        "server_pub_key",
        b.option([]const u8, "gizclaw_e2e_server_pub_key", "Override GizClaw e2e server public key") orelse "",
    );
    e2e_build_config.addOption(
        []const u8,
        "client_pri_key",
        b.option([]const u8, "gizclaw_e2e_client_pri_key", "Override GizClaw e2e client private key") orelse "",
    );
    e2e_build_config.addOption(
        []const u8,
        "cipher_mode",
        b.option([]const u8, "gizclaw_e2e_cipher_mode", "Override GizClaw e2e cipher mode") orelse "",
    );

    const common_mod = b.createModule(.{
        .root_source_file = b.path("test/gizclaw-e2e/common.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "gizclaw", .module = b.modules.get("gizclaw") orelse @panic("missing module: gizclaw") },
            .{ .name = "giznet", .module = b.modules.get("giznet") orelse @panic("missing module: giznet") },
            .{ .name = "giznoise", .module = b.modules.get("giznoise") orelse @panic("missing module: giznoise") },
            .{ .name = "gstd", .module = b.modules.get("gstd") orelse @panic("missing module: gstd") },
            .{ .name = "e2e_build_config", .module = e2e_build_config.createModule() },
        },
    });

    const Entry = struct {
        name: []const u8,
        root: []const u8,
        step: []const u8,
        description: []const u8,
    };
    const entries = [_]Entry{
        .{
            .name = "gizclaw-e2e-rpc",
            .root = "test/gizclaw-e2e/client/rpc/main.zig",
            .step = "run-gizclaw-e2e-rpc",
            .description = "Run GizClaw RPC e2e checks against a remote server",
        },
        .{
            .name = "gizclaw-e2e-rpc-server-run",
            .root = "test/gizclaw-e2e/client/rpc/server_run_main.zig",
            .step = "run-gizclaw-e2e-rpc-server-run",
            .description = "Run GizClaw server-run RPC e2e checks against a remote server",
        },
        .{
            .name = "gizclaw-e2e-rpc-resources",
            .root = "test/gizclaw-e2e/client/rpc/resources_main.zig",
            .step = "run-gizclaw-e2e-rpc-resources",
            .description = "Run GizClaw resource RPC e2e checks against a remote server",
        },
        .{
            .name = "gizclaw-e2e-chat",
            .root = "test/gizclaw-e2e/client/chat/main.zig",
            .step = "run-gizclaw-e2e-chat",
            .description = "Run GizClaw chat e2e checks against a remote server",
        },
        .{
            .name = "gizclaw-e2e-speed",
            .root = "test/gizclaw-e2e/client/speed/main.zig",
            .step = "run-gizclaw-e2e-speed",
            .description = "Run GizClaw speed-test RPC e2e checks against a remote server",
        },
    };

    for (entries) |entry| {
        const exe_mod = b.createModule(.{
            .root_source_file = b.path(entry.root),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "gizclaw", .module = b.modules.get("gizclaw") orelse @panic("missing module: gizclaw") },
                .{ .name = "giznet", .module = b.modules.get("giznet") orelse @panic("missing module: giznet") },
                .{ .name = "giznoise", .module = b.modules.get("giznoise") orelse @panic("missing module: giznoise") },
                .{ .name = "gstd", .module = b.modules.get("gstd") orelse @panic("missing module: gstd") },
                .{ .name = "embed", .module = b.modules.get("embed") orelse @panic("missing module: embed") },
                .{ .name = "opus", .module = b.modules.get("opus") orelse @panic("missing module: opus") },
                .{ .name = "opus_osal", .module = b.modules.get("opus_osal") orelse @panic("missing module: opus_osal") },
                .{ .name = "common", .module = common_mod },
            },
        });
        const exe = b.addExecutable(.{
            .name = entry.name,
            .root_module = exe_mod,
        });
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        if (b.args) |args| run_cmd.addArgs(args);
        const run_step = b.step(entry.step, entry.description);
        run_step.dependOn(&run_cmd.step);
    }
}

fn zuxSpeedTestBuildConfigOptions(b: *std.Build) *std.Build.Step.Options {
    const options = b.addOptions();
    options.addOption([]const u8, "wifi_ssid", "");
    options.addOption([]const u8, "wifi_password", "");
    options.addOption([]const u8, "gizclaw_server_addr", "");
    options.addOption([]const u8, "gizclaw_server_key", "");
    options.addOption([]const u8, "gizclaw_client_key", "");
    return options;
}

fn createZuxSpeedTestSource(b: *std.Build) std.Build.LazyPath {
    const write_files = b.addWriteFiles();
    return write_files.add("zux_speedtest_test.zig",
        \\const glib = @import("glib");
        \\const gstd = @import("gstd");
        \\const selected_app = @import("selected_app");
        \\
        \\test "zux speedtest user stories" {
        \\    var t = glib.testing.T.new(gstd.runtime.std, gstd.runtime.time, .zux_app);
        \\    defer t.deinit();
        \\
        \\    t.run("app", selected_app.speedtestTestRunner(gstd.runtime));
        \\    if (!t.wait()) return error.TestFailed;
        \\}
        \\
    );
}
