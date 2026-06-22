const std = @import("std");
const embed_zig_build = @import("embed_zig");

const app_name = "gizclaw_zux_smoke";
const exe_name = "desktop_launcher";
const bundle_name = "GizClawDesktop";
const bundle_id = "dev.gizclaw.desktop.launcher";
const location_usage = "GizClaw uses location permission to let CoreWLAN read WiFi network information.";
const default_wifi_ssid = "";
const default_wifi_password = "";
const default_gizclaw_server_addr = "";
const default_gizclaw_server_key = "";
const default_gizclaw_client_key = "";

const SmokeBuildConfig = struct {
    wifi_ssid: []const u8,
    wifi_password: []const u8,
    gizclaw_server_addr: []const u8,
    gizclaw_server_key: []const u8,
    gizclaw_client_key: []const u8,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const port = b.option(u16, "port", "HTTP port for the desktop launcher") orelse 8080;
    const smoke_config = smokeBuildConfigFromOptions(b);

    const embed_zig_dep = b.dependency("embed_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const gizclaw_dep = b.dependency("gizclaw", .{
        .target = target,
        .optimize = optimize,
    });
    const app_mod = createApp(b, target, optimize, embed_zig_dep, gizclaw_dep, smoke_config);
    const launcher_config = b.addOptions();
    launcher_config.addOption([]const u8, "app_name", app_name);
    launcher_config.addOption(u16, "port", port);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "desktop", .module = embed_zig_dep.module("desktop") },
            .{ .name = "gstd", .module = embed_zig_dep.module("gstd") },
            .{ .name = "app", .module = app_mod },
        },
    });
    exe_mod.addOptions("desktop_launcher_config", launcher_config);

    const exe = b.addExecutable(.{
        .name = exe_name,
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the desktop launcher example");
    const build_step = b.step("build", "Build the desktop launcher example");
    switch (target.result.os.tag) {
        .macos => {
            const app_bundle = createAppBundle(b, exe);

            const app_step = b.step("app", "Create a macOS .app wrapper for the desktop launcher");
            app_step.dependOn(app_bundle.step);

            const run_app = b.addSystemCommand(&.{ "open", "-W", app_bundle.bundle_path });
            if (b.args) |args| {
                run_app.addArg("--args");
                run_app.addArgs(args);
            }
            run_app.step.dependOn(app_bundle.step);

            run_step.dependOn(&run_app.step);
            build_step.dependOn(app_bundle.step);
        },
        else => {
            const unsupported = b.addFail("examples/desktop currently supports macOS only");
            run_step.dependOn(&unsupported.step);
            build_step.dependOn(&unsupported.step);
        },
    }
    b.default_step = build_step;
}

fn createAppBundle(
    b: *std.Build,
    exe: *std.Build.Step.Compile,
) embed_zig_build.desktop.macos.App {
    return embed_zig_build.desktop.macos.addApp(b, .{
        .exe = exe,
        .bundle_name = bundle_name,
        .bundle_identifier = bundle_id,
        .executable_name = exe_name,
        .display_name = bundle_name,
        .minimum_system_version = "13.0",
        .usage_descriptions = .{
            .location = location_usage,
            .location_when_in_use = location_usage,
        },
        .sign = .ad_hoc,
    });
}

fn createApp(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    embed_zig_dep: *std.Build.Dependency,
    gizclaw_dep: *std.Build.Dependency,
    smoke_config: SmokeBuildConfig,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("../zux/smoke/src/app.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "embed", .module = embed_zig_dep.module("embed") },
            .{ .name = "glib", .module = embed_zig_dep.module("glib") },
            .{ .name = "gizclaw", .module = gizclaw_dep.module("gizclaw") },
            .{ .name = "giznet", .module = gizclaw_dep.module("giznet") },
            .{ .name = "launcher", .module = embed_zig_dep.module("apps/launcher") },
        },
    });
    const build_config = b.addOptions();
    build_config.addOption([]const u8, "wifi_ssid", smoke_config.wifi_ssid);
    build_config.addOption([]const u8, "wifi_password", smoke_config.wifi_password);
    build_config.addOption([]const u8, "gizclaw_server_addr", smoke_config.gizclaw_server_addr);
    build_config.addOption([]const u8, "gizclaw_server_key", smoke_config.gizclaw_server_key);
    build_config.addOption([]const u8, "gizclaw_client_key", smoke_config.gizclaw_client_key);
    module.addOptions("build_config", build_config);
    return module;
}

fn smokeBuildConfigFromOptions(b: *std.Build) SmokeBuildConfig {
    return .{
        .wifi_ssid = b.option([]const u8, "wifi_ssid", "WiFi SSID for the zux smoke app") orelse default_wifi_ssid,
        .wifi_password = b.option([]const u8, "wifi_password", "WiFi password for the zux smoke app") orelse default_wifi_password,
        .gizclaw_server_addr = b.option([]const u8, "gizclaw_server_addr", "GizClaw server host:port") orelse default_gizclaw_server_addr,
        .gizclaw_server_key = b.option([]const u8, "gizclaw_server_key", "GizClaw server public key") orelse default_gizclaw_server_key,
        .gizclaw_client_key = b.option([]const u8, "gizclaw_client_key", "GizClaw client private key") orelse default_gizclaw_client_key,
    };
}
