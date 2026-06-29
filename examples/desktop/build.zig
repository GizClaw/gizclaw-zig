const std = @import("std");
const embed_zig_build = @import("embed_zig");

const default_app_name = "speedtest";
const exe_name = "desktop_launcher_app";
const default_bundle_id = "dev.gizclaw.desktop.launcher";
const location_usage = "GizClaw uses location permission to let CoreWLAN read WiFi network information.";
const microphone_usage = "GizClaw uses microphone permission to capture chat audio.";
const default_wifi_ssid = "";
const default_wifi_password = "";
const default_gizclaw_server_addr = "115.190.62.76:9820";
const default_gizclaw_server_key = "FZvSffUDZbtJWDyqbuDv8nqjYs5jjSuHwZmxDLANVcx7";
const default_gizclaw_client_key = "";
const default_chat_workspace = "volc-ast-translate-zh-en-realtime-roundtrip";
const default_chat_workflow = "volc-ast-translate-zh-en-realtime-roundtrip";
const default_chat_mode = "push_to_talk";
const default_e2e_suite = "speed";
const default_e2e_cipher_mode = "chacha_poly";
const default_e2e_connect_timeout_ms: i64 = 30_000;
const default_e2e_speed_bytes: u64 = 5 * 1024 * 1024;
const default_e2e_speed_timeout_ms: i64 = 180_000;
const default_e2e_chat_rounds: u32 = 3;
const default_e2e_chat_run_timeout_ms: u32 = 30_000;
const default_e2e_chat_conversation_timeout_ms: u32 = 10_000;

const SmokeBuildConfig = struct {
    wifi_ssid: []const u8,
    wifi_password: []const u8,
    gizclaw_server_addr: []const u8,
    gizclaw_server_key: []const u8,
    gizclaw_client_key: []const u8,
    server_addr: []const u8,
    server_pub_key: []const u8,
    client_pri_key: []const u8,
    chat_workspace: []const u8,
    chat_workflow: []const u8,
    chat_default_mode: []const u8,
    e2e_suite: []const u8,
    e2e_cipher_mode: []const u8,
    e2e_connect_timeout_ms: i64,
    e2e_allow_mutations: bool,
    e2e_speed_bytes: u64,
    e2e_speed_timeout_ms: i64,
    e2e_chat_rounds: u32,
    e2e_chat_run_timeout_ms: u32,
    e2e_chat_conversation_timeout_ms: u32,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const selected_app_name = b.option([]const u8, "app", "Selected Zux app: speedtest, e2e, or chat_smoke") orelse default_app_name;
    const port = b.option(u16, "desktop_port", "HTTP port for the desktop launcher") orelse
        b.option(u16, "port", "Deprecated alias for desktop_port") orelse
        8080;
    const identity = desktopIdentity(selected_app_name);
    const bundle_name = b.option([]const u8, "desktop_bundle_name", "macOS app bundle name for the desktop launcher") orelse identity.bundle_name;
    const bundle_id = b.option([]const u8, "desktop_bundle_id", "macOS app bundle identifier for the desktop launcher") orelse identity.bundle_id;
    const display_name = b.option([]const u8, "desktop_display_name", "macOS display name for the desktop launcher") orelse identity.display_name;
    const systray_name = b.option([]const u8, "desktop_systray_name", "macOS menu bar name for the desktop launcher") orelse identity.systray_name;
    const storage_root = normalizeHostPath(b, b.option([]const u8, "desktop_storage_root", "Host storage root for the desktop launcher") orelse "");
    const home_dir = normalizeHostPath(b, b.option([]const u8, "desktop_home_dir", "Host home directory used by the desktop platform for Application Support storage") orelse "");
    const output_subdir = b.option([]const u8, "desktop_output_subdir", "zig-out subdirectory for the desktop .app") orelse "app";
    const run_tray = b.option(bool, "desktop_run_tray", "Run the macOS menu bar launcher") orelse true;
    const smoke_config = smokeBuildConfigFromOptions(b);

    const embed_zig_dep = b.dependency("embed_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const gizclaw_dep = b.dependency("gizclaw", .{
        .target = target,
        .optimize = optimize,
    });
    const app_mod = createApp(b, target, optimize, embed_zig_dep, gizclaw_dep, smoke_config, selected_app_name);
    const launcher_config = b.addOptions();
    launcher_config.addOption([]const u8, "app_name", launcherAppName(selected_app_name));
    launcher_config.addOption(u16, "port", port);
    launcher_config.addOption([]const u8, "bundle_id", bundle_id);
    launcher_config.addOption([]const u8, "home_dir", home_dir);
    launcher_config.addOption([]const u8, "storage_root", storage_root);
    launcher_config.addOption(bool, "run_tray", run_tray);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "desktop", .module = embed_zig_dep.module("desktop") },
            .{ .name = "gstd", .module = embed_zig_dep.module("gstd") },
            .{ .name = "lvgl_osal", .module = embed_zig_dep.module("thirdparty/lvgl_osal") },
            .{ .name = "opus_osal", .module = embed_zig_dep.module("thirdparty/opus_osal") },
            .{ .name = "app", .module = app_mod },
        },
    });
    exe_mod.addOptions("desktop_launcher_config", launcher_config);
    if (target.result.os.tag == .macos) {
        exe_mod.addCSourceFile(.{
            .file = createTraySource(b),
            .flags = &.{
                "-fobjc-arc",
                b.fmt("-DDESKTOP_LAUNCHER_SYSTRAY_NAME=\"{s}\"", .{systray_name}),
            },
        });
        exe_mod.linkFramework("Cocoa", .{});
    }

    const exe = b.addExecutable(.{
        .name = exe_name,
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the desktop launcher example");
    const build_step = b.step("build", "Build the desktop launcher example");
    switch (target.result.os.tag) {
        .macos => {
            const app_bundle = createAppBundle(b, exe, .{
                .bundle_name = bundle_name,
                .bundle_id = bundle_id,
                .display_name = display_name,
                .output_subdir = output_subdir,
            });

            const app_step = b.step("app", "Create a macOS .app wrapper for the desktop launcher");
            app_step.dependOn(app_bundle.step);

            const run_app = b.addSystemCommand(&.{ "/bin/sh", "-c", run_app_script, "desktop-run" });
            run_app.addArg(app_bundle.bundle_path);
            run_app.addArg(b.fmt("{d}", .{port}));
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
    config: struct {
        bundle_name: []const u8,
        bundle_id: []const u8,
        display_name: []const u8,
        output_subdir: []const u8,
    },
) embed_zig_build.desktop.macos.App {
    return embed_zig_build.desktop.macos.addApp(b, .{
        .exe = exe,
        .bundle_name = config.bundle_name,
        .bundle_identifier = config.bundle_id,
        .executable_name = exe_name,
        .display_name = config.display_name,
        .minimum_system_version = "13.0",
        .usage_descriptions = .{
            .location = location_usage,
            .location_when_in_use = location_usage,
            .microphone = microphone_usage,
        },
        .agent = true,
        .sign = .ad_hoc,
        .output_subdir = config.output_subdir,
    });
}

fn createApp(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    embed_zig_dep: *std.Build.Dependency,
    gizclaw_dep: *std.Build.Dependency,
    smoke_config: SmokeBuildConfig,
    selected_app_name: []const u8,
) *std.Build.Module {
    const root_source_file = if (std.mem.eql(u8, selected_app_name, "speedtest"))
        b.path("../zux/speedtest/src/app.zig")
    else if (std.mem.eql(u8, selected_app_name, "e2e"))
        b.path("../zux/e2e/src/app.zig")
    else if (std.mem.eql(u8, selected_app_name, "chat_smoke"))
        b.path("../zux/chat_smoke/src/app.zig")
    else
        std.debug.panic("unknown zux app: {s}; expected speedtest, e2e, or chat_smoke", .{selected_app_name});

    const e2e_modules = createE2EModules(b, target, optimize, gizclaw_dep, embed_zig_dep.module("gstd"), embed_zig_dep.module("embed"), embed_zig_dep.module("thirdparty/opus"), smoke_config);

    const module = b.createModule(.{
        .root_source_file = root_source_file,
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "embed", .module = embed_zig_dep.module("embed") },
            .{ .name = "glib", .module = embed_zig_dep.module("glib") },
            .{ .name = "desktop", .module = embed_zig_dep.module("desktop") },
            .{ .name = "gizclaw", .module = gizclaw_dep.module("gizclaw") },
            .{ .name = "giznet", .module = gizclaw_dep.module("giznet") },
            .{ .name = "launcher", .module = embed_zig_dep.module("apps/launcher") },
            .{ .name = "lvgl", .module = embed_zig_dep.module("thirdparty/lvgl") },
            .{ .name = "opus", .module = embed_zig_dep.module("thirdparty/opus") },
            .{ .name = "e2e_assets", .module = e2e_modules.assets },
            .{ .name = "e2e_common", .module = e2e_modules.common },
            .{ .name = "e2e_runners", .module = e2e_modules.runners },
        },
    });
    const build_config = b.addOptions();
    build_config.addOption([]const u8, "wifi_ssid", smoke_config.wifi_ssid);
    build_config.addOption([]const u8, "wifi_password", smoke_config.wifi_password);
    build_config.addOption([]const u8, "gizclaw_server_addr", smoke_config.gizclaw_server_addr);
    build_config.addOption([]const u8, "gizclaw_server_key", smoke_config.gizclaw_server_key);
    build_config.addOption([]const u8, "gizclaw_client_key", smoke_config.gizclaw_client_key);
    build_config.addOption([]const u8, "server_addr", smoke_config.server_addr);
    build_config.addOption([]const u8, "server_pub_key", smoke_config.server_pub_key);
    build_config.addOption([]const u8, "client_pri_key", smoke_config.client_pri_key);
    build_config.addOption([]const u8, "chat_workspace", smoke_config.chat_workspace);
    build_config.addOption([]const u8, "chat_workflow", smoke_config.chat_workflow);
    build_config.addOption([]const u8, "chat_default_mode", smoke_config.chat_default_mode);
    build_config.addOption([]const u8, "e2e_suite", smoke_config.e2e_suite);
    build_config.addOption([]const u8, "e2e_cipher_mode", smoke_config.e2e_cipher_mode);
    build_config.addOption(i64, "e2e_connect_timeout_ms", smoke_config.e2e_connect_timeout_ms);
    build_config.addOption(bool, "e2e_allow_mutations", smoke_config.e2e_allow_mutations);
    build_config.addOption(u64, "e2e_speed_bytes", smoke_config.e2e_speed_bytes);
    build_config.addOption(i64, "e2e_speed_timeout_ms", smoke_config.e2e_speed_timeout_ms);
    build_config.addOption(u32, "e2e_chat_rounds", smoke_config.e2e_chat_rounds);
    build_config.addOption(u32, "e2e_chat_run_timeout_ms", smoke_config.e2e_chat_run_timeout_ms);
    build_config.addOption(u32, "e2e_chat_conversation_timeout_ms", smoke_config.e2e_chat_conversation_timeout_ms);
    module.addOptions("build_config", build_config);
    return module;
}

fn smokeBuildConfigFromOptions(b: *std.Build) SmokeBuildConfig {
    const gizclaw_server_addr = b.option([]const u8, "gizclaw_server_addr", "GizClaw server host:port") orelse default_gizclaw_server_addr;
    const gizclaw_server_key = b.option([]const u8, "gizclaw_server_key", "GizClaw server public key") orelse default_gizclaw_server_key;
    const gizclaw_client_key = b.option([]const u8, "gizclaw_client_key", "GizClaw client private key") orelse default_gizclaw_client_key;
    return .{
        .wifi_ssid = b.option([]const u8, "wifi_ssid", "WiFi SSID for the zux speedtest app") orelse default_wifi_ssid,
        .wifi_password = b.option([]const u8, "wifi_password", "WiFi password for the zux speedtest app") orelse default_wifi_password,
        .gizclaw_server_addr = gizclaw_server_addr,
        .gizclaw_server_key = gizclaw_server_key,
        .gizclaw_client_key = gizclaw_client_key,
        .server_addr = b.option([]const u8, "server_addr", "GizClaw e2e server host:port") orelse gizclaw_server_addr,
        .server_pub_key = b.option([]const u8, "server_pub_key", "GizClaw e2e server public key") orelse gizclaw_server_key,
        .client_pri_key = b.option([]const u8, "client_pri_key", "GizClaw e2e client private key") orelse gizclaw_client_key,
        .chat_workspace = b.option([]const u8, "chat_workspace", "GizClaw chat smoke workspace name") orelse default_chat_workspace,
        .chat_workflow = b.option([]const u8, "chat_workflow", "GizClaw chat smoke workflow name") orelse default_chat_workflow,
        .chat_default_mode = b.option([]const u8, "chat_default_mode", "GizClaw chat smoke mode: push_to_talk or realtime") orelse default_chat_mode,
        .e2e_suite = b.option([]const u8, "e2e_suite", "GizClaw e2e suite: rpc, rpc_server_run, rpc_resources, speed, chat, or all") orelse default_e2e_suite,
        .e2e_cipher_mode = b.option([]const u8, "e2e_cipher_mode", "GizClaw e2e cipher mode: chacha_poly, aes_256_gcm, or plaintext") orelse default_e2e_cipher_mode,
        .e2e_connect_timeout_ms = b.option(i64, "e2e_connect_timeout_ms", "GizClaw e2e connect timeout in milliseconds") orelse default_e2e_connect_timeout_ms,
        .e2e_allow_mutations = b.option(bool, "e2e_allow_mutations", "Allow GizClaw e2e mutation RPC checks") orelse false,
        .e2e_speed_bytes = b.option(u64, "e2e_speed_bytes", "GizClaw e2e speed-test bytes per direction") orelse default_e2e_speed_bytes,
        .e2e_speed_timeout_ms = b.option(i64, "e2e_speed_timeout_ms", "GizClaw e2e speed-test timeout in milliseconds") orelse default_e2e_speed_timeout_ms,
        .e2e_chat_rounds = b.option(u32, "e2e_chat_rounds", "GizClaw e2e chat rounds") orelse default_e2e_chat_rounds,
        .e2e_chat_run_timeout_ms = b.option(u32, "e2e_chat_run_timeout_ms", "GizClaw e2e chat run timeout in milliseconds") orelse default_e2e_chat_run_timeout_ms,
        .e2e_chat_conversation_timeout_ms = b.option(u32, "e2e_chat_conversation_timeout_ms", "GizClaw e2e chat conversation timeout in milliseconds") orelse default_e2e_chat_conversation_timeout_ms,
    };
}

fn launcherAppName(selected_app_name: []const u8) []const u8 {
    if (std.mem.eql(u8, selected_app_name, "e2e")) return "gizclaw_zux_e2e";
    if (std.mem.eql(u8, selected_app_name, "chat_smoke")) return "gizclaw_zux_chat_smoke";
    return "gizclaw_zux_speedtest";
}

fn desktopIdentity(selected_app_name: []const u8) struct {
    bundle_name: []const u8,
    bundle_id: []const u8,
    display_name: []const u8,
    systray_name: []const u8,
} {
    if (std.mem.eql(u8, selected_app_name, "chat_smoke")) return .{
        .bundle_name = "GizClawChat",
        .bundle_id = default_bundle_id,
        .display_name = "GizClaw Chat",
        .systray_name = "GizClaw Chat",
    };
    if (std.mem.eql(u8, selected_app_name, "e2e")) return .{
        .bundle_name = "GizClawE2E",
        .bundle_id = default_bundle_id,
        .display_name = "GizClaw E2E",
        .systray_name = "GizClaw E2E",
    };
    return .{
        .bundle_name = "GizClawSpeedtest",
        .bundle_id = default_bundle_id,
        .display_name = "GizClaw Speedtest",
        .systray_name = "GizClaw Speedtest",
    };
}

const E2EModules = struct {
    assets: *std.Build.Module,
    common: *std.Build.Module,
    runners: *std.Build.Module,
};

fn createE2EModules(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    gizclaw_dep: *std.Build.Dependency,
    gstd: *std.Build.Module,
    embed: *std.Build.Module,
    opus: *std.Build.Module,
    config: SmokeBuildConfig,
) E2EModules {
    const e2e_build_config = b.addOptions();
    e2e_build_config.addOption([]const u8, "server_addr", config.server_addr);
    e2e_build_config.addOption([]const u8, "server_pub_key", config.server_pub_key);
    e2e_build_config.addOption([]const u8, "client_pri_key", config.client_pri_key);
    e2e_build_config.addOption([]const u8, "cipher_mode", config.e2e_cipher_mode);

    const runtime_source = b.addWriteFiles().add("e2e_runtime.zig",
        \\pub const runtime = @import("gstd").runtime;
        \\
    );
    const runtime_mod = b.createModule(.{
        .root_source_file = runtime_source,
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "gstd", .module = gstd },
        },
    });
    const common = b.createModule(.{
        .root_source_file = b.path("../zux/e2e/src/common.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "gizclaw", .module = gizclaw_dep.module("gizclaw") },
            .{ .name = "giznet", .module = gizclaw_dep.module("giznet") },
            .{ .name = "giznoise", .module = gizclaw_dep.module("giznoise") },
            .{ .name = "e2e_runtime", .module = runtime_mod },
            .{ .name = "e2e_build_config", .module = e2e_build_config.createModule() },
        },
    });

    return .{
        .assets = createE2EAssetsModule(b, target, optimize, "../../test/gizclaw-e2e/Assets.zig"),
        .common = common,
        .runners = createE2ERunnerModule(b, target, optimize, runtime_mod, common, embed, opus, "../../test/gizclaw-e2e/client/Runners.zig"),
    };
}

fn createE2EAssetsModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    root: []const u8,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
    });
}

fn createE2ERunnerModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    runtime_mod: *std.Build.Module,
    common: *std.Build.Module,
    embed: *std.Build.Module,
    opus: *std.Build.Module,
    root: []const u8,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "gstd", .module = runtime_mod },
            .{ .name = "common", .module = common },
            .{ .name = "embed", .module = embed },
            .{ .name = "opus", .module = opus },
        },
    });
}

fn normalizeHostPath(b: *std.Build, value: []const u8) []const u8 {
    if (value.len == 0 or std.fs.path.isAbsolute(value)) return value;
    return b.pathFromRoot(value);
}

const run_app_script =
    \\set -eu
    \\app="$1"
    \\port="$2"
    \\app_dir="$(cd "$(dirname "$app")" && pwd -P)"
    \\app="$app_dir/$(basename "$app")"
    \\/usr/bin/pkill -f "$app/Contents/MacOS/desktop_launcher_app" 2>/dev/null || true
    \\open "$app"
    \\i=0
    \\while [ "$i" -lt 300 ]; do
    \\  if /usr/bin/curl -fsS "http://127.0.0.1:$port/topology" >/dev/null 2>&1; then
    \\    echo "desktop server ready: http://127.0.0.1:$port/"
    \\    exit 0
    \\  fi
    \\  sleep 0.1
    \\  i=$((i + 1))
    \\done
    \\echo "desktop server did not become ready on port $port" >&2
    \\exit 1
;

fn createTraySource(b: *std.Build) std.Build.LazyPath {
    const write_files = b.addWriteFiles();
    return write_files.add("desktop_launcher_tray.m",
        \\#import <Cocoa/Cocoa.h>
        \\#include <arpa/inet.h>
        \\#include <stdbool.h>
        \\#include <stdlib.h>
        \\#include <string.h>
        \\#include <sys/socket.h>
        \\#include <unistd.h>
        \\
        \\extern void desktop_launcher_quit(void);
        \\
        \\#ifndef DESKTOP_LAUNCHER_SYSTRAY_NAME
        \\#define DESKTOP_LAUNCHER_SYSTRAY_NAME "GizClaw"
        \\#endif
        \\
        \\static int launcherPort = 8080;
        \\
        \\static BOOL serverReady(int port) {
        \\    int fd = socket(AF_INET, SOCK_STREAM, 0);
        \\    if (fd < 0) return NO;
        \\
        \\    struct sockaddr_in addr;
        \\    memset(&addr, 0, sizeof(addr));
        \\    addr.sin_family = AF_INET;
        \\    addr.sin_port = htons(port);
        \\    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        \\
        \\    int result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        \\    close(fd);
        \\    return result == 0 ? YES : NO;
        \\}
        \\
        \\@interface AppDelegate : NSObject <NSApplicationDelegate>
        \\@property(strong) NSStatusItem *statusItem;
        \\@end
        \\
        \\@implementation AppDelegate
        \\
        \\- (void)applicationDidFinishLaunching:(NSNotification *)notification {
        \\    (void)notification;
        \\    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        \\    [self installStatusItem];
        \\}
        \\
        \\- (void)installStatusItem {
        \\    NSString *systrayName = [NSString stringWithUTF8String:DESKTOP_LAUNCHER_SYSTRAY_NAME];
        \\    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
        \\    self.statusItem.button.title = systrayName;
        \\    self.statusItem.button.toolTip = systrayName;
        \\
        \\    NSMenu *menu = [[NSMenu alloc] initWithTitle:systrayName];
        \\    NSMenuItem *openItem = [[NSMenuItem alloc] initWithTitle:@"Open Browser" action:@selector(openBrowser:) keyEquivalent:@"o"];
        \\    openItem.target = self;
        \\    [menu addItem:openItem];
        \\    [menu addItem:[NSMenuItem separatorItem]];
        \\    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit" action:@selector(quit:) keyEquivalent:@"q"];
        \\    quitItem.target = self;
        \\    [menu addItem:quitItem];
        \\    self.statusItem.menu = menu;
        \\}
        \\
        \\- (void)openBrowser:(id)sender {
        \\    (void)sender;
        \\    [self waitForServerAndOpenBrowser];
        \\}
        \\
        \\- (void)waitForServerAndOpenBrowser {
        \\    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        \\        for (int i = 0; i < 100; i++) {
        \\            if (serverReady(launcherPort)) {
        \\                dispatch_async(dispatch_get_main_queue(), ^{
        \\                    NSString *urlString = [NSString stringWithFormat:@"http://127.0.0.1:%d/", launcherPort];
        \\                    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:urlString]];
        \\                });
        \\                return;
        \\            }
        \\            usleep(100000);
        \\        }
        \\        NSLog(@"desktop server did not become ready on port %d", launcherPort);
        \\    });
        \\}
        \\
        \\- (void)quit:(id)sender {
        \\    (void)sender;
        \\    desktop_launcher_quit();
        \\}
        \\
        \\@end
        \\
        \\void desktop_launcher_run_tray(unsigned int port) {
        \\    launcherPort = (int)port;
        \\    @autoreleasepool {
        \\        NSApplication *app = [NSApplication sharedApplication];
        \\        AppDelegate *delegate = [[AppDelegate alloc] init];
        \\        app.delegate = delegate;
        \\        [app run];
        \\    }
        \\}
        \\
    );
}
