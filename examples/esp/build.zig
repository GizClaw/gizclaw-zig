const std = @import("std");
const embed_pkg = @import("embed");

const default_wifi_ssid = "";
const default_wifi_password = "";
const default_gizclaw_server_addr = "";
const default_gizclaw_server_key = "";
const default_gizclaw_client_key = "";
const default_giznet_benchmark_suite = "service";
const default_giznet_benchmark_relay_host = "192.168.1.6";
const default_giznet_benchmark_relay_base_port: u16 = 39001;

const SmokeBuildConfig = struct {
    wifi_ssid: []const u8,
    wifi_password: []const u8,
    gizclaw_server_addr: []const u8,
    gizclaw_server_key: []const u8,
    gizclaw_client_key: []const u8,
    giznet_benchmark_suite: []const u8,
    giznet_benchmark_relay_host: []const u8,
    giznet_benchmark_relay_base_port: u16,
};

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const board_name = b.option([]const u8, "board", "Board under esp.embed.boards") orelse "devkit";
    const app_name = b.option([]const u8, "app", "Selected Zux app: smoke, benchmark, or http_client") orelse "smoke";
    const smoke_config = smokeBuildConfigFromOptions(b);

    const embed_build_dep = b.dependency("embed", .{});
    const board_build_config_module = createBoardBuildConfigModule(b, embed_build_dep, board_name);
    const build_config_module = b.createModule(.{
        .root_source_file = b.path("build_config.zig"),
        .imports = &.{
            .{ .name = "esp", .module = embed_build_dep.module("esp") },
            .{ .name = "board_build_config", .module = board_build_config_module },
        },
    });
    const context = embed_pkg.esp.idf.resolveBuildContext(b, .{
        .build_config = build_config_module,
        .esp_dep = embed_build_dep,
        .esp_root = embed_build_dep.path("esp"),
    });

    const sysroot_path = if (context.toolchain_sysroot) |sysroot| sysroot.root else "";
    if (sysroot_path.len != 0) b.sysroot = sysroot_path;

    const embed_dep = b.dependency("embed", .{
        .target = context.target,
        .optimize = optimize,
    });
    const runtime_build_config_module = createBoardBuildConfigModule(b, embed_dep, board_name);
    const esp_grt_module = embed_dep.module("esp").import_table.get("esp_grt") orelse
        @panic("esp module is missing esp_grt import");
    esp_grt_module.addImport("build_config", runtime_build_config_module);
    const gizclaw_dep = b.dependency("gizclaw", .{
        .target = context.target,
        .optimize = optimize,
        .sysroot = sysroot_path,
    });
    if (context.toolchain_sysroot) |sysroot| {
        addGizclawSysrootIncludes(gizclaw_dep, sysroot);
    }

    const launcher_options_module = createLauncherOptionsModule(b, board_name);
    const selected_app = createSelectedApp(b, context.target, optimize, embed_dep, gizclaw_dep, smoke_config, app_name);
    const entry_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = context.target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "esp", .module = embed_dep.module("esp") },
            .{ .name = "selected_app", .module = selected_app },
            .{ .name = "launcher_options", .module = launcher_options_module },
        },
        .link_libc = true,
    });

    const board_component = addBoardComponent(b, embed_build_dep, board_name);
    const app_components = if (std.mem.eql(u8, app_name, "http_client"))
        &.{ board_component, addPosixHttpProbeComponent(b) }
    else
        &.{board_component};
    const app = embed_pkg.esp.idf.addApp(b, "launcher", .{
        .context = context,
        .entry = .{
            .symbol = "zig_esp_main",
            .module = entry_module,
        },
        .components = app_components,
    });

    const build_step = b.step("build", "Build the ESP launcher example");
    build_step.dependOn(app.combine_binaries);
    build_step.dependOn(app.elf_layout);
    b.default_step = build_step;

    const flash_step = b.step("flash", "Flash the ESP launcher example");
    flash_step.dependOn(app.flash);

    const monitor_step = b.step("monitor", "Monitor the ESP launcher example");
    monitor_step.dependOn(app.monitor);
}

fn createSelectedApp(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    embed_dep: *std.Build.Dependency,
    gizclaw_dep: *std.Build.Dependency,
    smoke_config: SmokeBuildConfig,
    app_name: []const u8,
) *std.Build.Module {
    const root_source_file = if (std.mem.eql(u8, app_name, "smoke"))
        b.path("../zux/smoke/src/app.zig")
    else if (std.mem.eql(u8, app_name, "benchmark"))
        b.path("../zux/benchmark/src/app.zig")
    else if (std.mem.eql(u8, app_name, "http_client"))
        b.path("../zux/http_client/src/app.zig")
    else
        std.debug.panic("unknown zux app: {s}; expected smoke, benchmark, or http_client", .{app_name});

    const module = b.createModule(.{
        .root_source_file = root_source_file,
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "embed", .module = embed_dep.module("embed") },
            .{ .name = "glib", .module = embed_dep.module("glib") },
            .{ .name = "gizclaw", .module = gizclaw_dep.module("gizclaw") },
            .{ .name = "giznet", .module = gizclaw_dep.module("giznet") },
            .{ .name = "kcp", .module = gizclaw_dep.module("kcp") },
            .{ .name = "launcher", .module = embed_dep.module("apps/launcher") },
        },
    });
    module.addOptions("build_config", smokeBuildConfigOptions(b, smoke_config));
    return module;
}

fn smokeBuildConfigFromOptions(b: *std.Build) SmokeBuildConfig {
    return .{
        .wifi_ssid = b.option([]const u8, "wifi_ssid", "WiFi SSID for the zux smoke app") orelse default_wifi_ssid,
        .wifi_password = b.option([]const u8, "wifi_password", "WiFi password for the zux smoke app") orelse default_wifi_password,
        .gizclaw_server_addr = b.option([]const u8, "gizclaw_server_addr", "GizClaw server host:port") orelse default_gizclaw_server_addr,
        .gizclaw_server_key = b.option([]const u8, "gizclaw_server_key", "GizClaw server public key") orelse default_gizclaw_server_key,
        .gizclaw_client_key = b.option([]const u8, "gizclaw_client_key", "GizClaw client private key") orelse default_gizclaw_client_key,
        .giznet_benchmark_suite = b.option([]const u8, "benchmark_suite", "GizNet benchmark suite: service, kcp_stream, kcp_stream_real_udp, kcp_stream_relay_udp, noise, giz_net, or all") orelse default_giznet_benchmark_suite,
        .giznet_benchmark_relay_host = b.option([]const u8, "benchmark_relay_host", "Host IP for the kcp_stream_relay_udp benchmark") orelse default_giznet_benchmark_relay_host,
        .giznet_benchmark_relay_base_port = b.option(u16, "benchmark_relay_base_port", "Base UDP port for the kcp_stream_relay_udp benchmark") orelse default_giznet_benchmark_relay_base_port,
    };
}

fn smokeBuildConfigOptions(b: *std.Build, config: SmokeBuildConfig) *std.Build.Step.Options {
    const options = b.addOptions();
    options.addOption([]const u8, "wifi_ssid", config.wifi_ssid);
    options.addOption([]const u8, "wifi_password", config.wifi_password);
    options.addOption([]const u8, "gizclaw_server_addr", config.gizclaw_server_addr);
    options.addOption([]const u8, "gizclaw_server_key", config.gizclaw_server_key);
    options.addOption([]const u8, "gizclaw_client_key", config.gizclaw_client_key);
    options.addOption([]const u8, "giznet_benchmark_suite", config.giznet_benchmark_suite);
    options.addOption([]const u8, "giznet_benchmark_relay_host", config.giznet_benchmark_relay_host);
    options.addOption(u16, "giznet_benchmark_relay_base_port", config.giznet_benchmark_relay_base_port);
    return options;
}

fn addGizclawSysrootIncludes(gizclaw_dep: *std.Build.Dependency, sysroot: embed_pkg.esp.idf.ToolchainSysroot) void {
    const gstd_module = gizclaw_dep.module("gstd");
    const mbedtls_module = gstd_module.import_table.get("mbedtls") orelse @panic("gstd module is missing mbedtls import");
    addModuleSysrootInclude(mbedtls_module, sysroot.include_dir);
}

fn addModuleSysrootInclude(module: *std.Build.Module, include_dir: std.Build.LazyPath) void {
    module.addSystemIncludePath(include_dir);
    for (module.link_objects.items) |link_object| {
        switch (link_object) {
            .other_step => |compile| compile.root_module.addSystemIncludePath(include_dir),
            else => {},
        }
    }
}

fn createLauncherOptionsModule(b: *std.Build, board_name: []const u8) *std.Build.Module {
    const write_files = b.addWriteFiles();
    const source = write_files.add("launcher_options.zig", b.fmt(
        \\pub const board_name: []const u8 = "{f}";
        \\
    , .{
        std.zig.fmtString(board_name),
    }));

    return b.createModule(.{
        .root_source_file = source,
    });
}

const Board = struct {
    name: []const u8,
    component_name: []const u8,
    c_files: []const []const u8,
    requires: []const []const u8,
    include_path: ?[]const u8 = null,
};

const devkit = Board{
    .name = "devkit",
    .component_name = "devkit_board",
    .c_files = &.{
        "power_button.c",
        "led_strip.c",
    },
    .requires = &.{
        "driver",
        "esp_driver_gpio",
        "esp_event",
        "esp_netif",
        "esp_wifi",
        "led_strip",
        "log",
        "nvs_flash",
    },
};

const szp = Board{
    .name = "szp",
    .component_name = "szp_board",
    .c_files = &.{
        "szp_board.c",
        "szp_storage.c",
        "szp_audio.c",
        "szp_button.c",
        "szp_display.c",
    },
    .requires = &.{
        "driver",
        "esp_driver_gpio",
        "esp_driver_i2s",
        "esp_driver_ledc",
        "esp_driver_spi",
        "esp_event",
        "esp_lcd",
        "esp_netif",
        "esp_timer",
        "esp_wifi",
        "log",
        "nvs_flash",
        "spiffs",
    },
    .include_path = "include",
};

fn createBoardBuildConfigModule(
    b: *std.Build,
    embed_dep: *std.Build.Dependency,
    name: []const u8,
) *std.Build.Module {
    const board = resolveBoard(name);
    return b.createModule(.{
        .root_source_file = embed_dep.path(espBoardPath(b, board, "build_config.zig")),
        .imports = &.{
            .{ .name = "esp", .module = embed_dep.module("esp") },
        },
    });
}

fn addBoardComponent(
    b: *std.Build,
    embed_dep: *std.Build.Dependency,
    name: []const u8,
) *embed_pkg.esp.idf.Component {
    const board = resolveBoard(name);
    const component = embed_pkg.esp.idf.Component.create(b, .{ .name = board.component_name });
    component.addFile(.{
        .relative_path = "idf_component.yml",
        .file = embed_dep.path(espBoardPath(b, board, "idf_component.yml")),
    });
    if (board.include_path) |include_path| {
        component.addIncludePath(embed_dep.path(espBoardPath(b, board, include_path)));
    }
    component.addCSourceFiles(.{
        .root = embed_dep.path(espBoardPath(b, board, "bindings")),
        .files = board.c_files,
    });
    for (board.requires) |require| {
        component.addRequire(require);
    }
    return component;
}

fn addPosixHttpProbeComponent(b: *std.Build) *embed_pkg.esp.idf.Component {
    const component = embed_pkg.esp.idf.Component.create(b, .{ .name = "posix_http_probe" });
    component.addCSourceFiles(.{
        .root = b.path("src"),
        .files = &.{
            "posix_http_probe.c",
            "esp_http_client_probe.c",
        },
    });
    component.addRequire("esp_http_client");
    component.addRequire("esp_timer");
    component.addRequire("lwip");
    return component;
}

fn resolveBoard(name: []const u8) Board {
    if (std.mem.eql(u8, name, devkit.name)) return devkit;
    if (std.mem.eql(u8, name, szp.name)) return szp;
    std.debug.panic("unknown ESP board: {s}", .{name});
}

fn espBoardPath(b: *std.Build, board: Board, sub_path: []const u8) []const u8 {
    return b.fmt("esp/lib/boards/{s}/{s}", .{ board.name, sub_path });
}
