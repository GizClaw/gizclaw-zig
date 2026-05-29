const std = @import("std");
const build_test = @import("build/test.zig");

const lib_giznet = @import("build/lib/giznet.zig");
const lib_gizclaw = @import("build/lib/gizclaw.zig");
const cmd_gizclaw = @import("build/cmd/gizclaw.zig");

const Libraries = struct {
    pub const giznet = lib_giznet;
    pub const gizclaw = lib_gizclaw;
};

const Commands = struct {
    pub const gizclaw = cmd_gizclaw;
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sysroot = b.option([]const u8, "sysroot", "C sysroot path for cross-target libc headers") orelse "";
    if (sysroot.len != 0) b.sysroot = sysroot;
    const embed_dep = b.dependency("embed", .{
        .target = target,
        .optimize = optimize,
        .sysroot = sysroot,
    });
    const zig_kcp_dep = b.dependency("zig_kcp", .{
        .target = target,
        .optimize = optimize,
    });

    const glib = embed_dep.module("glib");
    const gstd = embed_dep.module("gstd");
    const embed = embed_dep.module("embed");
    const openapi = embed_dep.module("openapi");
    const codegen = embed_dep.module("codegen");

    b.modules.put("glib", glib) catch @panic("OOM");
    b.modules.put("gstd", gstd) catch @panic("OOM");
    b.modules.put("embed", embed) catch @panic("OOM");
    b.modules.put("kcp", zig_kcp_dep.module("kcp")) catch @panic("OOM");
    b.modules.put("openapi", openapi) catch @panic("OOM");
    b.modules.put("codegen", codegen) catch @panic("OOM");

    const models_options = b.addOptions();
    models_options.addOption([]const u8, "rpc_json", readBuildFile(b, "api/rpc.json"));
    models_options.addOption([]const u8, "rpc_peer_json", readBuildFile(b, "api/rpc/peer.json"));
    models_options.addOption([]const u8, "rpc_device_json", readBuildFile(b, "api/rpc/device.json"));
    models_options.addOption([]const u8, "rpc_public_json", readBuildFile(b, "api/rpc/public.json"));
    models_options.addOption([]const u8, "rpc_gear_json", readBuildFile(b, "api/rpc/gear.json"));
    models_options.addOption([]const u8, "type_configuration_json", readBuildFile(b, "api/type/configuration.json"));
    models_options.addOption([]const u8, "type_server_info_json", readBuildFile(b, "api/type/server_info.json"));
    models_options.addOption([]const u8, "type_device_info_json", readBuildFile(b, "api/type/device_info.json"));
    models_options.addOption([]const u8, "type_refresh_info_json", readBuildFile(b, "api/type/refresh_info.json"));
    models_options.addOption([]const u8, "type_refresh_identifiers_json", readBuildFile(b, "api/type/refresh_identifiers.json"));
    models_options.addOption([]const u8, "type_registration_json", readBuildFile(b, "api/type/registration.json"));
    models_options.addOption([]const u8, "type_gear_json", readBuildFile(b, "api/type/gear.json"));
    models_options.addOption([]const u8, "type_runtime_json", readBuildFile(b, "api/type/runtime.json"));
    models_options.addOption([]const u8, "type_hardware_info_json", readBuildFile(b, "api/type/hardware_info.json"));
    models_options.addOption([]const u8, "type_gear_role_json", readBuildFile(b, "api/type/gear_role.json"));
    models_options.addOption([]const u8, "type_gear_status_json", readBuildFile(b, "api/type/gear_status.json"));
    models_options.addOption([]const u8, "type_gear_imei_json", readBuildFile(b, "api/type/gear_imei.json"));
    models_options.addOption([]const u8, "type_gear_label_json", readBuildFile(b, "api/type/gear_label.json"));
    b.modules.put("gizclaw_models_options", models_options.createModule()) catch @panic("OOM");

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).create(b, target, optimize);
    }

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).link(b);
    }

    inline for (@typeInfo(Commands).@"struct".decls) |decl| {
        @field(Commands, decl.name).create(b, target, optimize);
    }

    inline for (@typeInfo(Commands).@"struct".decls) |decl| {
        @field(Commands, decl.name).link(b);
    }

    build_test.createTestModule(b, target, optimize, Libraries);
}

fn readBuildFile(b: *std.Build, path: []const u8) []const u8 {
    return b.build_root.handle.readFileAlloc(b.allocator, path, 16 * 1024 * 1024) catch |err| {
        std.debug.panic("read {s}: {s}", .{ path, @errorName(err) });
    };
}
