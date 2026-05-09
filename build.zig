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
    const embed_dep = b.dependency("embed", .{
        .target = target,
        .optimize = optimize,
    });
    const zig_kcp_dep = b.dependency("zig_kcp", .{
        .target = target,
        .optimize = optimize,
    });
    const openapi_codegen_dep = b.dependency("openapi_codegen", .{
        .target = target,
        .optimize = optimize,
    });

    b.modules.put("glib", embed_dep.module("glib")) catch @panic("OOM");
    b.modules.put("gstd", embed_dep.module("gstd")) catch @panic("OOM");
    b.modules.put("embed", embed_dep.module("embed")) catch @panic("OOM");
    b.modules.put("kcp", zig_kcp_dep.module("kcp")) catch @panic("OOM");

    const openapi_mod = b.addModule("openapi", .{
        .root_source_file = openapi_codegen_dep.path("lib/openapi.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("openapi", openapi_mod) catch @panic("OOM");

    const embed_std_mod = b.addModule("embed_std", .{
        .root_source_file = b.path("build/shim/embed_std.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "gstd", .module = embed_dep.module("gstd") },
        },
    });
    b.modules.put("embed_std", embed_std_mod) catch @panic("OOM");

    const codegen_mod = b.addModule("codegen", .{
        .root_source_file = openapi_codegen_dep.path("lib/codegen.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "openapi", .module = openapi_mod },
            .{ .name = "embed", .module = embed_dep.module("embed") },
            .{ .name = "embed_std", .module = embed_std_mod },
        },
    });
    b.modules.put("codegen", codegen_mod) catch @panic("OOM");

    const rpc_types_options = b.addOptions();
    rpc_types_options.addOption([]const u8, "rpc_json", readBuildFile(b, "api/rpc.json"));
    rpc_types_options.addOption([]const u8, "ping_json", readBuildFile(b, "api/rpc/ping.json"));
    rpc_types_options.addOption([]const u8, "gear_config_json", readBuildFile(b, "api/rpc/gear_config.json"));
    rpc_types_options.addOption([]const u8, "gear_info_json", readBuildFile(b, "api/rpc/gear_info.json"));
    rpc_types_options.addOption([]const u8, "gear_ota_json", readBuildFile(b, "api/rpc/gear_ota.json"));
    rpc_types_options.addOption([]const u8, "gear_registration_json", readBuildFile(b, "api/rpc/gear_registration.json"));
    rpc_types_options.addOption([]const u8, "gear_runtime_json", readBuildFile(b, "api/rpc/gear_runtime.json"));
    rpc_types_options.addOption([]const u8, "type_configuration_json", readBuildFile(b, "api/type/configuration.json"));
    rpc_types_options.addOption([]const u8, "type_device_info_json", readBuildFile(b, "api/type/device_info.json"));
    rpc_types_options.addOption([]const u8, "type_ota_summary_json", readBuildFile(b, "api/type/ota_summary.json"));
    rpc_types_options.addOption([]const u8, "type_registration_json", readBuildFile(b, "api/type/registration.json"));
    rpc_types_options.addOption([]const u8, "type_gear_json", readBuildFile(b, "api/type/gear.json"));
    rpc_types_options.addOption([]const u8, "type_runtime_json", readBuildFile(b, "api/type/runtime.json"));
    rpc_types_options.addOption([]const u8, "type_gear_certification_json", readBuildFile(b, "api/type/gear_certification.json"));
    rpc_types_options.addOption([]const u8, "type_firmware_config_json", readBuildFile(b, "api/type/firmware_config.json"));
    rpc_types_options.addOption([]const u8, "type_hardware_info_json", readBuildFile(b, "api/type/hardware_info.json"));
    rpc_types_options.addOption([]const u8, "type_depot_file_json", readBuildFile(b, "api/type/depot_file.json"));
    rpc_types_options.addOption([]const u8, "type_gear_role_json", readBuildFile(b, "api/type/gear_role.json"));
    rpc_types_options.addOption([]const u8, "type_gear_status_json", readBuildFile(b, "api/type/gear_status.json"));
    rpc_types_options.addOption([]const u8, "type_gear_certification_type_json", readBuildFile(b, "api/type/gear_certification_type.json"));
    rpc_types_options.addOption([]const u8, "type_gear_certification_authority_json", readBuildFile(b, "api/type/gear_certification_authority.json"));
    rpc_types_options.addOption([]const u8, "type_gear_firmware_channel_json", readBuildFile(b, "api/type/gear_firmware_channel.json"));
    rpc_types_options.addOption([]const u8, "type_gear_imei_json", readBuildFile(b, "api/type/gear_imei.json"));
    rpc_types_options.addOption([]const u8, "type_gear_label_json", readBuildFile(b, "api/type/gear_label.json"));
    b.modules.put("gizclaw_rpc_types_options", rpc_types_options.createModule()) catch @panic("OOM");

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
    return std.fs.cwd().readFileAlloc(b.allocator, path, 16 * 1024 * 1024) catch |err| {
        std.debug.panic("read {s}: {s}", .{ path, @errorName(err) });
    };
}
