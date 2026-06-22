const std = @import("std");
const build_test = @import("build/test.zig");

const lib_giznet = @import("build/lib/giznet.zig");
const lib_gizclaw = @import("build/lib/gizclaw.zig");

const Libraries = struct {
    pub const giznet = lib_giznet;
    pub const gizclaw = lib_gizclaw;
};

const model_api_paths = [_][]const u8{
    "client_service.json",
    "rpc/zig.json",
    "rpc/all.json",
    "rpc/client.json",
    "rpc/zig_server.json",
    "rpc/device.json",
    "rpc/gear.json",
    "type/agent_selection.json",
    "type/configuration.json",
    "type/credential.json",
    "type/credential_body.json",
    "type/credential_method.json",
    "type/credential_spec.json",
    "type/dashscope_tenant.json",
    "type/dashscope_tenant_spec.json",
    "type/device_info.json",
    "type/error_payload.json",
    "type/error_response.json",
    "type/firmware.json",
    "type/firmware_artifact.json",
    "type/firmware_artifact_kind.json",
    "type/firmware_selection.json",
    "type/firmware_slot.json",
    "type/firmware_slots.json",
    "type/firmware_spec.json",
    "type/gear.json",
    "type/gear_imei.json",
    "type/gear_label.json",
    "type/gear_role.json",
    "type/gear_status.json",
    "type/gemini_tenant.json",
    "type/gemini_tenant_spec.json",
    "type/hardware_info.json",
    "type/minimax_tenant.json",
    "type/minimax_tenant_spec.json",
    "type/model.json",
    "type/model_capabilities.json",
    "type/model_kind.json",
    "type/model_provider.json",
    "type/model_provider_data.json",
    "type/model_provider_kind.json",
    "type/model_source.json",
    "type/model_spec.json",
    "type/openai_tenant.json",
    "type/openai_tenant_spec.json",
    "type/peer.json",
    "type/peer_imei.json",
    "type/peer_label.json",
    "type/peer_registration_status.json",
    "type/peer_role.json",
    "type/peer_run_agent.json",
    "type/peer_run_status.json",
    "type/peer_status.json",
    "type/peer_stream_event.json",
    "type/provider.json",
    "type/provider_kind.json",
    "type/refresh_info.json",
    "type/refresh_identifiers.json",
    "type/registration.json",
    "type/runtime.json",
    "type/server_info.json",
    "type/voice.json",
    "type/voice_provider.json",
    "type/voice_provider_data.json",
    "type/voice_provider_kind.json",
    "type/voice_source.json",
    "type/voice_spec.json",
    "type/volc_tenant.json",
    "type/volc_tenant_spec.json",
    "type/workflow_api_version.json",
    "type/workflow_document.json",
    "type/workflow_metadata.json",
    "type/workflows/flowcraft.json",
    "type/workspace.json",
    "type/workspace_spec.json",
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
    const glib = embed_dep.module("glib");
    const gstd = embed_dep.module("gstd");
    const embed = embed_dep.module("embed");
    const kcp = embed_dep.module("thirdparty/kcp");
    const openapi = embed_dep.module("openapi");
    const codegen = embed_dep.module("codegen");

    b.modules.put("glib", glib) catch @panic("OOM");
    b.modules.put("gstd", gstd) catch @panic("OOM");
    b.modules.put("embed", embed) catch @panic("OOM");
    b.modules.put("kcp", kcp) catch @panic("OOM");
    b.modules.put("openapi", openapi) catch @panic("OOM");
    b.modules.put("codegen", codegen) catch @panic("OOM");
    const models_options = b.addOptions();
    inline for (model_api_paths) |path| {
        models_options.addOption([]const u8, apiOptionName(path), readBuildFile(b, "api/" ++ path));
    }
    b.modules.put("gizclaw_models_options", models_options.createModule()) catch @panic("OOM");

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).create(b, target, optimize);
    }

    inline for (@typeInfo(Libraries).@"struct".decls) |decl| {
        @field(Libraries, decl.name).link(b);
    }

    build_test.createTestModule(b, target, optimize, Libraries);
    build_test.createGizClawE2E(b, target, optimize);
    build_test.createZuxSmokeTest(b, target, optimize, embed_dep, glib, gstd, embed);
}

fn readBuildFile(b: *std.Build, path: []const u8) []const u8 {
    return b.build_root.handle.readFileAlloc(b.allocator, path, 16 * 1024 * 1024) catch |err| {
        std.debug.panic("read {s}: {s}", .{ path, @errorName(err) });
    };
}

fn apiOptionName(comptime path: []const u8) []const u8 {
    comptime var buf: [path.len + 5]u8 = undefined;
    inline for (path, 0..) |ch, i| {
        buf[i] = switch (ch) {
            '/', '.', '-' => '_',
            else => ch,
        };
    }
    buf[path.len + 0] = '_';
    buf[path.len + 1] = 'j';
    buf[path.len + 2] = 's';
    buf[path.len + 3] = 'o';
    buf[path.len + 4] = 'n';
    const final = buf;
    return &final;
}
