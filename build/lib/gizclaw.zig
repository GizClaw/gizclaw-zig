const std = @import("std");

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const gizclaw = b.createModule(.{
        .root_source_file = b.path("lib/gizclaw.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("gizclaw", gizclaw) catch @panic("OOM");
}

pub fn link(b: *std.Build) void {
    const glib = b.modules.get("glib") orelse @panic("missing module: glib");
    const gstd = b.modules.get("gstd") orelse @panic("missing module: gstd");
    const giznet = b.modules.get("giznet") orelse @panic("missing module: giznet");
    const openapi = b.modules.get("openapi") orelse @panic("missing module: openapi");
    const codegen = b.modules.get("codegen") orelse @panic("missing module: codegen");
    const rpc_types_options = b.modules.get("gizclaw_rpc_types_options") orelse @panic("missing module: gizclaw_rpc_types_options");
    const gizclaw = b.modules.get("gizclaw") orelse @panic("missing module: gizclaw");

    gizclaw.addImport("glib", glib);
    gizclaw.addImport("gstd", gstd);
    gizclaw.addImport("giznet", giznet);
    gizclaw.addImport("openapi", openapi);
    gizclaw.addImport("codegen", codegen);
    gizclaw.addImport("gizclaw_rpc_types_options", rpc_types_options);
}
