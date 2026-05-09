const std = @import("std");

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const cmd = b.createModule(.{
        .root_source_file = b.path("cmd/gizclaw/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put("cmd/gizclaw", cmd) catch @panic("OOM");

    const exe = b.addExecutable(.{
        .name = "gizclaw",
        .root_module = cmd,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run-gizclaw", "Run the gizclaw CLI");
    run_step.dependOn(&run_cmd.step);
}

pub fn link(b: *std.Build) void {
    const glib = b.modules.get("glib") orelse @panic("missing module: glib");
    const gstd = b.modules.get("gstd") orelse @panic("missing module: gstd");
    const giznet = b.modules.get("giznet") orelse @panic("missing module: giznet");
    const gizclaw = b.modules.get("gizclaw") orelse @panic("missing module: gizclaw");
    const cmd = b.modules.get("cmd/gizclaw") orelse @panic("missing module: cmd/gizclaw");

    cmd.addImport("glib", glib);
    cmd.addImport("gstd", gstd);
    cmd.addImport("giznet", giznet);
    cmd.addImport("gizclaw", gizclaw);
}
