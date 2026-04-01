const std = @import("std");

const Self = @This();

pub const ImportOptions = struct {
    noise: bool = false,
    zig_kcp: bool = false,
    embed_std: bool = false,
    testing: bool = false,
};

pub const Modules = struct {
    embed: *std.Build.Module,
    noise: ?*std.Build.Module = null,
    zig_kcp: ?*std.Build.Module = null,
    embed_std: ?*std.Build.Module = null,
    testing: ?*std.Build.Module = null,
};

b: *std.Build,
modules: Modules,

pub fn init(b: *std.Build, modules: Modules) Self {
    return .{
        .b = b,
        .modules = modules,
    };
}

pub fn createModule(
    self: Self,
    root_source_file: std.Build.LazyPath,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    imports: ImportOptions,
) *std.Build.Module {
    const module = self.b.createModule(.{
        .root_source_file = root_source_file,
        .target = target,
        .optimize = optimize,
    });
    module.addImport("embed", self.modules.embed);
    if (imports.noise) module.addImport("noise", self.modules.noise orelse @panic("missing module: noise"));
    if (imports.zig_kcp) module.addImport("zig_kcp", self.modules.zig_kcp orelse @panic("missing module: zig_kcp"));
    if (imports.embed_std) module.addImport("embed_std", self.modules.embed_std orelse @panic("missing module: embed_std"));
    if (imports.testing) module.addImport("testing", self.modules.testing orelse @panic("missing module: testing"));
    return module;
}

pub fn addRun(self: Self, module: *std.Build.Module) *std.Build.Step.Run {
    const compile = self.b.addTest(.{
        .root_module = module,
    });
    return self.b.addRunArtifact(compile);
}

pub fn addNamedTest(
    self: Self,
    step_name: []const u8,
    description: []const u8,
    module: *std.Build.Module,
) *std.Build.Step.Run {
    const run = self.addRun(module);
    const step = self.b.step(step_name, description);
    step.dependOn(&run.step);
    return run;
}
