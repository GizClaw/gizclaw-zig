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
    for ([_][]const u8{ "embed", "embed_std", "kcp" }) |name| {
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
            test_type.parent_step.dependOn(&run_test.step);
            module_step.dependOn(&run_test.step);
        }
    }
}
