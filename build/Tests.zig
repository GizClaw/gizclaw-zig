const std = @import("std");

const Tests = @This();

const unit_test_tag = "unit_tests";
const integration_test_tag = "integration_tests";

pub const LinkHook = *const fn (b: *std.Build, compile: *std.Build.Step.Compile) void;

unit_step: *std.Build.Step,
integration_step: *std.Build.Step,
full_step: *std.Build.Step,

pub fn create(b: *std.Build) Tests {
    var tests: Tests = .{
        .unit_step = b.step("test-unit", "Run unit tests"),
        .integration_step = b.step("test-integration", "Run integration tests"),
        .full_step = b.step("test", "Run all tests"),
    };
    tests.full_step.dependOn(tests.unit_step);
    tests.full_step.dependOn(tests.integration_step);
    return tests;
}

pub fn addTest(self: Tests, b: *std.Build, mod_name: []const u8, link_hook: ?LinkHook) void {
    const root_module = b.modules.get(mod_name) orelse @panic("test module missing");
    const module_step_name = if (std.mem.eql(u8, mod_name, "integration"))
        "test-lib-integration"
    else
        b.fmt("test-{s}", .{mod_name});
    const module_step = b.step(
        module_step_name,
        b.fmt("Run {s} tests", .{mod_name}),
    );

    const compile_unit_test = b.addTest(.{
        .root_module = root_module,
        .filters = &.{unit_test_tag},
    });
    if (link_hook) |hook| hook(b, compile_unit_test);
    const run_unit_test = b.addRunArtifact(compile_unit_test);
    run_unit_test.setName(b.fmt("{s}:unit", .{mod_name}));
    self.unit_step.dependOn(&run_unit_test.step);
    module_step.dependOn(&run_unit_test.step);

    const compile_integration_test = b.addTest(.{
        .root_module = root_module,
        .filters = &.{integration_test_tag},
    });
    if (link_hook) |hook| hook(b, compile_integration_test);
    const run_integration_test = b.addRunArtifact(compile_integration_test);
    run_integration_test.setName(b.fmt("{s}:integration", .{mod_name}));
    self.integration_step.dependOn(&run_integration_test.step);
    module_step.dependOn(&run_integration_test.step);
}
