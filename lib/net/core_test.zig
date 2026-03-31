const runtime = @import("embed_std").std;
const testing_api = @import("testing");
const core_runner = @import("test_runner/core.zig");

test "core" {
    var t = testing_api.T.new(runtime, .core);
    defer t.deinit();

    t.timeout(5 * runtime.time.ns_per_s);
    t.run("core", core_runner.runner(runtime));
    if (!t.wait()) return error.TestFailed;
}
