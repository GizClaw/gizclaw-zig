const runtime = @import("embed_std").std;
const testing_api = @import("testing");
const noise_runner = @import("test_runner/noise.zig");

test "noise" {
    var t = testing_api.T.new(runtime, .noise);
    defer t.deinit();

    t.timeout(5 * runtime.time.ns_per_s);
    t.run("noise", noise_runner.runner(runtime));
    if (!t.wait()) return error.TestFailed;
}
