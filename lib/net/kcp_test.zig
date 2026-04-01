const runtime = @import("embed_std").std;
const testing_api = @import("testing");
const kcp_runner = @import("test_runner/kcp.zig");

test "kcp" {
    var t = testing_api.T.new(runtime, .kcp);
    defer t.deinit();

    t.timeout(5 * runtime.time.ns_per_s);
    t.run("kcp", kcp_runner.runner(runtime));
    if (!t.wait()) return error.TestFailed;
}
