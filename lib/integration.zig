const runtime = @import("dep").embed_std.std;
const testing_api = @import("dep").testing;

pub const net = @import("net/test_runner/integration.zig");

test {
    _ = @This();
    _ = net;
}

test "integration_tests/net" {
    var t = testing_api.T.new(runtime, .integration);
    defer t.deinit();

    t.timeout(20 * runtime.time.ns_per_s);
    t.run("net", net.make(runtime));
    if (!t.wait()) return error.TestFailed;
}
