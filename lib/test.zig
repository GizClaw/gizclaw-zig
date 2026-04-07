const runtime = @import("dep").embed_std.std;
const testing_api = @import("dep").testing;
const net = @import("net");

test "net/unit" {
    var t = testing_api.T.new(runtime, .net);
    defer t.deinit();

    t.timeout(5 * runtime.time.ns_per_s);
    t.run("net/unit", net.test_runner.unit.make(runtime));
    if (!t.wait()) return error.TestFailed;
}

test "net/integration" {
    var t = testing_api.T.new(runtime, .integration);
    defer t.deinit();

    t.timeout(20 * runtime.time.ns_per_s);
    t.run("net/integration", net.test_runner.integration.make(runtime));
    if (!t.wait()) return error.TestFailed;
}

test "net/benchmark" {
    var t = testing_api.T.new(runtime, .benchmark);
    defer t.deinit();

    t.timeout(60 * runtime.time.ns_per_s);
    t.run("net/benchmark", net.test_runner.benchmark.make(runtime));
    if (!t.wait()) return error.TestFailed;
}

test "net/cork" {
    var t = testing_api.T.new(runtime, .benchmark);
    defer t.deinit();

    t.timeout(5 * runtime.time.ns_per_s);
    t.run("net/cork", net.test_runner.cork.make(runtime));
    if (!t.wait()) return error.TestFailed;
}
