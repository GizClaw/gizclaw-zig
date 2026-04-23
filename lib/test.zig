const runtime = @import("embed_std").std;
const testing_api = @import("embed").testing;
const giznet = @import("giznet");

test "giznet/unit" {
    var t = testing_api.T.new(runtime, .net);
    defer t.deinit();

    t.timeout(10 * runtime.time.ns_per_s);
    t.run("giznet/unit", giznet.test_runner.unit.make(runtime));
    if (!t.wait()) return error.TestFailed;
}

test "giznet/integration" {
    var t = testing_api.T.new(runtime, .integration);
    defer t.deinit();

    t.timeout(10 * runtime.time.ns_per_s);
    t.run("giznet/integration", giznet.test_runner.integration.make(runtime));
    if (!t.wait()) return error.TestFailed;
}

test "giznet/benchmark" {
    var t = testing_api.T.new(runtime, .benchmark);
    defer t.deinit();

    t.timeout(30 * runtime.time.ns_per_s);
    t.run("giznet/benchmark", giznet.test_runner.benchmark.make(runtime));
    if (!t.wait()) return error.TestFailed;
}

test "giznet/cork" {
    var t = testing_api.T.new(runtime, .cork);
    defer t.deinit();

    t.timeout(5 * runtime.time.ns_per_s);
    t.run("giznet/cork", giznet.test_runner.cork.make(runtime));
    if (!t.wait()) return error.TestFailed;
}
