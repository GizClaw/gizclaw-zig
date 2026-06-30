const glib = @import("glib");
const grt = @import("gstd").runtime;
const std = @import("std");
const testing_api = glib.testing;
const giznet = @import("giznet");
const giznoise = @import("giznoise");
const gizclaw = @import("gizclaw");

test "giznet/unit" {
    var t = testing_api.T.new(grt.std, grt.time, .net);
    defer t.deinit();

    t.timeout(10 * glib.time.duration.Second);
    t.run("giznet/unit", giznet.test_runner.unit.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "giznet/integration" {
    var t = testing_api.T.new(grt.std, grt.time, .integration);
    defer t.deinit();

    t.timeout(10 * glib.time.duration.Second);
    t.run("giznet/integration", giznet.test_runner.integration.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "giznet/benchmark" {
    var t = testing_api.T.new(grt.std, grt.time, .benchmark);
    defer t.deinit();

    t.timeout(30 * glib.time.duration.Second);
    t.run("giznet/benchmark", giznet.test_runner.benchmark.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "giznet/cork" {
    var t = testing_api.T.new(grt.std, grt.time, .cork);
    defer t.deinit();

    t.timeout(5 * glib.time.duration.Second);
    t.run("giznet/cork", giznet.test_runner.cork.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "giznoise/unit" {
    var t = testing_api.T.new(grt.std, grt.time, .net);
    defer t.deinit();

    t.timeout(10 * glib.time.duration.Second);
    t.run("giznoise/unit", giznoise.test_runner.unit.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "giznoise/integration" {
    var t = testing_api.T.new(grt.std, grt.time, .integration);
    defer t.deinit();

    t.timeout(10 * glib.time.duration.Second);
    t.run("giznoise/integration", giznoise.test_runner.integration.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "giznoise/benchmark" {
    var t = testing_api.T.new(grt.std, grt.time, .benchmark);
    defer t.deinit();

    t.timeout(30 * glib.time.duration.Second);
    t.run("giznoise/benchmark", giznoise.test_runner.benchmark.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "giznoise/cork" {
    var t = testing_api.T.new(grt.std, grt.time, .cork);
    defer t.deinit();

    t.timeout(5 * glib.time.duration.Second);
    t.run("giznoise/cork", giznoise.test_runner.cork.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "gizclaw/unit" {
    var t = testing_api.T.new(grt.std, grt.time, .net);
    defer t.deinit();

    t.timeout(5 * glib.time.duration.Second);
    t.run("gizclaw/unit", gizclaw.test_runner.unit.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "gizclaw/integration" {
    var t = testing_api.T.new(grt.std, grt.time, .integration);
    defer t.deinit();

    t.timeout(5 * glib.time.duration.Second);
    t.run("gizclaw/integration", gizclaw.test_runner.integration.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "gizclaw/benchmark" {
    var t = testing_api.T.new(grt.std, grt.time, .benchmark);
    defer t.deinit();

    t.timeout(5 * glib.time.duration.Second);
    t.run("gizclaw/benchmark", gizclaw.test_runner.benchmark.make(grt));
    if (!t.wait()) return error.TestFailed;
}

test "gizclaw/cork" {
    var t = testing_api.T.new(grt.std, grt.time, .cork);
    defer t.deinit();

    t.timeout(5 * glib.time.duration.Second);
    t.run("gizclaw/cork", gizclaw.test_runner.cork.make(grt));
    if (!t.wait()) return error.TestFailed;
}
