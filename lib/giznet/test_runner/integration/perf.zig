const glib = @import("glib");
const testing_api = glib.testing;

const giznet = @import("../../../giznet.zig");
const test_utils = @import("../test_utils/giz_net.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Fixture = test_utils.DefaultFixture(grt, &[_]u32{ 5101, 5102 });

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;

            runPeerPacketSmoke(grt, Fixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/perf peer_packet smoke failed: {}", .{err});
                return false;
            };
            runKcpStreamSmoke(grt, Fixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/perf kcp_stream smoke failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runPeerPacketSmoke(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    const PerfClient = giznet.PerfClient.make(grt);
    const PerfServer = giznet.PerfServer.make(grt);

    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    var server = ServerTask(PerfServer){
        .conn = pair.b,
        .count = 4,
    };
    const server_thread = try grt.task.go("giznet/test/perf/packet/server", .{}, grt.task.Routine.init(&server, @TypeOf(server).run));

    var results: [4]giznet.PerfServer.Result = undefined;
    const count = try PerfClient.runAll(pair.a, .{
        .mode = .peer_packet,
        .direction = .all,
        .packet_count = 8,
        .packet_payload_size = 32,
        .packet_pps = 0,
        .timeout = 2 * glib.time.duration.Second,
    }, &results, .{});

    server_thread.join();
    if (server.err) |err| return err;
    try grt.std.testing.expectEqual(@as(usize, 4), count);

    for (results[0..count]) |result| {
        try grt.std.testing.expectEqual(giznet.PerfServer.Status.ok, result.status);
        switch (result.direction) {
            .ping => {
                try grt.std.testing.expectEqual(@as(u64, 1), result.client.received_packets);
                try grt.std.testing.expectEqual(@as(u64, 1), result.server.sent_packets);
            },
            .up => {
                try grt.std.testing.expectEqual(@as(u64, 8), result.client.sent_packets);
                try grt.std.testing.expectEqual(@as(u64, 8), result.server.received_packets);
                try grt.std.testing.expectEqual(@as(u64, 0), result.server.missing_packets);
            },
            .down => {
                try grt.std.testing.expectEqual(@as(u64, 8), result.server.sent_packets);
                try grt.std.testing.expectEqual(@as(u64, 8), result.client.received_packets);
                try grt.std.testing.expectEqual(@as(u64, 0), result.client.missing_packets);
            },
            .duplex => {
                try grt.std.testing.expectEqual(@as(u64, 8), result.client.sent_packets);
                try grt.std.testing.expectEqual(@as(u64, 8), result.client.received_packets);
                try grt.std.testing.expectEqual(@as(u64, 8), result.server.sent_packets);
                try grt.std.testing.expectEqual(@as(u64, 8), result.server.received_packets);
            },
            .all => return error.TestUnexpectedResult,
        }
    }
}

fn runKcpStreamSmoke(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    const PerfClient = giznet.PerfClient.make(grt);
    const PerfServer = giznet.PerfServer.make(grt);
    const stream_bytes: u64 = 4096;

    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    var server = ServerTask(PerfServer){
        .conn = pair.b,
        .count = 4,
    };
    const server_thread = try grt.task.go("giznet/test/perf/stream/server", .{}, grt.task.Routine.init(&server, @TypeOf(server).run));

    var results: [4]giznet.PerfServer.Result = undefined;
    const count = try PerfClient.runAll(pair.a, .{
        .mode = .kcp_stream,
        .direction = .all,
        .stream_bytes = stream_bytes,
        .stream_chunk_size = 512,
        .timeout = 2 * glib.time.duration.Second,
    }, &results, .{});

    server_thread.join();
    if (server.err) |err| return err;
    try grt.std.testing.expectEqual(@as(usize, 4), count);

    for (results[0..count]) |result| {
        try grt.std.testing.expectEqual(giznet.PerfServer.Status.ok, result.status);
        switch (result.direction) {
            .ping => {
                try grt.std.testing.expectEqual(@as(u64, 1), result.client.sent_bytes);
                try grt.std.testing.expectEqual(@as(u64, 1), result.client.received_bytes);
                try grt.std.testing.expectEqual(@as(u64, 1), result.server.sent_bytes);
                try grt.std.testing.expectEqual(@as(u64, 1), result.server.received_bytes);
            },
            .up => {
                try grt.std.testing.expectEqual(stream_bytes, result.client.sent_bytes);
                try grt.std.testing.expectEqual(stream_bytes, result.server.received_bytes);
            },
            .down => {
                try grt.std.testing.expectEqual(stream_bytes, result.server.sent_bytes);
                try grt.std.testing.expectEqual(stream_bytes, result.client.received_bytes);
            },
            .duplex => {
                try grt.std.testing.expectEqual(stream_bytes, result.client.sent_bytes);
                try grt.std.testing.expectEqual(stream_bytes, result.client.received_bytes);
                try grt.std.testing.expectEqual(stream_bytes, result.server.sent_bytes);
                try grt.std.testing.expectEqual(stream_bytes, result.server.received_bytes);
            },
            .all => return error.TestUnexpectedResult,
        }
    }
}

fn ServerTask(comptime PerfServer: type) type {
    return struct {
        conn: giznet.Conn,
        count: usize,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            var served: usize = 0;
            while (served < task.count) : (served += 1) {
                _ = PerfServer.serveOnce(task.conn, .{}) catch |err| {
                    task.err = err;
                    return;
                };
            }
        }
    };
}
