const glib = @import("glib");
const testing_api = glib.testing;

const test_utils = @import("../test_utils/giz_net.zig");

const transfer_bytes: usize = 10 * 1024 * 1024;
const transfer_packet_channel_capacity: usize =
    (transfer_bytes + test_utils.transfer_chunk_bytes - 1) / test_utils.transfer_chunk_bytes + 64;
const multi_pair_count: usize = 3;

pub fn make(comptime grt: type) testing_api.TestRunner {
    const PairFixture = test_utils.DefaultFixture(grt, &[_]u32{ 3001, 3002 });
    const MultiFixture = test_utils.DefaultFixture(grt, &[_]u32{ 3101, 3102, 3103, 3104, 3105, 3106 });

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;

            runDirectRoundtrip(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net direct_roundtrip failed: {}", .{err});
                return false;
            };
            runBidirectionalConcurrentTransfer(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net bidirectional_concurrent_transfer failed: {}", .{err});
                return false;
            };
            runMultiPairConcurrentTransfer(grt, MultiFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net multi_pair_concurrent_transfer failed: {}", .{err});
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

fn runDirectRoundtrip(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    try fixture.testCorrectness(pair.forward(0x31), 13);
    try fixture.testCorrectness(pair.backward(0x32), 17);
}

fn runBidirectionalConcurrentTransfer(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{
        .service = .{ .peer = .{ .packet_channel_capacity = transfer_packet_channel_capacity } },
        .transfer_yield_every = 1,
    });
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const Task = struct {
        fixture: *Fixture,
        rw: test_utils.ReadWriter,
        err: ?anyerror = null,
        rate: test_utils.Rate = .{
            .bytes = 0,
            .elapsed_ns = 0,
            .bytes_per_second = 0,
            .mbps = 0,
        },

        fn run(task: *@This()) void {
            task.rate = task.fixture.measureTransferSeqChecked(task.rw, transfer_bytes) catch |err| {
                task.err = err;
                return;
            };
        }
    };

    var forward: Task = .{
        .fixture = &fixture,
        .rw = pair.forward(0x41),
    };
    var backward: Task = .{
        .fixture = &fixture,
        .rw = pair.backward(0x42),
    };

    var forward_thread = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, Task.run, .{&forward});
    var backward_thread = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, Task.run, .{&backward});
    forward_thread.join();
    backward_thread.join();

    if (forward.err) |err| return err;
    if (backward.err) |err| return err;
    try expectRate(grt, forward.rate, transfer_bytes);
    try expectRate(grt, backward.rate, transfer_bytes);
}

fn runMultiPairConcurrentTransfer(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{
        .service = .{ .peer = .{ .packet_channel_capacity = transfer_packet_channel_capacity } },
        .transfer_yield_every = 1,
    });
    defer fixture.deinit();

    var pairs: [multi_pair_count]Fixture.ConnPair = undefined;
    var pair_count: usize = 0;
    errdefer {
        while (pair_count > 0) {
            pair_count -= 1;
            pairs[pair_count].deinit();
        }
    }

    for (0..multi_pair_count) |idx| {
        pairs[idx] = try fixture.connect(idx * 2, idx * 2 + 1);
        pair_count += 1;
    }
    defer {
        while (pair_count > 0) {
            pair_count -= 1;
            pairs[pair_count].deinit();
        }
    }

    const Task = struct {
        fixture: *Fixture,
        rw: test_utils.ReadWriter,
        err: ?anyerror = null,
        rate: test_utils.Rate = .{
            .bytes = 0,
            .elapsed_ns = 0,
            .bytes_per_second = 0,
            .mbps = 0,
        },

        fn run(task: *@This()) void {
            task.rate = task.fixture.measureTransferSeqChecked(task.rw, transfer_bytes) catch |err| {
                task.err = err;
                return;
            };
        }
    };

    var tasks: [multi_pair_count]Task = undefined;
    var threads: [multi_pair_count]grt.std.Thread = undefined;
    for (0..multi_pair_count) |idx| {
        tasks[idx] = .{
            .fixture = &fixture,
            .rw = pairs[idx].forward(@intCast(0x50 + idx)),
        };
        threads[idx] = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, Task.run, .{&tasks[idx]});
    }

    for (0..multi_pair_count) |idx| {
        threads[idx].join();
    }
    for (0..multi_pair_count) |idx| {
        if (tasks[idx].err) |err| return err;
        try expectRate(grt, tasks[idx].rate, transfer_bytes);
    }
}

fn expectRate(comptime grt: type, rate: test_utils.Rate, expected_bytes: usize) !void {
    if (rate.sent_bytes != expected_bytes or
        rate.received_bytes != expected_bytes or
        rate.missing_packets != 0 or
        rate.duplicate_packets != 0 or
        rate.total_mismatches != 0)
    {
        grt.std.debug.print(
            "giznet integration transfer failed: expected_bytes={d} sent_bytes={d} received_bytes={d} expected_packets={d} received_packets={d} missing_packets={d} duplicate_packets={d} mismatches={d}\n",
            .{
                expected_bytes,
                rate.sent_bytes,
                rate.received_bytes,
                rate.expected_packets,
                rate.received_packets,
                rate.missing_packets,
                rate.duplicate_packets,
                rate.total_mismatches,
            },
        );
    }
    try grt.std.testing.expectEqual(expected_bytes, rate.sent_bytes);
    try grt.std.testing.expectEqual(expected_bytes, rate.received_bytes);
    try grt.std.testing.expectEqual(@as(u64, 0), rate.missing_packets);
    try grt.std.testing.expectEqual(@as(u64, 0), rate.duplicate_packets);
    try grt.std.testing.expectEqual(@as(u64, 0), rate.total_mismatches);
}
