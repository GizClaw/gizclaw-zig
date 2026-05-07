const glib = @import("glib");
const testing_api = glib.testing;

const giznet = @import("../../../giznet.zig");
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
            runStreamRoundtrip(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net stream_roundtrip failed: {}", .{err});
                return false;
            };
            runStreamSmallBufferRead(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net stream_small_buffer_read failed: {}", .{err});
                return false;
            };
            runStreamLargeBufferReadDrainsReadyData(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net stream_large_buffer_read_drains_ready_data failed: {}", .{err});
                return false;
            };
            runNetListenerAcceptsStream(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net net_listener_accepts_stream failed: {}", .{err});
                return false;
            };
            runStreamReadDeadlineWake(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net stream_read_deadline_wake failed: {}", .{err});
                return false;
            };
            runStreamReadDeadlinePayloadWins(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net stream_read_deadline_payload_wins failed: {}", .{err});
                return false;
            };
            runStreamReadDeadlineLatePayload(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net stream_read_deadline_late_payload failed: {}", .{err});
                return false;
            };
            runStreamReadDeadlineConcurrentUpdates(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net stream_read_deadline_concurrent_updates failed: {}", .{err});
                return false;
            };
            runStreamConcurrentWriteDeadlineReadyWrites(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/giz_net stream_concurrent_write_deadline_ready_writes failed: {}", .{err});
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

fn runStreamRoundtrip(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const service_id: u64 = 9;
    const payload = "hello over kcp stream";

    const writer = try pair.a.openStream(service_id);
    defer writer.deinit();

    const written = try writer.write(payload);
    try grt.std.testing.expectEqual(payload.len, written);

    const reader = try pair.b.accept(fixture.config.accept_timeout);
    defer reader.deinit();

    try grt.std.testing.expectEqual(service_id, reader.service);
    try grt.std.testing.expectEqual(writer.stream, reader.stream);

    var buf: [128]u8 = undefined;
    const read_n = try reader.read(&buf);
    try grt.std.testing.expectEqual(payload.len, read_n);
    try grt.std.testing.expectEqualSlices(u8, payload, buf[0..read_n]);
}

fn runStreamSmallBufferRead(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const service_id: u64 = 15;
    const payload = "stream-read-must-not-require-caller-buffer-to-fit-payload";

    const writer = try pair.a.openStream(service_id);
    defer writer.deinit();
    try writeAll(writer, payload);

    const reader = try pair.b.accept(fixture.config.accept_timeout);
    defer reader.deinit();
    try reader.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), fixture.config.accept_timeout));

    var received: [payload.len]u8 = undefined;
    var total: usize = 0;
    var small_buf: [5]u8 = undefined;
    while (total < payload.len) {
        const n = try reader.read(&small_buf);
        if (n == 0) return error.TestUnexpectedResult;
        if (total + n > received.len) return error.TestUnexpectedResult;
        @memcpy(received[total..][0..n], small_buf[0..n]);
        total += n;
    }

    try grt.std.testing.expectEqualSlices(u8, payload, received[0..total]);
}

fn runStreamLargeBufferReadDrainsReadyData(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const service_id: u64 = 16;
    const chunks = [_][]const u8{ "aa", "bbb", "cccc" };
    const expected = "aabbbcccc";

    const writer = try pair.a.openStream(service_id);
    defer writer.deinit();
    for (chunks) |chunk| try writeAll(writer, chunk);

    const reader = try pair.b.accept(fixture.config.accept_timeout);
    defer reader.deinit();
    try reader.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), fixture.config.accept_timeout));

    // Give the runtime a chance to deliver all already-written KCP payloads.
    // The read under test must not block for these extra chunks; it drains only
    // data that is ready via recvTimeout(0).
    grt.std.Thread.sleep(@intCast(50 * glib.time.duration.MilliSecond));

    var buf: [64]u8 = undefined;
    const n = try reader.read(&buf);
    try grt.std.testing.expectEqual(expected.len, n);
    try grt.std.testing.expectEqualSlices(u8, expected, buf[0..n]);
}

fn runNetListenerAcceptsStream(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    var listener_impl = giznet.Listener.make(grt).init(allocator, pair.b);
    defer listener_impl.deinit();
    const listener = listener_impl.listener();

    const service_id: u64 = 17;
    const payload = "listener-stream";
    const writer = try pair.a.openStream(service_id);
    defer writer.deinit();
    try writeAll(writer, payload);

    var net_conn = try listener.accept();
    defer net_conn.deinit();
    net_conn.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), fixture.config.accept_timeout));

    var buf: [64]u8 = undefined;
    const n = try net_conn.read(&buf);
    try grt.std.testing.expectEqualStrings(payload, buf[0..n]);
}

fn runStreamReadDeadlineWake(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const writer = try pair.a.openStream(10);
    defer writer.deinit();

    const seed = "ready";
    const seed_written = try writer.write(seed);
    try grt.std.testing.expectEqual(seed.len, seed_written);

    var reader = try pair.b.accept(fixture.config.accept_timeout);
    defer reader.deinit();

    var seed_buf: [16]u8 = undefined;
    const seed_read = try reader.read(&seed_buf);
    try grt.std.testing.expectEqual(seed.len, seed_read);
    try grt.std.testing.expectEqualSlices(u8, seed, seed_buf[0..seed_read]);

    const StartedChannel = grt.sync.Channel(void);
    var started = try StartedChannel.make(allocator, 1);
    defer started.deinit();

    const StreamType = @TypeOf(reader);
    const Task = struct {
        stream: StreamType,
        started: *StartedChannel,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            _ = task.started.send({}) catch {};
            var buf: [16]u8 = undefined;
            _ = task.stream.read(&buf) catch |err| {
                task.err = err;
                return;
            };
            task.err = error.ExpectedReadTimeout;
        }
    };

    var task: Task = .{
        .stream = reader,
        .started = &started,
    };
    var thread = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, Task.run, .{&task});

    const started_result = try started.recvTimeout(fixture.config.accept_timeout);
    try grt.std.testing.expect(started_result.ok);
    for (0..16) |_| grt.std.Thread.yield() catch {};

    try reader.setReadDeadline(grt.time.instant.now());
    thread.join();

    if (task.err) |err| {
        try grt.std.testing.expectEqual(error.Timeout, err);
    } else {
        return error.ExpectedReadTimeout;
    }
}

fn runStreamReadDeadlinePayloadWins(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const writer = try pair.a.openStream(11);
    defer writer.deinit();

    const seed = "ready";
    _ = try writer.write(seed);

    const reader = try pair.b.accept(fixture.config.accept_timeout);
    defer reader.deinit();

    var seed_buf: [16]u8 = undefined;
    const seed_read = try reader.read(&seed_buf);
    try grt.std.testing.expectEqualSlices(u8, seed, seed_buf[0..seed_read]);

    try reader.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), fixture.config.accept_timeout));

    const StartedChannel = grt.sync.Channel(void);
    var started = try StartedChannel.make(allocator, 1);
    defer started.deinit();

    const payload = "payload-before-deadline";
    const StreamType = @TypeOf(reader);
    const ReadTask = struct {
        stream: StreamType,
        started: *StartedChannel,
        buf: [64]u8 = undefined,
        len: usize = 0,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            _ = task.started.send({}) catch {};
            task.len = task.stream.read(&task.buf) catch |err| {
                task.err = err;
                return;
            };
        }
    };
    const WriteTask = struct {
        stream: StreamType,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            const written = task.stream.write(task.payload) catch |err| {
                task.err = err;
                return;
            };
            if (written != task.payload.len) task.err = error.ShortWrite;
        }
    };

    var read_task: ReadTask = .{ .stream = reader, .started = &started };
    var read_thread = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, ReadTask.run, .{&read_task});

    const started_result = try started.recvTimeout(fixture.config.accept_timeout);
    try grt.std.testing.expect(started_result.ok);

    var write_task: WriteTask = .{ .stream = writer, .payload = payload };
    var write_thread = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, WriteTask.run, .{&write_task});
    write_thread.join();
    read_thread.join();

    if (write_task.err) |err| return err;
    if (read_task.err) |err| return err;
    try grt.std.testing.expectEqual(payload.len, read_task.len);
    try grt.std.testing.expectEqualSlices(u8, payload, read_task.buf[0..read_task.len]);
}

fn runStreamReadDeadlineLatePayload(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const writer = try pair.a.openStream(12);
    defer writer.deinit();

    const seed = "ready";
    _ = try writer.write(seed);

    const reader = try pair.b.accept(fixture.config.accept_timeout);
    defer reader.deinit();

    var seed_buf: [16]u8 = undefined;
    const seed_read = try reader.read(&seed_buf);
    try grt.std.testing.expectEqualSlices(u8, seed, seed_buf[0..seed_read]);

    const StartedChannel = grt.sync.Channel(void);
    var started = try StartedChannel.make(allocator, 1);
    defer started.deinit();

    const StreamType = @TypeOf(reader);
    const ReadTask = struct {
        stream: StreamType,
        started: *StartedChannel,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            _ = task.started.send({}) catch {};
            var buf: [16]u8 = undefined;
            _ = task.stream.read(&buf) catch |err| {
                task.err = err;
                return;
            };
            task.err = error.ExpectedReadTimeout;
        }
    };

    var read_task: ReadTask = .{ .stream = reader, .started = &started };
    var read_thread = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, ReadTask.run, .{&read_task});

    const started_result = try started.recvTimeout(fixture.config.accept_timeout);
    try grt.std.testing.expect(started_result.ok);
    for (0..16) |_| grt.std.Thread.yield() catch {};

    try reader.setReadDeadline(grt.time.instant.now());
    read_thread.join();
    if (read_task.err) |err| {
        try grt.std.testing.expectEqual(error.Timeout, err);
    } else {
        return error.ExpectedReadTimeout;
    }

    const late_payload = "late";
    const written = try writer.write(late_payload);
    try grt.std.testing.expectEqual(late_payload.len, written);

    try reader.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), fixture.config.accept_timeout));
    var buf: [16]u8 = undefined;
    const read_n = try reader.read(&buf);
    try grt.std.testing.expectEqual(late_payload.len, read_n);
    try grt.std.testing.expectEqualSlices(u8, late_payload, buf[0..read_n]);
}

fn runStreamReadDeadlineConcurrentUpdates(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const writer = try pair.a.openStream(13);
    defer writer.deinit();

    const seed = "ready";
    _ = try writer.write(seed);

    const reader = try pair.b.accept(fixture.config.accept_timeout);
    defer reader.deinit();

    var seed_buf: [16]u8 = undefined;
    const seed_read = try reader.read(&seed_buf);
    try grt.std.testing.expectEqualSlices(u8, seed, seed_buf[0..seed_read]);

    const StartedChannel = grt.sync.Channel(void);
    var started = try StartedChannel.make(allocator, 1);
    defer started.deinit();

    const StreamType = @TypeOf(reader);
    const ReadTask = struct {
        stream: StreamType,
        started: *StartedChannel,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            _ = task.started.send({}) catch {};
            var buf: [16]u8 = undefined;
            _ = task.stream.read(&buf) catch |err| {
                task.err = err;
                return;
            };
            task.err = error.ExpectedReadTimeout;
        }
    };
    const DeadlineTask = struct {
        stream: StreamType,
        timeout: glib.time.duration.Duration,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            for (0..4) |_| {
                task.stream.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), task.timeout)) catch |err| {
                    task.err = err;
                    return;
                };
                grt.std.Thread.yield() catch {};
            }
            task.stream.setReadDeadline(grt.time.instant.now()) catch |err| {
                task.err = err;
            };
        }
    };

    var read_task: ReadTask = .{ .stream = reader, .started = &started };
    var read_thread = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, ReadTask.run, .{&read_task});

    const started_result = try started.recvTimeout(fixture.config.accept_timeout);
    try grt.std.testing.expect(started_result.ok);

    var deadline_task: DeadlineTask = .{ .stream = reader, .timeout = fixture.config.accept_timeout };
    var deadline_thread = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, DeadlineTask.run, .{&deadline_task});
    deadline_thread.join();
    read_thread.join();

    if (deadline_task.err) |err| return err;
    if (read_task.err) |err| {
        try grt.std.testing.expectEqual(error.Timeout, err);
    } else {
        return error.ExpectedReadTimeout;
    }
}

fn runStreamConcurrentWriteDeadlineReadyWrites(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const writer = try pair.a.openStream(14);
    defer writer.deinit();

    const payloads = [_][]const u8{ "a", "bb", "ccc" };
    const StreamType = @TypeOf(writer);
    const WriteTask = struct {
        stream: StreamType,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            task.stream.setWriteDeadline(grt.time.instant.now()) catch |err| {
                task.err = err;
                return;
            };
            const written = task.stream.write(task.payload) catch |err| {
                task.err = err;
                return;
            };
            if (written != task.payload.len) task.err = error.ShortWrite;
        }
    };

    var tasks: [payloads.len]WriteTask = undefined;
    var threads: [payloads.len]grt.std.Thread = undefined;
    for (payloads, 0..) |payload, idx| {
        tasks[idx] = .{ .stream = writer, .payload = payload };
        threads[idx] = try grt.std.Thread.spawn(fixture.config.transfer_spawn_config, WriteTask.run, .{&tasks[idx]});
    }

    const reader = try pair.b.accept(fixture.config.accept_timeout);
    defer reader.deinit();
    try reader.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), fixture.config.accept_timeout));

    for (0..payloads.len) |idx| {
        threads[idx].join();
        if (tasks[idx].err) |err| return err;
    }

    var expected_total: usize = 0;
    for (payloads) |payload| expected_total += payload.len;

    var actual_counts = [_]usize{0} ** 256;
    var received: usize = 0;
    var buf: [32]u8 = undefined;
    while (received < expected_total) {
        const read_n = try reader.read(&buf);
        received += read_n;
        for (buf[0..read_n]) |byte| actual_counts[byte] += 1;
    }
    try grt.std.testing.expectEqual(expected_total, received);
    try grt.std.testing.expectEqual(@as(usize, 1), actual_counts['a']);
    try grt.std.testing.expectEqual(@as(usize, 2), actual_counts['b']);
    try grt.std.testing.expectEqual(@as(usize, 3), actual_counts['c']);
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

fn writeAll(stream: anytype, payload: []const u8) !void {
    var offset: usize = 0;
    while (offset < payload.len) {
        const written = try stream.write(payload[offset..]);
        if (written == 0) return error.ShortWrite;
        offset += written;
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
