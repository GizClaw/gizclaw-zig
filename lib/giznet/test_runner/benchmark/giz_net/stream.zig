const glib = @import("glib");
const testing_api = glib.testing;

const bench = @import("../test_utils/common.zig");
const NoiseCipher = @import("../../../noise/Cipher.zig");
const Session = @import("../../../noise/Session.zig");
const test_utils = @import("../../test_utils/giz_net.zig");

const write_chunk_bytes: usize = 900;
const transfer_chunks: usize = (100 * 1024 * 1024 + write_chunk_bytes - 1) / write_chunk_bytes;
const transfer_bytes: usize = transfer_chunks * write_chunk_bytes;
const read_buffer_bytes: usize = write_chunk_bytes;
const runtime_channel_capacity: usize = 64;
const stream_channel_capacity: usize = 4096;
const stream_idle_timeout: glib.time.duration.Duration = 2 * glib.time.duration.Second;

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            t.timeout(180 * glib.time.duration.Second);

            runCase(grt, allocator, .plaintext) catch |err| {
                t.logErrorf("benchmark/giz_net/stream plaintext failed: {}", .{err});
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

fn runCase(
    comptime grt: type,
    allocator: grt.std.mem.Allocator,
    comptime cipher_kind: NoiseCipher.Kind,
) !void {
    const Fixture = test_utils.Fixture(
        grt,
        Session.legacy_packet_size_capacity,
        cipher_kind,
        &[_]u32{ 3601, 3602 },
    );
    var fixture = try Fixture.init(allocator, .{
        .channel_capacity = runtime_channel_capacity,
        .service = .{
            .kcp_stream = .{ .stream = .{
                .channel_capacity = stream_channel_capacity,
                .kcp_nodelay = 1,
                .kcp_interval = 10,
                .kcp_resend = 2,
                .kcp_no_congestion_control = 0,
                .kcp_send_window = 1024,
                .kcp_recv_window = 1024,
            } },
        },
        .transfer_yield_every = 1,
    });
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const writer = try pair.a.openStream(serviceId(cipher_kind));
    defer writer.deinit();

    const seed = "giz-net-kcp-stream-ready";
    if (try writer.write(seed) != seed.len) return error.ShortWrite;

    const reader = try pair.b.accept(fixture.config.accept_timeout);
    defer reader.deinit();
    try grt.std.testing.expectEqual(serviceId(cipher_kind), reader.service);
    try grt.std.testing.expectEqual(writer.stream, reader.stream);
    try reader.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), fixture.config.accept_timeout));
    var seed_buf: [64]u8 = undefined;
    const seed_read = try reader.read(&seed_buf);
    try grt.std.testing.expectEqual(seed.len, seed_read);
    try grt.std.testing.expectEqualSlices(u8, seed, seed_buf[0..seed_read]);

    const StreamType = @TypeOf(writer);
    const State = struct {
        writer: StreamType,
        reader: StreamType,
        sent_bytes: usize = 0,
        received_bytes: usize = 0,
        checksum: u64 = 0,

        fn runRound(self: *@This()) !void {
            const WriterTask = struct {
                stream: StreamType,
                sent_bytes: usize = 0,
                checksum: u64 = 0,
                err: ?anyerror = null,

                fn run(task: *@This()) void {
                    var buf: [write_chunk_bytes]u8 = undefined;
                    var offset: usize = 0;
                    while (offset < transfer_bytes) {
                        const chunk_len = @min(write_chunk_bytes, transfer_bytes - offset);
                        fillPattern(buf[0..chunk_len], offset);
                        task.stream.setWriteDeadline(glib.time.instant.add(grt.time.instant.now(), stream_idle_timeout)) catch |err| {
                            task.err = err;
                            return;
                        };
                        const written = task.stream.write(buf[0..chunk_len]) catch |err| {
                            if (err != error.Timeout) task.err = err;
                            return;
                        };
                        if (written != chunk_len) {
                            task.err = error.ShortWrite;
                            return;
                        }
                        task.sent_bytes += written;
                        task.checksum +%= buf[written - 1];
                        offset += written;
                    }
                }
            };
            const ReaderTask = struct {
                stream: StreamType,
                received_bytes: usize = 0,
                checksum: u64 = 0,
                err: ?anyerror = null,

                fn run(task: *@This()) void {
                    var buf: [read_buffer_bytes]u8 = undefined;
                    while (true) {
                        if (task.received_bytes >= transfer_bytes) return;
                        task.stream.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), stream_idle_timeout)) catch |err| {
                            task.err = err;
                            return;
                        };
                        const read_n = task.stream.read(&buf) catch |err| switch (err) {
                            error.Timeout => {
                                return;
                            },
                            else => {
                                task.err = err;
                                return;
                            },
                        };
                        if (read_n == 0 or task.received_bytes + read_n > transfer_bytes) {
                            task.err = error.ShortRead;
                            return;
                        }
                        if (!checkPattern(buf[0..read_n], task.received_bytes)) {
                            task.err = error.PayloadMismatch;
                            return;
                        }
                        task.received_bytes += read_n;
                        task.checksum +%= buf[read_n - 1];
                    }
                }
            };

            var writer_task: WriterTask = .{
                .stream = self.writer,
            };
            var reader_task: ReaderTask = .{
                .stream = self.reader,
            };

            const start_ns = grt.time.instant.now();
            var reader_thread = try grt.std.Thread.spawn(.{}, ReaderTask.run, .{&reader_task});
            var writer_thread = try grt.std.Thread.spawn(.{}, WriterTask.run, .{&writer_task});
            writer_thread.join();
            reader_thread.join();
            const end_ns = grt.time.instant.now();

            self.sent_bytes +%= writer_task.sent_bytes;
            self.received_bytes +%= reader_task.received_bytes;
            self.checksum +%= writer_task.checksum +% reader_task.checksum;

            if (writer_task.err) |err| return err;
            if (reader_task.err) |err| return err;

            self.checksum +%= @as(u64, @intCast(glib.time.instant.sub(end_ns, start_ns)));
        }
    };

    var state = State{
        .writer = writer,
        .reader = reader,
    };
    const config = bench.Config{ .warmup = 0, .iterations = 1 };
    const elapsed_ns = bench.runLoop(grt, config, &state, State.runRound) catch |err| {
        grt.std.debug.print(
            "bench label={s}.failed_progress sent_bytes={d} received_bytes={d} checksum={d} err={}\n",
            .{ labelFor(cipher_kind), state.sent_bytes, state.received_bytes, state.checksum, err },
        );
        return err;
    };

    grt.std.mem.doNotOptimizeAway(state.checksum);

    const label = labelFor(cipher_kind);
    bench.print(grt, label, config, elapsed_ns, .{
        .tier = .regular,
        .payload_bytes_per_op = state.received_bytes,
        .copy_bytes_per_op = state.sent_bytes,
        .extra_name = "chunks",
        .extra_value = transfer_chunks,
    });
    grt.std.debug.print(
        "bench label={s}.observed sent_bytes={d} received_bytes={d} checksum={d}\n",
        .{ label, state.sent_bytes, state.received_bytes, state.checksum },
    );
}

fn serviceId(comptime cipher_kind: NoiseCipher.Kind) u64 {
    return switch (cipher_kind) {
        .chacha_poly => 0x2001,
        .aes_256_gcm => 0x2002,
        .plaintext => 0x2003,
    };
}

fn labelFor(comptime cipher_kind: NoiseCipher.Kind) []const u8 {
    return switch (cipher_kind) {
        .chacha_poly => "giznet.giz_net.stream.real_udp.chacha_poly",
        .aes_256_gcm => "giznet.giz_net.stream.real_udp.aes_256_gcm",
        .plaintext => "giznet.giz_net.stream.real_udp.plaintext",
    };
}

fn fillPattern(buf: []u8, offset: usize) void {
    for (buf, 0..) |*byte, index| {
        byte.* = @truncate((offset + index) *% 131 +% 17);
    }
}

fn checkPattern(buf: []const u8, offset: usize) bool {
    for (buf, 0..) |byte, index| {
        if (byte != @as(u8, @truncate((offset + index) *% 131 +% 17))) return false;
    }
    return true;
}
