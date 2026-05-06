const glib = @import("glib");
const testing_api = glib.testing;

const bench = @import("../test_utils/common.zig");
const rate_utils = @import("../../test_utils/rate.zig");
const NoiseCipher = @import("../../../noise/Cipher.zig");
const Session = @import("../../../noise/Session.zig");
const test_utils = @import("../../test_utils/giz_net.zig");

const total_transfer_bytes: usize = 100 * 1024 * 1024;

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;

            runCase(grt, allocator, .chacha_poly) catch |err| {
                t.logErrorf("benchmark/giz_net/packet chacha_poly concurrent_transfer failed: {}", .{err});
                return false;
            };
            runCase(grt, allocator, .aes_256_gcm) catch |err| {
                t.logErrorf("benchmark/giz_net/packet aes_256_gcm concurrent_transfer failed: {}", .{err});
                return false;
            };
            runCase(grt, allocator, .plaintext) catch |err| {
                t.logErrorf("benchmark/giz_net/packet plaintext concurrent_transfer failed: {}", .{err});
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
    try runCaseConnCount(grt, allocator, cipher_kind, 4);
    try runCaseConnCount(grt, allocator, cipher_kind, 8);
}

fn runCaseConnCount(
    comptime grt: type,
    allocator: grt.std.mem.Allocator,
    comptime cipher_kind: NoiseCipher.Kind,
    comptime pair_count: usize,
) !void {
    const Fixture = test_utils.Fixture(
        grt,
        Session.legacy_packet_size_capacity,
        cipher_kind,
        fixtureSeeds(pair_count),
    );

    try runConcurrentUdpTransfer(grt, Fixture, allocator, cipher_kind, pair_count, .{
        .warmup = 0,
        .iterations = 1,
    });
}

fn runConcurrentUdpTransfer(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
    comptime cipher_kind: NoiseCipher.Kind,
    comptime pair_count: usize,
    config: bench.Config,
) !void {
    const stream_count = pair_count * 2;
    const stream_transfer_bytes = total_transfer_bytes / stream_count;
    const transfer_packet_channel_capacity =
        (stream_transfer_bytes + test_utils.transfer_chunk_bytes - 1) / test_utils.transfer_chunk_bytes + 64;

    var fixture = try Fixture.init(allocator, .{
        .channel_capacity = transfer_packet_channel_capacity * 2,
        .service = .{ .peer = .{ .packet_channel_capacity = transfer_packet_channel_capacity } },
        .transfer_yield_every = 16,
    });
    defer fixture.deinit();

    var pairs: [pair_count]Fixture.ConnPair = undefined;
    var initialized_pairs: usize = 0;
    errdefer {
        while (initialized_pairs > 0) {
            initialized_pairs -= 1;
            pairs[initialized_pairs].deinit();
        }
    }

    for (0..pair_count) |idx| {
        pairs[idx] = try fixture.connect(idx * 2, idx * 2 + 1);
        initialized_pairs += 1;
    }
    defer {
        while (initialized_pairs > 0) {
            initialized_pairs -= 1;
            pairs[initialized_pairs].deinit();
        }
    }

    const State = struct {
        fixture: *Fixture,
        pairs: *[pair_count]Fixture.ConnPair,
        checksum: u64 = 0,
        sent_bytes: usize = 0,
        received_bytes: usize = 0,
        expected_packets: u64 = 0,
        received_packets: u64 = 0,
        missing_packets: u64 = 0,
        duplicate_packets: u64 = 0,
        total_mismatches: u64 = 0,

        fn runRound(self: *@This()) !void {
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
                    task.rate = task.fixture.measureTransferSeqObserved(
                        task.rw,
                        stream_transfer_bytes,
                        100 * glib.time.duration.MilliSecond,
                    ) catch |err| {
                        task.err = err;
                        return;
                    };
                }
            };

            var tasks: [stream_count]Task = undefined;
            var threads: [stream_count]grt.std.Thread = undefined;
            for (0..pair_count) |idx| {
                const forward_idx = idx * 2;
                const backward_idx = forward_idx + 1;
                tasks[forward_idx] = .{
                    .fixture = self.fixture,
                    .rw = self.pairs[idx].forward(protocolFor(cipher_kind, @intCast(forward_idx))),
                };
                tasks[backward_idx] = .{
                    .fixture = self.fixture,
                    .rw = self.pairs[idx].backward(protocolFor(cipher_kind, @intCast(backward_idx))),
                };
            }

            for (0..stream_count) |idx| {
                threads[idx] = try grt.std.Thread.spawn(self.fixture.config.transfer_spawn_config, Task.run, .{&tasks[idx]});
            }
            for (0..stream_count) |idx| {
                threads[idx].join();
            }

            var round_sent: usize = 0;
            var round_received: usize = 0;
            var round_expected_packets: u64 = 0;
            var round_received_packets: u64 = 0;
            var round_missing: u64 = 0;
            var round_duplicates: u64 = 0;
            var round_mismatches: u64 = 0;
            var round_checksum: u64 = 0;
            for (0..stream_count) |idx| {
                if (tasks[idx].err) |err| return err;
                round_sent += tasks[idx].rate.sent_bytes;
                round_received += tasks[idx].rate.received_bytes;
                round_expected_packets += tasks[idx].rate.expected_packets;
                round_received_packets += tasks[idx].rate.received_packets;
                round_missing += tasks[idx].rate.missing_packets;
                round_duplicates += tasks[idx].rate.duplicate_packets;
                round_mismatches += tasks[idx].rate.total_mismatches;
                round_checksum +%= tasks[idx].rate.bytes_per_second + tasks[idx].rate.mbps;
            }

            self.checksum +%= round_checksum;
            self.sent_bytes +%= round_sent;
            self.received_bytes +%= round_received;
            self.expected_packets +%= round_expected_packets;
            self.received_packets +%= round_received_packets;
            self.missing_packets +%= round_missing;
            self.duplicate_packets +%= round_duplicates;
            self.total_mismatches +%= round_mismatches;
        }
    };

    var state = State{
        .fixture = &fixture,
        .pairs = &pairs,
    };
    const elapsed_ns = try bench.runLoop(grt, config, &state, State.runRound);

    grt.std.mem.doNotOptimizeAway(state.checksum);

    const label = benchmarkLabel(cipher_kind, pair_count);
    const payload_bytes_per_op = if (config.iterations == 0) 0 else @divTrunc(state.received_bytes, config.iterations);
    bench.print(grt, label, config, elapsed_ns, .{
        .tier = .regular,
        .payload_bytes_per_op = payload_bytes_per_op,
        .copy_bytes_per_op = total_transfer_bytes,
        .extra_name = "connections",
        .extra_value = pair_count,
    });
    const loss_percent_milli: u64 = if (state.expected_packets == 0)
        0
    else
        @divTrunc(
            rate_utils.addSaturatingU64(
                rate_utils.mulSaturatingU64(state.missing_packets, 100_000),
                state.expected_packets / 2,
            ),
            state.expected_packets,
        );
    const loss_percent_whole = @divTrunc(loss_percent_milli, 1000);
    const loss_percent_frac = loss_percent_milli % 1000;
    grt.std.debug.print(
        "bench label={s}.observed connections={d} streams={d} sent_bytes={d} received_bytes={d} expected_packets={d} received_packets={d} missing_packets={d} duplicate_packets={d} mismatches={d} loss_percent={d}.{d:0>3}\n",
        .{
            label,
            pair_count,
            stream_count,
            state.sent_bytes,
            state.received_bytes,
            state.expected_packets,
            state.received_packets,
            state.missing_packets,
            state.duplicate_packets,
            state.total_mismatches,
            loss_percent_whole,
            loss_percent_frac,
        },
    );
}

fn fixtureSeeds(comptime pair_count: usize) []const u32 {
    return &struct {
        const values = blk: {
            var seeds: [pair_count * 2]u32 = undefined;
            for (0..seeds.len) |idx| {
                seeds[idx] = 3301 + @as(u32, @intCast(idx));
            }
            break :blk seeds;
        };
    }.values;
}

fn benchmarkLabel(comptime cipher_kind: NoiseCipher.Kind, comptime pair_count: usize) []const u8 {
    return switch (pair_count) {
        4 => switch (cipher_kind) {
            .chacha_poly => "giznet.giz_net.packet.real_udp.chacha_poly.4_conn",
            .aes_256_gcm => "giznet.giz_net.packet.real_udp.aes_256_gcm.4_conn",
            .plaintext => "giznet.giz_net.packet.real_udp.plaintext.4_conn",
        },
        8 => switch (cipher_kind) {
            .chacha_poly => "giznet.giz_net.packet.real_udp.chacha_poly.8_conn",
            .aes_256_gcm => "giznet.giz_net.packet.real_udp.aes_256_gcm.8_conn",
            .plaintext => "giznet.giz_net.packet.real_udp.plaintext.8_conn",
        },
        else => @compileError("unsupported benchmark connection count"),
    };
}

fn protocolFor(comptime cipher_kind: NoiseCipher.Kind, stream_idx: u8) u8 {
    return switch (cipher_kind) {
        .chacha_poly => 0x61,
        .aes_256_gcm => 0x71,
        .plaintext => 0x81,
    } + stream_idx;
}
