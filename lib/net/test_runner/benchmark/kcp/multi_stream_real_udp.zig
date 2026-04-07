const dep = @import("dep");
const testing_api = dep.testing;

const bench = @import("../common.zig");
const RealUdpFixtureFile = @import("../../integration/core/real_udp_fixture.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Fixture = RealUdpFixtureFile.make(lib);

    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            runCase(lib, Fixture, allocator, 4, bench.no_impairment, .{
                .warmup = 1,
                .iterations = 4,
            }) catch |err| {
                t.logErrorf("benchmark/kcp/multi_stream_real_udp 4-stream failed: {}", .{err});
                return false;
            };
            runCase(lib, Fixture, allocator, 16, bench.no_impairment, .{
                .warmup = 1,
                .iterations = 4,
            }) catch |err| {
                t.logErrorf("benchmark/kcp/multi_stream_real_udp 16-stream failed: {}", .{err});
                return false;
            };
            runCase(lib, Fixture, allocator, 64, bench.no_impairment, .{
                .warmup = 1,
                .iterations = 2,
            }) catch |err| {
                t.logErrorf("benchmark/kcp/multi_stream_real_udp 64-stream failed: {}", .{err});
                return false;
            };
            runCase(lib, Fixture, allocator, 64, bench.low_loss, .{
                .warmup = 1,
                .iterations = 3,
            }) catch |err| {
                t.logErrorf("benchmark/kcp/multi_stream_real_udp low_loss failed: {}", .{err});
                return false;
            };
            runCase(lib, Fixture, allocator, 16, bench.reorder_only, .{
                .warmup = 1,
                .iterations = 4,
            }) catch |err| {
                t.logErrorf("benchmark/kcp/multi_stream_real_udp reorder failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runCase(
    comptime lib: type,
    comptime Fixture: type,
    allocator: dep.embed.mem.Allocator,
    comptime stream_count: usize,
    impairment: bench.ImpairmentProfile,
    config: bench.Config,
) !void {
    const payload_len: usize = 512;
    const payload: [payload_len]u8 = [_]u8{0x63} ** payload_len;
    const max_rounds: usize = 2048;

    var fixture = try Fixture.init(allocator, .{
        .enable_kcp = true,
        .client_impairment = impairment,
        .kcp_accept_backlog = stream_count,
        .kcp_max_active_streams = stream_count,
    });
    defer fixture.deinit();

    try fixture.establish();

    const client_mux = fixture.client_udp.serviceMux(fixture.server_static.public) orelse return error.TestUnexpectedResult;

    var opened_ids: [stream_count]u64 = undefined;
    var accepted_ids: [stream_count]u64 = undefined;

    var index: usize = 0;
    while (index < stream_count) : (index += 1) {
        opened_ids[index] = try client_mux.openStream(Fixture.service_id);
    }

    index = 0;
    while (index < stream_count) : (index += 1) {
        const accepted = fixture.waitForAcceptedServerStream(max_rounds) catch |err| switch (err) {
            error.TimedOut => return error.AcceptTimedOut,
            else => return err,
        };
        if (!containsStreamId(&opened_ids, accepted)) return error.TestUnexpectedResult;
        accepted_ids[index] = accepted;
    }

    const State = struct {
        fixture: *Fixture,
        opened_ids: [stream_count]u64,
        accepted_ids: [stream_count]u64,
        payload: []const u8,
        buffers: [stream_count][payload_len]u8 = [_][payload_len]u8{[_]u8{0} ** payload_len} ** stream_count,
        sink: usize = 0,
    };

    var state = State{
        .fixture = &fixture,
        .opened_ids = opened_ids,
        .accepted_ids = accepted_ids,
        .payload = &payload,
    };

    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            var stream_index: usize = 0;
            while (stream_index < stream_count) : (stream_index += 1) {
                _ = try value.fixture.client_udp.sendStreamData(
                    value.fixture.server_static.public,
                    Fixture.service_id,
                    value.opened_ids[stream_index],
                    value.payload,
                );
            }
            try value.fixture.flushClientWrites();

            stream_index = 0;
            while (stream_index < stream_count) : (stream_index += 1) {
                const read_n = value.fixture.waitForServerStreamData(
                    value.accepted_ids[stream_index],
                    &value.buffers[stream_index],
                    max_rounds,
                ) catch |err| switch (err) {
                    error.TimedOut => return error.ServerReadTimedOut,
                    else => return err,
                };
                if (read_n != value.payload.len) return error.TestUnexpectedResult;
                if (!dep.embed.mem.eql(u8, value.payload, value.buffers[stream_index][0..read_n])) {
                    return error.TestUnexpectedResult;
                }
                value.sink +%= read_n;
            }
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    for (opened_ids) |stream_id| {
        try fixture.client_udp.closeStream(fixture.server_static.public, Fixture.service_id, stream_id);
    }
    if (fixture.client_udp.serviceMux(fixture.server_static.public)) |mux| {
        try mux.closeService(Fixture.service_id);
    }
    if (fixture.server_udp.serviceMux(fixture.client_static.public)) |mux| {
        try mux.closeService(Fixture.service_id);
    }
    try fixture.flushClientWrites();
    try driveIgnoreServiceRejected(&fixture, 128);

    bench.print(lib, "kcp.real_udp.multi_stream_transfer_rate", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = impairment,
        .payload_bytes_per_op = payload_len * stream_count,
        .copy_bytes_per_op = payload_len * stream_count,
        .extra_name = "streams",
        .extra_value = stream_count,
    });
}

fn containsStreamId(ids: anytype, target: u64) bool {
    for (ids.*) |value| {
        if (value == target) return true;
    }
    return false;
}

fn driveIgnoreServiceRejected(fixture: anytype, rounds: usize) !void {
    var round: usize = 0;
    while (round < rounds) : (round += 1) {
        fixture.drive(1) catch |err| switch (err) {
            error.ServiceRejected => continue,
            else => return err,
        };
    }
}
