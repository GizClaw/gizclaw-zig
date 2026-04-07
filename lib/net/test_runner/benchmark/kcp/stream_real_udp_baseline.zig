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

            var fixture = Fixture.init(allocator, .{
                .enable_kcp = true,
            }) catch |err| {
                t.logErrorf("benchmark/kcp/stream_real_udp_baseline setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runBaselineCase(lib, Fixture, &fixture) catch |err| {
                t.logErrorf("benchmark/kcp/stream_real_udp_baseline failed: {}", .{err});
                return false;
            };
            runTransferRateCase(lib, Fixture, &fixture) catch |err| {
                t.logErrorf("benchmark/kcp/stream_real_udp_transfer_rate failed: {}", .{err});
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

fn runBaselineCase(comptime lib: type, comptime Fixture: type, fixture: anytype) !void {
    const payload_len: usize = 256;
    const payload: [payload_len]u8 = [_]u8{0x37} ** payload_len;
    const config: bench.Config = .{
        .warmup = 2,
        .iterations = 8,
    };

    try fixture.establish();

    const client_mux = fixture.client_udp.serviceMux(fixture.server_static.public) orelse return error.TestUnexpectedResult;
    const opened = try client_mux.openStream(Fixture.service_id);
    const accepted = fixture.waitForAcceptedServerStream(512) catch |err| switch (err) {
        error.TimedOut => return error.AcceptTimedOut,
        else => return err,
    };
    if (opened != accepted) return error.TestUnexpectedResult;

    const State = struct {
        fixture: @TypeOf(fixture),
        stream_id: u64,
        payload: []const u8,
        buffer: [payload_len]u8 = undefined,
        sink: usize = 0,
    };

    var state = State{
        .fixture = fixture,
        .stream_id = accepted,
        .payload = &payload,
    };

    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            _ = try value.fixture.client_udp.sendStreamData(
                value.fixture.server_static.public,
                Fixture.service_id,
                value.stream_id,
                value.payload,
            );
            const read_n = value.fixture.waitForServerStreamData(value.stream_id, &value.buffer, 512) catch |err| switch (err) {
                error.TimedOut => return error.ServerReadTimedOut,
                else => return err,
            };
            if (read_n != value.payload.len) return error.TestUnexpectedResult;
            if (!dep.embed.mem.eql(u8, value.payload, value.buffer[0..read_n])) return error.TestUnexpectedResult;
            value.sink +%= read_n;
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    try fixture.client_udp.closeStream(fixture.server_static.public, Fixture.service_id, opened);
    try fixture.drive(24);

    bench.print(lib, "kcp.real_udp.stream_baseline", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .payload_bytes_per_op = payload_len,
        .copy_bytes_per_op = payload_len,
    });
}

fn runTransferRateCase(comptime lib: type, comptime Fixture: type, fixture: anytype) !void {
    const payload_len: usize = 1024;
    const payload: [payload_len]u8 = [_]u8{0x4d} ** payload_len;
    const config: bench.Config = .{
        .warmup = 4,
        .iterations = 32,
    };

    const client_mux = fixture.client_udp.serviceMux(fixture.server_static.public) orelse return error.TestUnexpectedResult;
    const opened = try client_mux.openStream(Fixture.service_id);
    const accepted = fixture.waitForAcceptedServerStream(512) catch |err| switch (err) {
        error.TimedOut => return error.AcceptTimedOut,
        else => return err,
    };
    if (opened != accepted) return error.TestUnexpectedResult;

    const State = struct {
        fixture: @TypeOf(fixture),
        stream_id: u64,
        payload: []const u8,
        buffer: [payload_len]u8 = undefined,
        sink: usize = 0,
    };

    var state = State{
        .fixture = fixture,
        .stream_id = accepted,
        .payload = &payload,
    };

    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            _ = try value.fixture.client_udp.sendStreamData(
                value.fixture.server_static.public,
                Fixture.service_id,
                value.stream_id,
                value.payload,
            );
            const read_n = value.fixture.waitForServerStreamData(value.stream_id, &value.buffer, 512) catch |err| switch (err) {
                error.TimedOut => return error.ServerReadTimedOut,
                else => return err,
            };
            if (read_n != value.payload.len) return error.TestUnexpectedResult;
            if (!dep.embed.mem.eql(u8, value.payload, value.buffer[0..read_n])) return error.TestUnexpectedResult;
            value.sink +%= read_n;
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    try fixture.client_udp.closeStream(fixture.server_static.public, Fixture.service_id, opened);
    try fixture.drive(24);

    bench.print(lib, "kcp.real_udp.stream_transfer_rate", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .payload_bytes_per_op = payload_len,
        .copy_bytes_per_op = payload_len,
        .extra_name = "payload_bytes",
        .extra_value = payload_len,
    });
}
