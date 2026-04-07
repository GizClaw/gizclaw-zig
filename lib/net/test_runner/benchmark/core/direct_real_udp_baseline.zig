const dep = @import("dep");
const testing_api = dep.testing;
const net_pkg = @import("../../../../net.zig");

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

            var fixture = Fixture.init(allocator, .{}) catch |err| {
                t.logErrorf("benchmark/core/direct_real_udp_baseline setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runBaselineCase(lib, &fixture) catch |err| {
                t.logErrorf("benchmark/core/direct_real_udp_baseline failed: {}", .{err});
                return false;
            };
            runTransferRateCase(lib, &fixture) catch |err| {
                t.logErrorf("benchmark/core/direct_real_udp_transfer_rate failed: {}", .{err});
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

fn runBaselineCase(comptime lib: type, fixture: anytype) !void {
    const payload_len: usize = 256;
    const payload: [payload_len]u8 = [_]u8{0x51} ** payload_len;
    const config: bench.Config = .{
        .warmup = 2,
        .iterations = 12,
    };

    try fixture.establish();

    const State = struct {
        fixture: @TypeOf(fixture),
        payload: []const u8,
        buffer: [payload_len]u8 = undefined,
        sink: usize = 0,
    };

    var state = State{
        .fixture = fixture,
        .payload = &payload,
    };

    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            const sent = try value.fixture.client_udp.writeDirect(
                value.fixture.server_static.public,
                net_pkg.core.protocol.event,
                value.payload,
            );
            if (sent != .sent) return error.TestUnexpectedResult;

            const read = try value.fixture.waitForServerDirect(&value.buffer, 256);
            if (read.protocol_byte != net_pkg.core.protocol.event) return error.TestUnexpectedResult;
            if (read.n != value.payload.len) return error.TestUnexpectedResult;
            if (!dep.embed.mem.eql(u8, value.payload, value.buffer[0..read.n])) return error.TestUnexpectedResult;
            value.sink +%= read.n;
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    bench.print(lib, "core.real_udp.direct_baseline", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .payload_bytes_per_op = payload_len,
        .copy_bytes_per_op = payload_len,
    });
}

fn runTransferRateCase(comptime lib: type, fixture: anytype) !void {
    const payload_len: usize = 1024;
    const payload: [payload_len]u8 = [_]u8{0x63} ** payload_len;
    const config: bench.Config = .{
        .warmup = 4,
        .iterations = 48,
    };

    const State = struct {
        fixture: @TypeOf(fixture),
        payload: []const u8,
        buffer: [payload_len]u8 = undefined,
        sink: usize = 0,
    };

    var state = State{
        .fixture = fixture,
        .payload = &payload,
    };

    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            const sent = try value.fixture.client_udp.writeDirect(
                value.fixture.server_static.public,
                net_pkg.core.protocol.event,
                value.payload,
            );
            if (sent != .sent) return error.TestUnexpectedResult;

            const read = try value.fixture.waitForServerDirect(&value.buffer, 256);
            if (read.protocol_byte != net_pkg.core.protocol.event) return error.TestUnexpectedResult;
            if (read.n != value.payload.len) return error.TestUnexpectedResult;
            if (!dep.embed.mem.eql(u8, value.payload, value.buffer[0..read.n])) return error.TestUnexpectedResult;
            value.sink +%= read.n;
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    bench.print(lib, "core.real_udp.direct_transfer_rate", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .payload_bytes_per_op = payload_len,
        .copy_bytes_per_op = payload_len,
        .extra_name = "payload_bytes",
        .extra_value = payload_len,
    });
}
