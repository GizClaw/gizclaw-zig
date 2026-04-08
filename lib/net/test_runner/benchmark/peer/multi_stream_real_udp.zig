const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");
const testing_api = dep.testing;

const bench = @import("../common.zig");
const PeerRealUdpHarnessFile = @import("../test_utils/peer_real_udp_harness.zig");

const CoreFile = net_pkg.core;
const PeerFile = net_pkg.peer;

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Core = CoreFile.make(lib);
    const Peer = PeerFile.make(Core);
    const Fixture = PeerRealUdpHarnessFile.make(lib);

    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            runCase(lib, Fixture, Peer, allocator, 16, bench.no_impairment, .{
                .warmup = 1,
                .iterations = 3,
            }) catch |err| {
                t.logErrorf("benchmark/peer/multi_stream_real_udp clean failed: {}", .{err});
                return false;
            };
            runCase(lib, Fixture, Peer, allocator, 16, bench.low_loss, .{
                .warmup = 1,
                .iterations = 3,
            }) catch |err| {
                t.logErrorf("benchmark/peer/multi_stream_real_udp low_loss failed: {}", .{err});
                return false;
            };
            runCase(lib, Fixture, Peer, allocator, 16, bench.reorder_only, .{
                .warmup = 1,
                .iterations = 3,
            }) catch |err| {
                t.logErrorf("benchmark/peer/multi_stream_real_udp reorder failed: {}", .{err});
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
    comptime Peer: type,
    allocator: dep.embed.mem.Allocator,
    comptime stream_count: usize,
    impairment: bench.ImpairmentProfile,
    config: bench.Config,
) !void {
    const payload_len: usize = 384;
    const payload: [payload_len]u8 = [_]u8{0x52} ** payload_len;
    const max_rounds: usize = 2048;

    var fixture = try Fixture.init(allocator, .{
        .enable_kcp = true,
        .client_impairment = impairment,
        .kcp_accept_backlog = stream_count,
        .kcp_max_active_streams = stream_count,
    });
    defer fixture.deinit();

    try fixture.dialAndAccept();

    var client_streams: [stream_count]?*Peer.Stream = [_]?*Peer.Stream{null} ** stream_count;
    var server_streams: [stream_count]?*Peer.Stream = [_]?*Peer.Stream{null} ** stream_count;
    defer {
        for (server_streams) |maybe_stream| {
            if (maybe_stream) |stream| stream.deinit();
        }
        for (client_streams) |maybe_stream| {
            if (maybe_stream) |stream| stream.deinit();
        }
    }

    const client_conn = try fixture.clientConn();
    const server_conn = try fixture.serverConn();
    var index: usize = 0;
    while (index < stream_count) : (index += 1) {
        client_streams[index] = try client_conn.openRPC();
    }

    index = 0;
    while (index < stream_count) : (index += 1) {
        server_streams[index] = try fixture.waitForAcceptedServerRPC(max_rounds);
    }

    var owned_client_streams: [stream_count]*Peer.Stream = undefined;
    var owned_server_streams: [stream_count]*Peer.Stream = undefined;
    for (client_streams, 0..) |maybe_stream, stream_index| {
        owned_client_streams[stream_index] = maybe_stream orelse return error.TestUnexpectedResult;
    }
    for (server_streams, 0..) |maybe_stream, stream_index| {
        owned_server_streams[stream_index] = maybe_stream orelse return error.TestUnexpectedResult;
    }

    const State = struct {
        fixture: *Fixture,
        client_streams: [stream_count]*Peer.Stream,
        server_streams: [stream_count]*Peer.Stream,
        payload: []const u8,
        buffers: [stream_count][payload_len]u8 = [_][payload_len]u8{[_]u8{0} ** payload_len} ** stream_count,
        sink: usize = 0,
    };

    var state = State{
        .fixture = &fixture,
        .client_streams = owned_client_streams,
        .server_streams = owned_server_streams,
        .payload = &payload,
    };

    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            var stream_index: usize = 0;
            while (stream_index < stream_count) : (stream_index += 1) {
                _ = try value.client_streams[stream_index].write(value.payload);
            }
            try value.fixture.flushClientWrites();

            stream_index = 0;
            while (stream_index < stream_count) : (stream_index += 1) {
                const read_n = try value.fixture.waitForStreamRead(
                    value.server_streams[stream_index],
                    &value.buffers[stream_index],
                    max_rounds,
                );
                if (read_n != value.payload.len) return error.TestUnexpectedResult;
                if (!dep.embed.mem.eql(u8, value.payload, value.buffers[stream_index][0..read_n])) {
                    return error.TestUnexpectedResult;
                }
                value.sink +%= read_n;
            }
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    try client_conn.closeService(Peer.ServicePublic);
    try server_conn.closeService(Peer.ServicePublic);
    try fixture.flushClientWrites();
    try driveIgnoreServiceRejected(&fixture, 96);

    bench.print(lib, "peer.real_udp.multi_stream_transfer_rate", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = impairment,
        .payload_bytes_per_op = payload_len * stream_count,
        .copy_bytes_per_op = payload_len * stream_count,
        .extra_name = "streams",
        .extra_value = stream_count,
    });
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
