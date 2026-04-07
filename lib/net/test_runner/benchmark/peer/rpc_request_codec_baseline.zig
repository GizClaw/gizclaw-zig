const dep = @import("dep");
const testing_api = dep.testing;
const net_pkg = @import("../../../../net.zig");

const bench = @import("../common.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            runCase(lib, allocator) catch |err| {
                t.logErrorf("benchmark/peer/rpc_request_codec_baseline failed: {}", .{err});
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

fn runCase(comptime lib: type, allocator: dep.embed.mem.Allocator) !void {
    const CountingAllocator = bench.CountingAllocator(lib);
    const peer = net_pkg.peer;
    const config: bench.Config = .{
        .warmup = 16,
        .iterations = 128,
    };
    const request = peer.RPCRequest{
        .id = "req-42",
        .method = "room.publish",
        .params = "{\"room\":\"alpha\",\"seq\":7,\"muted\":false}",
    };

    const sample = try peer.encodeRPCRequest(allocator, request);
    const encoded_len = sample.len;
    allocator.free(sample);

    const State = struct {
        bench_allocator: dep.embed.mem.Allocator,
        request: peer.RPCRequest,
        sink: usize = 0,
    };

    var counting = CountingAllocator.init(allocator);
    const bench_allocator = counting.allocator();
    var state = State{
        .bench_allocator = bench_allocator,
        .request = request,
    };

    var warmup: usize = 0;
    while (warmup < config.warmup) : (warmup += 1) try runIteration(&state);
    counting.reset();
    state.sink = 0;

    const start_ns = lib.time.nanoTimestamp();
    var iteration: usize = 0;
    while (iteration < config.iterations) : (iteration += 1) try runIteration(&state);
    const elapsed_ns: u64 = @intCast(lib.time.nanoTimestamp() - start_ns);
    lib.mem.doNotOptimizeAway(state.sink);

    // Treat payload throughput as bytes processed by encode + decode, and use
    // copy_B/op as a coarse proxy for emitted JSON plus decoded owned slices.
    bench.print(lib, "peer.package_local.rpc_request_codec", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .payload_bytes_per_op = encoded_len * 2,
        .copy_bytes_per_op = encoded_len + request.id.len + request.method.len + request.params.?.len,
        .alloc_calls_total = counting.stats.alloc_calls + counting.stats.resize_calls + counting.stats.remap_calls,
        .alloc_bytes_total = counting.stats.bytes_allocated,
        .peak_live_bytes = counting.stats.peak_live_bytes,
    });
}

fn runIteration(state: anytype) !void {
    const encoded = try net_pkg.peer.encodeRPCRequest(state.bench_allocator, state.request);
    defer state.bench_allocator.free(encoded);

    var decoded = try net_pkg.peer.decodeRPCRequest(state.bench_allocator, encoded);
    defer decoded.deinit(state.bench_allocator);

    if (!dep.embed.mem.eql(u8, decoded.id, state.request.id)) return error.TestUnexpectedResult;
    if (!dep.embed.mem.eql(u8, decoded.method, state.request.method)) return error.TestUnexpectedResult;
    if (decoded.params == null) return error.TestUnexpectedResult;
    if (!dep.embed.mem.eql(u8, decoded.params.?, state.request.params.?)) return error.TestUnexpectedResult;

    state.sink +%= encoded.len;
    state.sink +%= decoded.params.?.len;
}
