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
                t.logErrorf("benchmark/core/routing_lookup_baseline failed: {}", .{err});
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
    const sizes = [_]usize{ 64, 1024, 8192 };
    for (sizes) |size| {
        try runScale(lib, allocator, size);
    }
}

fn runScale(comptime lib: type, allocator: dep.embed.mem.Allocator, size: usize) !void {
    const Noise = net_pkg.noise.make(lib);
    const Core = net_pkg.core.make(lib);
    const Host = Core.Host;
    const config: bench.Config = .{
        .warmup = 2_000,
        .iterations = 20_000,
    };

    const local_static = try Noise.KeyPair.fromPrivate(
        net_pkg.noise.Key.fromBytes([_]u8{ 24, 1, 0, 0 } ++ [_]u8{0} ** (net_pkg.noise.Key.key_size - 4)),
    );
    var host = try Host.init(allocator, local_static, true, .{});
    defer host.deinit();

    var index: usize = 0;
    while (index < size) : (index += 1) {
        try host.registerPeer(keyFor(index));
    }

    const State = struct {
        host: *Host,
        key: net_pkg.noise.Key,
        sink: u64 = 0,
    };

    var state = State{
        .host = &host,
        .key = keyFor(size / 2),
    };

    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            const found = value.host.peerState(value.key) orelse return error.TestUnexpectedResult;
            if (found != net_pkg.core.Host.PeerState.new) return error.TestUnexpectedResult;
            value.sink +%= @intFromEnum(found);
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    bench.print(lib, "core.package_local.routing_lookup", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .extra_name = "keys",
        .extra_value = size,
    });
}

fn keyFor(index: usize) net_pkg.noise.Key {
    var bytes: [net_pkg.noise.Key.key_size]u8 = [_]u8{0} ** net_pkg.noise.Key.key_size;
    var value = index + 1;
    var offset: usize = 0;
    while (offset < bytes.len and value != 0) : (offset += 1) {
        bytes[offset] = @intCast(value & 0xff);
        value >>= 8;
    }
    bytes[bytes.len - 1] = @intCast(index % 251);
    return net_pkg.noise.Key.fromBytes(bytes);
}
