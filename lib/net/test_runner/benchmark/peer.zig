const dep = @import("dep");
const testing_api = dep.testing;

const ConcurrentRealUdpRunner = @import("peer/concurrent_real_udp.zig");
const MultiStreamRealUdpRunner = @import("peer/multi_stream_real_udp.zig");
const RpcRequestCodecBaselineRunner = @import("peer/rpc_request_codec_baseline.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("concurrent_real_udp", ConcurrentRealUdpRunner.make(lib));
            t.run("multi_stream_real_udp", MultiStreamRealUdpRunner.make(lib));
            t.run("rpc_request_codec_baseline", RpcRequestCodecBaselineRunner.make(lib));
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
