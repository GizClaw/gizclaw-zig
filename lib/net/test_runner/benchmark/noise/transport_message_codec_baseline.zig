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
            _ = allocator;

            runCase(lib) catch |err| {
                t.logErrorf("benchmark/noise/transport_message_codec_baseline failed: {}", .{err});
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

fn runCase(comptime lib: type) !void {
    const Message = net_pkg.noise.Message;
    const ciphertext_len: usize = 1024;
    const config: bench.Config = .{
        .warmup = 500,
        .iterations = 5_000,
    };

    const State = struct {
        ciphertext: [ciphertext_len]u8 = [_]u8{0x7a} ** ciphertext_len,
        buffer: [Message.transport_header_size + ciphertext_len]u8 = undefined,
        counter: u64 = 1,
        sink: u64 = 0,
    };

    var state = State{};
    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            const encoded_len = try Message.buildTransportMessage(
                &value.buffer,
                0x0102_0304,
                value.counter,
                &value.ciphertext,
            );
            const decoded = try Message.parseTransportMessage(value.buffer[0..encoded_len]);
            if (decoded.receiver_index != 0x0102_0304) return error.TestUnexpectedResult;
            if (decoded.counter != value.counter) return error.TestUnexpectedResult;
            value.counter +%= 1;
            value.sink +%= decoded.counter;
            value.sink +%= decoded.ciphertext[0];
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    bench.print(lib, "noise.package_local.transport_message_codec", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .payload_bytes_per_op = ciphertext_len,
        .copy_bytes_per_op = Message.transport_header_size + ciphertext_len,
    });
}
