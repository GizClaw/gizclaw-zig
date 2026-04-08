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

            runCase(lib, 512, .{
                .warmup = 2_000,
                .iterations = 20_000,
            }) catch |err| {
                t.logErrorf("benchmark/noise/transport_session_roundtrip_baseline 512 failed: {}", .{err});
                return false;
            };
            runCase(lib, 1024, .{
                .warmup = 2_000,
                .iterations = 20_000,
            }) catch |err| {
                t.logErrorf("benchmark/noise/transport_session_roundtrip_baseline 1024 failed: {}", .{err});
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

fn runCase(comptime lib: type, comptime payload_len: usize, config: bench.Config) !void {
    const Noise = net_pkg.noise.make(lib);
    const protocol = net_pkg.core.protocol;
    const sender_key = net_pkg.noise.Key.fromBytes([_]u8{0x11} ** net_pkg.noise.Key.key_size);
    const receiver_key = net_pkg.noise.Key.fromBytes([_]u8{0x22} ** net_pkg.noise.Key.key_size);
    const remote_pk = net_pkg.noise.Key.fromBytes([_]u8{0x33} ** net_pkg.noise.Key.key_size);

    const State = struct {
        sender: Noise.Session,
        receiver: Noise.Session,
        payload: [payload_len]u8 = [_]u8{0x5a} ** payload_len,
        plaintext: [1 + payload_len]u8 = undefined,
        ciphertext: [1 + payload_len + net_pkg.noise.TagSize]u8 = undefined,
        wire: [net_pkg.noise.Message.transport_header_size + 1 + payload_len + net_pkg.noise.TagSize]u8 = undefined,
        decode_buf: [1 + payload_len]u8 = undefined,
        sink: u64 = 0,
    };

    var state = State{
        .sender = Noise.Session.init(.{
            .local_index = 1,
            .remote_index = 2,
            .send_key = sender_key,
            .recv_key = receiver_key,
            .remote_pk = remote_pk,
        }),
        .receiver = Noise.Session.init(.{
            .local_index = 2,
            .remote_index = 1,
            .send_key = receiver_key,
            .recv_key = sender_key,
            .remote_pk = remote_pk,
        }),
    };

    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            const plaintext_n = try net_pkg.noise.Message.encodePayload(
                &value.plaintext,
                protocol.event,
                &value.payload,
            );
            const encrypted = try value.sender.encrypt(value.plaintext[0..plaintext_n], &value.ciphertext);
            const wire_n = try net_pkg.noise.Message.buildTransportMessage(
                &value.wire,
                value.sender.remoteIndex(),
                encrypted.nonce,
                value.ciphertext[0..encrypted.n],
            );
            const decoded_transport = try net_pkg.noise.Message.parseTransportMessage(value.wire[0..wire_n]);
            if (decoded_transport.receiver_index != value.receiver.localIndex()) return error.TestUnexpectedResult;

            const plaintext_read = try value.receiver.decrypt(
                decoded_transport.ciphertext,
                decoded_transport.counter,
                &value.decode_buf,
            );
            const decoded_payload = try net_pkg.noise.Message.decodePayload(value.decode_buf[0..plaintext_read]);
            if (decoded_payload.protocol != protocol.event) return error.TestUnexpectedResult;
            if (decoded_payload.payload.len != value.payload.len) return error.TestUnexpectedResult;
            if (!dep.embed.mem.eql(u8, &value.payload, decoded_payload.payload)) return error.TestUnexpectedResult;
            value.sink +%= decoded_transport.counter;
            value.sink +%= decoded_payload.payload[0];
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    bench.print(lib, "noise.package_local.transport_session_roundtrip", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .payload_bytes_per_op = payload_len,
        .copy_bytes_per_op = payload_len * 2,
        .extra_name = "payload_bytes",
        .extra_value = payload_len,
    });
}
