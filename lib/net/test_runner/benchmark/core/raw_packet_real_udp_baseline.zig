const dep = @import("dep");
const testing_api = dep.testing;

const bench = @import("../common.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Net = dep.net.make(lib);
    const PacketConn = dep.net.PacketConn;

    const LocalAddr = struct {
        storage: PacketConn.AddrStorage = [_]u8{0} ** @sizeOf(PacketConn.AddrStorage),
        len: u32 = 0,
    };

    const Fixture = struct {
        allocator: dep.embed.mem.Allocator,
        client: PacketConn,
        server: PacketConn,
        server_addr: LocalAddr,

        fn init(allocator: dep.embed.mem.Allocator) !@This() {
            var client = try Net.listenPacket(.{
                .allocator = allocator,
                .address = dep.net.netip.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
            });
            errdefer client.deinit();

            var server = try Net.listenPacket(.{
                .allocator = allocator,
                .address = dep.net.netip.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
            });
            errdefer server.deinit();

            client.setWriteTimeout(1_000);
            server.setReadTimeout(1_000);

            return .{
                .allocator = allocator,
                .client = client,
                .server = server,
                .server_addr = try localSockAddr(server),
            };
        }

        fn deinit(self: *@This()) void {
            self.client.deinit();
            self.server.deinit();
            self.* = undefined;
        }

        fn localSockAddr(packet: PacketConn) !LocalAddr {
            const udp_impl = try packet.as(Net.UdpConn);
            var bound: lib.posix.sockaddr.storage = undefined;
            var bound_len: lib.posix.socklen_t = @sizeOf(lib.posix.sockaddr.storage);
            try lib.posix.getsockname(udp_impl.fd, @ptrCast(&bound), &bound_len);

            var result = LocalAddr{};
            result.len = @intCast(bound_len);
            const copy_len = @min(@as(usize, result.len), @sizeOf(PacketConn.AddrStorage));
            @memcpy(result.storage[0..copy_len], @as([*]const u8, @ptrCast(&bound))[0..copy_len]);
            return result;
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            var fixture = Fixture.init(allocator) catch |err| {
                t.logErrorf("benchmark/core/raw_packet_real_udp_baseline setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(lib, &fixture, 256, .{
                .warmup = 2_000,
                .iterations = 20_000,
            }, "core.real_udp.raw_packet_baseline") catch |err| {
                t.logErrorf("benchmark/core/raw_packet_real_udp_baseline 256 failed: {}", .{err});
                return false;
            };
            runCase(lib, &fixture, 1024, .{
                .warmup = 4_000,
                .iterations = 40_000,
            }, "core.real_udp.raw_packet_transfer_rate") catch |err| {
                t.logErrorf("benchmark/core/raw_packet_real_udp_baseline 1024 failed: {}", .{err});
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
    fixture: anytype,
    comptime payload_len: usize,
    config: bench.Config,
    label: []const u8,
) !void {
    const PacketConn = dep.net.PacketConn;

    const State = struct {
        fixture: @TypeOf(fixture),
        payload: [payload_len]u8 = [_]u8{0x43} ** payload_len,
        buffer: [payload_len]u8 = undefined,
        recv_addr: PacketConn.AddrStorage = undefined,
        recv_addr_len: u32 = 0,
        sink: usize = 0,
    };

    var state = State{
        .fixture = fixture,
    };

    const elapsed_ns = try bench.runLoop(lib, config, &state, struct {
        fn body(value: *State) !void {
            const written = try value.fixture.client.writeTo(
                &value.payload,
                @ptrCast(&value.fixture.server_addr.storage),
                value.fixture.server_addr.len,
            );
            if (written != value.payload.len) return error.TestUnexpectedResult;

            const recv = try value.fixture.server.readFrom(&value.buffer);
            value.recv_addr = recv.addr;
            value.recv_addr_len = recv.addr_len;
            if (recv.bytes_read != value.payload.len) return error.TestUnexpectedResult;
            if (!dep.embed.mem.eql(u8, &value.payload, value.buffer[0..recv.bytes_read])) {
                return error.TestUnexpectedResult;
            }
            value.sink +%= recv.bytes_read;
            value.sink +%= recv.addr_len;
        }
    }.body);
    lib.mem.doNotOptimizeAway(state.sink);

    bench.print(lib, label, config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .payload_bytes_per_op = payload_len,
        .copy_bytes_per_op = payload_len,
        .extra_name = "payload_bytes",
        .extra_value = payload_len,
    });
}
