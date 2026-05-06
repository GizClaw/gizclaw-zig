const glib = @import("glib");

const Key = @import("../noise/Key.zig");
const NoiseMessage = @import("../noise/Message.zig");
const packet = @import("../packet.zig");
const KcpStreamType = @import("KcpStream.zig");

pub const Config = struct {
    packet_channel_capacity: usize = 32,
    stream_accept_channel_capacity: usize = 32,
};

pub fn make(comptime grt: type) type {
    const KcpStream = KcpStreamType.make(grt);
    const PacketChannelType = grt.sync.Channel(*packet.Inbound);
    const StreamAcceptChannelType = grt.sync.Channel(KcpStream.Port);

    return struct {
        remote_static: Key,
        packet_ch: PacketChannel,
        stream_accept_ch: StreamAcceptChannelType,
        closed: bool = false,

        const Self = @This();
        pub const PacketChannel = PacketChannelType;

        pub fn init(
            allocator: grt.std.mem.Allocator,
            remote_static: Key,
            config: Config,
        ) !Self {
            var packet_ch = try PacketChannel.make(allocator, config.packet_channel_capacity);
            errdefer packet_ch.deinit();

            return .{
                .remote_static = remote_static,
                .packet_ch = packet_ch,
                .stream_accept_ch = try StreamAcceptChannelType.make(allocator, config.stream_accept_channel_capacity),
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.drainPackets();
            self.drainStreams();
            self.stream_accept_ch.deinit();
            self.packet_ch.deinit();
        }

        pub fn deliverPacket(self: *Self, inbound: *packet.Inbound) !void {
            if (self.closed) return error.PeerClosed;

            const previous_state = inbound.state;
            inbound.state = .service_delivered;
            const send_result = self.packet_ch.sendTimeout(inbound, 0) catch |err| {
                inbound.state = previous_state;
                return err;
            };
            if (!send_result.ok) {
                inbound.state = previous_state;
                return error.PacketChannelFull;
            }
        }

        pub fn deliverStream(self: *Self, port: KcpStream.Port) !void {
            if (self.closed) return error.PeerClosed;

            const send_result = try self.stream_accept_ch.sendTimeout(port, 0);
            if (!send_result.ok) return error.StreamAcceptChannelFull;
        }

        fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;
            self.packet_ch.close();
            self.stream_accept_ch.close();
        }

        fn drainPackets(self: *Self) void {
            while (true) {
                const result = self.packet_ch.recvTimeout(0) catch break;
                if (!result.ok) break;
                result.value.deinit();
            }
        }

        fn drainStreams(self: *Self) void {
            while (true) {
                const result = self.stream_accept_ch.recvTimeout(0) catch break;
                if (!result.ok) break;
            }
        }
    };
}

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    const testing_api = glib.testing;

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase(grt) catch |err| {
                t.logErrorf("giznet/service Peer unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryCase(comptime any_lib: type) !void {
            _ = any_lib;

            var pool = try packet.Inbound.initPool(grt, grt.std.testing.allocator, 2560);
            defer pool.deinit();

            const Peer = make(grt);
            const remote_key = Key{ .bytes = [_]u8{0x22} ** 32 };
            var peer = try Peer.init(grt.std.testing.allocator, remote_key, .{
                .packet_channel_capacity = 1,
            });
            defer peer.deinit();

            const pkt = try makePacket(pool, &[_]u8{7} ++ "ping");
            try peer.deliverPacket(pkt);

            const result = try peer.packet_ch.recvTimeout(0);
            try grt.std.testing.expect(result.ok);
            result.value.deinit();
        }

        fn makePacket(pool: packet.Inbound.Pool, data: []const u8) !*packet.Inbound {
            const inbound = pool.get() orelse return error.OutOfMemory;
            const plaintext_buf = inbound.bufRef()[NoiseMessage.TransportHeaderSize..];
            if (plaintext_buf.len < data.len) return error.BufferTooSmall;
            @memcpy(plaintext_buf[0..data.len], data);
            inbound.len = data.len;
            inbound.kind = .transport;
            inbound.state = .ready_to_consume;
            return inbound;
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
