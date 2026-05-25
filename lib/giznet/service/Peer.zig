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
    const PacketChannelArc = grt.sync.Arc.make(grt.std, PacketChannelType);
    const StreamAcceptChannelArc = grt.sync.Arc.make(grt.std, StreamAcceptChannelType);

    return struct {
        remote_static: Key,
        packet_ch: PacketChannelArc.Arc,
        stream_accept_ch: StreamAcceptChannelArc.Arc,
        closed: bool = false,

        const Self = @This();
        pub const PacketChannel = PacketChannelType;
        pub const PacketChannelRef = PacketChannelArc.Arc;
        pub const StreamAcceptChannel = StreamAcceptChannelType;
        pub const StreamAcceptChannelRef = StreamAcceptChannelArc.Arc;

        pub fn init(
            allocator: grt.std.mem.Allocator,
            remote_static: Key,
            config: Config,
        ) !Self {
            const packet_ch = try makeChannelRef(PacketChannel, PacketChannelArc, allocator, config.packet_channel_capacity);
            errdefer packet_ch.deinit();

            return .{
                .remote_static = remote_static,
                .packet_ch = packet_ch,
                .stream_accept_ch = try makeChannelRef(
                    StreamAcceptChannelType,
                    StreamAcceptChannelArc,
                    allocator,
                    config.stream_accept_channel_capacity,
                ),
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
            const send_result = self.packet_ch.ptr().sendTimeout(inbound, 0) catch |err| {
                inbound.state = previous_state;
                return err;
            };
            if (!send_result.ok) {
                inbound.state = previous_state;
                return error.PacketChannelFull;
            }
        }

        pub fn deliverStream(self: *Self, port: KcpStream.Port) !void {
            if (self.closed) {
                var owned_port = port;
                owned_port.deinit();
                return error.PeerClosed;
            }

            const send_result = self.stream_accept_ch.ptr().sendTimeout(port, 0) catch |err| {
                var owned_port = port;
                owned_port.deinit();
                return err;
            };
            if (!send_result.ok) {
                var owned_port = port;
                owned_port.deinit();
                return error.StreamAcceptChannelFull;
            }
        }

        fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;
            self.packet_ch.ptr().close();
            self.stream_accept_ch.ptr().close();
        }

        fn drainPackets(self: *Self) void {
            while (true) {
                const result = self.packet_ch.ptr().recvTimeout(0) catch break;
                if (!result.ok) break;
                result.value.deinit();
            }
        }

        fn drainStreams(self: *Self) void {
            while (true) {
                const result = self.stream_accept_ch.ptr().recvTimeout(0) catch break;
                if (!result.ok) break;
                var port = result.value;
                port.deinit();
            }
        }

        fn makeChannelRef(
            comptime Channel: type,
            comptime ChannelArc: type,
            allocator: grt.std.mem.Allocator,
            capacity: usize,
        ) !ChannelArc.Arc {
            const channel = try allocator.create(Channel);
            errdefer allocator.destroy(channel);
            channel.* = try Channel.make(allocator, capacity);
            errdefer channel.deinit();
            return try ChannelArc.adopt(allocator, channel);
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
            tryReusedPeerStorageDoesNotReviveOldStreamChannel(grt) catch |err| {
                t.logErrorf("giznet/service Peer reused storage stream channel failed: {}", .{err});
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

            const result = try peer.packet_ch.ptr().recvTimeout(0);
            try grt.std.testing.expect(result.ok);
            result.value.deinit();
        }

        fn tryReusedPeerStorageDoesNotReviveOldStreamChannel(comptime any_lib: type) !void {
            _ = any_lib;

            const Peer = make(grt);
            const remote_key = Key{ .bytes = [_]u8{0x23} ** 32 };
            const replacement_key = Key{ .bytes = [_]u8{0x24} ** 32 };
            var peer = try Peer.init(grt.std.testing.allocator, remote_key, .{});
            const old_stream_accept_ch = peer.stream_accept_ch.clone();
            defer old_stream_accept_ch.deinit();

            peer.deinit();
            peer = try Peer.init(grt.std.testing.allocator, replacement_key, .{});
            defer peer.deinit();

            const result = try old_stream_accept_ch.ptr().recvTimeout(0);
            try grt.std.testing.expect(!result.ok);
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
