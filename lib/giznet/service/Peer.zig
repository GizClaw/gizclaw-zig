const glib = @import("glib");

const Key = @import("../noise/Key.zig");
const NoiseMessage = @import("../noise/Message.zig");
const PacketInbound = @import("../packet/Inbound.zig");

pub const Config = struct {
    packet_channel_capacity: usize = 32,
};

pub fn make(comptime grt: type) type {
    const PacketChannelType = grt.sync.Channel(*PacketInbound);

    return struct {
        remote_static: Key,
        packet_ch: PacketChannel,
        closed: bool = false,

        const Self = @This();
        pub const PacketChannel = PacketChannelType;

        pub fn init(
            allocator: grt.std.mem.Allocator,
            remote_static: Key,
            config: Config,
        ) !Self {
            return .{
                .remote_static = remote_static,
                .packet_ch = try PacketChannel.make(allocator, config.packet_channel_capacity),
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.drainPackets();
            self.packet_ch.deinit();
        }

        pub fn deliverPacket(self: *Self, packet: *PacketInbound) !void {
            if (self.closed) return error.PeerClosed;

            const previous_state = packet.state;
            packet.state = .service_delivered;
            const send_result = self.packet_ch.sendTimeout(packet, 0) catch |err| {
                packet.state = previous_state;
                return err;
            };
            if (!send_result.ok) {
                packet.state = previous_state;
                return error.PacketChannelFull;
            }
        }

        fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;
            self.packet_ch.close();
        }

        fn drainPackets(self: *Self) void {
            while (true) {
                const result = self.packet_ch.recvTimeout(0) catch break;
                if (!result.ok) break;
                result.value.deinit();
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

            var pool = try PacketInbound.initPool(grt, grt.std.testing.allocator, 2560);
            defer pool.deinit();

            const Peer = make(grt);
            const remote_key = Key{ .bytes = [_]u8{0x22} ** 32 };
            var peer = try Peer.init(grt.std.testing.allocator, remote_key, .{
                .packet_channel_capacity = 1,
            });
            defer peer.deinit();

            const packet = try makePacket(pool, &[_]u8{7} ++ "ping");
            try peer.deliverPacket(packet);

            const result = try peer.packet_ch.recvTimeout(0);
            try grt.std.testing.expect(result.ok);
            result.value.deinit();
        }

        fn makePacket(pool: PacketInbound.Pool, data: []const u8) !*PacketInbound {
            const packet = pool.get() orelse return error.OutOfMemory;
            const plaintext_buf = packet.bufRef()[NoiseMessage.TransportHeaderSize..];
            if (plaintext_buf.len < data.len) return error.BufferTooSmall;
            @memcpy(plaintext_buf[0..data.len], data);
            packet.len = data.len;
            packet.kind = .transport;
            packet.state = .ready_to_consume;
            return packet;
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
