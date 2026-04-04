const dep = @import("dep");
const noise_pkg = @import("../../../noise.zig");
const core_ns = @import("../../../core.zig");
const peer_ns = @import("../../../peer.zig");

pub fn Fixture(comptime lib: type) type {
    const ContextApi = dep.context.make(lib);
    const Noise = noise_pkg.make(lib);
    const Core = core_ns.make(lib);
    const Peer = peer_ns.make(Core);
    const PacketConn = dep.net.PacketConn;
    const UdpType = Core.UDP;
    const Kcp = @import("../../../kcp.zig").make(@import("../../../core.zig"));

    return struct {
        allocator: dep.embed.mem.Allocator,
        ctx_api: ContextApi,
        kcp_factory: Kcp.Adapter.Factory,
        server_key: Noise.KeyPair,
        client_key: Noise.KeyPair,
        server_pc: *LinkedPacketConn(UdpType),
        client_pc: *LinkedPacketConn(UdpType),
        server_udp: *UdpType,
        client_udp: *UdpType,
        clock_ms: *u64,
        server_listener: *Peer.Listener,
        client_listener: *Peer.Listener,
        server_conn: *Peer.Conn,
        client_conn: *Peer.Conn,

        const Self = @This();

        pub fn init(allocator: dep.embed.mem.Allocator) !Self {
            return initWithServices(allocator, true);
        }

        pub fn initWithServices(allocator: dep.embed.mem.Allocator, allow_all_services: bool) !Self {
            var ctx_api = try ContextApi.init(allocator);
            errdefer ctx_api.deinit();

            const server_key = try Noise.KeyPair.fromPrivate(
                noise_pkg.Key.fromBytes([_]u8{71} ** noise_pkg.Key.key_size),
            );
            const client_key = try Noise.KeyPair.fromPrivate(
                noise_pkg.Key.fromBytes([_]u8{72} ** noise_pkg.Key.key_size),
            );

            const clock_ms = try allocator.create(u64);
            errdefer allocator.destroy(clock_ms);
            clock_ms.* = 10_000;

            const server_pc = try allocator.create(LinkedPacketConn(UdpType));
            errdefer allocator.destroy(server_pc);
            server_pc.* = LinkedPacketConn(UdpType).init(31, clock_ms);
            const client_pc = try allocator.create(LinkedPacketConn(UdpType));
            errdefer allocator.destroy(client_pc);
            client_pc.* = LinkedPacketConn(UdpType).init(32, clock_ms);
            const server_packet = PacketConn.init(server_pc);
            const client_packet = PacketConn.init(client_pc);

            var kcp_factory = Kcp.Adapter.Factory{};
            const server_udp = try allocator.create(UdpType);
            errdefer allocator.destroy(server_udp);
            server_udp.* = try UdpType.init(allocator, server_packet, server_key, .{
                .allow_unknown = true,
                .service_config = if (allow_all_services)
                    .{
                        .on_new_service = allowAllServices,
                        .stream_adapter_factory = kcp_factory.adapterFactory(),
                    }
                else
                    .{
                        .stream_adapter_factory = kcp_factory.adapterFactory(),
                    },
            });
            errdefer server_udp.deinit();
            const client_udp = try allocator.create(UdpType);
            errdefer allocator.destroy(client_udp);
            client_udp.* = try UdpType.init(allocator, client_packet, client_key, .{
                .allow_unknown = false,
                .service_config = if (allow_all_services)
                    .{
                        .on_new_service = allowAllServices,
                        .stream_adapter_factory = kcp_factory.adapterFactory(),
                    }
                else
                    .{
                        .stream_adapter_factory = kcp_factory.adapterFactory(),
                    },
            });
            errdefer client_udp.deinit();

            server_pc.peer_udp = client_udp;
            client_pc.peer_udp = server_udp;

            const server_listener = try Peer.Listener.init(allocator, server_udp, false);
            errdefer server_listener.deinit();
            const client_listener = try Peer.Listener.init(allocator, client_udp, false);
            errdefer client_listener.deinit();

            const client_conn = try client_listener.dialContext(
                ctx_api.background(),
                server_key.public,
                @ptrCast(&server_pc.local_addr),
                server_pc.local_addr_len,
            );
            errdefer client_conn.deinit();
            const server_conn = try server_listener.accept();
            errdefer server_conn.deinit();

            return .{
                .allocator = allocator,
                .ctx_api = ctx_api,
                .kcp_factory = kcp_factory,
                .server_key = server_key,
                .client_key = client_key,
                .server_pc = server_pc,
                .client_pc = client_pc,
                .server_udp = server_udp,
                .client_udp = client_udp,
                .clock_ms = clock_ms,
                .server_listener = server_listener,
                .client_listener = client_listener,
                .server_conn = server_conn,
                .client_conn = client_conn,
            };
        }

        pub fn deinit(self: *Self) void {
            self.server_conn.deinit();
            self.client_conn.deinit();
            self.server_listener.deinit();
            self.client_listener.deinit();
            self.server_udp.deinit();
            self.client_udp.deinit();
            self.allocator.destroy(self.server_udp);
            self.allocator.destroy(self.client_udp);
            self.allocator.destroy(self.server_pc);
            self.allocator.destroy(self.client_pc);
            self.allocator.destroy(self.clock_ms);
            self.ctx_api.deinit();
        }

        pub fn drive(self: *Self, steps: usize) !void {
            var index: usize = 0;
            while (index < steps) : (index += 1) {
                try self.client_udp.testTickAt(nextFakeNowMs(self.clock_ms));
                try self.server_udp.testTickAt(nextFakeNowMs(self.clock_ms));
            }
        }
    };
}

fn LinkedPacketConn(comptime UdpType: type) type {
    const PacketConn = dep.net.PacketConn;
    return struct {
        peer_udp: ?*UdpType = null,
        local_addr: PacketConn.AddrStorage = [_]u8{0} ** @sizeOf(PacketConn.AddrStorage),
        local_addr_len: u32 = 1,
        read_timeout_ms: ?u32 = null,
        write_timeout_ms: ?u32 = null,
        clock_ms: *u64,
        closed: bool = false,
        deinit_count: usize = 0,

        const Self = @This();

        fn init(tag: u8, clock_ms: *u64) Self {
            var value = Self{ .clock_ms = clock_ms };
            value.local_addr[0] = tag;
            return value;
        }

        pub fn readFrom(self: *Self, _: []u8) PacketConn.ReadFromError!PacketConn.ReadFromResult {
            if (self.closed) return error.Closed;
            return error.TimedOut;
        }

        pub fn writeTo(self: *Self, buf: []const u8, _: [*]const u8, _: u32) PacketConn.WriteToError!usize {
            if (self.closed) return error.Closed;
            const peer_udp = self.peer_udp orelse return error.NetworkUnreachable;
            _ = peer_udp.testHandleDatagram(buf, @ptrCast(&self.local_addr), self.local_addr_len, nextFakeNowMs(self.clock_ms)) catch {
                return error.Unexpected;
            };
            return buf.len;
        }

        pub fn close(self: *Self) void {
            self.closed = true;
        }

        pub fn deinit(self: *Self) void {
            self.closed = true;
            self.deinit_count += 1;
        }

        pub fn setReadTimeout(self: *Self, ms: ?u32) void {
            self.read_timeout_ms = ms;
        }

        pub fn setWriteTimeout(self: *Self, ms: ?u32) void {
            self.write_timeout_ms = ms;
        }
    };
}

fn allowAllServices(_: noise_pkg.Key, _: u64) bool {
    return true;
}

fn nextFakeNowMs(clock_ms: *u64) u64 {
    clock_ms.* += 1;
    return clock_ms.*;
}
