//! Service-layer engine shape.
//!
//! The service engine consumes plaintext packets from noise on inbound paths,
//! and produces plaintext service payloads for noise on outbound paths.

const glib = @import("glib");

const Key = @import("../noise/Key.zig");
const NoiseMessage = @import("../noise/Message.zig");
const KcpStreamType = @import("KcpStream.zig");
const KcpStreamTableType = @import("KcpStreamTable.zig");
const PeerType = @import("Peer.zig");
const PeerTableType = @import("PeerTable.zig");
const packet = @import("../packet.zig");
const protocol_ns = @import("protocol.zig");
const Uvarint = @import("Uvarint.zig");

pub const Config = struct {
    peer: PeerType.Config = .{},
    kcp_stream: KcpStreamTableType.Config = .{},
};

pub const DriveInput = union(enum) {
    peer_established: Key,
    close_conn: Key,
    inbound: *packet.Inbound,
    outbound: *packet.Outbound,
    tick: void,
};

pub fn make(comptime grt: type) type {
    const PeerTable = PeerTableType.make(grt);
    const PacketChannel = PeerTable.PeerType.PacketChannel;
    const KcpStreamTable = KcpStreamTableType.make(grt);
    const KcpStream = KcpStreamTable.Stream;
    const StreamAcceptChannel = grt.sync.Channel(KcpStream.Port);

    return struct {
        allocator: grt.std.mem.Allocator,
        peers: PeerTable,
        streams: KcpStreamTable,

        const Self = @This();
        pub const StreamPort = KcpStream.Port;
        pub const PeerPort = struct {
            remote_static: Key,
            packet_ch: *PacketChannel,
            stream_accept_ch: *StreamAcceptChannel,

            pub fn recvPacket(self: PeerPort) @TypeOf(self.packet_ch.recv()) {
                return self.packet_ch.recv();
            }

            pub fn recvPacketTimeout(self: PeerPort, timeout: glib.time.duration.Duration) @TypeOf(self.packet_ch.recvTimeout(timeout)) {
                return self.packet_ch.recvTimeout(timeout);
            }

            pub fn acceptStream(self: PeerPort, timeout: ?glib.time.duration.Duration) @TypeOf(self.stream_accept_ch.recv()) {
                if (timeout) |duration| {
                    return self.stream_accept_ch.recvTimeout(duration);
                }
                return self.stream_accept_ch.recv();
            }
        };
        pub const DriveOutput = union(enum) {
            peer_port: PeerPort,
            opened_stream: KcpStream.Port,
            outbound: *packet.Outbound,
            next_tick_deadline: glib.time.instant.Time,
        };
        pub const Callback = struct {
            ctx: *anyopaque,
            call: *const fn (ctx: *anyopaque, output: DriveOutput) anyerror!void,

            pub fn handle(self: Callback, output: DriveOutput) !void {
                try self.call(self.ctx, output);
            }
        };

        pub fn init(allocator: grt.std.mem.Allocator, config: Config, pools: *packet.Pools) Self {
            return .{
                .allocator = allocator,
                .peers = PeerTable.init(allocator, config.peer),
                .streams = KcpStreamTable.init(allocator, pools, config.kcp_stream),
            };
        }

        pub fn deinit(self: *Self) void {
            self.streams.deinit();
            self.peers.deinit();
        }

        pub fn drive(self: *Self, input: DriveInput, callback: Callback) !void {
            switch (input) {
                .tick => {
                    var stream_callback = StreamCallback{ .service = self, .parent_callback = callback };
                    try self.streams.driveTick(grt.time.instant.now(), stream_callback.callback());
                },
                .peer_established => |remote_static| {
                    const peer_result = try self.peers.getOrCreateWithStatus(remote_static);
                    if (peer_result.created) {
                        try callback.handle(.{ .peer_port = self.peerPort(peer_result.peer) });
                    }
                },
                .close_conn => |remote_static| {
                    _ = self.peers.remove(remote_static);
                    self.streams.removeRemote(remote_static);
                },
                .inbound => |pkt| {
                    const frame = try pkt.parseServiceData();
                    switch (frame.service_data orelse return error.PayloadNotParsed) {
                        .direct => {
                            const peer_result = try self.peers.getOrCreateWithStatus(pkt.remote_static);
                            if (peer_result.created) {
                                try callback.handle(.{ .peer_port = self.peerPort(peer_result.peer) });
                            }
                            try peer_result.peer.deliverPacket(frame);
                        },
                        .kcp => |kcp| {
                            const peer_result = try self.peers.getOrCreateWithStatus(pkt.remote_static);
                            if (peer_result.created) {
                                try callback.handle(.{ .peer_port = self.peerPort(peer_result.peer) });
                            }
                            const stream_result = try self.streams.getOrCreateFromFrame(pkt.remote_static, kcp.service, kcp.frame);
                            if (stream_result.created) {
                                try peer_result.peer.deliverStream(stream_result.stream.port());
                            }
                            var stream_callback = StreamCallback{ .service = self, .parent_callback = callback };
                            try stream_result.stream.drive(.{ .inbound = frame }, stream_callback.callback());
                        },
                        .close => {
                            _ = self.peers.remove(pkt.remote_static);
                            self.streams.removeRemote(pkt.remote_static);
                            frame.deinit();
                        },
                    }
                },
                .outbound => |pkt| {
                    _ = try self.peers.getOrCreate(pkt.remote_static);

                    const service_data = pkt.service_data orelse return error.PayloadNotParsed;
                    switch (service_data) {
                        .direct => |direct| {
                            if (direct.protocol == protocol_ns.ProtocolKCP or
                                direct.protocol == protocol_ns.ProtocolConnCtrl) return error.InvalidDirectProtocol;
                            if (pkt.len != direct.payload.len + 1) return error.InvalidPacketLength;

                            const plaintext = pkt.transportPlaintextBufRef();
                            plaintext[0] = direct.protocol;

                            try callback.handle(.{ .outbound = pkt });
                        },
                        .open_stream => |open_stream| {
                            const peer = try self.peers.getOrCreate(pkt.remote_static);
                            const stream_result = try self.streams.open(pkt.remote_static, open_stream.service);
                            _ = peer;
                            try callback.handle(.{ .opened_stream = stream_result.stream.port() });
                            pkt.deinit();
                        },
                        .write_stream => |write_stream| {
                            if (write_stream.stream > grt.std.math.maxInt(u32)) return error.InvalidKcpStreamId;
                            const peer = try self.peers.getOrCreate(pkt.remote_static);
                            const stream_result = try self.streams.getOrCreate(
                                pkt.remote_static,
                                write_stream.service,
                                @intCast(write_stream.stream),
                            );
                            if (stream_result.created) {
                                try peer.deliverStream(stream_result.stream.port());
                            }
                            var stream_callback = StreamCallback{ .service = self, .parent_callback = callback };
                            try stream_result.stream.drive(.{ .outbound = pkt }, stream_callback.callback());
                        },
                    }
                },
            }
        }

        const StreamCallback = struct {
            service: *Self,
            parent_callback: Callback,

            fn callback(self: *@This()) KcpStream.Callback {
                return .{ .ctx = self, .call = call };
            }

            fn call(ctx: *anyopaque, output: KcpStreamType.DriveOutput) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                switch (output) {
                    .outbound => |pkt| {
                        try self.service.prepareKcpOutbound(pkt);
                        try self.parent_callback.handle(.{ .outbound = pkt });
                    },
                    .next_tick_deadline => |deadline| {
                        try self.parent_callback.handle(.{ .next_tick_deadline = deadline });
                    },
                }
            }
        };

        fn peerPort(self: *Self, peer: *PeerTable.PeerType) PeerPort {
            _ = self;
            return .{
                .remote_static = peer.remote_static,
                .packet_ch = &peer.packet_ch,
                .stream_accept_ch = &peer.stream_accept_ch,
            };
        }

        fn prepareKcpOutbound(self: *Self, outbound: *packet.Outbound) !void {
            _ = self;
            const write = switch (outbound.service_data orelse return error.PayloadNotParsed) {
                .write_stream => |data| data,
                else => return error.InvalidKcpPacket,
            };
            const plaintext = outbound.transportPlaintextBufRef();
            if (plaintext.len < 1) return error.BufferTooSmall;

            var service_buf: [10]u8 = undefined;
            const service_len = try Uvarint.write(write.service, service_buf[0..]);
            const header_len = 1 + service_len;
            if (plaintext.len < header_len + write.payload.len) return error.BufferTooSmall;

            glib.std.mem.copyBackwards(u8, plaintext[header_len..][0..write.payload.len], write.payload);
            plaintext[0] = protocol_ns.ProtocolKCP;
            @memcpy(plaintext[1..header_len], service_buf[0..service_len]);
            outbound.len = header_len + write.payload.len;
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

            tryDirectInboundTransfersOwnership(grt) catch |err| {
                t.logErrorf("giznet/service Engine direct inbound ownership failed: {}", .{err});
                return false;
            };
            tryDirectInboundCallbackErrorLeavesOwnership(grt) catch |err| {
                t.logErrorf("giznet/service Engine callback error ownership failed: {}", .{err});
                return false;
            };
            tryDirectInboundChannelFullLeavesOwnership(grt) catch |err| {
                t.logErrorf("giznet/service Engine channel full ownership failed: {}", .{err});
                return false;
            };
            tryKcpInboundErrorLeavesOwnership(grt) catch |err| {
                t.logErrorf("giznet/service Engine kcp error ownership failed: {}", .{err});
                return false;
            };
            tryCloseInboundConsumesPacket(grt) catch |err| {
                t.logErrorf("giznet/service Engine close inbound ownership failed: {}", .{err});
                return false;
            };
            tryOpenStreamReturnsPort(grt) catch |err| {
                t.logErrorf("giznet/service Engine open stream port failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryDirectInboundTransfersOwnership(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x21} ** 32 };
            const pkt = try makeInboundPacket(pools.inbound, remote_key, &[_]u8{0x31} ++ "hello");

            var callback_state: CallbackState(ServiceEngine) = .{};
            try engine.drive(.{ .inbound = pkt }, callback_state.callback());

            const peer_port = callback_state.peer_port orelse return error.MissingPeerPort;
            const result = try peer_port.recvPacketTimeout(0);
            try grt.std.testing.expect(result.ok);
            try grt.std.testing.expect(result.value.eql(pkt));
            result.value.deinit();
        }

        fn tryDirectInboundCallbackErrorLeavesOwnership(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x22} ** 32 };
            const pkt = try makeInboundPacket(pools.inbound, remote_key, &[_]u8{0x32} ++ "hello");
            defer pkt.deinit();

            var callback_state: CallbackState(ServiceEngine) = .{ .fail_peer_port = true };
            try grt.std.testing.expectError(
                error.InjectPeerPortFailure,
                engine.drive(.{ .inbound = pkt }, callback_state.callback()),
            );
        }

        fn tryDirectInboundChannelFullLeavesOwnership(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{
                .peer = .{ .packet_channel_capacity = 1 },
            }, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x23} ** 32 };
            const first = try makeInboundPacket(pools.inbound, remote_key, &[_]u8{0x33} ++ "first");
            const second = try makeInboundPacket(pools.inbound, remote_key, &[_]u8{0x33} ++ "second");
            defer second.deinit();

            var callback_state: CallbackState(ServiceEngine) = .{};
            try engine.drive(.{ .inbound = first }, callback_state.callback());
            try grt.std.testing.expectError(
                error.Timeout,
                engine.drive(.{ .inbound = second }, callback_state.callback()),
            );

            const peer_port = callback_state.peer_port orelse return error.MissingPeerPort;
            const result = try peer_port.recvPacketTimeout(0);
            try grt.std.testing.expect(result.ok);
            try grt.std.testing.expect(result.value.eql(first));
            result.value.deinit();
        }

        fn tryKcpInboundErrorLeavesOwnership(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            var payload: [4]u8 = undefined;
            payload[0] = protocol_ns.ProtocolKCP;
            const service_len = try Uvarint.write(7, payload[1..]);
            const remote_key = Key{ .bytes = [_]u8{0x24} ** 32 };
            const pkt = try makeInboundPacket(pools.inbound, remote_key, payload[0 .. 1 + service_len]);
            defer pkt.deinit();

            var callback_state: CallbackState(ServiceEngine) = .{};
            engine.drive(.{ .inbound = pkt }, callback_state.callback()) catch return;
            return error.ExpectedKcpInboundFailure;
        }

        fn tryCloseInboundConsumesPacket(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x25} ** 32 };
            const pkt = try makeInboundPacket(pools.inbound, remote_key, &[_]u8{protocol_ns.ProtocolConnCtrl});
            var callback_state: CallbackState(ServiceEngine) = .{};
            try engine.drive(.{ .inbound = pkt }, callback_state.callback());
        }

        fn tryOpenStreamReturnsPort(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x26} ** 32 };
            var callback_state: CallbackState(ServiceEngine) = .{};
            try engine.drive(.{ .peer_established = remote_key }, callback_state.callback());

            const pkt = try makeOpenStreamPacket(pools.outbound, remote_key, 9);
            try engine.drive(.{ .outbound = pkt }, callback_state.callback());

            const port = callback_state.opened_stream orelse return error.MissingOpenedStream;
            try grt.std.testing.expect(port.remote_static.eql(remote_key));
            try grt.std.testing.expectEqual(@as(u64, 9), port.service);
            try grt.std.testing.expectEqual(@as(u32, 1), port.stream);
        }

        fn CallbackState(comptime ServiceEngine: type) type {
            return struct {
                peer_port: ?ServiceEngine.PeerPort = null,
                opened_stream: ?ServiceEngine.StreamPort = null,
                fail_peer_port: bool = false,

                fn callback(self: *@This()) ServiceEngine.Callback {
                    return .{ .ctx = self, .call = call };
                }

                fn call(ctx: *anyopaque, output: ServiceEngine.DriveOutput) anyerror!void {
                    const self: *@This() = @ptrCast(@alignCast(ctx));
                    switch (output) {
                        .peer_port => |peer_port| {
                            if (self.fail_peer_port) return error.InjectPeerPortFailure;
                            self.peer_port = peer_port;
                        },
                        .opened_stream => |port| self.opened_stream = port,
                        .outbound => |pkt| {
                            pkt.deinit();
                            return error.UnexpectedOutbound;
                        },
                        .next_tick_deadline => |_| {},
                    }
                }
            };
        }

        fn makeInboundPacket(pool: packet.Inbound.Pool, remote_key: Key, data: []const u8) !*packet.Inbound {
            const inbound = pool.get() orelse return error.OutOfMemory;
            errdefer inbound.deinit();

            const plaintext = inbound.bufRef()[NoiseMessage.TransportHeaderSize..];
            if (plaintext.len < data.len) return error.BufferTooSmall;
            @memcpy(plaintext[0..data.len], data);
            inbound.len = data.len;
            inbound.kind = .transport;
            inbound.state = .ready_to_consume;
            inbound.remote_static = remote_key;
            return inbound;
        }

        fn makeOpenStreamPacket(pool: packet.Outbound.Pool, remote_key: Key, service: u64) !*packet.Outbound {
            const outbound = pool.get() orelse return error.OutOfMemory;
            errdefer outbound.deinit();

            outbound.remote_static = remote_key;
            outbound.len = 0;
            outbound.service_data = .{ .open_stream = .{
                .service = service,
            } };
            return outbound;
        }

        fn initPacketPools(comptime any_lib: type, allocator: glib.std.mem.Allocator, comptime packet_size: usize) !packet.Pools {
            var pools = packet.Pools{
                .inbound = try packet.Inbound.initPool(any_lib, allocator, packet_size),
                .outbound = undefined,
            };
            errdefer pools.inbound.deinit();

            pools.outbound = try packet.Outbound.initPool(any_lib, allocator, packet_size);
            return pools;
        }

        fn deinitPacketPools(pools: *packet.Pools) void {
            pools.outbound.deinit();
            pools.inbound.deinit();
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
