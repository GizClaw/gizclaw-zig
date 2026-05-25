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
    local_static: Key = .{},
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
    const PacketChannelRef = PeerTable.PeerType.PacketChannelRef;
    const KcpStreamTable = KcpStreamTableType.make(grt);
    const KcpStream = KcpStreamTable.Stream;
    const StreamAcceptChannelRef = PeerTable.PeerType.StreamAcceptChannelRef;

    return struct {
        allocator: grt.std.mem.Allocator,
        local_static: Key,
        peers: PeerTable,
        streams: KcpStreamTable,

        const Self = @This();
        pub const StreamPort = KcpStream.Port;
        pub const PeerPort = struct {
            remote_static: Key,
            packet_ch: PacketChannelRef,
            stream_accept_ch: StreamAcceptChannelRef,

            pub fn recvPacket(self: PeerPort) @TypeOf(self.packet_ch.ptr().recv()) {
                return self.packet_ch.ptr().recv();
            }

            pub fn recvPacketTimeout(self: PeerPort, timeout: glib.time.duration.Duration) @TypeOf(self.packet_ch.ptr().recvTimeout(timeout)) {
                return self.packet_ch.ptr().recvTimeout(timeout);
            }

            pub fn acceptStream(self: PeerPort, timeout: ?glib.time.duration.Duration) @TypeOf(self.stream_accept_ch.ptr().recv()) {
                if (timeout) |duration| {
                    return self.stream_accept_ch.ptr().recvTimeout(duration);
                }
                return self.stream_accept_ch.ptr().recv();
            }

            pub fn close(self: PeerPort) void {
                self.packet_ch.ptr().close();
                self.stream_accept_ch.ptr().close();
            }

            pub fn clone(self: PeerPort) PeerPort {
                return .{
                    .remote_static = self.remote_static,
                    .packet_ch = self.packet_ch.clone(),
                    .stream_accept_ch = self.stream_accept_ch.clone(),
                };
            }

            pub fn deinit(self: *PeerPort) void {
                self.stream_accept_ch.deinit();
                self.packet_ch.deinit();
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
                .local_static = config.local_static,
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
                            if (kcp.stream > grt.std.math.maxInt(u32)) return error.InvalidKcpStreamId;
                            switch (kcp.frame_type) {
                                protocol_ns.KcpMuxFrameOpen => {
                                    if (kcp.frame.len != 0) return error.InvalidKcpPacket;
                                },
                                protocol_ns.KcpMuxFrameData,
                                protocol_ns.KcpMuxFrameClose,
                                protocol_ns.KcpMuxFrameCloseAck,
                                => {},
                                else => return error.InvalidKcpPacket,
                            }

                            if (kcp.frame_type == protocol_ns.KcpMuxFrameClose or
                                kcp.frame_type == protocol_ns.KcpMuxFrameCloseAck)
                            {
                                frame.deinit();
                                return;
                            }

                            const peer_result = try self.peers.getOrCreateWithStatus(pkt.remote_static);
                            if (peer_result.created) {
                                try callback.handle(.{ .peer_port = self.peerPort(peer_result.peer) });
                            }
                            const stream_result = switch (kcp.frame_type) {
                                protocol_ns.KcpMuxFrameOpen => try self.streams.getOrCreate(pkt.remote_static, kcp.service, @intCast(kcp.stream)),
                                protocol_ns.KcpMuxFrameData => try self.streams.getOrCreateFromFrame(pkt.remote_static, kcp.service, kcp.frame),
                                else => unreachable,
                            };
                            switch (kcp.frame_type) {
                                protocol_ns.KcpMuxFrameOpen => {
                                    if (stream_result.created) {
                                        try peer_result.peer.deliverStream(stream_result.stream.port());
                                    }
                                    frame.deinit();
                                },
                                protocol_ns.KcpMuxFrameData => {
                                    if (stream_result.created) {
                                        try peer_result.peer.deliverStream(stream_result.stream.port());
                                    }
                                    var stream_callback = StreamCallback{ .service = self, .parent_callback = callback };
                                    try stream_result.stream.drive(.{ .inbound = frame }, stream_callback.callback());
                                },
                                else => unreachable,
                            }
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
                            const stream_result = try self.streams.open(self.local_static, pkt.remote_static, open_stream.service);
                            _ = peer;
                            try self.prepareKcpControlOutbound(pkt, open_stream.service, stream_result.stream.stream, protocol_ns.KcpMuxFrameOpen, "");
                            try callback.handle(.{ .outbound = pkt });
                            try callback.handle(.{ .opened_stream = stream_result.stream.port() });
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
                        .close_stream => |close_stream| {
                            if (close_stream.stream > grt.std.math.maxInt(u32)) return error.InvalidKcpStreamId;
                            try self.prepareKcpControlOutbound(
                                pkt,
                                close_stream.service,
                                @intCast(close_stream.stream),
                                protocol_ns.KcpMuxFrameClose,
                                &[_]u8{0},
                            );
                            try callback.handle(.{ .outbound = pkt });
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
                .packet_ch = peer.packet_ch.clone(),
                .stream_accept_ch = peer.stream_accept_ch.clone(),
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
            const header_len = 1 + service_len + 1;
            if (plaintext.len < header_len + write.payload.len) return error.BufferTooSmall;

            glib.std.mem.copyBackwards(u8, plaintext[header_len..][0..write.payload.len], write.payload);
            plaintext[0] = protocol_ns.ProtocolKCP;
            @memcpy(plaintext[1..][0..service_len], service_buf[0..service_len]);
            plaintext[1 + service_len] = protocol_ns.KcpMuxFrameData;
            outbound.len = header_len + write.payload.len;
        }

        fn prepareKcpControlOutbound(
            self: *Self,
            outbound: *packet.Outbound,
            service: u64,
            stream: u32,
            frame_type: u8,
            payload: []const u8,
        ) !void {
            _ = self;
            const plaintext = outbound.transportPlaintextBufRef();

            var service_buf: [10]u8 = undefined;
            const service_len = try Uvarint.write(service, service_buf[0..]);
            const header_len = 1 + service_len + 1 + 4;
            if (plaintext.len < header_len + payload.len) return error.BufferTooSmall;

            plaintext[0] = protocol_ns.ProtocolKCP;
            @memcpy(plaintext[1..][0..service_len], service_buf[0..service_len]);
            plaintext[1 + service_len] = frame_type;
            glib.std.mem.writeInt(u32, plaintext[1 + service_len + 1 ..][0..4], stream, .little);
            if (payload.len != 0) {
                @memcpy(plaintext[header_len..][0..payload.len], payload);
            }
            outbound.len = header_len + payload.len;
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
            tryInvalidKcpMuxFrameDoesNotCreateState(grt) catch |err| {
                t.logErrorf("giznet/service Engine invalid kcp mux state failed: {}", .{err});
                return false;
            };
            tryCloseInboundConsumesPacket(grt) catch |err| {
                t.logErrorf("giznet/service Engine close inbound ownership failed: {}", .{err});
                return false;
            };
            tryRemovedPeerPortDoesNotUseFreedChannel(grt) catch |err| {
                t.logErrorf("giznet/service Engine removed peer port channel lifetime failed: {}", .{err});
                return false;
            };
            tryOpenStreamReturnsPort(grt) catch |err| {
                t.logErrorf("giznet/service Engine open stream port failed: {}", .{err});
                return false;
            };
            tryOpenStreamWritesKcpMuxOpenFrame(grt) catch |err| {
                t.logErrorf("giznet/service Engine open stream mux frame failed: {}", .{err});
                return false;
            };
            tryWriteStreamWritesKcpMuxDataFrame(grt) catch |err| {
                t.logErrorf("giznet/service Engine write stream mux frame failed: {}", .{err});
                return false;
            };
            tryCloseStreamWritesKcpMuxCloseFrame(grt) catch |err| {
                t.logErrorf("giznet/service Engine close stream mux frame failed: {}", .{err});
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
            defer callback_state.deinit();
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
            defer callback_state.deinit();
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
            defer callback_state.deinit();
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
            defer callback_state.deinit();
            engine.drive(.{ .inbound = pkt }, callback_state.callback()) catch return;
            return error.ExpectedKcpInboundFailure;
        }

        fn tryInvalidKcpMuxFrameDoesNotCreateState(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            var payload: [32]u8 = undefined;
            payload[0] = protocol_ns.ProtocolKCP;
            const service_len = try Uvarint.write(7, payload[1..]);
            const frame_type_offset = 1 + service_len;
            payload[frame_type_offset] = 0xff;

            const remote_key = Key{ .bytes = [_]u8{0x27} ** 32 };
            const pkt = try makeInboundPacket(
                pools.inbound,
                remote_key,
                payload[0 .. frame_type_offset + 1],
            );
            defer pkt.deinit();

            var callback_state: CallbackState(ServiceEngine) = .{};
            defer callback_state.deinit();
            try grt.std.testing.expectError(
                error.InvalidKcpPacket,
                engine.drive(.{ .inbound = pkt }, callback_state.callback()),
            );
            try grt.std.testing.expect(engine.peers.get(remote_key) == null);
            try grt.std.testing.expect(engine.streams.get(remote_key, 7, 1) == null);
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
            defer callback_state.deinit();
            try engine.drive(.{ .inbound = pkt }, callback_state.callback());
        }

        fn tryRemovedPeerPortDoesNotUseFreedChannel(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x28} ** 32 };
            var callback_state: CallbackState(ServiceEngine) = .{};
            defer callback_state.deinit();
            try engine.drive(.{ .peer_established = remote_key }, callback_state.callback());
            var peer_port = (callback_state.peer_port orelse return error.MissingPeerPort).clone();
            defer peer_port.deinit();

            try engine.drive(.{ .close_conn = remote_key }, callback_state.callback());

            const replacement_key = Key{ .bytes = [_]u8{0x29} ** 32 };
            try engine.drive(.{ .peer_established = replacement_key }, callback_state.callback());

            const result = try peer_port.acceptStream(0);
            if (result.ok) {
                return error.TestUnexpectedResult;
            }
        }

        fn tryOpenStreamReturnsPort(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x26} ** 32 };
            var callback_state: CallbackState(ServiceEngine) = .{ .allow_outbound = true };
            defer callback_state.deinit();
            try engine.drive(.{ .peer_established = remote_key }, callback_state.callback());

            const pkt = try makeOpenStreamPacket(pools.outbound, remote_key, 9);
            try engine.drive(.{ .outbound = pkt }, callback_state.callback());

            const port = callback_state.opened_stream orelse return error.MissingOpenedStream;
            try grt.std.testing.expect(port.remote_static.eql(remote_key));
            try grt.std.testing.expectEqual(@as(u64, 9), port.service);
            try grt.std.testing.expectEqual(@as(u32, 1), port.stream);
            try grt.std.testing.expectEqual(@as(usize, 1), callback_state.outbound_count);
        }

        fn tryOpenStreamWritesKcpMuxOpenFrame(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x28} ** 32 };
            var callback_state: CallbackState(ServiceEngine) = .{ .allow_outbound = true };
            defer callback_state.deinit();
            const pkt = try makeOpenStreamPacket(pools.outbound, remote_key, 9);
            try engine.drive(.{ .outbound = pkt }, callback_state.callback());

            try grt.std.testing.expectEqual(@as(usize, 1), callback_state.outbound_count);
            try grt.std.testing.expectEqualSlices(u8, &[_]u8{
                protocol_ns.ProtocolKCP,
                9,
                protocol_ns.KcpMuxFrameOpen,
                1,
                0,
                0,
                0,
            }, callback_state.outbound_buf[0..callback_state.outbound_len]);
        }

        fn tryWriteStreamWritesKcpMuxDataFrame(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 256);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x2a} ** 32 };
            const stream: u64 = 0x01020304;
            var callback_state: CallbackState(ServiceEngine) = .{ .allow_outbound = true };
            defer callback_state.deinit();
            const pkt = try makeWriteStreamPacket(pools.outbound, remote_key, 9, stream, "hello");
            try engine.drive(.{ .outbound = pkt }, callback_state.callback());

            try grt.std.testing.expectEqual(@as(usize, 1), callback_state.outbound_count);
            try grt.std.testing.expect(callback_state.outbound_len >= 7);
            try grt.std.testing.expectEqual(protocol_ns.ProtocolKCP, callback_state.outbound_buf[0]);
            try grt.std.testing.expectEqual(@as(u8, 9), callback_state.outbound_buf[1]);
            try grt.std.testing.expectEqual(protocol_ns.KcpMuxFrameData, callback_state.outbound_buf[2]);
            try grt.std.testing.expectEqual(
                @as(u32, @intCast(stream)),
                glib.std.mem.readInt(u32, callback_state.outbound_buf[3..7], .little),
            );
        }

        fn tryCloseStreamWritesKcpMuxCloseFrame(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pools = try initPacketPools(any_lib, grt.std.testing.allocator, 128);
            defer deinitPacketPools(&pools);

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{}, &pools);
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x29} ** 32 };
            var callback_state: CallbackState(ServiceEngine) = .{ .allow_outbound = true };
            defer callback_state.deinit();
            const pkt = try makeCloseStreamPacket(pools.outbound, remote_key, 9, 3);
            try engine.drive(.{ .outbound = pkt }, callback_state.callback());

            try grt.std.testing.expectEqual(@as(usize, 1), callback_state.outbound_count);
            try grt.std.testing.expectEqualSlices(u8, &[_]u8{
                protocol_ns.ProtocolKCP,
                9,
                protocol_ns.KcpMuxFrameClose,
                3,
                0,
                0,
                0,
                0,
            }, callback_state.outbound_buf[0..callback_state.outbound_len]);
        }

        fn CallbackState(comptime ServiceEngine: type) type {
            return struct {
                peer_port: ?ServiceEngine.PeerPort = null,
                opened_stream: ?ServiceEngine.StreamPort = null,
                fail_peer_port: bool = false,
                allow_outbound: bool = false,
                outbound_count: usize = 0,
                outbound_buf: [64]u8 = undefined,
                outbound_len: usize = 0,

                fn callback(self: *@This()) ServiceEngine.Callback {
                    return .{ .ctx = self, .call = call };
                }

                fn deinit(self: *@This()) void {
                    if (self.peer_port) |*peer_port| {
                        peer_port.deinit();
                        self.peer_port = null;
                    }
                    if (self.opened_stream) |*port| {
                        port.deinit();
                        self.opened_stream = null;
                    }
                }

                fn call(ctx: *anyopaque, output: ServiceEngine.DriveOutput) anyerror!void {
                    const self: *@This() = @ptrCast(@alignCast(ctx));
                    switch (output) {
                        .peer_port => |peer_port| {
                            if (self.fail_peer_port) return error.InjectPeerPortFailure;
                            if (self.peer_port) |*previous| previous.deinit();
                            self.peer_port = peer_port;
                        },
                        .opened_stream => |port| {
                            if (self.opened_stream) |*previous| previous.deinit();
                            self.opened_stream = port;
                        },
                        .outbound => |pkt| {
                            const plaintext = pkt.transportPlaintextBufRef()[0..pkt.len];
                            if (plaintext.len > self.outbound_buf.len) return error.OutboundCaptureTooSmall;
                            @memcpy(self.outbound_buf[0..plaintext.len], plaintext);
                            self.outbound_len = plaintext.len;
                            self.outbound_count += 1;
                            pkt.deinit();
                            if (self.allow_outbound) return;
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

        fn makeWriteStreamPacket(
            pool: packet.Outbound.Pool,
            remote_key: Key,
            service: u64,
            stream: u64,
            payload: []const u8,
        ) !*packet.Outbound {
            const outbound = pool.get() orelse return error.OutOfMemory;
            errdefer outbound.deinit();

            const plaintext = outbound.transportPlaintextBufRef();
            if (plaintext.len < payload.len) return error.BufferTooSmall;
            @memcpy(plaintext[0..payload.len], payload);

            outbound.remote_static = remote_key;
            outbound.len = payload.len;
            outbound.service_data = .{ .write_stream = .{
                .service = service,
                .stream = stream,
                .payload = plaintext[0..payload.len],
            } };
            return outbound;
        }

        fn makeCloseStreamPacket(pool: packet.Outbound.Pool, remote_key: Key, service: u64, stream: u64) !*packet.Outbound {
            const outbound = pool.get() orelse return error.OutOfMemory;
            errdefer outbound.deinit();

            outbound.remote_static = remote_key;
            outbound.len = 0;
            outbound.service_data = .{ .close_stream = .{
                .service = service,
                .stream = stream,
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
