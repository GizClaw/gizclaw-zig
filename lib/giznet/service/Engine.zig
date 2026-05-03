//! Service-layer engine shape.
//!
//! The service engine consumes plaintext packets from noise on inbound paths,
//! and produces plaintext service payloads for noise on outbound paths.

const glib = @import("glib");

const Key = @import("../noise/Key.zig");
const NoiseMessage = @import("../noise/Message.zig");
const PacketInbound = @import("../packet/Inbound.zig");
const PacketOutbound = @import("../packet/Outbound.zig");
const PeerType = @import("Peer.zig");
const PeerTableType = @import("PeerTable.zig");
const protocol_ns = @import("protocol.zig");
const Uvarint = @import("Uvarint.zig");

pub const Config = struct {
    peer: PeerType.Config = .{},
};

pub const DriveInput = union(enum) {
    peer_established: Key,
    close_conn: Key,
    inbound: *PacketInbound,
    outbound: *PacketOutbound,
    tick: void,
};

pub fn make(comptime grt: type) type {
    const PeerTable = PeerTableType.make(grt);
    const PacketChannel = PeerTable.PeerType.PacketChannel;

    return struct {
        peers: PeerTable,

        const Self = @This();
        pub const PeerPort = struct {
            remote_static: Key,
            packet_ch: *PacketChannel,

            pub fn recvPacket(self: PeerPort) @TypeOf(self.packet_ch.recv()) {
                return self.packet_ch.recv();
            }

            pub fn recvPacketTimeout(self: PeerPort, timeout: glib.time.duration.Duration) @TypeOf(self.packet_ch.recvTimeout(timeout)) {
                return self.packet_ch.recvTimeout(timeout);
            }
        };
        pub const DriveOutput = union(enum) {
            peer_port: PeerPort,
            outbound: *PacketOutbound,
            next_tick_deadline: glib.time.instant.Time,
        };
        pub const Callback = struct {
            ctx: *anyopaque,
            call: *const fn (ctx: *anyopaque, output: DriveOutput) anyerror!void,

            pub fn handle(self: Callback, output: DriveOutput) !void {
                try self.call(self.ctx, output);
            }
        };

        pub fn init(allocator: grt.std.mem.Allocator, config: Config) Self {
            return .{
                .peers = PeerTable.init(allocator, config.peer),
            };
        }

        pub fn deinit(self: *Self) void {
            self.peers.deinit();
        }

        pub fn drive(self: *Self, input: DriveInput, callback: Callback) !void {
            switch (input) {
                .tick => {},
                .peer_established => |remote_static| {
                    const peer_result = try self.peers.getOrCreateWithStatus(remote_static);
                    if (peer_result.created) {
                        try callback.handle(.{ .peer_port = .{
                            .remote_static = peer_result.peer.remote_static,
                            .packet_ch = &peer_result.peer.packet_ch,
                        } });
                    }
                },
                .close_conn => |remote_static| {
                    _ = self.peers.remove(remote_static);
                },
                .inbound => |packet| {
                    const frame = try packet.parseServiceData();
                    switch (frame.service_data orelse return error.PayloadNotParsed) {
                        .direct => {
                            const peer_result = try self.peers.getOrCreateWithStatus(packet.remote_static);
                            if (peer_result.created) {
                                try callback.handle(.{ .peer_port = .{
                                    .remote_static = peer_result.peer.remote_static,
                                    .packet_ch = &peer_result.peer.packet_ch,
                                } });
                            }
                            try peer_result.peer.deliverPacket(frame);
                        },
                        .kcp => {
                            return error.ServiceEngineKcpNotImplemented;
                        },
                        .close => {
                            _ = self.peers.remove(packet.remote_static);
                            frame.deinit();
                        },
                    }
                },
                .outbound => |packet| {
                    _ = try self.peers.getOrCreate(packet.remote_static);

                    const service_data = packet.service_data orelse return error.PayloadNotParsed;
                    switch (service_data) {
                        .direct => |direct| {
                            if (direct.protocol == protocol_ns.ProtocolKCP or
                                direct.protocol == protocol_ns.ProtocolConnCtrl) return error.InvalidDirectProtocol;
                            if (packet.len != direct.payload.len + 1) return error.InvalidPacketLength;

                            const plaintext = packet.transportPlaintextBufRef();
                            plaintext[0] = direct.protocol;

                            try callback.handle(.{ .outbound = packet });
                        },
                        .open_stream,
                        .write_stream,
                        => return error.ServiceEngineKcpNotImplemented,
                    }
                },
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
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryDirectInboundTransfersOwnership(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pool = try PacketInbound.initPool(any_lib, grt.std.testing.allocator, 128);
            defer pool.deinit();

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{});
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x21} ** 32 };
            const packet = try makeInboundPacket(pool, remote_key, &[_]u8{0x31} ++ "hello");

            var callback_state: CallbackState(ServiceEngine) = .{};
            try engine.drive(.{ .inbound = packet }, callback_state.callback());

            const peer_port = callback_state.peer_port orelse return error.MissingPeerPort;
            const result = try peer_port.recvPacketTimeout(0);
            try grt.std.testing.expect(result.ok);
            try grt.std.testing.expect(result.value.eql(packet));
            result.value.deinit();
        }

        fn tryDirectInboundCallbackErrorLeavesOwnership(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pool = try PacketInbound.initPool(any_lib, grt.std.testing.allocator, 128);
            defer pool.deinit();

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{});
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x22} ** 32 };
            const packet = try makeInboundPacket(pool, remote_key, &[_]u8{0x32} ++ "hello");
            defer packet.deinit();

            var callback_state: CallbackState(ServiceEngine) = .{ .fail_peer_port = true };
            try grt.std.testing.expectError(
                error.InjectPeerPortFailure,
                engine.drive(.{ .inbound = packet }, callback_state.callback()),
            );
        }

        fn tryDirectInboundChannelFullLeavesOwnership(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pool = try PacketInbound.initPool(any_lib, grt.std.testing.allocator, 128);
            defer pool.deinit();

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{
                .peer = .{ .packet_channel_capacity = 1 },
            });
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x23} ** 32 };
            const first = try makeInboundPacket(pool, remote_key, &[_]u8{0x33} ++ "first");
            const second = try makeInboundPacket(pool, remote_key, &[_]u8{0x33} ++ "second");
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
            var pool = try PacketInbound.initPool(any_lib, grt.std.testing.allocator, 128);
            defer pool.deinit();

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{});
            defer engine.deinit();

            var payload: [4]u8 = undefined;
            payload[0] = protocol_ns.ProtocolKCP;
            const service_len = try Uvarint.write(7, payload[1..]);
            const remote_key = Key{ .bytes = [_]u8{0x24} ** 32 };
            const packet = try makeInboundPacket(pool, remote_key, payload[0 .. 1 + service_len]);
            defer packet.deinit();

            var callback_state: CallbackState(ServiceEngine) = .{};
            try grt.std.testing.expectError(
                error.ServiceEngineKcpNotImplemented,
                engine.drive(.{ .inbound = packet }, callback_state.callback()),
            );
        }

        fn tryCloseInboundConsumesPacket(comptime any_lib: type) !void {
            const ServiceEngine = make(any_lib);
            var pool = try PacketInbound.initPool(any_lib, grt.std.testing.allocator, 128);
            defer pool.deinit();

            var engine = ServiceEngine.init(grt.std.testing.allocator, .{});
            defer engine.deinit();

            const remote_key = Key{ .bytes = [_]u8{0x25} ** 32 };
            const packet = try makeInboundPacket(pool, remote_key, &[_]u8{protocol_ns.ProtocolConnCtrl});
            var callback_state: CallbackState(ServiceEngine) = .{};
            try engine.drive(.{ .inbound = packet }, callback_state.callback());
        }

        fn CallbackState(comptime ServiceEngine: type) type {
            return struct {
                peer_port: ?ServiceEngine.PeerPort = null,
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
                        .outbound => |packet| {
                            packet.deinit();
                            return error.UnexpectedOutbound;
                        },
                        .next_tick_deadline => |_| {},
                    }
                }
            };
        }

        fn makeInboundPacket(pool: PacketInbound.Pool, remote_key: Key, data: []const u8) !*PacketInbound {
            const packet = pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();

            const plaintext = packet.bufRef()[NoiseMessage.TransportHeaderSize..];
            if (plaintext.len < data.len) return error.BufferTooSmall;
            @memcpy(plaintext[0..data.len], data);
            packet.len = data.len;
            packet.kind = .transport;
            packet.state = .ready_to_consume;
            packet.remote_static = remote_key;
            return packet;
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
