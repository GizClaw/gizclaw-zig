//! Service-layer engine shape.
//!
//! The service engine consumes plaintext packets from noise on inbound paths,
//! and produces plaintext service payloads for noise on outbound paths.

const glib = @import("glib");

const Key = @import("../noise/Key.zig");
const PacketInbound = @import("../packet/Inbound.zig");
const PacketOutbound = @import("../packet/Outbound.zig");
const PeerType = @import("Peer.zig");
const PeerTableType = @import("PeerTable.zig");
const protocol_ns = @import("protocol.zig");

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
            inbound_delivered: void,
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
                            try callback.handle(.{ .inbound_delivered = {} });
                        },
                        .kcp => {
                            frame.deinit();
                            return error.ServiceEngineKcpNotImplemented;
                        },
                        .close => {
                            frame.deinit();
                            _ = self.peers.remove(packet.remote_static);
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
