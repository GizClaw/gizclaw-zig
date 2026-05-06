//! `giznet/service` routes plaintext payloads above the noise transport.

const packet_ns = @import("packet.zig");
const EngineType = @import("service/Engine.zig");
const KcpStreamType = @import("service/KcpStream.zig");
const KcpStreamTableType = @import("service/KcpStreamTable.zig");
const PeerType = @import("service/Peer.zig");
const PeerTableType = @import("service/PeerTable.zig");
const protocol_ns = @import("service/protocol.zig");

pub const ProtocolKCP = protocol_ns.ProtocolKCP;
pub const ProtocolConnCtrl = protocol_ns.ProtocolConnCtrl;

pub fn make(comptime grt: type) type {
    return struct {
        pub const packet = packet_ns;
        pub const Engine = EngineType.make(grt);
        pub const KcpStream = KcpStreamType.make(grt);
        pub const KcpStreamTable = KcpStreamTableType.make(grt);
        pub const Peer = PeerType.make(grt);
        pub const PeerTable = PeerTableType.make(grt);
        pub const Uvarint = @import("service/Uvarint.zig");
        pub const ProtocolKCP = protocol_ns.ProtocolKCP;
        pub const ProtocolConnCtrl = protocol_ns.ProtocolConnCtrl;
    };
}
