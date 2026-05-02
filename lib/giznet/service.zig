//! `giznet/service` routes plaintext payloads above the noise transport.

const packet_ns = @import("packet.zig");
const ServiceEngine = @import("service/Engine.zig");
const ServicePeer = @import("service/Peer.zig");
const ServicePeerTable = @import("service/PeerTable.zig");
const ServiceUvarint = @import("service/Uvarint.zig");
const protocol_ns = @import("service/protocol.zig");

pub const packet = packet_ns;
pub const Engine = ServiceEngine;
pub const Peer = ServicePeer;
pub const PeerTable = ServicePeerTable;
pub const Uvarint = ServiceUvarint;
pub const ProtocolKCP = protocol_ns.ProtocolKCP;
pub const ProtocolConnCtrl = protocol_ns.ProtocolConnCtrl;

pub fn make(comptime grt: type) type {
    return struct {
        pub const packet = packet_ns;
        pub const Engine = ServiceEngine.make(grt);
        pub const Peer = ServicePeer.make(grt);
        pub const PeerTable = ServicePeerTable.make(grt);
        pub const Uvarint = ServiceUvarint;
        pub const ProtocolKCP = protocol_ns.ProtocolKCP;
        pub const ProtocolConnCtrl = protocol_ns.ProtocolConnCtrl;
    };
}
