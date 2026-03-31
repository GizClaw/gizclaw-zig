const noise = @import("noise");

const consts = @import("core/consts.zig");
const conn = @import("core/conn.zig");
const dial = @import("core/dial.zig");
const errors = @import("core/errors.zig");
const host = @import("core/host.zig");
const listener = @import("core/listener.zig");
const protocol = @import("core/protocol.zig");
const service_mux = @import("core/service_mux.zig");
const session_manager = @import("core/session_manager.zig");

pub const Error = errors.Error;

pub const ProtocolHTTP = protocol.http;
pub const ProtocolRPC = protocol.rpc;
pub const ProtocolEVENT = protocol.event;
pub const ProtocolOPUS = protocol.opus;
pub const ProtocolKind = protocol.Kind;

pub const RekeyAfterTimeMs = consts.rekey_after_time_ms;
pub const RekeyAttemptTimeMs = consts.rekey_attempt_time_ms;
pub const RekeyTimeoutMs = consts.rekey_timeout_ms;
pub const KeepaliveTimeoutMs = consts.keepalive_timeout_ms;
pub const RekeyOnRecvThresholdMs = consts.rekey_on_recv_threshold_ms;
pub const RekeyAfterMessages = consts.rekey_after_messages;
pub const RawQueueSize = consts.raw_queue_size;
pub const DecryptedQueueSize = consts.decrypted_queue_size;
pub const InboundQueueSize = consts.inbound_queue_size;
pub const DefaultAcceptQueueSize = consts.default_accept_queue_size;

pub const ConnState = conn.State;
pub const TickAction = conn.TickAction;
pub const DecryptResult = conn.DecryptResult;
pub const ServiceMuxConfig = service_mux.Config;
pub const StreamAdapter = service_mux.StreamAdapter;
pub const HostPeerState = host.PeerState;
pub const HostRoute = host.Route;

pub fn isFoundationProtocol(value: u8) bool {
    return protocol.isFoundation(value);
}

pub fn isStreamProtocol(value: u8) bool {
    return protocol.isStream(value);
}

pub fn isDirectProtocol(value: u8) bool {
    return protocol.isDirect(value);
}

pub fn make(comptime Crypto: type) type {
    const Noise = noise.make(Crypto);

    return struct {
        pub const Conn = conn.Conn(Noise);
        pub const Dial = dial.Dial(Noise);
        pub const Listener = listener.Listener(Noise);
        pub const SessionManager = session_manager.SessionManager(Noise);
        pub const ServiceMux = service_mux.ServiceMux(Noise);
        pub const Host = host.Host(Noise);
    };
}
