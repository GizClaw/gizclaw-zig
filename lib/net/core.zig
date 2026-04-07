const noise = @import("noise.zig");

const root = @This();

const consts = @import("core/consts.zig");
const errors = @import("core/errors.zig");
pub const Conn = @import("core/Conn.zig");
pub const Dialer = @import("core/Dialer.zig");
pub const Host = @import("core/Host.zig");
pub const Listener = @import("core/Listener.zig");
pub const protocol = @import("core/protocol.zig");
pub const ServiceMux = @import("core/ServiceMux.zig");
pub const SessionManager = @import("core/SessionManager.zig");
pub const UDP = @import("core/UDP.zig");

pub const Error = errors.Error;

pub const MaxPayloadSize = noise.MaxPayloadSize;
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

pub fn isFoundationProtocol(value: u8) bool {
    return protocol.isFoundation(value);
}

pub fn isStreamProtocol(value: u8) bool {
    return protocol.isStream(value);
}

pub fn isDirectProtocol(value: u8) bool {
    return protocol.isDirect(value);
}

pub fn make(comptime lib: type) type {
    const Noise = noise.make(lib);
    const DialerType = Dialer.make(lib, Noise);

    return struct {
        pub const Conn = root.Conn.make(Noise);
        pub const Dial = DialerType;
        pub const Dialer = DialerType;
        pub const Host = root.Host.make(lib, Noise);
        pub const Listener = root.Listener.make(lib, Noise);
        pub const ServiceMux = root.ServiceMux.make(lib, Noise);
        pub const SessionManager = root.SessionManager.make(lib, Noise);
        pub const UDP = root.UDP.make(lib, Noise);
    };
}
