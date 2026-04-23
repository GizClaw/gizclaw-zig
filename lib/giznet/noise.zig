//! `giznet/noise` is a giznet-specific handshake/session package.
//! It is intentionally self-contained and distinct from `lib/net/noise`.

const CipherFile = @import("noise/Cipher.zig");
const EngineFile = @import("noise/Engine.zig");
const SessionType = @import("noise/Session.zig");

pub const Key = @import("noise/Key.zig");
pub const KeyPair = @import("noise/KeyPair.zig");
pub const Cipher = CipherFile;
pub const Engine = EngineFile;
pub const default_cipher_kind: Cipher.Kind = Cipher.default_kind;

pub fn make(comptime lib: type, comptime cipher_kind: Cipher.Kind) type {
    return struct {
        pub const Key = @import("noise/Key.zig");
        pub const KeyPair = @import("noise/KeyPair.zig");
        pub const Blake2s = @import("noise/Blake2s.zig");
        pub const Cipher = @import("noise/Cipher.zig");
        pub const Message = @import("noise/Message.zig");
        pub const Handshake = @import("noise/Handshake.zig").make(lib, cipher_kind);
        pub const Session = SessionType.make(lib, SessionType.legacy_packet_size_capacity, cipher_kind);
        pub const Engine = EngineFile.make(lib, SessionType.legacy_packet_size_capacity, cipher_kind);
        pub const TimerState = @import("noise/TimerState.zig");
        pub const Peer = @import("noise/Peer.zig").make(lib, cipher_kind);
        pub const PeerTable = @import("noise/PeerTable.zig").make(lib, cipher_kind);
    };
}
