const key = @import("noise/key.zig");
const key_pair = @import("noise/key_pair.zig");
const replay_filter = @import("noise/replay_filter.zig");
const transport = @import("noise/transport.zig");
const blake2s = @import("noise/blake2s.zig");
const lib_adapter = @import("noise/lib_adapter.zig");
const cipher = @import("noise/cipher.zig");
const cipher_state = @import("noise/cipher_state.zig");
const symmetric_state = @import("noise/symmetric_state.zig");
const handshake = @import("noise/handshake.zig");
const session = @import("noise/session.zig");
const varint = @import("noise/varint.zig");
const address = @import("noise/address.zig");
const message = @import("noise/message.zig");
const errors = @import("noise/errors.zig");

pub const Key = key;
pub const PublicKey = key;
pub const ReplayFilter = replay_filter;
pub const Blake2s256 = blake2s;
pub const LibAdapter = lib_adapter;

pub const MessageType = message.MessageType;
pub const HandshakeInit = message.HandshakeInit;
pub const HandshakeResp = message.HandshakeResp;
pub const TransportMessage = message.TransportMessage;

pub const Address = address;
pub const AddressType = address.Type;
pub const Addr = transport.Addr;
pub const Transport = transport.Transport;
pub const Varint = varint;
pub const Message = message;

pub const Pattern = handshake.Pattern;
pub const SessionState = session.State;
pub const SessionConfig = session.Config;
pub const SessionTimeoutMs = session.session_timeout_ms;
pub const MaxNonce = session.max_nonce;
pub const HashSize = cipher.hash_size;
pub const TagSize = cipher.tag_size;
pub const SuiteName = cipher.suite_name;

pub const MaxPayloadSize = message.max_payload_size;
pub const MaxPacketSize = message.max_packet_size;

pub const KeyError = errors.KeyError;
pub const CipherError = errors.CipherError;
pub const MessageError = errors.MessageError;
pub const HandshakeError = errors.HandshakeError;
pub const SessionError = errors.SessionError;

pub fn make(comptime Crypto: type) type {
    return struct {
        pub const KeyPair = key_pair.KeyPair(Crypto);
        pub const CipherState = cipher_state.CipherState(Crypto);
        pub const SymmetricState = symmetric_state.SymmetricState(Crypto);
        pub const Handshake = handshake.Handshake(Crypto);
        pub const Session = session.Session(Crypto);

        pub const Key = key;
        pub const PublicKey = key;
        pub const ReplayFilter = replay_filter;
        pub const Pattern = handshake.Pattern;
        pub const Address = address;
        pub const Addr = transport.Addr;
        pub const Transport = transport.Transport;
        pub const Varint = varint;
        pub const Message = message;
    };
}
