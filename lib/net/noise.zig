const dep = @import("dep");
const KeyFile = @import("noise/Key.zig");
const KeyPairFile = @import("noise/KeyPair.zig");
const ReplayFilterFile = @import("noise/ReplayFilter.zig");
const Blake2sFile = @import("noise/Blake2s.zig");
const cipher_ns = @import("noise/cipher.zig");
const CipherStateFile = @import("noise/CipherState.zig");
const SymmetricStateFile = @import("noise/SymmetricState.zig");
const HandshakeFile = @import("noise/Handshake.zig");
const SessionFile = @import("noise/Session.zig");
const varint = @import("noise/varint.zig");
const message = @import("noise/message.zig");
const errors = @import("noise/errors.zig");

pub const Key = KeyFile;
pub const PublicKey = KeyFile;
pub const KeyPair = KeyPairFile;
pub const ReplayFilter = ReplayFilterFile;
pub const Blake2s = Blake2sFile;
pub const Blake2s256 = Blake2sFile;
pub const Cipher = cipher_ns;
pub const CipherState = CipherStateFile;
pub const SymmetricState = SymmetricStateFile;
pub const Handshake = HandshakeFile;
pub const Session = SessionFile;

pub const MessageType = message.MessageType;
pub const HandshakeInit = message.HandshakeInit;
pub const HandshakeResp = message.HandshakeResp;
pub const TransportMessage = message.TransportMessage;

pub const Varint = varint;
pub const Message = message;

pub const Pattern = HandshakeFile.Pattern;
pub const SessionState = SessionFile.State;
pub const SessionConfig = SessionFile.Config;
pub const SessionTimeoutMs = SessionFile.session_timeout_ms;
pub const MaxNonce = SessionFile.max_nonce;
pub const HashSize = cipher_ns.hash_size;
pub const TagSize = cipher_ns.tag_size;
pub const SuiteName = cipher_ns.suite_name;

pub const MaxPayloadSize = message.max_payload_size;
pub const MaxPacketSize = message.max_packet_size;

pub const KeyError = errors.KeyError;
pub const CipherError = errors.CipherError;
pub const MessageError = errors.MessageError;
pub const HandshakeError = errors.HandshakeError;
pub const SessionError = errors.SessionError;

pub fn make(comptime lib: type) type {
    return struct {
        pub const KeyPair = KeyPairFile.make(lib);
        pub const CipherState = CipherStateFile.make(lib);
        pub const SymmetricState = SymmetricStateFile.make(lib);
        pub const Handshake = HandshakeFile.make(lib);
        pub const Session = SessionFile.make(lib);

        pub const Key = KeyFile;
        pub const PublicKey = KeyFile;
        pub const ReplayFilter = ReplayFilterFile.make(lib);
        pub const Pattern = HandshakeFile.Pattern;
        pub const Varint = varint;
        pub const Message = message;
    };
}

test "net/unit_tests/noise" {
    const runtime = dep.embed_std.std;
    const testing_api = dep.testing;
    const noise_runner = @import("test_runner/unit/noise.zig");

    var t = testing_api.T.new(runtime, .noise);
    defer t.deinit();

    t.timeout(5 * runtime.time.ns_per_s);
    t.run("noise", noise_runner.runner(runtime));
    if (!t.wait()) return error.TestFailed;
}
