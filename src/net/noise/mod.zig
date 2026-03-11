const std = @import("std");
const runtime = @import("embed").runtime;

const keypair = @import("keypair.zig");
const replay = @import("replay.zig");
const message = @import("message.zig");
const crypto = @import("crypto.zig");
const cipher = @import("cipher.zig");
const state = @import("state.zig");
const handshake = @import("handshake.zig");
const session = @import("session.zig");

pub const Key = keypair.Key;
pub const key_size = keypair.key_size;
pub const ReplayFilter = replay.ReplayFilter;
pub const MessageType = message.MessageType;
pub const HandshakeInit = message.HandshakeInit;
pub const HandshakeResp = message.HandshakeResp;
pub const TransportMessage = message.TransportMessage;
pub const tag_size = crypto.tag_size;
pub const hash_size = crypto.hash_size;

pub fn Protocol(comptime Crypto: type) type {
    const hs = handshake.Handshake(Crypto);
    const st = state.State(Crypto);
    const sess = session.SessionMod(Crypto);

    return struct {
        pub const KeyPair = keypair.KeyPair(Crypto);
        pub const CipherState = st.CipherState;
        pub const SymmetricState = st.SymmetricState;
        pub const HandshakeState = hs.HandshakeState;
        pub const Config = hs.Config;
        pub const Session = sess.Session;

        pub const Key = keypair.Key;
        pub const key_size = keypair.key_size;
        pub const Pattern = handshake.Pattern;
        pub const Error = handshake.Error;
        pub const SessionConfig = session.SessionConfig;
        pub const SessionState = session.SessionState;
        pub const SessionError = session.SessionError;
        pub const ReplayFilter = replay.ReplayFilter;
    };
}

pub const StdProtocol = Protocol(runtime.std.Crypto);
pub const Pattern = handshake.Pattern;
pub const Error = handshake.Error;
pub const SessionConfig = session.SessionConfig;
pub const SessionState = session.SessionState;
pub const SessionError = session.SessionError;

test {
    std.testing.refAllDecls(@This());

    _ = keypair;
    _ = replay;
    _ = message;
    _ = crypto;
    _ = cipher;
    _ = state;
    _ = handshake;
    _ = session;
}
