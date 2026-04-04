const dep = @import("dep");
const testing_api = dep.testing;

const root = @This();
const conn = @import("peer/Conn.zig");
const listener = @import("peer/Listener.zig");
const stream = @import("peer/Stream.zig");
const errors = @import("peer/errors.zig");
const opus_frame = @import("peer/opus_frame.zig");
const prologue = @import("peer/prologue.zig");

pub const Error = errors.Error;

pub const PrologueVersion = prologue.PrologueVersion;
pub const ServicePublic = prologue.ServicePublic;
pub const ServiceAdmin = prologue.ServiceAdmin;
pub const ServiceReverse = prologue.ServiceReverse;

pub const RPCRequest = prologue.RPCRequest;
pub const RPCResponse = prologue.RPCResponse;
pub const RPCError = prologue.RPCError;
pub const Event = prologue.Event;

pub const OpusFrameVersion = opus_frame.OpusFrameVersion;
pub const MaxOpusTimestamp = opus_frame.max_timestamp;
pub const EpochMillis = opus_frame.EpochMillis;
pub const StampedOpusFrame = opus_frame.StampedOpusFrame;

pub const encodeRPCRequest = prologue.encodeRPCRequest;
pub const decodeRPCRequest = prologue.decodeRPCRequest;
pub const encodeRPCResponse = prologue.encodeRPCResponse;
pub const decodeRPCResponse = prologue.decodeRPCResponse;
pub const encodeEvent = prologue.encodeEvent;
pub const decodeEvent = prologue.decodeEvent;

pub const stampOpusFrame = opus_frame.stampOpusFrame;
pub const parseStampedOpusFrame = opus_frame.parseStampedOpusFrame;

pub fn make(comptime Core: type) type {
    return struct {
        pub const Error = errors.Error;

        pub const PrologueVersion = root.PrologueVersion;
        pub const ServicePublic = root.ServicePublic;
        pub const ServiceAdmin = root.ServiceAdmin;
        pub const ServiceReverse = root.ServiceReverse;

        pub const RPCRequest = root.RPCRequest;
        pub const RPCResponse = root.RPCResponse;
        pub const RPCError = root.RPCError;
        pub const Event = root.Event;

        pub const OpusFrameVersion = root.OpusFrameVersion;
        pub const MaxOpusTimestamp = root.MaxOpusTimestamp;
        pub const EpochMillis = root.EpochMillis;
        pub const StampedOpusFrame = root.StampedOpusFrame;

        pub const Stream = stream.make(Core);
        pub const Conn = conn.make(Core);
        pub const Listener = listener.make(Core);

        pub const encodeRPCRequest = root.encodeRPCRequest;
        pub const decodeRPCRequest = root.decodeRPCRequest;
        pub const encodeRPCResponse = root.encodeRPCResponse;
        pub const decodeRPCResponse = root.decodeRPCResponse;
        pub const encodeEvent = root.encodeEvent;
        pub const decodeEvent = root.decodeEvent;
        pub const stampOpusFrame = root.stampOpusFrame;
        pub const parseStampedOpusFrame = root.parseStampedOpusFrame;
    };
}

test "net/unit_tests/peer" {
    const runtime = dep.embed_std.std;
    const peer_runner = @import("test_runner/unit/peer.zig");

    var t = testing_api.T.new(runtime, .peer);
    defer t.deinit();

    t.timeout(5 * runtime.time.ns_per_s);
    t.run("peer", peer_runner.runner(runtime));
    if (!t.wait()) return error.TestFailed;
}
