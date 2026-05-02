//! `giznet/runtime` coordinates UDP, noise, and service engines.

const GizNetRoot = @import("GizNet.zig");
const NoiseCipher = @import("noise/Cipher.zig");
const RuntimeEngine = @import("runtime/Engine.zig");

pub const Engine = RuntimeEngine;

pub fn make(
    comptime grt: type,
    comptime packet_size_capacity: usize,
    comptime cipher_kind: NoiseCipher.Kind,
) type {
    const EngineType = RuntimeEngine.make(grt, packet_size_capacity, cipher_kind);

    return struct {
        pub const Engine = EngineType;
        pub const GizNet = GizNetRoot.make(grt, EngineType, RuntimeEngine.Config);
    };
}
