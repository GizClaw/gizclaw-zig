const Key = @import("Key.zig");

const KeyPair = @This();

public: Key = Key.zero,
private: Key = Key.zero,

pub fn seed(comptime lib: type, value: u32) KeyPair {
    const X25519 = lib.crypto.dh.X25519;

    var private_bytes: [32]u8 = undefined;
    var offset: usize = 0;
    var counter: u32 = 0;
    while (offset < private_bytes.len) : (offset += 4) {
        var chunk: [4]u8 = undefined;
        lib.mem.writeInt(u32, &chunk, value +% counter, .little);
        @memcpy(private_bytes[offset .. offset + 4], &chunk);
        counter +%= 1;
    }
    private_bytes[0] |= 1;
    const public_bytes = X25519.recoverPublicKey(clamp(private_bytes)) catch @panic("invalid test key");
    return .{
        .public = .{ .bytes = public_bytes },
        .private = .{ .bytes = private_bytes },
    };
}

pub fn rand(comptime lib: type) KeyPair {
    const X25519 = lib.crypto.dh.X25519;
    const generated = X25519.KeyPair.generate();
    return .{
        .public = .{ .bytes = generated.public_key },
        .private = .{ .bytes = generated.secret_key },
    };
}

fn clamp(private_bytes: [32]u8) [32]u8 {
    var out = private_bytes;
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    return out;
}
