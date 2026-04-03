const errors = @import("errors.zig");
const Key = @import("Key.zig");

pub fn make(comptime lib: type) type {
    const X25519 = lib.crypto.dh.X25519;

    return struct {
        private: Key,
        public: Key,

        const Self = @This();

        pub fn generate() !Self {
            var seed: [Key.key_size]u8 = undefined;
            lib.crypto.random.bytes(&seed);
            return fromPrivate(Key.fromBytes(seed));
        }

        pub fn fromPrivate(private_key: Key) !Self {
            const clamped = clamp(private_key.data);
            const public_key = X25519.recoverPublicKey(clamped) catch {
                return errors.KeyError.InvalidPublicKey;
            };

            return .{
                .private = Key.fromBytes(clamped),
                .public = Key.fromBytes(public_key),
            };
        }

        pub fn dh(self: Self, peer_public: Key) !Key {
            const shared = X25519.scalarmult(self.private.data, peer_public.data) catch {
                return errors.KeyError.InvalidPublicKey;
            };

            const key = Key.fromBytes(shared);
            if (key.isZero()) return errors.KeyError.InvalidPublicKey;
            return key;
        }

        fn clamp(bytes: [Key.key_size]u8) [Key.key_size]u8 {
            var out = bytes;
            out[0] &= 248;
            out[31] &= 127;
            out[31] |= 64;
            return out;
        }
    };
}
