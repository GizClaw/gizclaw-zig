const errors = @import("errors.zig");
const Key = @import("key.zig");
const lib_adapter = @import("lib_adapter.zig");

pub fn KeyPair(comptime Crypto: type) type {
    const X25519 = Crypto.X25519;

    return struct {
        private: Key,
        public: Key,

        const Self = @This();

        pub fn generate() !Self {
            var seed: [Key.key_size]u8 = undefined;
            Crypto.random.bytes(&seed);
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

pub fn testAll(comptime lib: type, testing: anytype) !void {
    const Crypto = lib_adapter.make(lib);
    const T = KeyPair(Crypto);

    const private_a = Key.fromBytes([_]u8{42} ** Key.key_size);
    const private_b = Key.fromBytes([_]u8{99} ** Key.key_size);

    const alice = try T.fromPrivate(private_a);
    const alice_again = try T.fromPrivate(private_a);
    const bob = try T.fromPrivate(private_b);

    try testing.expect(!alice.private.isZero());
    try testing.expect(!alice.public.isZero());
    try testing.expect(alice.public.eql(alice_again.public));

    const shared_ab = try alice.dh(bob.public);
    const shared_ba = try bob.dh(alice.public);
    try testing.expect(shared_ab.eql(shared_ba));
    try testing.expect(!shared_ab.isZero());
}
