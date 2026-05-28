const giznet = @import("giznet");
const glib = @import("glib");

const base58btc = glib.encoding.base58btc;
const crockford_base32 = glib.encoding.base32crockford;

pub const DecodeError = error{
    EmptyKey,
    InvalidKeyText,
};

pub fn make(comptime grt: type) type {
    return struct {
        pub fn fromPrivate(private: giznet.Key) !giznet.KeyPair {
            return giznet.noise.KeyPair.fromPrivate(grt, private);
        }

        pub fn randomKeyPair() giznet.KeyPair {
            return giznet.noise.KeyPair.rand(grt);
        }

        pub fn parse(text: []const u8) DecodeError!giznet.Key {
            const value = grt.std.mem.trim(u8, text, " \t\r\n");
            if (value.len == 0) return error.EmptyKey;

            if (decodeBase58(value)) |key_value| return key_value;
            if (decodeCrockford(value)) |key_value| return key_value;
            if (decodeBase64(value)) |key_value| return key_value;
            if (decodeHex(value)) |key_value| return key_value;
            return error.InvalidKeyText;
        }

        pub fn format(key_value: giznet.Key, out: *[52]u8) []const u8 {
            var scratch: [base58btc.encodedMaxLen(32)]u8 = undefined;
            return base58btc.encodeBuf(&key_value.bytes, out[0..], &scratch) catch unreachable;
        }

        fn decodeBase58(value: []const u8) ?giznet.Key {
            var out: [32]u8 = undefined;
            var scratch: [128]u8 = undefined;
            const decoded = base58btc.decodeBuf(value, out[0..], scratch[0..]) catch return null;
            if (decoded.len != out.len) return null;
            return .{ .bytes = out };
        }

        fn decodeHex(value: []const u8) ?giznet.Key {
            if (value.len != 64) return null;
            var bytes: [32]u8 = undefined;
            _ = grt.std.fmt.hexToBytes(&bytes, value) catch return null;
            return .{ .bytes = bytes };
        }

        fn decodeBase64(value: []const u8) ?giznet.Key {
            if (decodeBase64Variant(value, true)) |key_value| return key_value;
            if (decodeBase64Variant(value, false)) |key_value| return key_value;
            return null;
        }

        fn decodeBase64Variant(value: []const u8, url_safe: bool) ?giznet.Key {
            var out: [32]u8 = undefined;
            var out_len: usize = 0;
            var buffer: u32 = 0;
            var bits: u8 = 0;
            var padded = false;

            for (value) |ch| {
                if (ch == '=') {
                    padded = true;
                    continue;
                }
                if (padded) return null;
                const decoded = base64Value(ch, url_safe) orelse return null;
                buffer = (buffer << 6) | decoded;
                bits += 6;
                while (bits >= 8) {
                    if (out_len >= out.len) return null;
                    out[out_len] = @intCast((buffer >> @intCast(bits - 8)) & 0xff);
                    out_len += 1;
                    bits -= 8;
                    if (bits == 0) {
                        buffer = 0;
                    } else {
                        buffer &= (@as(u32, 1) << @intCast(bits)) - 1;
                    }
                }
            }

            if (out_len != out.len or buffer != 0) return null;
            return .{ .bytes = out };
        }

        fn base64Value(ch: u8, url_safe: bool) ?u6 {
            switch (ch) {
                'A'...'Z' => return @intCast(ch - 'A'),
                'a'...'z' => return @intCast(ch - 'a' + 26),
                '0'...'9' => return @intCast(ch - '0' + 52),
                '+' => return if (url_safe) null else 62,
                '/' => return if (url_safe) null else 63,
                '-' => return if (url_safe) 62 else null,
                '_' => return if (url_safe) 63 else null,
                else => return null,
            }
        }

        fn decodeCrockford(value: []const u8) ?giznet.Key {
            var out: [32]u8 = undefined;
            const decoded = crockford_base32.decodeBuf(value, out[0..]) catch return null;
            if (decoded.len != out.len) return null;
            return .{ .bytes = out };
        }
    };
}
