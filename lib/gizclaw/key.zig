const giznet = @import("giznet");

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub const DecodeError = error{
    EmptyKey,
    InvalidKeyText,
};

pub fn make(comptime grt: type) type {
    const rt = grt.std;

    return struct {
        pub fn fromPrivate(private: giznet.Key) !giznet.KeyPair {
            var clamped = private.bytes;
            clamped[0] &= 248;
            clamped[31] &= 127;
            clamped[31] |= 64;
            const public = try rt.crypto.dh.X25519.recoverPublicKey(clamped);
            return .{
                .private = .{ .bytes = clamped },
                .public = .{ .bytes = public },
            };
        }

        pub fn randomKeyPair() giznet.KeyPair {
            var private_bytes: [32]u8 = undefined;
            rt.crypto.random.bytes(&private_bytes);
            return fromPrivate(.{ .bytes = private_bytes }) catch unreachable;
        }

        pub fn parse(text: []const u8) DecodeError!giznet.Key {
            const value = rt.mem.trim(u8, text, " \t\r\n");
            if (value.len == 0) return error.EmptyKey;

            if (decodeCrockford(value)) |key_value| return key_value;
            if (decodeHex(value)) |key_value| return key_value;
            if (decodeBase64(value)) |key_value| return key_value;
            return error.InvalidKeyText;
        }

        pub fn format(key_value: giznet.Key, out: *[52]u8) []const u8 {
            var buffer: u32 = 0;
            var bits: u5 = 0;
            var index: usize = 0;
            for (key_value.bytes) |byte| {
                buffer = (buffer << 8) | byte;
                bits += 8;
                while (bits >= 5) {
                    out[index] = alphabet[(buffer >> (bits - 5)) & 31];
                    index += 1;
                    bits -= 5;
                    if (bits == 0) {
                        buffer = 0;
                    } else {
                        buffer &= (@as(u32, 1) << bits) - 1;
                    }
                }
            }
            if (bits > 0) {
                out[index] = alphabet[(buffer << (5 - bits)) & 31];
                index += 1;
            }
            return out[0..index];
        }

        fn decodeHex(value: []const u8) ?giznet.Key {
            if (value.len != 64) return null;
            var bytes: [32]u8 = undefined;
            _ = rt.fmt.hexToBytes(&bytes, value) catch return null;
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
            var out_len: usize = 0;
            var buffer: u32 = 0;
            var bits: u5 = 0;

            for (value) |ch| {
                if (ch == '-') continue;
                const decoded = crockfordValue(ch) orelse return null;
                buffer = (buffer << 5) | decoded;
                bits += 5;
                while (bits >= 8) {
                    if (out_len >= out.len) return null;
                    out[out_len] = @intCast(buffer >> (bits - 8));
                    out_len += 1;
                    bits -= 8;
                    if (bits == 0) {
                        buffer = 0;
                    } else {
                        buffer &= (@as(u32, 1) << bits) - 1;
                    }
                }
            }

            if (out_len != out.len or buffer != 0) return null;
            return .{ .bytes = out };
        }

        fn crockfordValue(raw: u8) ?u5 {
            switch (raw) {
                'O', 'o' => return 0,
                'I', 'i', 'L', 'l' => return 1,
                '0'...'9' => return @intCast(raw - '0'),
                else => {},
            }
            var ch = raw;
            if (ch >= 'a' and ch <= 'z') ch -= 'a' - 'A';
            for (alphabet, 0..) |candidate, index| {
                if (candidate == ch) return @intCast(index);
            }
            return null;
        }
    };
}
