const glib = @import("glib");
const gizclaw = @import("../../../gizclaw.zig");

pub fn make(comptime grt: type) glib.testing.TestRunner {
    return glib.testing.TestRunner.fromFn(grt.std, 1024 * 1024, struct {
        fn run(_: *glib.testing.T, _: grt.std.mem.Allocator) !void {
            const testing = grt.std.testing;
            const key = gizclaw.key.make(grt);
            const pair = key.randomKeyPair();
            var buf: [52]u8 = undefined;
            const text = key.format(pair.public, &buf);
            const parsed = try key.parse(text);
            try testing.expect(pair.public.eql(parsed));

            var bytes: [32]u8 = undefined;
            for (&bytes, 0..) |*byte, index| byte.* = @intCast(index + 1);
            const known = try key.parse("4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw");
            try testing.expectEqualSlices(u8, &bytes, &known.bytes);

            var known_buf: [52]u8 = undefined;
            try testing.expectEqualStrings(
                "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw",
                key.format(known, &known_buf),
            );

            const from_crockford = try key.parse("041061050R3GG28A1C60T3GF208H44RM2MB1E60S38DHR78Y3WG0");
            try testing.expectEqualSlices(u8, &bytes, &from_crockford.bytes);

            const from_hex = try key.parse("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
            try testing.expectEqualSlices(u8, &bytes, &from_hex.bytes);

            const from_base64_url = try key.parse("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA");
            try testing.expectEqualSlices(u8, &bytes, &from_base64_url.bytes);
        }
    }.run);
}
