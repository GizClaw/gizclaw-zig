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
        }
    }.run);
}
