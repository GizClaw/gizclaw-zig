const glib = @import("glib");
const testing_api = glib.testing;

const giznet = @import("../../../giznet.zig");
const test_utils = @import("../test_utils/giz_net.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const PairFixture = test_utils.DefaultFixture(grt, &[_]u32{ 3201, 3202 });

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;

            runAcceptsStream(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/listener accepts_stream failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runAcceptsStream(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();

    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    var listener_impl = giznet.Listener.make(grt).init(allocator, pair.b);
    defer listener_impl.deinit();
    const listener = listener_impl.listener();

    const service_id: u64 = 17;
    const payload = "listener-stream";
    const writer = try pair.a.openStream(service_id);
    defer writer.deinit();
    try writeAll(writer, payload);

    var net_conn = try listener.accept();
    defer net_conn.deinit();
    net_conn.setReadDeadline(glib.time.instant.add(grt.time.instant.now(), fixture.config.accept_timeout));

    var buf: [64]u8 = undefined;
    const n = try net_conn.read(&buf);
    try grt.std.testing.expectEqualStrings(payload, buf[0..n]);
}

fn writeAll(stream: anytype, payload: []const u8) !void {
    var offset: usize = 0;
    while (offset < payload.len) {
        const written = try stream.write(payload[offset..]);
        if (written == 0) return error.ShortWrite;
        offset += written;
    }
}
