const glib = @import("glib");
const testing_api = glib.testing;

const giznet = @import("../../../../giznet.zig");
const http_utils = @import("test_utils.zig");
const test_utils = @import("../../test_utils/giz_net.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const PairFixture = test_utils.DefaultFixture(grt, &[_]u32{ 3301, 3302 });

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            runGetRoundTrip(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/get round_trip failed: {}", .{err});
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

fn runGetRoundTrip(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
) !void {
    const Http = grt.net.http;
    const Header = Http.Header;
    const Handler = Http.Handler;
    const Request = Http.Request;
    const Server = Http.Server;
    const Writer = Http.ResponseWriter;

    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();
    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const AcceptCount = grt.std.atomic.Value(usize);
    var accept_count = AcceptCount.init(0);
    var stream_ids: grt.std.ArrayList(u64) = .{};
    defer stream_ids.deinit(allocator);
    var listener_impl = http_utils.RecordingListener(grt).init(allocator, pair.b, &accept_count, &stream_ids);
    defer listener_impl.deinit();

    const Helpers = struct {
        fn headerValue(headers: []const Header, name: []const u8) ?[]const u8 {
            for (headers) |hdr| {
                if (hdr.is(name)) return hdr.value;
            }
            return null;
        }
    };
    const HandlerState = struct {
        pub fn serveHTTP(_: *@This(), rw: *Writer, req: *Request) void {
            const ok =
                grt.std.mem.eql(u8, req.effectiveMethod(), "GET") and
                grt.std.mem.eql(u8, req.url.path, "/hello") and
                grt.std.mem.eql(u8, req.url.raw_query, "x=1") and
                Helpers.headerValue(req.header, "X-Test") != null;
            if (!ok) {
                rw.writeHeader(400) catch {};
                return;
            }
            rw.setHeader("Content-Type", "text/plain") catch {};
            _ = rw.write("get-ok") catch {};
        }
    };
    var handler_state = HandlerState{};
    var server = try Server.init(allocator, .{
        .handler = Handler.init(&handler_state),
        .idle_timeout = 100 * glib.time.duration.MilliSecond,
    });
    defer server.deinit();

    const server_thread = try grt.std.Thread.spawn(
        .{},
        http_utils.ServerTask(grt, Server).run,
        .{ &server, grt.net.Listener.init(&listener_impl) },
    );
    defer server_thread.join();
    defer server.close();

    var transport = giznet.HttpTransport.make(grt).init(allocator, pair.a, 18);
    defer transport.deinit();
    var client = try Http.Client.init(allocator, .{ .round_tripper = transport.roundTripper() });
    defer client.deinit();

    var req = try Http.Request.init(allocator, "GET", "http://giznet.local/hello?x=1");
    defer req.deinit();
    try req.addHeader("X-Test", "yes");

    var resp = try client.do(&req);
    defer resp.deinit();
    try grt.std.testing.expectEqual(@as(u16, 200), resp.status_code);

    var body_buf: [32]u8 = undefined;
    const n = try http_utils.readAllBody(resp.body().?, &body_buf);
    try grt.std.testing.expectEqualStrings("get-ok", body_buf[0..n]);
    try grt.std.testing.expectEqual(@as(usize, 1), accept_count.load(.acquire));
}
