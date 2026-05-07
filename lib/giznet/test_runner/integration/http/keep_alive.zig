const glib = @import("glib");
const testing_api = glib.testing;

const giznet = @import("../../../../giznet.zig");
const http_utils = @import("test_utils.zig");
const test_utils = @import("../../test_utils/giz_net.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const PairFixture = test_utils.DefaultFixture(grt, &[_]u32{ 3341, 3342 });

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            runSequentialRequestsReuseStream(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/keep_alive sequential_reuse failed: {}", .{err});
                return false;
            };
            runRequestCloseOpensNewStream(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/keep_alive request_close_new_stream failed: {}", .{err});
                return false;
            };
            runPartialBodyReadOpensNewStream(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/keep_alive partial_body_new_stream failed: {}", .{err});
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

fn runSequentialRequestsReuseStream(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
    try runKeepAliveCase(grt, Fixture, allocator, .{
        .service_id = 23,
        .request_close = false,
        .partial_first_body = false,
        .expected_accepts = 1,
    });
}

fn runRequestCloseOpensNewStream(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
    try runKeepAliveCase(grt, Fixture, allocator, .{
        .service_id = 24,
        .request_close = true,
        .partial_first_body = false,
        .expected_accepts = 2,
    });
}

fn runPartialBodyReadOpensNewStream(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
    try runKeepAliveCase(grt, Fixture, allocator, .{
        .service_id = 25,
        .request_close = false,
        .partial_first_body = true,
        .expected_accepts = 2,
    });
}

fn runKeepAliveCase(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
    comptime spec: anytype,
) !void {
    const Http = grt.net.http;
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

    const HandlerState = struct {
        pub fn serveHTTP(_: *@This(), rw: *Writer, req: *Request) void {
            if (grt.std.mem.eql(u8, req.url.path, "/large")) {
                _ = rw.write("large-response-body") catch {};
                return;
            }
            _ = rw.write("ok") catch {};
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

    var transport = giznet.HttpTransport.make(grt).init(allocator, pair.a, spec.service_id);
    defer transport.deinit();
    var client = try Http.Client.init(allocator, .{ .round_tripper = transport.roundTripper() });
    defer client.deinit();

    if (spec.partial_first_body) {
        var resp1 = try client.get("http://giznet.local/large");
        var first: [5]u8 = undefined;
        const first_n = try resp1.body().?.read(&first);
        try grt.std.testing.expectEqualStrings("large", first[0..first_n]);
        resp1.deinit();
    } else if (spec.request_close) {
        var req1 = try Http.Request.init(allocator, "GET", "http://giznet.local/hello");
        defer req1.deinit();
        req1.close = true;
        var resp1 = try client.do(&req1);
        defer resp1.deinit();
        try expectBody(grt, resp1.body().?, "ok");
    } else {
        var resp1 = try client.get("http://giznet.local/hello");
        defer resp1.deinit();
        try expectBody(grt, resp1.body().?, "ok");
    }

    var resp2 = try client.get("http://giznet.local/hello");
    defer resp2.deinit();
    try expectBody(grt, resp2.body().?, "ok");

    try grt.std.testing.expectEqual(@as(usize, spec.expected_accepts), accept_count.load(.acquire));
}

fn expectBody(comptime grt: type, body: anytype, expected: []const u8) !void {
    var buf: [32]u8 = undefined;
    const n = try http_utils.readAllBody(body, &buf);
    try grt.std.testing.expectEqualStrings(expected, buf[0..n]);
}
