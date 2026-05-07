const glib = @import("glib");
const testing_api = glib.testing;

const giznet = @import("../../../../giznet.zig");
const http_utils = @import("test_utils.zig");
const test_utils = @import("../../test_utils/giz_net.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const PairFixture = test_utils.DefaultFixture(grt, &[_]u32{ 3311, 3312 });

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            runPostFixedUpload(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/upload post_fixed failed: {}", .{err});
                return false;
            };
            runPutChunkedUpload(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/upload put_chunked failed: {}", .{err});
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

fn runPostFixedUpload(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
    try runUpload(grt, Fixture, allocator, .{
        .method = "POST",
        .path = "/upload-fixed",
        .content_length = "alphabeta".len,
        .chunks = &[_][]const u8{ "alpha", "beta" },
        .expected = "alphabeta",
    });
}

fn runPutChunkedUpload(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
    try runUpload(grt, Fixture, allocator, .{
        .method = "PUT",
        .path = "/upload-chunked",
        .content_length = 0,
        .chunks = &[_][]const u8{ "chunk-", "one-", "two" },
        .expected = "chunk-one-two",
    });
}

fn runUpload(
    comptime grt: type,
    comptime Fixture: type,
    allocator: grt.std.mem.Allocator,
    comptime spec: anytype,
) !void {
    const Http = grt.net.http;
    const Handler = Http.Handler;
    const ReadCloser = Http.ReadCloser;
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
            if (!grt.std.mem.eql(u8, req.effectiveMethod(), spec.method) or
                !grt.std.mem.eql(u8, req.url.path, spec.path))
            {
                rw.writeHeader(400) catch {};
                return;
            }
            var body_buf: [64]u8 = undefined;
            const n = http_utils.readAllRequestBody(req.*, &body_buf) catch {
                rw.writeHeader(500) catch {};
                return;
            };
            if (!grt.std.mem.eql(u8, body_buf[0..n], spec.expected)) {
                rw.writeHeader(422) catch {};
                return;
            }
            _ = rw.write("upload-ok") catch {};
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

    var transport = giznet.HttpTransport.make(grt).init(allocator, pair.a, 19);
    defer transport.deinit();
    var client = try Http.Client.init(allocator, .{ .round_tripper = transport.roundTripper() });
    defer client.deinit();

    var body = http_utils.ChunkBody(grt){ .chunks = spec.chunks };
    var req = try Http.Request.init(allocator, spec.method, "http://giznet.local" ++ spec.path);
    defer req.deinit();
    req = req.withBody(ReadCloser.init(&body));
    req.content_length = spec.content_length;

    var resp = try client.do(&req);
    defer resp.deinit();
    try grt.std.testing.expectEqual(@as(u16, 200), resp.status_code);

    var resp_buf: [32]u8 = undefined;
    const n = try http_utils.readAllBody(resp.body().?, &resp_buf);
    try grt.std.testing.expectEqualStrings("upload-ok", resp_buf[0..n]);
    try grt.std.testing.expectEqual(@as(usize, 1), accept_count.load(.acquire));
}
