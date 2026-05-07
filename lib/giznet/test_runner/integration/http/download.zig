const glib = @import("glib");
const testing_api = glib.testing;

const giznet = @import("../../../../giznet.zig");
const http_utils = @import("test_utils.zig");
const test_utils = @import("../../test_utils/giz_net.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const PairFixture = test_utils.DefaultFixture(grt, &[_]u32{ 3321, 3322 });

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            runStreamingDownload(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/download streaming failed: {}", .{err});
                return false;
            };
            runFixedLengthDownload(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/download fixed_length failed: {}", .{err});
                return false;
            };
            runSplitChunkCrlfDownload(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/download split_chunk_crlf failed: {}", .{err});
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

fn runStreamingDownload(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
    const Http = grt.net.http;
    const Handler = Http.Handler;
    const Request = Http.Request;
    const Server = Http.Server;
    const Writer = Http.ResponseWriter;
    const Signal = grt.sync.Channel(void);

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

    var first_sent = try Signal.make(allocator, 1);
    defer first_sent.deinit();
    var release_second = try Signal.make(allocator, 1);
    defer release_second.deinit();

    const HandlerState = struct {
        first_sent: *Signal,
        release_second: *Signal,

        pub fn serveHTTP(self: *@This(), rw: *Writer, req: *Request) void {
            if (!grt.std.mem.eql(u8, req.url.path, "/stream")) {
                rw.writeHeader(404) catch {};
                return;
            }
            _ = rw.write("first") catch {};
            rw.flush() catch {};
            _ = self.first_sent.send({}) catch {};
            const release = self.release_second.recvTimeout(2 * glib.time.duration.Second) catch return;
            if (!release.ok) return;
            _ = rw.write("-second") catch {};
        }
    };
    var handler_state = HandlerState{
        .first_sent = &first_sent,
        .release_second = &release_second,
    };
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

    var transport = giznet.HttpTransport.make(grt).init(allocator, pair.a, 20);
    defer transport.deinit();
    var client = try Http.Client.init(allocator, .{ .round_tripper = transport.roundTripper() });
    defer client.deinit();

    var resp = try client.get("http://giznet.local/stream");
    defer resp.deinit();
    try grt.std.testing.expectEqual(@as(u16, 200), resp.status_code);

    const sent = try first_sent.recvTimeout(2 * glib.time.duration.Second);
    try grt.std.testing.expect(sent.ok);

    var first_buf: [5]u8 = undefined;
    const first_n = try resp.body().?.read(&first_buf);
    try grt.std.testing.expectEqualStrings("first", first_buf[0..first_n]);

    _ = try release_second.send({});
    var rest_buf: [16]u8 = undefined;
    const rest_n = try http_utils.readAllBody(resp.body().?, &rest_buf);
    try grt.std.testing.expectEqualStrings("-second", rest_buf[0..rest_n]);
}

fn runFixedLengthDownload(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
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
        pub fn serveHTTP(_: *@This(), rw: *Writer, _: *Request) void {
            rw.setHeader("Content-Length", "12") catch {};
            _ = rw.write("fixed-length") catch {};
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

    var transport = giznet.HttpTransport.make(grt).init(allocator, pair.a, 21);
    defer transport.deinit();
    var client = try Http.Client.init(allocator, .{ .round_tripper = transport.roundTripper() });
    defer client.deinit();

    var resp = try client.get("http://giznet.local/fixed");
    defer resp.deinit();
    try grt.std.testing.expectEqual(@as(i64, 12), resp.content_length);

    var body_buf: [16]u8 = undefined;
    const n = try http_utils.readAllBody(resp.body().?, &body_buf);
    try grt.std.testing.expectEqualStrings("fixed-length", body_buf[0..n]);
}

fn runSplitChunkCrlfDownload(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
    const Http = grt.net.http;

    var fixture = try Fixture.init(allocator, .{});
    defer fixture.deinit();
    const pair = try fixture.connect(0, 1);
    defer pair.deinit();

    const RawServer = struct {
        fn run(conn: giznet.Conn, timeout: glib.time.duration.Duration) void {
            var stream = conn.accept(timeout) catch return;
            defer stream.deinit();

            var req_buf: [256]u8 = undefined;
            var total: usize = 0;
            while (total < req_buf.len) {
                const n = stream.read(req_buf[total..]) catch return;
                if (n == 0) return;
                total += n;
                if (grt.std.mem.indexOf(u8, req_buf[0..total], "\r\n\r\n") != null) break;
            }

            writeAllStream(stream, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n") catch return;
            writeAllStream(stream, "5\r\nhello") catch return;
            writeAllStream(stream, "\r") catch return;
            grt.std.Thread.sleep(@intCast(10 * glib.time.duration.MilliSecond));
            writeAllStream(stream, "\n0\r\n\r\n") catch return;
        }
    };
    const server_thread = try grt.std.Thread.spawn(.{}, RawServer.run, .{ pair.b, fixture.config.accept_timeout });
    defer server_thread.join();

    var transport = giznet.HttpTransport.make(grt).init(allocator, pair.a, 27);
    defer transport.deinit();
    var client = try Http.Client.init(allocator, .{ .round_tripper = transport.roundTripper() });
    defer client.deinit();

    var resp = try client.get("http://giznet.local/split-chunk");
    defer resp.deinit();
    try grt.std.testing.expectEqual(@as(u16, 200), resp.status_code);

    var body_buf: [8]u8 = undefined;
    const n = try http_utils.readAllBody(resp.body().?, &body_buf);
    try grt.std.testing.expectEqualStrings("hello", body_buf[0..n]);
}

fn writeAllStream(stream: anytype, payload: []const u8) !void {
    var offset: usize = 0;
    while (offset < payload.len) {
        const n = try stream.write(payload[offset..]);
        if (n == 0) return error.ShortWrite;
        offset += n;
    }
}
