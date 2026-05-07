const glib = @import("glib");
const testing_api = glib.testing;

const giznet = @import("../../../../giznet.zig");
const http_utils = @import("test_utils.zig");
const test_utils = @import("../../test_utils/giz_net.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const PairFixture = test_utils.DefaultFixture(grt, &[_]u32{ 3331, 3332 });

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            runDuplexStreaming(grt, PairFixture, allocator) catch |err| {
                t.logErrorf("integration/giznet/http/duplex streaming failed: {}", .{err});
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

fn runDuplexStreaming(comptime grt: type, comptime Fixture: type, allocator: grt.std.mem.Allocator) !void {
    const Http = grt.net.http;
    const Handler = Http.Handler;
    const ReadCloser = Http.ReadCloser;
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

    var ack_sent = try Signal.make(allocator, 1);
    defer ack_sent.deinit();
    var release_upload = try Signal.make(allocator, 1);
    defer release_upload.deinit();

    const HandlerState = struct {
        ack_sent: *Signal,

        pub fn serveHTTP(self: *@This(), rw: *Writer, req: *Request) void {
            const body = req.body() orelse {
                rw.writeHeader(400) catch {};
                return;
            };
            var first: [5]u8 = undefined;
            const first_n = body.read(&first) catch {
                rw.writeHeader(500) catch {};
                return;
            };
            if (!grt.std.mem.eql(u8, first[0..first_n], "hello")) {
                rw.writeHeader(422) catch {};
                return;
            }

            _ = rw.write("ack") catch {};
            rw.flush() catch {};
            _ = self.ack_sent.send({}) catch {};

            var rest: [5]u8 = undefined;
            const rest_n = body.read(&rest) catch {
                rw.writeHeader(500) catch {};
                return;
            };
            if (!grt.std.mem.eql(u8, rest[0..rest_n], "world")) return;
            _ = rw.write("-done") catch {};
        }
    };
    var handler_state = HandlerState{ .ack_sent = &ack_sent };
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

    var transport = giznet.HttpTransport.make(grt).init(allocator, pair.a, 22);
    defer transport.deinit();
    var client = try Http.Client.init(allocator, .{ .round_tripper = transport.roundTripper() });
    defer client.deinit();

    const Releaser = struct {
        fn run(ack: *Signal, release: *Signal) void {
            const sent = ack.recvTimeout(2 * glib.time.duration.Second) catch return;
            if (!sent.ok) return;
            _ = release.send({}) catch {};
        }
    };
    const releaser_thread = try grt.std.Thread.spawn(.{}, Releaser.run, .{ &ack_sent, &release_upload });
    defer releaser_thread.join();

    const BlockingBody = struct {
        release: *Signal,
        phase: usize = 0,
        closed: bool = false,

        pub fn read(self: *@This(), buf: []u8) anyerror!usize {
            if (self.closed) return 0;
            if (self.phase == 0) {
                self.phase = 1;
                @memcpy(buf[0..5], "hello");
                return 5;
            }
            if (self.phase == 1) {
                const released = try self.release.recvTimeout(2 * glib.time.duration.Second);
                if (!released.ok) return error.TestUnexpectedResult;
                self.phase = 2;
                @memcpy(buf[0..5], "world");
                return 5;
            }
            return 0;
        }

        pub fn close(self: *@This()) void {
            self.closed = true;
            _ = self.release.sendTimeout({}, 0) catch {};
        }
    };
    var body = BlockingBody{ .release = &release_upload };
    var req = try Http.Request.init(allocator, "POST", "http://giznet.local/duplex");
    defer req.deinit();
    req = req.withBody(ReadCloser.init(&body));
    req.content_length = 10;

    var resp = try client.do(&req);
    defer resp.deinit();
    try grt.std.testing.expectEqual(@as(u16, 200), resp.status_code);

    var body_buf: [16]u8 = undefined;
    const body_n = try http_utils.readAllBody(resp.body().?, &body_buf);
    try grt.std.testing.expectEqualStrings("ack-done", body_buf[0..body_n]);
}
