const dep = @import("dep");
const testing_api = @import("dep").testing;
const kcp = @import("../../../kcp.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runImpl(lib, allocator) catch |err| {
                t.logErrorf("kcp/package failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runImpl(comptime lib: type, allocator: dep.embed.mem.Allocator) !void {
    try lib.testing.expectEqual(@as(u8, 0), kcp.frame_open);
    try lib.testing.expectEqual(@as(u8, 3), kcp.frame_close_ack);
    try lib.testing.expectEqual(@as(u8, 1), kcp.close_reason_abort);
    _ = kcp.Conn;
    _ = kcp.Mux;
    _ = kcp.Stream;
    _ = kcp.Error;

    const decoded = try kcp.decodeFrame(&[_]u8{ 1, kcp.frame_open });
    try lib.testing.expectEqual(@as(u64, 1), decoded.stream_id);
    try lib.testing.expectEqual(kcp.frame_open, decoded.frame_type);
    try lib.testing.expectEqual(@as(usize, 0), decoded.payload.len);
    try lib.testing.expectEqual(@as(u32, 7), try kcp.getConv(&[_]u8{ 7, 0, 0, 0 }));

    var sink = OutputSink{};
    var conn = try kcp.newConn(allocator, 9, .{
        .output = .{
            .ctx = &sink,
            .write = OutputSink.write,
        },
    });
    defer conn.deinit();
    try lib.testing.expectEqual(@as(u32, 9), conn.getConv());

    var mux = try kcp.newMux(allocator, 3, .{
        .is_client = true,
        .output = .{
            .ctx = &sink,
            .write = OutputSink.write,
        },
    });
    defer mux.deinit();
    var stream = try mux.openConn(1);
    try lib.testing.expectEqual(@as(u64, 1), stream.id());

    var zero_conn = try kcp.newConn(allocator, 10, .{
        .output = .{
            .ctx = &sink,
            .write = OutputSink.write,
        },
        .idle_timeout_ms = 0,
        .idle_timeout_pure_ms = 0,
        .mtu = 0,
        .snd_wnd = 0,
        .rcv_wnd = 0,
        .nodelay = 0,
        .interval = 0,
        .resend = 0,
        .nc = 0,
    });
    defer zero_conn.deinit();
    try lib.testing.expectEqual(@as(u32, 10), zero_conn.getConv());

    var zero_mux = try kcp.newMux(allocator, 4, .{
        .is_client = true,
        .output = .{
            .ctx = &sink,
            .write = OutputSink.write,
        },
        .close_ack_timeout_ms = 0,
        .idle_stream_timeout_ms = 0,
        .accept_backlog = 0,
        .max_active_streams = 0,
        .mtu = 0,
        .snd_wnd = 0,
        .rcv_wnd = 0,
        .nodelay = 0,
        .interval = 0,
        .resend = 0,
        .nc = 0,
    });
    defer zero_mux.deinit();
    var zero_stream = try zero_mux.openConn(1);
    try lib.testing.expectEqual(@as(u64, 1), zero_stream.id());
}

const OutputSink = struct {
    fn write(_: *anyopaque, _: []const u8) !void {}
};
