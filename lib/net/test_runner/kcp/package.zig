const embed = @import("embed");
const testing_api = @import("testing");
const kcp = @import("../../kcp.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: embed.mem.Allocator) bool {
            _ = self;
            runImpl(lib, allocator) catch |err| {
                t.logErrorf("kcp/package failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runImpl(comptime lib: type, allocator: embed.mem.Allocator) !void {
    _ = allocator;
    try lib.testing.expectEqual(@as(u8, 0), kcp.frame_open);
    try lib.testing.expectEqual(@as(u8, 3), kcp.frame_close_ack);
    try lib.testing.expectEqual(@as(u8, 1), kcp.close_reason_abort);
    _ = kcp.Conn;
    _ = kcp.Mux;
    _ = kcp.Error;

    const decoded = try kcp.decodeFrame(&[_]u8{ 1, kcp.frame_open });
    try lib.testing.expectEqual(@as(u64, 1), decoded.stream_id);
    try lib.testing.expectEqual(kcp.frame_open, decoded.frame_type);
    try lib.testing.expectEqual(@as(usize, 0), decoded.payload.len);
}
