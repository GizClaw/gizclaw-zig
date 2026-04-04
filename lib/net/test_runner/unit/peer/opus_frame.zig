const dep = @import("dep");
const testing_api = dep.testing;

const peer = @import("../../../peer.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib.testing, allocator) catch |err| {
                t.logErrorf("peer/opus_frame failed: {}", .{err});
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

fn runCases(testing: anytype, allocator: dep.embed.mem.Allocator) !void {
    var stamped = try peer.stampOpusFrame(allocator, "opus", 123456789);
    defer stamped.deinit(allocator);
    try testing.expectEqual(peer.OpusFrameVersion, stamped.version());
    try testing.expectEqual(@as(peer.EpochMillis, 123456789), stamped.stamp());
    try testing.expectEqualStrings("opus", stamped.frame());

    var max_frame = try peer.stampOpusFrame(allocator, "x", @intCast(peer.MaxOpusTimestamp));
    defer max_frame.deinit(allocator);
    try testing.expectEqual(@as(peer.EpochMillis, @intCast(peer.MaxOpusTimestamp)), max_frame.stamp());

    var header_only = try peer.stampOpusFrame(allocator, "", 0);
    defer header_only.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), header_only.frame().len);
    try testing.expectError(peer.Error.OpusFrameTooShort, header_only.validate());
    try testing.expectError(peer.Error.OpusFrameTooShort, peer.parseStampedOpusFrame(allocator, header_only.bytes));

    var raw = [_]u8{
        peer.OpusFrameVersion,
        0, 0, 0, 0, 0, 0, 5,
        'p', 'c', 'm',
    };
    var parsed = try peer.parseStampedOpusFrame(allocator, &raw);
    defer parsed.deinit(allocator);
    raw[8] = 'X';
    try testing.expectEqual(@as(peer.EpochMillis, 5), parsed.stamp());
    try testing.expectEqualStrings("pcm", parsed.frame());

    try testing.expectError(peer.Error.OpusFrameTooShort, peer.parseStampedOpusFrame(allocator, &[_]u8{ 1, 2, 3 }));
    try testing.expectError(
        peer.Error.InvalidOpusFrameVersion,
        peer.parseStampedOpusFrame(allocator, &[_]u8{ 2, 0, 0, 0, 0, 0, 0, 0, 0xff }),
    );
}
