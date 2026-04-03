const dep = @import("dep");
const testing_api = @import("dep").testing;
const errors = @import("../../../kcp/errors.zig");
const frame = @import("../../../kcp/frame.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        fn makeCaseRunner(
            comptime label: []const u8,
            comptime run_case: *const fn (dep.embed.mem.Allocator) anyerror!void,
        ) testing_api.TestRunner {
            const CaseRunner = struct {
                pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
                    _ = self;
                    _ = allocator;
                }

                pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
                    _ = self;
                    run_case(allocator) catch |err| {
                        t.logErrorf("{s} failed: {}", .{ label, err });
                        return false;
                    };
                    return true;
                }

                pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
                    _ = allocator;
                    lib.testing.allocator.destroy(self);
                }
            };

            const value = lib.testing.allocator.create(CaseRunner) catch @panic("OOM");
            value.* = .{};
            return testing_api.TestRunner.make(CaseRunner).new(value);
        }

        fn runEncodeDecode(_: dep.embed.mem.Allocator) !void {
            const testing = lib.testing;

            var buf: [32]u8 = undefined;
            const payload = "abc";
            const n = try frame.encode(&buf, 7, frame.data, payload);
            const decoded = try frame.decode(buf[0..n]);
            try testing.expectEqual(@as(u64, 7), decoded.stream_id);
            try testing.expectEqual(frame.data, decoded.frame_type);
            try testing.expectEqualStrings(payload, decoded.payload);

            const open_n = try frame.encode(&buf, 9, frame.open, &.{});
            const open_frame = try frame.decode(buf[0..open_n]);
            try testing.expectEqual(@as(u64, 9), open_frame.stream_id);
            try testing.expectEqual(frame.open, open_frame.frame_type);
            try testing.expectEqual(@as(usize, 0), open_frame.payload.len);

            const close_n = try frame.encode(&buf, 12, frame.close, &[_]u8{frame.close_reason_abort});
            const close_frame = try frame.decode(buf[0..close_n]);
            try testing.expectEqual(@as(u64, 12), close_frame.stream_id);
            try testing.expectEqual(frame.close, close_frame.frame_type);
            try testing.expectEqual(@as(u8, frame.close_reason_abort), close_frame.payload[0]);

            const close_ack_n = try frame.encode(&buf, 12, frame.close_ack, &.{});
            const close_ack_frame = try frame.decode(buf[0..close_ack_n]);
            try testing.expectEqual(@as(u64, 12), close_ack_frame.stream_id);
            try testing.expectEqual(frame.close_ack, close_ack_frame.frame_type);
            try testing.expectEqual(@as(usize, 0), close_ack_frame.payload.len);
        }

        fn runEncodeDecodeErrors(_: dep.embed.mem.Allocator) !void {
            const testing = lib.testing;

            var short_buf: [1]u8 = undefined;
            try testing.expectError(errors.Error.BufferTooSmall, frame.encode(&short_buf, 128, frame.data, "x"));

            try testing.expectError(errors.Error.InvalidServiceFrame, frame.decode(&.{}));
            try testing.expectError(errors.Error.InvalidServiceFrame, frame.decode(&[_]u8{0x80}));
            try testing.expectError(
                errors.Error.InvalidServiceFrame,
                frame.decode(&[_]u8{ 0xff, 0xff, 0xff, 0xff, 0x10, frame.data }),
            );
        }

        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("encode_decode", makeCaseRunner("kcp/frame/encode_decode", runEncodeDecode));
            t.run("errors", makeCaseRunner("kcp/frame/errors", runEncodeDecodeErrors));
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
