const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");

const AdapterMod = @import("../../../kcp/Adapter.zig");
const core = @import("../../../core.zig");
const frame = @import("../../../kcp/frame.zig");
const kcp_errors = @import("../../../kcp/errors.zig");

const Adapter = AdapterMod.make(core);

const TestErr = error{FailWrite};

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

        fn runAdapterBehavior(allocator: dep.embed.mem.Allocator) !void {
            const testing = lib.testing;

            var output_capture = OutputCapture{};
            var error_capture = ErrorCapture{};
            var adapter = try Adapter.init(allocator, .{
                .peer = noise.Key.fromBytes([_]u8{1} ** noise.Key.key_size),
                .is_client = true,
                .output = outputCaptureHook(&output_capture),
                .on_output_error = captureOutputError,
            }, .{});
            defer adapter.deinit();

            const stream_a = try adapter.open(7, 1);
            try testing.expectEqual(@as(u64, 1), stream_a);
            try testing.expectEqual(@as(u64, 7), output_capture.service);
            try testing.expectEqual(core.protocol.kcp, output_capture.protocol_byte);
            const open_frame = try frame.decode(output_capture.payload[0..output_capture.len]);
            try testing.expectEqual(@as(u64, 1), open_frame.stream_id);
            try testing.expectEqual(frame.open, open_frame.frame_type);

            output_capture.reset();
            const stream_b = try adapter.open(8, 2);
            try testing.expectEqual(@as(u64, 1), stream_b);
            try testing.expectEqual(@as(u64, 8), output_capture.service);
            try testing.expectEqual(@as(usize, 1), adapter.numStreams(7));
            try testing.expectEqual(@as(usize, 1), adapter.numStreams(8));

            var server_adapter = try Adapter.init(allocator, .{
                .peer = noise.Key.fromBytes([_]u8{2} ** noise.Key.key_size),
                .is_client = false,
                .output = outputCaptureHook(&output_capture),
            }, .{});
            defer server_adapter.deinit();
            output_capture.reset();
            try testing.expectEqual(@as(u64, 0), try server_adapter.open(3, 3));

            try testing.expectError(core.Error.UnsupportedProtocol, adapter.input(7, 0x03, "x", 4));
            try adapter.stopAccepting(9);
            try testing.expectError(kcp_errors.Error.AcceptQueueEmpty, adapter.accept(9));
            try adapter.closeService(10);
            try testing.expectError(core.Error.ServiceRejected, adapter.open(10, 5));

            var no_output_adapter = try Adapter.init(allocator, .{
                .peer = noise.Key.zero,
                .is_client = true,
            }, .{});
            defer no_output_adapter.deinit();
            try testing.expectError(core.Error.NoSession, no_output_adapter.open(11, 6));

            var factory = Adapter.Factory{};
            const adapter_factory = factory.adapterFactory();
            const built = try adapter_factory.build(adapter_factory.ctx, allocator, .{
                .peer = noise.Key.zero,
                .is_client = true,
                .output = outputCaptureHook(&output_capture),
            });
            defer if (built.deinit) |deinit_fn| deinit_fn(built.ctx);
            try testing.expect(built.open != null);

            var failing_output_adapter = try Adapter.init(allocator, .{
                .peer = noise.Key.zero,
                .is_client = true,
                .output = failingOutputHook(),
                .on_output_error = captureOutputError,
            }, .{});
            defer failing_output_adapter.deinit();
            error_capture.reset();
            output_error_capture = &error_capture;
            defer output_error_capture = null;
            try testing.expectError(TestErr.FailWrite, failing_output_adapter.open(12, 7));
            try testing.expectEqual(@as(u64, 12), error_capture.service);
            try testing.expectEqual(@as(usize, 1), error_capture.count);
        }

        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("behavior", makeCaseRunner("kcp/Adapter/behavior", runAdapterBehavior));
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

const OutputCapture = struct {
    service: u64 = 0,
    protocol_byte: u8 = 0,
    payload: [128]u8 = [_]u8{0} ** 128,
    len: usize = 0,

    fn reset(self: *OutputCapture) void {
        self.service = 0;
        self.protocol_byte = 0;
        self.len = 0;
    }
};

const ErrorCapture = struct {
    service: u64 = 0,
    count: usize = 0,

    fn reset(self: *ErrorCapture) void {
        self.service = 0;
        self.count = 0;
    }
};

var output_error_capture: ?*ErrorCapture = null;

fn outputCaptureHook(capture: *OutputCapture) core.ServiceMux.Output {
    return .{
        .ctx = capture,
        .write = captureOutput,
    };
}

fn captureOutput(ctx: *anyopaque, _: noise.Key, service: u64, protocol_byte: u8, data: []const u8) !void {
    const capture: *OutputCapture = @ptrCast(@alignCast(ctx));
    if (data.len > capture.payload.len) return error.BufferTooSmall;
    capture.service = service;
    capture.protocol_byte = protocol_byte;
    capture.len = data.len;
    @memcpy(capture.payload[0..data.len], data);
}

fn failingOutputHook() core.ServiceMux.Output {
    return .{
        .ctx = undefined,
        .write = failingOutputWrite,
    };
}

fn failingOutputWrite(_: *anyopaque, _: noise.Key, _: u64, _: u8, _: []const u8) !void {
    return TestErr.FailWrite;
}

fn captureOutputError(_: noise.Key, service: u64, _: anyerror) void {
    const capture = output_error_capture orelse return;
    capture.service = service;
    capture.count += 1;
}
