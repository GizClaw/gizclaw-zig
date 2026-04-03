const dep = @import("dep");
const testing_api = @import("dep").testing;
const mem = dep.embed.mem;
const noise = @import("../../../noise.zig");
const errors = @import("../../../core/errors.zig");
const protocol = @import("../../../core/protocol.zig");
const ServiceMuxFile = @import("../../../core/ServiceMux.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib, lib.testing, allocator) catch |err| {
                t.logErrorf("core/ServiceMux failed: {}", .{err});
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

fn runCases(comptime lib: type, testing: anytype, allocator: mem.Allocator) !void {
    const Noise = noise.make(lib);
    const Package = ServiceMuxFile.make(lib, Noise);
    var output_capture = OutputCapture{};

    var mux = try Package.init(allocator, noise.Key.zero, .{
        .on_new_service = allowAllServices,
        .output = outputCaptureHook(&output_capture),
    });
    defer mux.deinit();

    try mux.input(0, protocol.event, "event");
    try mux.input(2, protocol.opus, "opus");
    try mux.input(0, protocol.opus, "lane");

    var buf: [16]u8 = undefined;
    const event_n = try mux.readServiceProtocol(0, protocol.event, &buf);
    try testing.expectEqualStrings("event", buf[0..event_n]);

    const opus_n = try mux.readServiceProtocol(2, protocol.opus, &buf);
    try testing.expectEqualStrings("opus", buf[0..opus_n]);

    const default_read = try mux.read(&buf);
    try testing.expectEqual(protocol.opus, default_read.protocol_byte);
    try testing.expectEqualStrings("lane", buf[0..default_read.n]);

    try mux.input(0, protocol.event, "drop-me-not");
    var short_buf: [4]u8 = undefined;
    try testing.expectError(errors.Error.BufferTooSmall, mux.readServiceProtocol(0, protocol.event, &short_buf));
    const retained_n = try mux.readServiceProtocol(0, protocol.event, &buf);
    try testing.expectEqualStrings("drop-me-not", buf[0..retained_n]);

    try testing.expectError(errors.Error.QueueEmpty, mux.readServiceProtocol(2, protocol.opus, &buf));
    try testing.expectError(errors.Error.RPCMustUseStream, mux.write(protocol.rpc, "x"));
    var reject_mux = try Package.init(allocator, noise.Key.zero, .{});
    defer reject_mux.deinit();
    try testing.expectError(errors.Error.ServiceRejected, reject_mux.input(5, protocol.event, "x"));

    var no_output_mux = try Package.init(allocator, noise.Key.zero, .{
        .on_new_service = allowAllServices,
    });
    defer no_output_mux.deinit();
    try testing.expectError(errors.Error.NoSession, no_output_mux.write(protocol.event, "x"));

    var tiny_mux = try Package.init(allocator, noise.Key.zero, .{
        .on_new_service = allowAllServices,
        .inbound_queue_size = 1,
    });
    defer tiny_mux.deinit();
    try tiny_mux.input(0, protocol.event, "a");
    try testing.expectError(errors.Error.InboundQueueFull, tiny_mux.input(0, protocol.event, "b"));

    var factory_capture = StreamFactoryCapture{};
    const factory_peer = noise.Key.fromBytes([_]u8{3} ** noise.Key.key_size);
    {
        var factory_mux = try Package.init(allocator, factory_peer, .{
            .is_client = true,
            .stream_adapter_factory = streamCaptureFactory(&factory_capture),
        });
        defer factory_mux.deinit();
        try testing.expect(factory_capture.built);
        try testing.expect(factory_capture.runtime.peer.eql(factory_peer));
        try testing.expect(factory_capture.runtime.is_client);
        try factory_mux.tick(77);
        try testing.expectEqual(@as(u64, 77), factory_capture.last_tick_ms);
    }
    try testing.expect(factory_capture.deinitialized);
    try testing.expectError(error.FactoryFailed, Package.init(allocator, noise.Key.zero, .{
        .stream_adapter_factory = failingStreamFactory(),
    }));

    var frame: [noise.Varint.max_len + 2]u8 = undefined;
    const frame_n = noise.Varint.encode(&frame, 7);
    frame[frame_n] = ServiceMuxFile.service_mux_frame_open;
    frame[frame_n + 1] = 0;
    try testing.expect(ServiceMuxFile.shouldRejectStoppedService(protocol.rpc, frame[0 .. frame_n + 2]));
    try mux.stopAcceptingService(9);
    try testing.expectError(errors.Error.ServiceRejected, mux.input(9, protocol.rpc, frame[0 .. frame_n + 2]));
    try testing.expectEqual(@as(u64, 9), output_capture.service);
    try testing.expectEqual(protocol.rpc, output_capture.protocol_byte);
    const rejected_frame = try ServiceMuxFile.decodeServiceMuxFrame(output_capture.payload[0..output_capture.len]);
    try testing.expectEqual(@as(u64, 7), rejected_frame.stream_id);
    try testing.expectEqual(ServiceMuxFile.service_mux_frame_close, rejected_frame.frame_type);
    try testing.expectEqual(@as(u8, ServiceMuxFile.service_stream_close_reason_abort), rejected_frame.payload[0]);
}

fn allowAllServices(_: noise.Key, _: u64) bool {
    return true;
}

const OutputCapture = struct {
    service: u64 = 0,
    protocol_byte: u8 = 0,
    payload: [32]u8 = [_]u8{0} ** 32,
    len: usize = 0,
};

const StreamFactoryCapture = struct {
    runtime: ServiceMuxFile.StreamAdapterRuntime = .{
        .peer = noise.Key.zero,
        .is_client = false,
    },
    built: bool = false,
    deinitialized: bool = false,
    last_tick_ms: u64 = 0,
};

fn outputCaptureHook(capture: *OutputCapture) ServiceMuxFile.Output {
    return .{
        .ctx = capture,
        .write = captureOutput,
    };
}

fn captureOutput(ctx: *anyopaque, _: noise.Key, service: u64, protocol_byte: u8, data: []const u8) !void {
    const capture: *OutputCapture = @ptrCast(@alignCast(ctx));
    if (data.len > capture.payload.len) return errors.Error.BufferTooSmall;
    capture.service = service;
    capture.protocol_byte = protocol_byte;
    capture.len = data.len;
    @memcpy(capture.payload[0..data.len], data);
}

fn streamCaptureFactory(ctx: *StreamFactoryCapture) ServiceMuxFile.StreamAdapterFactory {
    return .{
        .ctx = ctx,
        .build = streamCaptureFactoryBuild,
    };
}

fn streamCaptureFactoryBuild(ctx: *anyopaque, _: mem.Allocator, runtime: ServiceMuxFile.StreamAdapterRuntime) !ServiceMuxFile.StreamAdapter {
    const capture: *StreamFactoryCapture = @ptrCast(@alignCast(ctx));
    capture.runtime = runtime;
    capture.built = true;
    return .{
        .ctx = capture,
        .input = streamFactoryInput,
        .tick = streamFactoryTick,
        .deinit = streamFactoryDeinit,
    };
}

fn failingStreamFactory() ServiceMuxFile.StreamAdapterFactory {
    return .{
        .ctx = undefined,
        .build = failingStreamFactoryBuild,
    };
}

fn failingStreamFactoryBuild(_: *anyopaque, _: mem.Allocator, _: ServiceMuxFile.StreamAdapterRuntime) !ServiceMuxFile.StreamAdapter {
    return error.FactoryFailed;
}

fn streamFactoryInput(_: *anyopaque, _: u64, _: u8, _: []const u8, _: u64) !void {}

fn streamFactoryTick(ctx: *anyopaque, now_ms: u64) !void {
    const capture: *StreamFactoryCapture = @ptrCast(@alignCast(ctx));
    capture.last_tick_ms = now_ms;
}

fn streamFactoryDeinit(ctx: *anyopaque) void {
    const capture: *StreamFactoryCapture = @ptrCast(@alignCast(ctx));
    capture.deinitialized = true;
}
