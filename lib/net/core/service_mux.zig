const embed = @import("embed");
const mem = embed.mem;
const noise = @import("noise");

const consts = @import("consts.zig");
const errors = @import("errors.zig");
const map = @import("map.zig");
const protocol = @import("protocol.zig");

// Single-threaded: callers must serialize all ServiceMux access.
pub const StreamAdapter = struct {
    ctx: *anyopaque,
    input: *const fn (ctx: *anyopaque, service: u64, protocol_byte: u8, data: []const u8) anyerror!void,
    open: ?*const fn (ctx: *anyopaque, service: u64) anyerror!u64 = null,
    accept: ?*const fn (ctx: *anyopaque, service: u64) anyerror!u64 = null,
    stop_accepting: ?*const fn (ctx: *anyopaque, service: u64) anyerror!void = null,
    close_service: ?*const fn (ctx: *anyopaque, service: u64) anyerror!void = null,
    num_streams: ?*const fn (ctx: *anyopaque, service: u64) usize = null,
};

pub const Config = struct {
    is_client: bool = false,
    output: ?*const fn (peer: noise.Key, service: u64, protocol_byte: u8, data: []const u8) anyerror!void = null,
    on_output_error: ?*const fn (peer: noise.Key, service: u64, err: anyerror) void = null,
    on_new_service: ?*const fn (peer: noise.Key, service: u64) bool = null,
    stream_adapter: ?StreamAdapter = null,
    inbound_queue_size: usize = consts.inbound_queue_size,
};

pub const service_mux_frame_open: u8 = 0;
pub const service_mux_frame_data: u8 = 1;
pub const service_mux_frame_close: u8 = 2;
pub const service_mux_frame_close_ack: u8 = 3;

pub const service_stream_close_reason_close: u8 = 0;
pub const service_stream_close_reason_abort: u8 = 1;
pub const service_stream_close_reason_invalid: u8 = 2;

pub fn ServiceMux(comptime Noise: type) type {
    _ = Noise;

    return struct {
        allocator: mem.Allocator,
        peer: noise.Key,
        config: Config,
        services: map.UIntMap(u64, ServiceState),
        closed: bool = false,
        output_errors: u64 = 0,

        const Self = @This();
        const ServiceState = struct {
            service_id: u64,
            event_queue: PacketQueue,
            opus_queue: PacketQueue,
            closed: bool = false,
            accepting_stopped: bool = false,

            fn deinit(self: *ServiceState) void {
                self.event_queue.deinit();
                self.opus_queue.deinit();
            }
        };

        const Packet = struct {
            protocol_byte: u8,
            payload: []u8,
        };

        const PacketQueue = struct {
            allocator: mem.Allocator,
            slots: []Slot,
            head: usize = 0,
            tail: usize = 0,
            len: usize = 0,

            const Slot = struct {
                used: bool = false,
                packet: Packet = .{
                    .protocol_byte = 0,
                    .payload = &.{},
                },
            };

            fn init(allocator: mem.Allocator, capacity: usize) !PacketQueue {
                const slots = try allocator.alloc(Slot, @max(capacity, 1));
                for (slots) |*slot| slot.* = .{};
                return .{
                    .allocator = allocator,
                    .slots = slots,
                };
            }

            fn deinit(self: *PacketQueue) void {
                while (self.len > 0) {
                    const packet = self.pop() orelse break;
                    self.allocator.free(packet.payload);
                }
                self.allocator.free(self.slots);
                self.slots = &.{};
            }

            fn pushCopy(self: *PacketQueue, protocol_byte: u8, payload: []const u8) !void {
                if (self.len == self.slots.len) return errors.Error.InboundQueueFull;

                const owned = try self.allocator.alloc(u8, payload.len);
                @memcpy(owned, payload);
                self.slots[self.tail] = .{
                    .used = true,
                    .packet = .{
                        .protocol_byte = protocol_byte,
                        .payload = owned,
                    },
                };
                self.tail = (self.tail + 1) % self.slots.len;
                self.len += 1;
            }

            fn pop(self: *PacketQueue) ?Packet {
                if (self.len == 0) return null;
                const slot = &self.slots[self.head];
                const packet = slot.packet;
                slot.* = .{};
                self.head = (self.head + 1) % self.slots.len;
                self.len -= 1;
                return packet;
            }
        };

        pub fn init(allocator: mem.Allocator, peer: noise.Key, config: Config) !Self {
            return .{
                .allocator = allocator,
                .peer = peer,
                .config = config,
                .services = try map.UIntMap(u64, ServiceState).init(allocator, 8),
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.services.deinit();
        }

        pub fn input(self: *Self, service: u64, protocol_byte: u8, data: []const u8) !void {
            if (self.closed) return errors.Error.ConnClosed;
            try protocol.validate(protocol_byte);

            const state = try self.getOrCreateService(service);
            if (state.closed) return try self.rejectUnknownService(service, protocol_byte, data);
            if (state.accepting_stopped and shouldRejectStoppedService(protocol_byte, data)) {
                return try self.rejectUnknownService(service, protocol_byte, data);
            }

            switch (protocol_byte) {
                protocol.http, protocol.rpc => {
                    const adapter = self.config.stream_adapter orelse return errors.Error.StreamAdapterUnavailable;
                    try adapter.input(adapter.ctx, service, protocol_byte, data);
                },
                protocol.event => try state.event_queue.pushCopy(protocol_byte, data),
                protocol.opus => try state.opus_queue.pushCopy(protocol_byte, data),
                else => return errors.Error.UnsupportedProtocol,
            }
        }

        pub fn read(self: *Self, out: []u8) !struct { protocol_byte: u8, n: usize } {
            const state = self.getService(0) orelse return errors.Error.QueueEmpty;
            if (state.event_queue.len > 0) {
                return .{
                    .protocol_byte = protocol.event,
                    .n = try self.readServiceProtocol(0, protocol.event, out),
                };
            }
            if (state.opus_queue.len > 0) {
                return .{
                    .protocol_byte = protocol.opus,
                    .n = try self.readServiceProtocol(0, protocol.opus, out),
                };
            }
            return errors.Error.QueueEmpty;
        }

        pub fn readServiceProtocol(self: *Self, service: u64, protocol_byte: u8, out: []u8) !usize {
            const state = self.getService(service) orelse return errors.Error.QueueEmpty;
            const queue = switch (protocol_byte) {
                protocol.event => &state.event_queue,
                protocol.opus => &state.opus_queue,
                protocol.rpc => return errors.Error.RPCMustUseStream,
                protocol.http => return errors.Error.HTTPMustUseStream,
                else => return errors.Error.UnsupportedProtocol,
            };

            if (queue.len == 0) return errors.Error.QueueEmpty;
            const packet = queue.slots[queue.head].packet;
            if (out.len < packet.payload.len) return errors.Error.BufferTooSmall;

            const owned = queue.pop() orelse return errors.Error.QueueEmpty;
            defer self.allocator.free(owned.payload);

            @memcpy(out[0..owned.payload.len], owned.payload);
            return owned.payload.len;
        }

        pub fn write(self: *Self, protocol_byte: u8, data: []const u8) !usize {
            return self.writeService(0, protocol_byte, data);
        }

        pub fn writeService(self: *Self, service: u64, protocol_byte: u8, data: []const u8) !usize {
            if (self.closed) return errors.Error.ConnClosed;
            switch (protocol_byte) {
                protocol.rpc => return errors.Error.RPCMustUseStream,
                protocol.http => return errors.Error.HTTPMustUseStream,
                protocol.event, protocol.opus => {},
                else => return errors.Error.UnsupportedProtocol,
            }

            const output = self.config.output orelse return errors.Error.NoSession;
            try output(self.peer, service, protocol_byte, data);
            return data.len;
        }

        pub fn openStream(self: *Self, service: u64) !u64 {
            if (self.closed) return errors.Error.ConnClosed;
            _ = try self.getOrCreateService(service);
            const adapter = self.config.stream_adapter orelse return errors.Error.StreamAdapterUnavailable;
            const open = adapter.open orelse return errors.Error.StreamAdapterUnavailable;
            return try open(adapter.ctx, service);
        }

        pub fn acceptStream(self: *Self, service: u64) !u64 {
            if (self.closed) return errors.Error.ConnClosed;
            _ = try self.getOrCreateService(service);
            const adapter = self.config.stream_adapter orelse return errors.Error.StreamAdapterUnavailable;
            const accept = adapter.accept orelse return errors.Error.StreamAdapterUnavailable;
            return try accept(adapter.ctx, service);
        }

        pub fn closeService(self: *Self, service: u64) !void {
            const state = try self.getOrCreateService(service);
            state.closed = true;
            state.accepting_stopped = true;
            if (self.config.stream_adapter) |adapter| {
                if (adapter.close_service) |close_service| try close_service(adapter.ctx, service);
            }
        }

        pub fn stopAcceptingService(self: *Self, service: u64) !void {
            const state = try self.getOrCreateService(service);
            state.accepting_stopped = true;
            if (self.config.stream_adapter) |adapter| {
                if (adapter.stop_accepting) |stop_accepting| try stop_accepting(adapter.ctx, service);
            }
        }

        pub fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;

            for (self.services.slots) |*slot| {
                if (slot.state != .full) continue;
                slot.value.deinit();
                slot.state = .empty;
            }
            self.services.count_value = 0;
            self.services.tombstones = 0;
        }

        pub fn numServices(self: *const Self) usize {
            return self.services.count();
        }

        pub fn numStreams(self: *const Self) usize {
            const adapter = self.config.stream_adapter orelse return 0;
            const count_fn = adapter.num_streams orelse return 0;

            var total: usize = 0;
            for (self.services.slots) |slot| {
                if (slot.state != .full) continue;
                total += count_fn(adapter.ctx, slot.key);
            }
            return total;
        }

        pub fn outputErrorCount(self: *const Self) u64 {
            return self.output_errors;
        }

        pub fn getService(self: *Self, service: u64) ?*ServiceState {
            return self.services.getPtr(service);
        }

        fn getOrCreateService(self: *Self, service: u64) !*ServiceState {
            if (self.getService(service)) |state| return state;

            if (self.config.on_new_service) |callback| {
                if (!callback(self.peer, service)) return errors.Error.ServiceRejected;
            } else if (service != 0) {
                return errors.Error.ServiceRejected;
            }

            var state = ServiceState{
                .service_id = service,
                .event_queue = try PacketQueue.init(self.allocator, self.config.inbound_queue_size),
                .opus_queue = try PacketQueue.init(self.allocator, self.config.inbound_queue_size),
            };
            errdefer state.deinit();
            _ = try self.services.put(service, state);
            return self.services.getPtr(service).?;
        }

        fn rejectUnknownService(self: *Self, service: u64, protocol_byte: u8, data: []const u8) !void {
            if (!protocol.isStream(protocol_byte)) return errors.Error.ServiceRejected;

            const decoded = try decodeServiceMuxFrame(data);
            switch (decoded.frame_type) {
                service_mux_frame_open => self.sendServiceControlFrame(
                    service,
                    decoded.stream_id,
                    service_mux_frame_close,
                    &[_]u8{service_stream_close_reason_abort},
                ),
                service_mux_frame_close => self.sendServiceControlFrame(service, decoded.stream_id, service_mux_frame_close_ack, &.{}),
                else => self.sendServiceControlFrame(
                    service,
                    decoded.stream_id,
                    service_mux_frame_close,
                    &[_]u8{service_stream_close_reason_invalid},
                ),
            }
            return errors.Error.ServiceRejected;
        }

        fn sendServiceControlFrame(self: *Self, service: u64, stream_id: u64, frame_type: u8, payload: []const u8) void {
            const output = self.config.output orelse return;

            var frame: [noise.Varint.max_len + 1 + 16]u8 = undefined;
            const prefix_len = noise.Varint.encode(&frame, stream_id);
            frame[prefix_len] = frame_type;
            const total = prefix_len + 1 + payload.len;
            if (total > frame.len) return;
            @memcpy(frame[prefix_len + 1 .. total], payload);
            output(self.peer, service, protocol.rpc, frame[0..total]) catch |err| self.reportOutputError(service, err);
        }

        fn reportOutputError(self: *Self, service: u64, err: anyerror) void {
            self.output_errors += 1;
            if (self.config.on_output_error) |callback| callback(self.peer, service, err);
        }
    };
}

pub fn decodeServiceMuxFrame(data: []const u8) !struct { stream_id: u64, frame_type: u8, payload: []const u8 } {
    const stream_id = try noise.Varint.decode(data);
    if (data.len <= stream_id.n) return errors.Error.InvalidServiceFrame;
    return .{
        .stream_id = stream_id.value,
        .frame_type = data[stream_id.n],
        .payload = data[stream_id.n + 1 ..],
    };
}

pub fn shouldRejectStoppedService(protocol_byte: u8, data: []const u8) bool {
    if (!protocol.isStream(protocol_byte)) return false;
    const decoded = decodeServiceMuxFrame(data) catch return false;
    return decoded.frame_type == service_mux_frame_open;
}

pub fn testAll(comptime lib: type, testing: anytype, allocator: mem.Allocator) !void {
    const noise_mod = @import("noise");
    const Package = ServiceMux(noise_mod.make(noise_mod.LibAdapter.make(lib)));
    var output_capture = OutputCapture{};
    active_output_capture = &output_capture;
    defer active_output_capture = null;

    var mux = try Package.init(allocator, noise.Key.zero, .{
        .on_new_service = allowAllServices,
        .output = captureOutput,
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

    var frame: [noise.Varint.max_len + 2]u8 = undefined;
    const frame_n = noise.Varint.encode(&frame, 7);
    frame[frame_n] = service_mux_frame_open;
    frame[frame_n + 1] = 0;
    try testing.expect(shouldRejectStoppedService(protocol.rpc, frame[0 .. frame_n + 2]));
    try mux.stopAcceptingService(9);
    try testing.expectError(errors.Error.ServiceRejected, mux.input(9, protocol.rpc, frame[0 .. frame_n + 2]));
    try testing.expectEqual(@as(u64, 9), output_capture.service);
    try testing.expectEqual(protocol.rpc, output_capture.protocol_byte);
    const rejected_frame = try decodeServiceMuxFrame(output_capture.payload[0..output_capture.len]);
    try testing.expectEqual(@as(u64, 7), rejected_frame.stream_id);
    try testing.expectEqual(service_mux_frame_close, rejected_frame.frame_type);
    try testing.expectEqual(@as(u8, service_stream_close_reason_abort), rejected_frame.payload[0]);
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

var active_output_capture: ?*OutputCapture = null;

fn captureOutput(_: noise.Key, service: u64, protocol_byte: u8, data: []const u8) !void {
    const capture = active_output_capture orelse return;
    if (data.len > capture.payload.len) return errors.Error.BufferTooSmall;
    capture.service = service;
    capture.protocol_byte = protocol_byte;
    capture.len = data.len;
    @memcpy(capture.payload[0..data.len], data);
}
