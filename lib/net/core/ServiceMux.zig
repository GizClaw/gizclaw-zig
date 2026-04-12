const dep = @import("dep");
const mem = dep.embed.mem;
const noise = @import("../noise.zig");

const consts = @import("consts.zig");
const errors = @import("errors.zig");
const protocol = @import("protocol.zig");
const UIntMapFile = @import("UIntMap.zig");

// Single-threaded: callers must serialize all ServiceMux access.
pub const StreamAdapter = struct {
    ctx: *anyopaque,
    input: *const fn (ctx: *anyopaque, service: u64, protocol_byte: u8, data: []const u8, now_ms: u64) anyerror!void,
    open: ?*const fn (ctx: *anyopaque, service: u64, now_ms: u64) anyerror!u64 = null,
    accept: ?*const fn (ctx: *anyopaque, service: u64) anyerror!u64 = null,
    send: ?*const fn (ctx: *anyopaque, service: u64, stream_id: u64, payload: []const u8, now_ms: u64) anyerror!usize = null,
    recv: ?*const fn (ctx: *anyopaque, service: u64, stream_id: u64, out: []u8) anyerror!usize = null,
    close_stream: ?*const fn (ctx: *anyopaque, service: u64, stream_id: u64, now_ms: u64) anyerror!void = null,
    stop_accepting: ?*const fn (ctx: *anyopaque, service: u64) anyerror!void = null,
    close_service: ?*const fn (ctx: *anyopaque, service: u64) anyerror!void = null,
    num_streams: ?*const fn (ctx: *anyopaque, service: u64) usize = null,
    tick: ?*const fn (ctx: *anyopaque, now_ms: u64) anyerror!void = null,
    deinit: ?*const fn (ctx: *anyopaque) void = null,
};

pub const Output = struct {
    ctx: *anyopaque,
    write: *const fn (
        ctx: *anyopaque,
        peer: noise.Key,
        service: u64,
        protocol_byte: u8,
        data: []const u8,
    ) anyerror!void,
};

pub const StreamAdapterRuntime = struct {
    peer: noise.Key,
    is_client: bool,
    output: ?Output = null,
    on_output_error: ?*const fn (peer: noise.Key, service: u64, err: anyerror) void = null,
};

pub const StreamAdapterFactory = struct {
    ctx: *anyopaque,
    build: *const fn (
        ctx: *anyopaque,
        allocator: mem.Allocator,
        runtime: StreamAdapterRuntime,
    ) anyerror!StreamAdapter,
};

pub const Config = struct {
    is_client: bool = false,
    output: ?Output = null,
    on_output_error: ?*const fn (peer: noise.Key, service: u64, err: anyerror) void = null,
    on_new_service: ?*const fn (peer: noise.Key, service: u64) bool = null,
    stream_adapter: ?StreamAdapter = null,
    stream_adapter_factory: ?StreamAdapterFactory = null,
    inbound_queue_size: usize = consts.inbound_queue_size,
};

pub const service_mux_frame_open: u8 = 0;
pub const service_mux_frame_data: u8 = 1;
pub const service_mux_frame_close: u8 = 2;
pub const service_mux_frame_close_ack: u8 = 3;

pub const service_stream_close_reason_close: u8 = 0;
pub const service_stream_close_reason_abort: u8 = 1;
pub const service_stream_close_reason_invalid: u8 = 2;

pub fn make(comptime lib: type, comptime Noise: type) type {
    _ = Noise;

    return struct {
        pub const ReadResult = struct {
            protocol_byte: u8,
            n: usize,
        };

        allocator: mem.Allocator,
        peer: noise.Key,
        config: Config,
        services: UIntMapFile.make(u64, ServiceState),
        direct_queue: PacketQueue,
        closed: bool = false,
        output_errors: u64 = 0,

        const Self = @This();
        const ServiceState = struct {
            service_id: u64,
            closed: bool = false,
            accepting_stopped: bool = false,

            fn deinit(_: *ServiceState) void {}
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
                while (self.pop()) |packet| {
                    self.allocator.free(packet.payload);
                }
                self.allocator.free(self.slots);
                self.slots = &.{};
                self.head = 0;
                self.tail = 0;
                self.len = 0;
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

            fn matchingOffset(self: *const PacketQueue, protocol_byte: u8) ?usize {
                var offset: usize = 0;
                while (offset < self.len) : (offset += 1) {
                    const index = (self.head + offset) % self.slots.len;
                    if (self.slots[index].packet.protocol_byte == protocol_byte) return offset;
                }
                return null;
            }

            fn packetAtOffset(self: *const PacketQueue, offset: usize) Packet {
                return self.slots[(self.head + offset) % self.slots.len].packet;
            }

            fn removeAtOffset(self: *PacketQueue, offset: usize) Packet {
                var cursor = offset;
                const removed = self.packetAtOffset(offset);
                while (cursor + 1 < self.len) : (cursor += 1) {
                    const to_index = (self.head + cursor) % self.slots.len;
                    const from_index = (self.head + cursor + 1) % self.slots.len;
                    self.slots[to_index] = self.slots[from_index];
                }
                self.tail = (self.tail + self.slots.len - 1) % self.slots.len;
                self.slots[self.tail] = .{};
                self.len -= 1;
                return removed;
            }
        };

        pub fn init(allocator: mem.Allocator, peer: noise.Key, config: Config) !Self {
            var resolved_config = config;
            if (resolved_config.stream_adapter == null) {
                if (resolved_config.stream_adapter_factory) |factory| {
                    resolved_config.stream_adapter = try factory.build(factory.ctx, allocator, .{
                        .peer = peer,
                        .is_client = resolved_config.is_client,
                        .output = resolved_config.output,
                        .on_output_error = resolved_config.on_output_error,
                    });
                }
            }
            return .{
                .allocator = allocator,
                .peer = peer,
                .config = resolved_config,
                .services = try UIntMapFile.make(u64, ServiceState).init(allocator, 8),
                .direct_queue = try PacketQueue.init(allocator, resolved_config.inbound_queue_size),
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            if (self.config.stream_adapter) |adapter| {
                if (adapter.deinit) |deinit_fn| deinit_fn(adapter.ctx);
            }
            self.services.deinit();
        }

        pub fn input(self: *Self, service: u64, protocol_byte: u8, data: []const u8) !void {
            return try self.inputAt(service, protocol_byte, data, nowMs());
        }

        pub fn inputAt(self: *Self, service: u64, protocol_byte: u8, data: []const u8, now_ms: u64) !void {
            if (self.closed) return errors.Error.ConnClosed;
            if (protocol.isStream(protocol_byte)) {
                const state = try self.getOrCreateService(service);
                if (state.closed) return try self.rejectUnknownService(service, protocol_byte, data);
                if (state.accepting_stopped and shouldRejectStoppedService(protocol_byte, data)) {
                    return try self.rejectUnknownService(service, protocol_byte, data);
                }

                const adapter = self.config.stream_adapter orelse return errors.Error.StreamAdapterUnavailable;
                try adapter.input(adapter.ctx, service, protocol_byte, data, now_ms);
                return;
            }

            try self.direct_queue.pushCopy(protocol_byte, data);
        }

        pub fn read(self: *Self, out: []u8) !ReadResult {
            if (self.direct_queue.len == 0) return errors.Error.QueueEmpty;

            const packet = self.direct_queue.packetAtOffset(0);
            if (out.len < packet.payload.len) return errors.Error.BufferTooSmall;

            const owned = self.direct_queue.pop() orelse return errors.Error.QueueEmpty;
            defer self.allocator.free(owned.payload);
            @memcpy(out[0..owned.payload.len], owned.payload);
            return .{
                .protocol_byte = owned.protocol_byte,
                .n = owned.payload.len,
            };
        }

        pub fn readServiceProtocol(self: *Self, service: u64, protocol_byte: u8, out: []u8) !usize {
            if (protocol.isStream(protocol_byte)) return errors.Error.KCPMustUseStream;
            if (service != 0) return errors.Error.QueueEmpty;

            const offset = self.direct_queue.matchingOffset(protocol_byte) orelse return errors.Error.QueueEmpty;
            const packet = self.direct_queue.packetAtOffset(offset);
            if (out.len < packet.payload.len) return errors.Error.BufferTooSmall;

            const owned = self.direct_queue.removeAtOffset(offset);
            defer self.allocator.free(owned.payload);

            @memcpy(out[0..owned.payload.len], owned.payload);
            return owned.payload.len;
        }

        pub fn write(self: *Self, protocol_byte: u8, data: []const u8) !usize {
            return self.writeService(0, protocol_byte, data);
        }

        pub fn writeService(self: *Self, service: u64, protocol_byte: u8, data: []const u8) !usize {
            if (self.closed) return errors.Error.ConnClosed;
            if (protocol.isStream(protocol_byte)) return errors.Error.KCPMustUseStream;
            if (service != 0) return errors.Error.ServiceRejected;

            const output = self.config.output orelse return errors.Error.NoSession;
            try output.write(output.ctx, self.peer, service, protocol_byte, data);
            return data.len;
        }

        pub fn openStream(self: *Self, service: u64) !u64 {
            return try self.openStreamAt(service, nowMs());
        }

        pub fn openStreamAt(self: *Self, service: u64, now_ms: u64) !u64 {
            if (self.closed) return errors.Error.ConnClosed;
            const state = try self.getOrCreateService(service);
            if (state.closed) return errors.Error.ServiceRejected;
            const adapter = self.config.stream_adapter orelse return errors.Error.StreamAdapterUnavailable;
            const open = adapter.open orelse return errors.Error.StreamAdapterUnavailable;
            return try open(adapter.ctx, service, now_ms);
        }

        pub fn acceptStream(self: *Self, service: u64) !u64 {
            if (self.closed) return errors.Error.ConnClosed;
            const state = try self.getOrCreateService(service);
            if (state.closed) return errors.Error.ServiceRejected;
            const adapter = self.config.stream_adapter orelse return errors.Error.StreamAdapterUnavailable;
            const accept = adapter.accept orelse return errors.Error.StreamAdapterUnavailable;
            return try accept(adapter.ctx, service);
        }

        pub fn sendStream(self: *Self, service: u64, stream_id: u64, payload: []const u8, now_ms: u64) !usize {
            if (self.closed) return errors.Error.ConnClosed;
            const state = try self.getOrCreateService(service);
            if (state.closed) return errors.Error.ServiceRejected;
            const adapter = self.config.stream_adapter orelse return errors.Error.StreamAdapterUnavailable;
            const send = adapter.send orelse return errors.Error.StreamAdapterUnavailable;
            return try send(adapter.ctx, service, stream_id, payload, now_ms);
        }

        pub fn recvStream(self: *Self, service: u64, stream_id: u64, out: []u8) !usize {
            if (self.closed) return errors.Error.ConnClosed;
            const state = try self.getOrCreateService(service);
            if (state.closed) return errors.Error.ServiceRejected;
            const adapter = self.config.stream_adapter orelse return errors.Error.StreamAdapterUnavailable;
            const recv = adapter.recv orelse return errors.Error.StreamAdapterUnavailable;
            return try recv(adapter.ctx, service, stream_id, out);
        }

        pub fn closeStream(self: *Self, service: u64, stream_id: u64, now_ms: u64) !void {
            if (self.closed) return errors.Error.ConnClosed;
            const state = try self.getOrCreateService(service);
            if (state.closed) return errors.Error.ServiceRejected;
            const adapter = self.config.stream_adapter orelse return errors.Error.StreamAdapterUnavailable;
            const close_stream = adapter.close_stream orelse return errors.Error.StreamAdapterUnavailable;
            try close_stream(adapter.ctx, service, stream_id, now_ms);
        }

        pub fn tick(self: *Self, now_ms: u64) !void {
            if (self.closed) return;
            const adapter = self.config.stream_adapter orelse return;
            const tick_fn = adapter.tick orelse return;
            try tick_fn(adapter.ctx, now_ms);
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
            self.direct_queue.deinit();

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

        fn nowMs() u64 {
            return @intCast(lib.time.milliTimestamp());
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
            output.write(output.ctx, self.peer, service, protocol.kcp, frame[0..total]) catch |err| self.reportOutputError(service, err);
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
