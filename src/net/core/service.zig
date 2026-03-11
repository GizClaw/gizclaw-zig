const std = @import("std");
const runtime = @import("embed").runtime;

pub const ServiceError = error{
    ServiceMuxClosed,
    ServiceRejected,
    AcceptQueueClosed,
    InboundQueueFull,
    UnsupportedProtocol,
    OutOfMemory,
};

const protocol_event: u8 = 0x03;
const protocol_opus: u8 = 0x10;
const protocol_rpc: u8 = 0x81;

pub fn ServiceMux(
    comptime KCPMuxType: type,
    comptime MutexImpl: type,
    comptime CondImpl: type,
    comptime TimeImpl: type,
) type {
    comptime {
        _ = runtime.sync.Mutex(MutexImpl);
        _ = runtime.sync.Condition(CondImpl);
        _ = runtime.time.from(TimeImpl);
        _ = KCPMuxType.Stream;
        _ = KCPMuxType.Config;
    }

    return struct {
        const Self = @This();

        pub const ReadResult = struct { protocol: u8, bytes_read: usize };

        pub const Config = struct {
            kcp_is_client: bool,
            output: *const fn (service_port: u64, protocol: u8, data: []const u8) anyerror!void,
            on_output_error: ?*const fn (service_port: u64, err: anyerror) void = null,
            on_new_service: ?*const fn (service_port: u64) bool = null,
            kcp_accept_backlog: usize = 32,
        };

        const ProtoPacket = struct {
            protocol: u8,
            payload: []u8,
        };

        const InboundQueue = struct {
            items: [256]?ProtoPacket = [_]?ProtoPacket{null} ** 256,
            head: usize = 0,
            tail: usize = 0,
            len: usize = 0,
            is_closed: bool = false,

            fn push(self: *InboundQueue, item: ProtoPacket) bool {
                if (self.len >= self.items.len) return false;
                self.items[self.tail] = item;
                self.tail = (self.tail + 1) % self.items.len;
                self.len += 1;
                return true;
            }

            fn pop(self: *InboundQueue) ?ProtoPacket {
                if (self.len == 0) return null;
                const item = self.items[self.head];
                self.items[self.head] = null;
                self.head = (self.head + 1) % self.items.len;
                self.len -= 1;
                return item;
            }
        };

        const ServiceState = struct {
            mux: *KCPMuxType,
            event_inbound: InboundQueue = .{},
            opus_inbound: InboundQueue = .{},
            inbound_mu: MutexImpl,
            inbound_cond: CondImpl,

            fn create(allocator: std.mem.Allocator, kcp_mux: *KCPMuxType) !*ServiceState {
                const state = try allocator.create(ServiceState);
                state.* = .{
                    .mux = kcp_mux,
                    .inbound_mu = MutexImpl.init(),
                    .inbound_cond = CondImpl.init(),
                };
                return state;
            }
        };

        config: Config,
        services: std.AutoHashMap(u64, *ServiceState),
        services_mu: MutexImpl,
        closed: std.atomic.Value(bool),
        output_errors: std.atomic.Value(u64),
        time: TimeImpl,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, time: TimeImpl, config: Config) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            self.* = .{
                .config = config,
                .services = std.AutoHashMap(u64, *ServiceState).init(allocator),
                .services_mu = MutexImpl.init(),
                .closed = std.atomic.Value(bool).init(false),
                .output_errors = std.atomic.Value(u64).init(0),
                .time = time,
                .allocator = allocator,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.cleanupServices();
            self.services_mu.deinit();
            self.allocator.destroy(self);
        }

        pub fn input(self: *Self, service_port: u64, protocol: u8, data: []const u8) ServiceError!void {
            if (self.closed.load(.acquire)) return ServiceError.ServiceMuxClosed;

            switch (protocol) {
                protocol_rpc => {
                    const state: *ServiceState = try self.getOrCreateService(service_port);
                    try state.mux.input(data);
                },
                protocol_event, protocol_opus => {
                    const state: *ServiceState = try self.getOrCreateService(service_port);
                    try self.pushDirectInbound(state, protocol, data);
                },
                else => return ServiceError.UnsupportedProtocol,
            }
        }

        /// Read a direct packet from service 0, merging EVENT and OPUS.
        pub fn read(self: *Self, buf: []u8) ServiceError!ReadResult {
            return self.readServiceProtocolAny(0, buf);
        }

        pub fn readProtocol(self: *Self, protocol: u8, buf: []u8) ServiceError!usize {
            return self.readServiceProtocol(0, protocol, buf);
        }

        pub fn readServiceProtocol(self: *Self, service_port: u64, protocol: u8, buf: []u8) ServiceError!usize {
            const state = try self.getOrCreateService(service_port);
            const pkt = try self.popDirectInbound(state, protocol);
            defer self.allocator.free(pkt.payload);
            const n = @min(buf.len, pkt.payload.len);
            @memcpy(buf[0..n], pkt.payload[0..n]);
            return n;
        }

        pub fn write(self: *Self, protocol: u8, data: []const u8) ServiceError!usize {
            if (self.closed.load(.acquire)) return ServiceError.ServiceMuxClosed;

            switch (protocol) {
                protocol_event, protocol_opus => {},
                protocol_rpc => return ServiceError.UnsupportedProtocol,
                else => return ServiceError.UnsupportedProtocol,
            }

            self.config.output(0, protocol, data) catch |err| {
                self.output_errors.fetchAdd(1, .seq_cst);
                if (self.config.on_output_error) |cb| cb(0, err);
                return ServiceError.ServiceMuxClosed;
            };
            return data.len;
        }

        pub fn openStream(self: *Self, service_port: u64) ServiceError!*KCPMuxType.Stream {
            if (self.closed.load(.acquire)) return ServiceError.ServiceMuxClosed;
            const state = try self.getOrCreateService(service_port);
            return state.mux.openStream() catch return ServiceError.ServiceMuxClosed;
        }

        pub fn acceptStream(self: *Self, service_port: u64) ServiceError!*KCPMuxType.Stream {
            if (self.closed.load(.acquire)) return ServiceError.ServiceMuxClosed;
            const state = try self.getOrCreateService(service_port);
            return state.mux.acceptStream() catch return ServiceError.AcceptQueueClosed;
        }

        pub fn close(self: *Self) void {
            if (self.closed.swap(true, .acq_rel)) return;

            self.services_mu.lock();
            var iter = self.services.valueIterator();
            while (iter.next()) |state_ptr| {
                const state = state_ptr.*;
                state.inbound_mu.lock();
                state.event_inbound.is_closed = true;
                state.opus_inbound.is_closed = true;
                state.inbound_cond.broadcast();
                state.inbound_mu.unlock();
                state.mux.close();
            }
            self.services_mu.unlock();
        }

        pub fn numServices(self: *Self) usize {
            self.services_mu.lock();
            defer self.services_mu.unlock();
            return self.services.count();
        }

        pub fn numStreams(self: *Self) usize {
            self.services_mu.lock();
            var total: usize = 0;
            var iter = self.services.valueIterator();
            while (iter.next()) |state_ptr| {
                total += state_ptr.*.mux.numStreams();
            }
            self.services_mu.unlock();
            return total;
        }

        pub fn outputErrorCount(self: *const Self) u64 {
            return self.output_errors.load(.acquire);
        }

        fn readServiceProtocolAny(self: *Self, service_port: u64, buf: []u8) ServiceError!ReadResult {
            const state = try self.getOrCreateService(service_port);

            state.inbound_mu.lock();
            defer state.inbound_mu.unlock();

            while (state.event_inbound.len == 0 and state.opus_inbound.len == 0) {
                if (self.closed.load(.acquire)) return ServiceError.ServiceMuxClosed;
                state.inbound_cond.wait(&state.inbound_mu);
            }

            const pkt = if (state.event_inbound.pop()) |event_pkt|
                event_pkt
            else
                state.opus_inbound.pop().?;
            defer self.allocator.free(pkt.payload);

            const n = @min(buf.len, pkt.payload.len);
            @memcpy(buf[0..n], pkt.payload[0..n]);
            return .{ .protocol = pkt.protocol, .bytes_read = n };
        }

        fn popDirectInbound(self: *Self, state: *ServiceState, protocol: u8) ServiceError!ProtoPacket {
            state.inbound_mu.lock();
            defer state.inbound_mu.unlock();

            const queue = switch (protocol) {
                protocol_event => &state.event_inbound,
                protocol_opus => &state.opus_inbound,
                else => return ServiceError.UnsupportedProtocol,
            };

            while (queue.len == 0) {
                if (self.closed.load(.acquire)) return ServiceError.ServiceMuxClosed;
                if (queue.is_closed) return ServiceError.AcceptQueueClosed;
                state.inbound_cond.wait(&state.inbound_mu);
            }

            return queue.pop() orelse return ServiceError.AcceptQueueClosed;
        }

        fn pushDirectInbound(self: *Self, state: *ServiceState, protocol: u8, data: []const u8) ServiceError!void {
            const copy = self.allocator.dupe(u8, data) catch return ServiceError.OutOfMemory;
            errdefer self.allocator.free(copy);

            state.inbound_mu.lock();
            defer state.inbound_mu.unlock();

            if (self.closed.load(.acquire)) return ServiceError.ServiceMuxClosed;

            const queue = switch (protocol) {
                protocol_event => &state.event_inbound,
                protocol_opus => &state.opus_inbound,
                else => return ServiceError.UnsupportedProtocol,
            };

            if (queue.is_closed) return ServiceError.ServiceMuxClosed;
            if (!queue.push(.{ .protocol = protocol, .payload = copy })) {
                return ServiceError.InboundQueueFull;
            }
            state.inbound_cond.signal();
        }

        fn getOrCreateService(self: *Self, service_port: u64) ServiceError!*ServiceState {
            if (self.closed.load(.acquire)) return ServiceError.ServiceMuxClosed;
            self.services_mu.lock();
            defer self.services_mu.unlock();

            if (self.closed.load(.acquire)) return ServiceError.ServiceMuxClosed;

            if (self.services.get(service_port)) |state| return state;

            if (self.config.on_new_service) |cb| {
                if (!cb(service_port)) return ServiceError.ServiceRejected;
            }

            const kcp_cfg: KCPMuxType.Config = .{
                .service_port = service_port,
                .is_client = self.config.kcp_is_client,
                .output_ctx = @ptrCast(self),
                .output = &serviceOutputTrampoline,
                .on_output_error = &serviceOutputErrorTrampoline,
                .accept_backlog = self.config.kcp_accept_backlog,
            };

            const mux = KCPMuxType.init(self.allocator, self.time, kcp_cfg) catch return ServiceError.OutOfMemory;
            const state = ServiceState.create(self.allocator, mux) catch {
                mux.deinit();
                return ServiceError.OutOfMemory;
            };
            self.services.put(service_port, state) catch {
                state.inbound_cond.deinit();
                state.inbound_mu.deinit();
                self.allocator.destroy(state);
                mux.deinit();
                return ServiceError.OutOfMemory;
            };
            return state;
        }

        fn serviceOutputTrampoline(ctx: *anyopaque, service_port: u64, data: []const u8) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return self.config.output(service_port, protocol_rpc, data);
        }

        fn serviceOutputErrorTrampoline(ctx: *anyopaque, service_port: u64, err: anyerror) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            _ = self.output_errors.fetchAdd(1, .seq_cst);
            if (self.config.on_output_error) |cb| cb(service_port, err);
        }

        fn cleanupServices(self: *Self) void {
            self.services_mu.lock();
            defer self.services_mu.unlock();

            var iter = self.services.valueIterator();
            while (iter.next()) |state_ptr| {
                const state = state_ptr.*;
                while (state.event_inbound.pop()) |pkt| {
                    self.allocator.free(pkt.payload);
                }
                while (state.opus_inbound.pop()) |pkt| {
                    self.allocator.free(pkt.payload);
                }
                state.mux.deinit();
                state.inbound_cond.deinit();
                state.inbound_mu.deinit();
                self.allocator.destroy(state);
            }
            self.services.deinit();
        }
    };
}

pub fn StdServiceMux(comptime KCPMuxType: type) type {
    return ServiceMux(KCPMuxType, runtime.std.Mutex, runtime.std.Condition, runtime.std.Time);
}

const testing = std.testing;

const MockKCPMux = struct {
    pub const Config = struct {
        service_port: u64,
        is_client: bool,
        output_ctx: *anyopaque,
        output: *const fn (ctx: *anyopaque, service_port: u64, data: []const u8) anyerror!void,
        on_output_error: ?*const fn (ctx: *anyopaque, service_port: u64, err: anyerror) void = null,
        accept_backlog: usize = 32,
    };

    pub const Stream = struct {
        writes: std.ArrayListUnmanaged(u8) = .{},
        allocator: std.mem.Allocator,

        pub fn read(_: *Stream, _: []u8) !usize {
            return 0;
        }

        pub fn write(self: *Stream, data: []const u8) !usize {
            try self.writes.appendSlice(self.allocator, data);
            return data.len;
        }

        pub fn close(_: *Stream) void {}

        pub fn isClosed(_: *Stream) bool {
            return false;
        }
    };

    allocator: std.mem.Allocator,
    config: Config,
    last_input: std.ArrayListUnmanaged(u8) = .{},
    stream: Stream,

    pub fn init(allocator: std.mem.Allocator, _: runtime.std.Time, config: Config) !*MockKCPMux {
        const self = try allocator.create(MockKCPMux);
        self.* = .{
            .allocator = allocator,
            .config = config,
            .stream = .{ .allocator = allocator },
        };
        return self;
    }

    pub fn deinit(self: *MockKCPMux) void {
        self.last_input.deinit(self.allocator);
        self.stream.writes.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn close(_: *MockKCPMux) void {}

    pub fn input(self: *MockKCPMux, data: []const u8) !void {
        try self.last_input.appendSlice(self.allocator, data);
    }

    pub fn openStream(self: *MockKCPMux) !*Stream {
        return &self.stream;
    }

    pub fn acceptStream(self: *MockKCPMux) !*Stream {
        return &self.stream;
    }

    pub fn numStreams(_: *MockKCPMux) usize {
        return 1;
    }

    pub fn outputErrorCount(_: *const MockKCPMux) u64 {
        return 0;
    }
};

const TestServiceMux = StdServiceMux(MockKCPMux);

const OutputCollector = struct {
    service_port: u64 = 0,
    protocol: u8 = 0,
    payload: std.ArrayListUnmanaged(u8) = .{},
    allocator: std.mem.Allocator,

    fn output(service_port: u64, protocol: u8, data: []const u8) !void {
        _ = service_port;
        _ = protocol;
        _ = data;
    }

    fn collectingOutput(service_port: u64, protocol: u8, data: []const u8) !void {
        _ = service_port;
        _ = protocol;
        _ = data;
    }
};

test "ServiceMux defaults to allowing new services and routes direct protocols" {
    const mux = try TestServiceMux.init(testing.allocator, runtime.std.Time{}, .{
        .kcp_is_client = true,
        .output = struct {
            fn output(_: u64, _: u8, _: []const u8) !void {}
        }.output,
    });
    defer mux.deinit();

    try mux.input(7, protocol_event, "evt");
    try testing.expectEqual(@as(usize, 1), mux.numServices());

    var out: [8]u8 = undefined;
    const n = try mux.readServiceProtocol(7, protocol_event, &out);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualStrings("evt", out[0..n]);
}

test "ServiceMux rejects service when policy callback denies it" {
    const mux = try TestServiceMux.init(testing.allocator, runtime.std.Time{}, .{
        .kcp_is_client = false,
        .output = struct {
            fn output(_: u64, _: u8, _: []const u8) !void {}
        }.output,
        .on_new_service = struct {
            fn reject(_: u64) bool {
                return false;
            }
        }.reject,
    });
    defer mux.deinit();

    try testing.expectError(ServiceError.ServiceRejected, mux.input(3, protocol_event, "x"));
}

test "ServiceMux routes rpc payloads into KCP mux input" {
    const mux = try TestServiceMux.init(testing.allocator, runtime.std.Time{}, .{
        .kcp_is_client = true,
        .output = struct {
            fn output(_: u64, _: u8, _: []const u8) !void {}
        }.output,
    });
    defer mux.deinit();

    try mux.input(9, protocol_rpc, "rpc-body");
    const state = mux.services.get(9).?;
    try testing.expectEqualStrings("rpc-body", state.mux.last_input.items);
}

test "ServiceMux does not create service state for unsupported protocols" {
    const mux = try TestServiceMux.init(testing.allocator, runtime.std.Time{}, .{
        .kcp_is_client = true,
        .output = struct {
            fn output(_: u64, _: u8, _: []const u8) !void {}
        }.output,
    });
    defer mux.deinit();

    try testing.expectError(ServiceError.UnsupportedProtocol, mux.input(42, 0xFF, "bad"));
    try testing.expectEqual(@as(usize, 0), mux.numServices());
}

test "ServiceMux readProtocol reads service 0 direct packets" {
    const mux = try TestServiceMux.init(testing.allocator, runtime.std.Time{}, .{
        .kcp_is_client = true,
        .output = struct {
            fn output(_: u64, _: u8, _: []const u8) !void {}
        }.output,
    });
    defer mux.deinit();

    try mux.input(0, protocol_event, "svc0");

    var out: [8]u8 = undefined;
    const n = try mux.readProtocol(protocol_event, &out);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqualStrings("svc0", out[0..n]);
}

test "ServiceMux read returns service 0 merged direct packets" {
    const mux = try TestServiceMux.init(testing.allocator, runtime.std.Time{}, .{
        .kcp_is_client = true,
        .output = struct {
            fn output(_: u64, _: u8, _: []const u8) !void {}
        }.output,
    });
    defer mux.deinit();

    try mux.input(0, protocol_opus, "opus");

    var out: [8]u8 = undefined;
    const result = try mux.read(&out);
    try testing.expectEqual(protocol_opus, result.protocol);
    try testing.expectEqual(@as(usize, 4), result.bytes_read);
    try testing.expectEqualStrings("opus", out[0..result.bytes_read]);
}

test "ServiceMux numStreams sums child muxes" {
    const mux = try TestServiceMux.init(testing.allocator, runtime.std.Time{}, .{
        .kcp_is_client = true,
        .output = struct {
            fn output(_: u64, _: u8, _: []const u8) !void {}
        }.output,
    });
    defer mux.deinit();

    try mux.input(1, protocol_rpc, "a");
    try mux.input(2, protocol_rpc, "b");
    try testing.expectEqual(@as(usize, 2), mux.numStreams());
}

test "ServiceMux close unblocks direct readers" {
    const mux = try TestServiceMux.init(testing.allocator, runtime.std.Time{}, .{
        .kcp_is_client = true,
        .output = struct {
            fn output(_: u64, _: u8, _: []const u8) !void {}
        }.output,
    });
    defer mux.deinit();

    _ = try mux.getOrCreateService(0);

    var read_err: ?ServiceError = null;
    const reader = try std.Thread.spawn(.{}, struct {
        fn run(m: *TestServiceMux, err_out: *?ServiceError) void {
            var buf: [8]u8 = undefined;
            _ = m.readProtocol(protocol_event, &buf) catch |err| {
                err_out.* = err;
            };
        }
    }.run, .{ mux, &read_err });

    var time = runtime.std.Time{};
    time.sleepMs(20);
    mux.close();
    reader.join();

    try testing.expectEqual(ServiceError.ServiceMuxClosed, read_err.?);
}
