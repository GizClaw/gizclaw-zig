const dep = @import("dep");
const noise = @import("../noise.zig");

const cfg = @import("config.zig");
const Mux = @import("Mux.zig");
const UIntMap = @import("UIntMap.zig");

const mem = dep.embed.mem;

pub fn make(comptime Core: type) type {
    const StreamAdapter = Core.ServiceMux.StreamAdapter;
    const StreamAdapterFactory = Core.ServiceMux.StreamAdapterFactory;
    const StreamAdapterRuntime = Core.ServiceMux.StreamAdapterRuntime;

    return struct {
        allocator: mem.Allocator,
        runtime: StreamAdapterRuntime,
        config: Config,
        services: UIntMap.make(u64, ServiceState),

        const Self = @This();

        pub const Config = struct {
            mux: cfg.Mux = .{
                .output = .{
                    .ctx = undefined,
                    .write = unreachableOutput,
                },
            },
        };

        pub const Factory = struct {
            config: Config = .{},

            pub fn adapterFactory(self: *const Factory) StreamAdapterFactory {
                return .{
                    .ctx = @constCast(self),
                    .build = buildAdapter,
                };
            }
        };

        const ServiceState = struct {
            mux: ?Mux = null,
            output_state: ?*ServiceOutputState = null,
            accepting_stopped: bool = false,
            closed: bool = false,
        };

        const ServiceOutputState = struct {
            adapter: *Self,
            service: u64,
        };

        pub fn init(allocator: mem.Allocator, runtime: StreamAdapterRuntime, config: Config) !Self {
            return .{
                .allocator = allocator,
                .runtime = runtime,
                .config = config,
                .services = try UIntMap.make(u64, ServiceState).init(allocator, 8),
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.services.slots) |*slot| {
                if (slot.state != .full) continue;
                self.deinitService(&slot.value);
            }
            self.services.deinit();
        }

        pub fn input(self: *Self, service: u64, protocol_byte: u8, data: []const u8, now_ms: u64) !void {
            if (!Core.isStreamProtocol(protocol_byte)) return Core.Error.UnsupportedProtocol;
            const mux = try self.getOrCreateMux(service);
            try mux.input(data, now_ms);
        }

        pub fn open(self: *Self, service: u64, now_ms: u64) !u64 {
            const mux = try self.getOrCreateMux(service);
            return try mux.open(now_ms);
        }

        pub fn accept(self: *Self, service: u64) !u64 {
            const mux = try self.getOrCreateMux(service);
            return try mux.accept();
        }

        pub fn send(self: *Self, service: u64, stream_id: u64, payload: []const u8, now_ms: u64) !usize {
            const mux = try self.getExistingMux(service);
            return try mux.send(stream_id, payload, now_ms);
        }

        pub fn recv(self: *Self, service: u64, stream_id: u64, out: []u8) !usize {
            const mux = try self.getExistingMux(service);
            return try mux.recv(stream_id, out);
        }

        pub fn closeStream(self: *Self, service: u64, stream_id: u64, now_ms: u64) !void {
            const mux = try self.getExistingMux(service);
            try mux.closeStream(stream_id, now_ms);
        }

        pub fn stopAccepting(self: *Self, service: u64) !void {
            const state = try self.getOrCreateService(service);
            state.accepting_stopped = true;
            if (state.mux) |*mux| mux.stopAccepting();
        }

        pub fn closeService(self: *Self, service: u64) !void {
            const state = try self.getOrCreateService(service);
            state.closed = true;
            state.accepting_stopped = true;
            if (state.mux) |*mux| {
                mux.close();
                mux.deinit();
                state.mux = null;
            }
            if (state.output_state) |output_state| {
                self.allocator.destroy(output_state);
                state.output_state = null;
            }
        }

        pub fn numStreams(self: *const Self, service: u64) usize {
            const state = self.getService(service) orelse return 0;
            const mux = state.mux orelse return 0;
            return mux.numStreams();
        }

        pub fn tick(self: *Self, now_ms: u64) !void {
            var first_error: ?anyerror = null;
            for (self.services.slots) |*slot| {
                if (slot.state != .full) continue;
                if (slot.value.mux) |*mux| {
                    mux.tick(now_ms) catch |err| {
                        if (first_error == null) first_error = err;
                    };
                }
            }
            if (first_error) |err| return err;
        }

        fn streamAdapter(self: *Self) StreamAdapter {
            return .{
                .ctx = self,
                .input = streamAdapterInput,
                .open = streamAdapterOpen,
                .accept = streamAdapterAccept,
                .send = streamAdapterSend,
                .recv = streamAdapterRecv,
                .close_stream = streamAdapterCloseStream,
                .stop_accepting = streamAdapterStopAccepting,
                .close_service = streamAdapterCloseService,
                .num_streams = streamAdapterNumStreams,
                .tick = streamAdapterTick,
                .deinit = streamAdapterDeinit,
            };
        }

        fn getService(self: *const Self, service: u64) ?*const ServiceState {
            return @constCast(self).services.getPtr(service);
        }

        fn getOrCreateService(self: *Self, service: u64) !*ServiceState {
            if (self.services.getPtr(service)) |state| return state;
            _ = try self.services.put(service, .{});
            return self.services.getPtr(service).?;
        }

        fn getOrCreateMux(self: *Self, service: u64) !*Mux {
            const state = try self.getOrCreateService(service);
            if (state.closed) return Core.Error.ServiceRejected;
            if (state.mux) |*mux| return mux;

            const output_state = try self.allocator.create(ServiceOutputState);
            errdefer self.allocator.destroy(output_state);
            output_state.* = .{
                .adapter = self,
                .service = service,
            };

            var mux_config = self.config.mux;
            mux_config.is_client = self.runtime.is_client;
            mux_config.output = .{
                .ctx = output_state,
                .write = muxOutputWrite,
            };

            var mux = try Mux.init(self.allocator, service, mux_config);
            errdefer mux.deinit();
            if (state.accepting_stopped) mux.stopAccepting();

            state.mux = mux;
            state.output_state = output_state;
            return &state.mux.?;
        }

        fn getExistingMux(self: *Self, service: u64) !*Mux {
            const state = self.services.getPtr(service) orelse return error.StreamNotFound;
            if (state.closed) return Core.Error.ServiceRejected;
            return if (state.mux) |*mux| mux else error.StreamNotFound;
        }

        fn deinitService(self: *Self, state: *ServiceState) void {
            if (state.mux) |*mux| {
                mux.deinit();
                state.mux = null;
            }
            if (state.output_state) |output_state| {
                self.allocator.destroy(output_state);
                state.output_state = null;
            }
        }

        fn emit(self: *Self, service: u64, data: []const u8) !void {
            const output = self.runtime.output orelse return Core.Error.NoSession;
            output.write(output.ctx, self.runtime.peer, service, Core.protocol.kcp, data) catch |err| {
                if (self.runtime.on_output_error) |callback| callback(self.runtime.peer, service, err);
                return err;
            };
        }

        fn buildAdapter(ctx: *anyopaque, allocator: mem.Allocator, runtime: StreamAdapterRuntime) !StreamAdapter {
            const factory: *const Factory = @ptrCast(@alignCast(ctx));
            const adapter = try allocator.create(Self);
            errdefer allocator.destroy(adapter);
            adapter.* = try Self.init(allocator, runtime, factory.config);
            return adapter.streamAdapter();
        }

        fn streamAdapterInput(ctx: *anyopaque, service: u64, protocol_byte: u8, data: []const u8, now_ms: u64) !void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.input(service, protocol_byte, data, now_ms);
        }

        fn streamAdapterOpen(ctx: *anyopaque, service: u64, now_ms: u64) !u64 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return try self.open(service, now_ms);
        }

        fn streamAdapterAccept(ctx: *anyopaque, service: u64) !u64 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return try self.accept(service);
        }

        fn streamAdapterStopAccepting(ctx: *anyopaque, service: u64) !void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.stopAccepting(service);
        }

        fn streamAdapterSend(ctx: *anyopaque, service: u64, stream_id: u64, payload: []const u8, now_ms: u64) !usize {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return try self.send(service, stream_id, payload, now_ms);
        }

        fn streamAdapterRecv(ctx: *anyopaque, service: u64, stream_id: u64, out: []u8) !usize {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return try self.recv(service, stream_id, out);
        }

        fn streamAdapterCloseStream(ctx: *anyopaque, service: u64, stream_id: u64, now_ms: u64) !void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.closeStream(service, stream_id, now_ms);
        }

        fn streamAdapterCloseService(ctx: *anyopaque, service: u64) !void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.closeService(service);
        }

        fn streamAdapterNumStreams(ctx: *anyopaque, service: u64) usize {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return self.numStreams(service);
        }

        fn streamAdapterTick(ctx: *anyopaque, now_ms: u64) !void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.tick(now_ms);
        }

        fn streamAdapterDeinit(ctx: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const allocator = self.allocator;
            self.deinit();
            allocator.destroy(self);
        }

        fn muxOutputWrite(ctx: *anyopaque, data: []const u8) !void {
            const output_state: *ServiceOutputState = @ptrCast(@alignCast(ctx));
            try output_state.adapter.emit(output_state.service, data);
        }

        fn unreachableOutput(_: *anyopaque, _: []const u8) !void {
            unreachable;
        }
    };
}
