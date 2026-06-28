//! Runtime orchestration layer for giznet.
//!
//! This engine owns the runtime event channel and coordinates lower-level
//! protocol engines.

const glib = @import("glib");

const Conn = @import("giznet").Conn;
const Stream = @import("giznet").Stream;
const NoiseCipher = @import("../noise/Cipher.zig");
const NoiseEngineType = @import("../noise/Engine.zig");
const NoiseKey = @import("giznet").Key;
const NoiseKeyPair = @import("giznet").KeyPair;
const packet = @import("../packet.zig");
const ServiceEngineType = @import("../service/Engine.zig");
const service_protocol = @import("../service/protocol.zig");
const StatsType = @import("giznet").Stats;

const Engine = @This();

pub const Config = struct {
    local_static: NoiseKeyPair,
    noise: NoiseEngineType.Config = .{},
    service: ServiceEngineType.Config = .{},
    channel_capacity: usize = 32,
    accept_channel_capacity: usize = 32,
    on_error: OnError = .{},
};

pub const OnError = struct {
    ctx: ?*anyopaque = null,
    call: ?*const fn (ctx: ?*anyopaque, err: anyerror) void = null,

    pub fn handle(self: OnError, err: anyerror) void {
        if (self.call) |call| call(self.ctx, err);
    }
};

pub const WriteDirect = struct {
    remote_static: NoiseKey,
    protocol: u8,
    payload: []u8,
};

pub const InitiatePeer = struct {
    remote_key: NoiseKey,
    remote_endpoint: glib.net.netip.AddrPort,
    keepalive_interval: ?glib.time.duration.Duration = null,
};

pub const OpenStream = struct {
    remote_static: NoiseKey,
    service: u64,
};

pub const WriteStream = struct {
    remote_static: NoiseKey,
    service: u64,
    stream: u64,
    payload: []u8,
};

pub const CloseStream = struct {
    remote_static: NoiseKey,
    service: u64,
    stream: u64,
};

pub fn make(
    comptime grt: type,
    comptime packet_size_capacity: usize,
    comptime cipher_kind: NoiseCipher.Kind,
) type {
    const NoiseEngine = NoiseEngineType.make(grt, packet_size_capacity, cipher_kind);
    const ServiceEngine = ServiceEngineType.make(grt);
    const Stats = StatsType.make(grt);
    const log = grt.std.log.scoped(.giznet_runtime);
    const OpenStreamResult = union(enum) {
        ok: ServiceEngine.StreamPort,
        err: anyerror,
    };
    const OpenStreamReplyChannel = grt.sync.Channel(OpenStreamResult);
    const OpenStreamRequest = struct {
        remote_static: NoiseKey,
        service: u64,
        reply: *OpenStreamReplyChannel,
    };
    const DriveInput = union(enum) {
        udp_inbound: *packet.Inbound,
        initiate_handshake: NoiseEngineType.InitiateHandshake,
        write_direct: WriteDirect,
        open_stream: OpenStreamRequest,
        write_stream: WriteStream,
        close_stream: CloseStream,
        close_conn: NoiseKey,
        tick: void,
        close: void,
    };
    const InputChannel = grt.sync.Channel(DriveInput);
    const AcceptChannel = grt.sync.Channel(Conn);
    const Timer = glib.sync.Timer;
    const TimerImpl = Timer.makeWithTask(grt.std, grt.time, grt.sync, grt.task);

    return struct {
        allocator: grt.std.mem.Allocator,
        conn: grt.net.PacketConn,
        input: InputChannel,
        accept: AcceptChannel,
        local_static: NoiseKey,
        packet_pools: *packet.Pools,
        noise: NoiseEngine,
        service: ServiceEngine,
        stats: Stats = .{},
        drive_thread: ?grt.task.Handle = null,
        read_thread: ?grt.task.Handle = null,
        timer: ?Timer = null,
        tick_deadline: ?glib.time.instant.Time = null,
        on_error: Engine.OnError,
        closed: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),

        const Self = @This();

        pub fn init(
            allocator: grt.std.mem.Allocator,
            conn: grt.net.PacketConn,
            config: Engine.Config,
        ) !Self {
            var channel = try InputChannel.make(allocator, config.channel_capacity);
            errdefer channel.deinit();

            var accept = try AcceptChannel.make(allocator, config.accept_channel_capacity);
            errdefer accept.deinit();

            const packet_pools = try allocator.create(packet.Pools);
            errdefer allocator.destroy(packet_pools);

            packet_pools.* = packet.Pools{
                .inbound = try packet.Inbound.initPool(grt, allocator, packet_size_capacity),
                .outbound = undefined,
            };
            errdefer packet_pools.inbound.deinit();

            packet_pools.outbound = try packet.Outbound.initPool(grt, allocator, packet_size_capacity);
            errdefer packet_pools.outbound.deinit();

            var noise = try NoiseEngine.init(allocator, config.local_static, config.noise, .{
                .inbound = packet_pools.inbound,
                .outbound = packet_pools.outbound,
            });
            errdefer noise.deinit();

            var service_config = config.service;
            service_config.local_static = config.local_static.public;
            var service = ServiceEngine.init(allocator, service_config, packet_pools);
            errdefer service.deinit();

            return .{
                .allocator = allocator,
                .conn = conn,
                .input = channel,
                .accept = accept,
                .local_static = config.local_static.public,
                .packet_pools = packet_pools,
                .noise = noise,
                .service = service,
                .on_error = config.on_error,
            };
        }

        pub fn deinit(self: *Self) void {
            self.close() catch {};
            self.join();
            if (self.timer) |timer| {
                timer.deinit();
                self.timer = null;
            }
            self.drainInput();
            self.drainAcceptedConns();
            self.service.deinit();
            self.noise.deinit();
            self.accept.deinit();
            self.input.deinit();
            self.packet_pools.outbound.deinit();
            self.packet_pools.inbound.deinit();
            self.allocator.destroy(self.packet_pools);
        }

        pub fn startDrive(self: *Self, task_options: grt.task.Options) !void {
            if (self.closed.load(.acquire)) return error.RuntimeEngineClosed;
            if (self.drive_thread != null) return error.RuntimeEngineAlreadyStarted;
            self.drive_thread = try grt.task.go("giznet/drive", task_options, grt.task.Routine.init(self, driveLoop));
        }

        pub fn startRead(self: *Self, task_options: grt.task.Options) !void {
            if (self.closed.load(.acquire)) return error.RuntimeEngineClosed;
            if (self.read_thread != null) return error.RuntimeUdpReaderAlreadyStarted;
            self.read_thread = try grt.task.go("giznet/read", task_options, grt.task.Routine.init(self, readLoop));
        }

        pub fn startTimer(self: *Self, task_options: grt.task.Options) !void {
            if (self.closed.load(.acquire)) return error.RuntimeEngineClosed;
            if (self.timer != null) return error.RuntimeTimerAlreadyStarted;

            const timer_impl = try TimerImpl.init(self.allocator, TimerCallback.call, self, task_options);
            self.timer = Timer.init(timer_impl);
        }

        pub fn acceptConn(self: *Self) @TypeOf(self.accept.recv()) {
            return self.accept.recv();
        }

        pub fn acceptConnTimeout(self: *Self, timeout: glib.time.duration.Duration) @TypeOf(self.accept.recvTimeout(timeout)) {
            return self.accept.recvTimeout(timeout);
        }

        pub fn snapshotStats(self: *Self) StatsType.Snapshot {
            return self.stats.snapshot();
        }

        pub fn initiatePeer(self: *Self, request: Engine.InitiatePeer) !void {
            const send_result = try self.input.send(.{ .initiate_handshake = .{
                .remote_key = request.remote_key,
                .remote_endpoint = request.remote_endpoint,
                .keepalive_interval = request.keepalive_interval,
            } });
            if (!send_result.ok) return error.RuntimeChannelClosed;
        }

        pub fn close(self: *Self) !void {
            if (self.closed.load(.acquire)) return;
            if (self.drive_thread == null) return error.RuntimeEngineNotStarted;

            const send_result = try self.input.send(.{ .close = {} });
            if (!send_result.ok) return error.RuntimeChannelClosed;
        }

        pub fn join(self: *Self) void {
            const drive_thread = self.drive_thread orelse return;
            drive_thread.join();
            self.drive_thread = null;

            if (self.timer) |timer| {
                timer.deinit();
                self.timer = null;
            }

            if (self.read_thread) |read_thread| {
                self.conn.setReadDeadline(grt.time.instant.now());
                read_thread.join();
                self.read_thread = null;
                self.conn.close();
            }
        }

        fn closeFromDrive(self: *Self) void {
            if (!self.closed.load(.acquire)) {
                self.closed.store(true, .release);
                self.accept.close();
                self.input.close();
            }
        }

        fn driveLoop(self: *Self) void {
            defer self.closeFromDrive();
            while (!self.closed.load(.acquire)) {
                const result = self.input.recv() catch |err| {
                    self.on_error.handle(err);
                    return;
                };
                if (!result.ok) break;
                self.drive(result.value) catch |err| {
                    self.on_error.handle(err);
                    continue;
                };
            }
        }

        fn readLoop(self: *Self) void {
            while (!self.closed.load(.acquire)) {
                const pkt = self.packet_pools.inbound.get() orelse {
                    self.on_error.handle(error.OutOfMemory);
                    return;
                };
                errdefer pkt.deinit();

                const result = self.conn.readFrom(pkt.bufRef()) catch |err| {
                    pkt.deinit();
                    if (self.closed.load(.acquire)) break;
                    self.on_error.handle(err);
                    return;
                };
                pkt.len = result.bytes_read;
                pkt.remote_endpoint = result.addr;

                const send_result = self.input.send(.{ .udp_inbound = pkt }) catch |err| {
                    pkt.deinit();
                    _ = self.stats.dropped_packets.fetchAdd(1, .monotonic);
                    self.on_error.handle(err);
                    return;
                };
                if (!send_result.ok) {
                    pkt.deinit();
                    _ = self.stats.dropped_packets.fetchAdd(1, .monotonic);
                    if (self.closed.load(.acquire)) break;
                    continue;
                }
                _ = self.stats.udp_rx_packets.fetchAdd(1, .monotonic);
            }
        }

        fn drive(self: *Self, input: DriveInput) !void {
            defer switch (input) {
                .write_direct => |request| self.allocator.free(request.payload),
                .write_stream => |request| self.allocator.free(request.payload),
                else => {},
            };

            if (self.closed.load(.acquire) and input != .close) return error.RuntimeEngineClosed;
            switch (input) {
                .udp_inbound => |pkt| {
                    errdefer pkt.deinit();

                    var callback = NoiseCallback{ .runtime = self };
                    try self.noise.drive(.{ .inbound_packet = pkt }, callback.callback());
                    return;
                },
                .initiate_handshake => |request| {
                    var callback = NoiseCallback{ .runtime = self };
                    try self.noise.drive(.{ .initiate_handshake = request }, callback.callback());
                    return;
                },
                .tick => {
                    self.tick_deadline = null;
                    if (self.timer) |timer| timer.reset(null);

                    var noise_callback = NoiseCallback{ .runtime = self };
                    try self.noise.drive(.{ .tick = {} }, noise_callback.callback());

                    var service_callback = ServiceCallback{ .runtime = self };
                    try self.service.drive(.{ .tick = {} }, service_callback.callback());
                    return;
                },
                .close => {
                    self.closeFromDrive();
                    return;
                },
                .write_direct => {},
                .open_stream => |request| {
                    try self.handleOpenStream(request);
                    return;
                },
                .write_stream => {},
                .close_stream => {},
                .close_conn => |remote_static| {
                    try self.sendConnClose(remote_static);
                    var service_callback = ServiceCallback{ .runtime = self };
                    try self.service.drive(.{ .close_conn = remote_static }, service_callback.callback());
                    return;
                },
            }

            const pkt = self.packet_pools.outbound.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();
            pkt.remote_static = switch (input) {
                .write_direct => |request| request.remote_static,
                .write_stream => |request| request.remote_static,
                .close_stream => |request| request.remote_static,
                else => unreachable,
            };

            switch (input) {
                .write_direct => |request| {
                    const buffer = pkt.transportPlaintextBufRef();
                    if (buffer.len < request.payload.len + 1) return error.BufferTooSmall;
                    @memcpy(buffer[1..][0..request.payload.len], request.payload);
                    pkt.len = request.payload.len + 1;
                    pkt.service_data = .{ .direct = .{
                        .protocol = request.protocol,
                        .payload = buffer[1..][0..request.payload.len],
                    } };
                },
                .write_stream => |request| {
                    const buffer = pkt.transportPlaintextBufRef();
                    if (buffer.len < request.payload.len) return error.BufferTooSmall;
                    @memcpy(buffer[0..request.payload.len], request.payload);
                    pkt.len = request.payload.len;
                    pkt.service_data = .{ .write_stream = .{
                        .service = request.service,
                        .stream = request.stream,
                        .payload = buffer[0..request.payload.len],
                    } };
                },
                .close_stream => |request| {
                    pkt.len = 0;
                    pkt.service_data = .{ .close_stream = .{
                        .service = request.service,
                        .stream = request.stream,
                    } };
                },
                else => unreachable,
            }
            var callback = ServiceCallback{ .runtime = self };
            try self.service.drive(.{ .outbound = pkt }, callback.callback());
        }

        fn handleOpenStream(self: *Self, request: OpenStreamRequest) !void {
            var port = self.openStreamPort(request.remote_static, request.service) catch |err| {
                const send_result = try request.reply.send(.{ .err = err });
                if (!send_result.ok) return error.RuntimeOpenStreamReplyClosed;
                return;
            };
            errdefer port.deinit();
            const send_result = try request.reply.send(.{ .ok = port });
            if (!send_result.ok) return error.RuntimeOpenStreamReplyClosed;
        }

        fn openStreamPort(self: *Self, remote_static: NoiseKey, service: u64) !ServiceEngine.StreamPort {
            const pkt = self.packet_pools.outbound.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();

            pkt.remote_static = remote_static;
            pkt.len = 0;
            pkt.service_data = .{ .open_stream = .{
                .service = service,
            } };

            var callback = OpenStreamCallback{ .runtime = self };
            errdefer callback.deinit();
            try self.service.drive(.{ .outbound = pkt }, callback.callback());
            const port = callback.opened_stream orelse return error.MissingOpenedStream;
            callback.opened_stream = null;
            return port;
        }

        fn sendConnClose(self: *Self, remote_static: NoiseKey) !void {
            const pkt = self.packet_pools.outbound.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();

            const plaintext = pkt.transportPlaintextBufRef();
            const close_payload = try prepareConnClosePlaintext(plaintext);
            pkt.remote_static = remote_static;
            pkt.len = close_payload.len;

            var noise_callback = NoiseCallback{ .runtime = self };
            try self.noise.drive(.{ .send_data = pkt }, noise_callback.callback());
        }

        fn prepareConnClosePlaintext(buffer: []u8) ![]const u8 {
            if (buffer.len < 2) return error.BufferTooSmall;
            buffer[0] = service_protocol.ProtocolConnCtrl;
            buffer[1] = service_protocol.ConnCtrlClose;
            return buffer[0..2];
        }

        fn updateTickDeadline(self: *Self, deadline: glib.time.instant.Time) void {
            if (self.tick_deadline != null and deadline >= self.tick_deadline.?) return;
            self.tick_deadline = deadline;
            if (self.timer) |timer| timer.reset(deadline);
        }

        fn durationUntil(deadline: glib.time.instant.Time) glib.time.duration.Duration {
            const now = grt.time.instant.now();
            if (deadline <= now) return 0;
            return glib.time.instant.sub(deadline, now);
        }

        fn drainAcceptedConns(self: *Self) void {
            while (true) {
                const result = self.accept.recvTimeout(0) catch break;
                if (!result.ok) break;
                result.value.deinit();
            }
        }

        fn drainInput(self: *Self) void {
            while (true) {
                const result = self.input.recvTimeout(0) catch break;
                if (!result.ok) break;
                self.releaseDriveInput(result.value);
            }
        }

        fn releaseDriveInput(self: *Self, input: DriveInput) void {
            switch (input) {
                .udp_inbound => |pkt| pkt.deinit(),
                .write_direct => |request| self.allocator.free(request.payload),
                .open_stream => |request| self.releaseOpenStreamRequest(request, error.RuntimeEngineClosed),
                .write_stream => |request| self.allocator.free(request.payload),
                else => {},
            }
        }

        fn releaseOpenStreamRequest(self: *Self, request: OpenStreamRequest, err: anyerror) void {
            _ = self;
            _ = request.reply.sendTimeout(.{ .err = err }, 0) catch {};
        }

        const NoiseCallback = struct {
            runtime: *Self,

            fn callback(self: *@This()) NoiseEngineType.Callback {
                return .{ .ctx = self, .call = call };
            }

            fn call(ctx: *anyopaque, output: NoiseEngineType.DriveOutput) !void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                switch (output) {
                    .outbound => |pkt| {
                        if (pkt.state != .ready_to_send) return error.InvalidOutboundPacketState;
                        const bytes = pkt.bytes();
                        const written = self.runtime.conn.writeTo(bytes, pkt.remote_endpoint) catch |err| switch (err) {
                            error.NetworkUnreachable,
                            error.AccessDenied,
                            error.TimedOut,
                            error.MessageTooLong,
                            => {
                                if (pkt.kind == .handshake) {
                                    log.warn("udp write drop kind={s} err={s} len={d}", .{
                                        @tagName(pkt.kind),
                                        @errorName(err),
                                        bytes.len,
                                    });
                                }
                                pkt.deinit();
                                _ = self.runtime.stats.dropped_packets.fetchAdd(1, .monotonic);
                                return;
                            },
                            else => return err,
                        };
                        if (written != bytes.len) return error.ShortUdpWrite;
                        if (pkt.kind == .handshake) {
                            log.info("udp write ok kind={s} len={d}", .{
                                @tagName(pkt.kind),
                                bytes.len,
                            });
                        }
                        pkt.deinit();
                        _ = self.runtime.stats.udp_tx_packets.fetchAdd(1, .monotonic);
                    },
                    .inbound => |pkt| {
                        switch (pkt.state) {
                            .consumed => {
                                var service_callback = ServiceCallback{ .runtime = self.runtime };
                                self.runtime.service.drive(.{ .inbound = pkt }, service_callback.callback()) catch |err| switch (err) {
                                    error.Timeout, error.PacketChannelFull => {
                                        pkt.deinit();
                                        _ = self.runtime.stats.dropped_packets.fetchAdd(1, .monotonic);
                                        return;
                                    },
                                    else => return err,
                                };
                            },
                            .initial,
                            .service_delivered,
                            .consume_failed,
                            => return error.InvalidInboundPacketState,
                        }
                    },
                    .established => |remote_static| {
                        var service_callback = ServiceCallback{ .runtime = self.runtime };
                        return self.runtime.service.drive(.{ .peer_established = remote_static }, service_callback.callback());
                    },
                    .offline => {},
                    .next_tick_deadline => |deadline| self.runtime.updateTickDeadline(deadline),
                }
            }
        };

        const ServiceCallback = struct {
            runtime: *Self,

            fn callback(self: *@This()) ServiceEngine.Callback {
                return .{ .ctx = self, .call = call };
            }

            fn call(ctx: *anyopaque, output: ServiceEngine.DriveOutput) !void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                switch (output) {
                    .peer_port => |peer_port| {
                        var owned_peer_port = peer_port;
                        const conn_impl = self.runtime.allocator.create(ConnImpl) catch |err| {
                            owned_peer_port.deinit();
                            return err;
                        };
                        errdefer conn_impl.deinit();
                        conn_impl.* = .{
                            .runtime = self.runtime,
                            .peer_port = owned_peer_port,
                        };
                        const send_result = try self.runtime.accept.send(Conn.init(conn_impl));
                        if (!send_result.ok) {
                            _ = self.runtime.stats.dropped_packets.fetchAdd(1, .monotonic);
                            return error.RuntimeAcceptChannelClosed;
                        }
                        _ = self.runtime.stats.active_peers.fetchAdd(1, .monotonic);
                    },
                    .opened_stream => |_| return error.UnexpectedOpenedStream,
                    .outbound => |pkt| {
                        var noise_callback = NoiseCallback{ .runtime = self.runtime };
                        return self.runtime.noise.drive(.{ .send_data = pkt }, noise_callback.callback());
                    },
                    .next_tick_deadline => |deadline| self.runtime.updateTickDeadline(deadline),
                }
            }
        };

        const OpenStreamCallback = struct {
            runtime: *Self,
            opened_stream: ?ServiceEngine.StreamPort = null,

            fn callback(self: *@This()) ServiceEngine.Callback {
                return .{ .ctx = self, .call = call };
            }

            fn deinit(self: *@This()) void {
                if (self.opened_stream) |*port| {
                    port.deinit();
                    self.opened_stream = null;
                }
            }

            fn call(ctx: *anyopaque, output: ServiceEngine.DriveOutput) !void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                switch (output) {
                    .opened_stream => |port| {
                        if (self.opened_stream) |*previous| previous.deinit();
                        self.opened_stream = port;
                    },
                    .peer_port => |peer_port| {
                        var owned_peer_port = peer_port;
                        const conn_impl = self.runtime.allocator.create(ConnImpl) catch |err| {
                            owned_peer_port.deinit();
                            return err;
                        };
                        errdefer conn_impl.deinit();
                        conn_impl.* = .{
                            .runtime = self.runtime,
                            .peer_port = owned_peer_port,
                        };
                        const send_result = try self.runtime.accept.send(Conn.init(conn_impl));
                        if (!send_result.ok) return error.RuntimeAcceptChannelClosed;
                        _ = self.runtime.stats.active_peers.fetchAdd(1, .monotonic);
                    },
                    .outbound => |pkt| {
                        var noise_callback = NoiseCallback{ .runtime = self.runtime };
                        return self.runtime.noise.drive(.{ .send_data = pkt }, noise_callback.callback());
                    },
                    .next_tick_deadline => |deadline| self.runtime.updateTickDeadline(deadline),
                }
            }
        };

        const ConnImpl = struct {
            runtime: *Self,
            peer_port: ServiceEngine.PeerPort,
            closed: bool = false,

            pub fn read(self: *@This(), buf: []u8) !Conn.ReadResult {
                if (self.closed) return error.ConnClosed;

                const result = try self.peer_port.recvPacket();
                if (!result.ok) return error.ConnClosed;
                return readPacket(result.value, buf);
            }

            pub fn readTimeout(self: *@This(), buf: []u8, timeout: glib.time.duration.Duration) !Conn.ReadResult {
                if (self.closed) return error.ConnClosed;

                const result = try self.peer_port.recvPacketTimeout(timeout);
                if (!result.ok) return error.ConnClosed;
                return readPacket(result.value, buf);
            }

            pub fn write(self: *@This(), protocol: u8, payload: []const u8) !usize {
                if (self.closed) return error.ConnClosed;
                const owned_payload = try self.runtime.allocator.dupe(u8, payload);
                errdefer self.runtime.allocator.free(owned_payload);

                const send_result = try self.runtime.input.send(.{ .write_direct = .{
                    .remote_static = self.peer_port.remote_static,
                    .protocol = protocol,
                    .payload = owned_payload,
                } });
                if (!send_result.ok) return error.RuntimeChannelClosed;
                return payload.len;
            }

            pub fn openStream(self: *@This(), service: u64) !Stream {
                if (self.closed) return error.ConnClosed;

                var reply = try OpenStreamReplyChannel.make(self.runtime.allocator, 1);
                defer reply.deinit();

                const send_result = try self.runtime.input.send(.{ .open_stream = .{
                    .remote_static = self.peer_port.remote_static,
                    .service = service,
                    .reply = &reply,
                } });
                if (!send_result.ok) return error.RuntimeChannelClosed;

                const result = try reply.recv();
                if (!result.ok) return error.RuntimeChannelClosed;
                const port = switch (result.value) {
                    .ok => |port| port,
                    .err => |err| return err,
                };
                return try self.wrapStream(port);
            }

            pub fn accept(self: *@This(), timeout: ?glib.time.duration.Duration) !Stream {
                if (self.closed) return error.ConnClosed;

                const result = try self.peer_port.acceptStream(timeout);
                if (!result.ok) return error.ConnClosed;

                return try self.wrapStream(result.value);
            }

            fn wrapStream(self: *@This(), port: ServiceEngine.StreamPort) !Stream {
                var owned_port = port;
                const stream_impl = self.runtime.allocator.create(StreamImpl) catch |err| {
                    owned_port.deinit();
                    return err;
                };
                errdefer self.runtime.allocator.destroy(stream_impl);
                stream_impl.* = .{
                    .runtime = self.runtime,
                    .port = owned_port,
                };
                return Stream.init(stream_impl, port.service, port.stream);
            }

            pub fn close(self: *@This()) !void {
                if (!self.closed) {
                    self.closed = true;
                    _ = self.runtime.stats.active_peers.fetchSub(1, .monotonic);
                    self.peer_port.close();
                    if (self.runtime.closed.load(.acquire)) return;
                    const send_result = try self.runtime.input.send(.{ .close_conn = self.peer_port.remote_static });
                    if (!send_result.ok) return error.RuntimeChannelClosed;
                }
            }

            pub fn deinit(self: *@This()) void {
                self.close() catch {};
                self.peer_port.deinit();
                self.runtime.allocator.destroy(self);
            }

            pub fn localStatic(self: *@This()) NoiseKey {
                return self.runtime.local_static;
            }

            pub fn remoteStatic(self: *@This()) NoiseKey {
                return self.peer_port.remote_static;
            }

            fn readPacket(inbound: *packet.Inbound, buf: []u8) !Conn.ReadResult {
                defer inbound.deinit();

                const service_data = inbound.service_data orelse return error.PayloadNotParsed;
                const direct = switch (service_data) {
                    .direct => |data| data,
                    .kcp => return error.RuntimeConnKcpNotImplemented,
                    .close => return error.ConnClosed,
                };
                if (buf.len < direct.payload.len) return error.BufferTooSmall;
                @memcpy(buf[0..direct.payload.len], direct.payload);
                return .{
                    .protocol = direct.protocol,
                    .n = direct.payload.len,
                };
            }
        };

        const StreamImpl = struct {
            runtime: *Self,
            port: ServiceEngine.StreamPort,
            closed: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),
            pending_inbound: ?*packet.Inbound = null,
            pending_offset: usize = 0,

            pub fn read(self: *@This(), buf: []u8) !usize {
                if (self.closed.load(.acquire)) return error.StreamClosed;
                if (buf.len == 0) return 0;

                var total: usize = self.readPending(buf);
                if (total == buf.len) return total;

                if (total == 0) {
                    const result = try self.port.recv();
                    if (!result.ok) return error.StreamClosed;
                    self.pending_inbound = result.value;
                    self.pending_offset = 0;
                    total += self.readPending(buf[total..]);
                    if (total == buf.len) return total;
                }

                while (total < buf.len and self.pending_inbound == null) {
                    const result = self.port.recvTimeout(0) catch |err| switch (err) {
                        error.Timeout => break,
                        else => return err,
                    };
                    if (!result.ok) break;
                    self.pending_inbound = result.value;
                    self.pending_offset = 0;
                    total += self.readPending(buf[total..]);
                }

                return total;
            }

            pub fn setReadDeadline(self: *@This(), deadline: glib.time.instant.Time) !void {
                try self.port.setReadDeadline(deadline);
            }

            pub fn write(self: *@This(), payload: []const u8) !usize {
                if (self.closed.load(.acquire)) return error.StreamClosed;
                if (payload.len == 0) return 0;

                var written_total: usize = 0;
                while (written_total < payload.len) {
                    if (self.closed.load(.acquire)) {
                        if (written_total > 0) return written_total;
                        return error.StreamClosed;
                    }

                    const chunk_len = @min(self.maxWriteChunkBytes(), payload.len - written_total);
                    const written = try self.writeChunk(payload[written_total..][0..chunk_len]);
                    if (written == 0) continue;
                    written_total += written;
                }
                return written_total;
            }

            pub fn setWriteDeadline(self: *@This(), deadline: glib.time.instant.Time) !void {
                try self.port.setWriteDeadline(deadline);
            }

            pub fn close(self: *@This()) !void {
                if (self.closed.swap(true, .acq_rel)) return;
                if (self.runtime.closed.load(.acquire)) {
                    self.port.wakeRead();
                    self.port.wakeWrite();
                    return;
                }
                const send_result = try self.runtime.input.send(.{ .close_stream = .{
                    .remote_static = self.port.remote_static,
                    .service = self.port.service,
                    .stream = self.port.stream,
                } });
                if (!send_result.ok) return error.RuntimeChannelClosed;
                self.port.wakeRead();
                self.port.wakeWrite();
            }

            fn maxWriteChunkBytes(self: *@This()) usize {
                const segment_bytes = @as(usize, self.port.write_segment_bytes);
                const max_payload = @min(segment_bytes, packet_size_capacity);
                return if (max_payload == 0) 1 else max_payload;
            }

            fn writeChunk(self: *@This(), payload: []const u8) !usize {
                const owned_payload = try self.runtime.allocator.dupe(u8, payload);
                var payload_owned = true;
                errdefer if (payload_owned) self.runtime.allocator.free(owned_payload);

                while (true) {
                    if (self.closed.load(.acquire)) return error.StreamClosed;

                    const granted = try self.port.waitWritable(@intCast(owned_payload.len));
                    if (granted == 0) continue;
                    if (granted < owned_payload.len) return error.KcpStreamShortWritableGrant;
                    break;
                }

                const input = DriveInput{ .write_stream = .{
                    .remote_static = self.port.remote_static,
                    .service = self.port.service,
                    .stream = self.port.stream,
                    .payload = owned_payload,
                } };
                try self.enqueueWriteStream(input);
                payload_owned = false;
                return owned_payload.len;
            }

            fn enqueueWriteStream(self: *@This(), input: DriveInput) !void {
                if (self.closed.load(.acquire) or self.runtime.closed.load(.acquire)) return error.StreamClosed;
                const send_result = try self.runtime.input.send(input);
                if (!send_result.ok) return error.RuntimeChannelClosed;
            }

            pub fn deinit(self: *@This()) void {
                self.close() catch {};
                self.freePendingInbound();
                self.port.deinit();
                self.runtime.allocator.destroy(self);
            }

            fn readPending(self: *@This(), buf: []u8) usize {
                const inbound = self.pending_inbound orelse return 0;
                const pending = inbound.bytes()[self.pending_offset..];
                const n = @min(buf.len, pending.len);
                @memcpy(buf[0..n], pending[0..n]);
                self.pending_offset += n;
                if (self.pending_offset == inbound.bytes().len) self.freePendingInbound();
                return n;
            }

            fn freePendingInbound(self: *@This()) void {
                const inbound = self.pending_inbound orelse return;
                inbound.deinit();
                self.pending_inbound = null;
                self.pending_offset = 0;
            }
        };

        const TimerCallback = struct {
            fn call(ctx: *anyopaque) void {
                const self: *Self = @ptrCast(@alignCast(ctx));
                if (self.closed.load(.acquire)) return;

                const send_result = self.input.send(.{ .tick = {} }) catch |err| {
                    self.on_error.handle(err);
                    return;
                };
                if (!send_result.ok and !self.closed.load(.acquire)) {
                    self.on_error.handle(error.RuntimeChannelClosed);
                }
            }
        };
    };
}

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    return glib.testing.TestRunner.fromFn(grt.std, 1024 * 1024, struct {
        fn run(_: *glib.testing.T, allocator: grt.std.mem.Allocator) !void {
            try connClosePlaintextUsesControlPayload(grt);
            try outboundWriteFailureReturnsPacketToPool(grt, allocator);
        }

        fn connClosePlaintextUsesControlPayload(comptime any_grt: type) !void {
            const Runtime = make(any_grt, 1053, .chacha_poly);

            var buffer: [2]u8 = undefined;
            const payload = try Runtime.prepareConnClosePlaintext(&buffer);
            try any_grt.std.testing.expectEqual(@as(usize, 2), payload.len);
            try any_grt.std.testing.expectEqual(service_protocol.ProtocolConnCtrl, payload[0]);
            try any_grt.std.testing.expectEqual(service_protocol.ConnCtrlClose, payload[1]);
            try any_grt.std.testing.expectError(error.BufferTooSmall, Runtime.prepareConnClosePlaintext(buffer[0..1]));
        }

        fn outboundWriteFailureReturnsPacketToPool(
            comptime any_grt: type,
            allocator: any_grt.std.mem.Allocator,
        ) !void {
            const Runtime = make(any_grt, 1053, .chacha_poly);
            const PacketConn = any_grt.net.PacketConn;
            const AddrPort = glib.net.netip.AddrPort;

            const FailingPacketConn = struct {
                write_calls: usize = 0,

                pub fn readFrom(_: *@This(), _: []u8) PacketConn.ReadFromError!PacketConn.ReadFromResult {
                    return error.Closed;
                }

                pub fn writeTo(self: *@This(), _: []const u8, _: AddrPort) PacketConn.WriteToError!usize {
                    self.write_calls += 1;
                    return error.NetworkUnreachable;
                }

                pub fn close(_: *@This()) void {}

                pub fn deinit(_: *@This()) void {}

                pub fn setReadDeadline(_: *@This(), _: ?glib.time.instant.Time) void {}

                pub fn setWriteDeadline(_: *@This(), _: ?glib.time.instant.Time) void {}
            };

            var failing_conn = FailingPacketConn{};
            var runtime = try Runtime.init(allocator, PacketConn.init(&failing_conn), .{
                .local_static = @import("giznet").KeyPair.seed(any_grt, 11),
            });
            defer runtime.deinit();

            const remote_pair = @import("giznet").KeyPair.seed(any_grt, 12);
            try runtime.drive(.{ .initiate_handshake = .{
                .remote_key = remote_pair.public,
                .remote_endpoint = AddrPort.from4(.{ 127, 0, 0, 1 }, 9820),
            } });
            try any_grt.std.testing.expectEqual(@as(usize, 1), failing_conn.write_calls);
        }
    }.run);
}
