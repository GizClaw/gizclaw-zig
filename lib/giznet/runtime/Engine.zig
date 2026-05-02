//! Runtime orchestration layer for giznet.
//!
//! This engine owns the runtime event channel and coordinates lower-level
//! protocol engines.

const glib = @import("glib");

const Conn = @import("../Conn.zig");
const NoiseCipher = @import("../noise/Cipher.zig");
const NoiseEngineType = @import("../noise/Engine.zig");
const NoiseKey = @import("../noise/Key.zig");
const NoiseKeyPair = @import("../noise/KeyPair.zig");
const PacketInbound = @import("../packet/Inbound.zig");
const PacketOutbound = @import("../packet/Outbound.zig");
const ServiceEngineType = @import("../service/Engine.zig");
const StatsType = @import("Stats.zig");

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
    payload: []const u8,
};

const DriveInput = union(enum) {
    udp_inbound: *PacketInbound,
    initiate_handshake: NoiseEngineType.InitiateHandshake,
    write_direct: WriteDirect,
    open_stream: OpenStream,
    write_stream: WriteStream,
    close_conn: NoiseKey,
    tick: void,
    close: void,
};

pub fn make(
    comptime grt: type,
    comptime packet_size_capacity: usize,
    comptime cipher_kind: NoiseCipher.Kind,
) type {
    const NoiseEngine = NoiseEngineType.make(grt, packet_size_capacity, cipher_kind);
    const ServiceEngine = ServiceEngineType.make(grt);
    const Stats = StatsType.make(grt);
    const InputChannel = grt.sync.Channel(DriveInput);
    const AcceptChannel = grt.sync.Channel(Conn);
    const Timer = glib.sync.Timer;
    const TimerImpl = Timer.make(grt.std, grt.time);

    return struct {
        allocator: grt.std.mem.Allocator,
        conn: grt.net.PacketConn,
        input: InputChannel,
        accept: AcceptChannel,
        local_static: NoiseKey,
        noise: NoiseEngine,
        service: ServiceEngine,
        stats: Stats = .{},
        drive_thread: ?grt.std.Thread = null,
        read_thread: ?grt.std.Thread = null,
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

            var noise = try NoiseEngine.init(allocator, config.local_static, config.noise);
            errdefer noise.deinit();

            var service = ServiceEngine.init(allocator, config.service);
            errdefer service.deinit();

            return .{
                .allocator = allocator,
                .conn = conn,
                .input = channel,
                .accept = accept,
                .local_static = config.local_static.public,
                .noise = noise,
                .service = service,
                .on_error = config.on_error,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.timer) |timer| {
                timer.deinit();
                self.timer = null;
            }
            self.service.deinit();
            self.noise.deinit();
            self.drainAcceptedConns();
            self.accept.deinit();
            self.input.deinit();
        }

        pub fn startDrive(self: *Self, spawn_config: grt.std.Thread.SpawnConfig) !void {
            if (self.closed.load(.acquire)) return error.RuntimeEngineClosed;
            if (self.drive_thread != null) return error.RuntimeEngineAlreadyStarted;
            self.drive_thread = try grt.std.Thread.spawn(spawn_config, driveLoop, .{self});
        }

        pub fn startRead(self: *Self, spawn_config: grt.std.Thread.SpawnConfig) !void {
            if (self.closed.load(.acquire)) return error.RuntimeEngineClosed;
            if (self.read_thread != null) return error.RuntimeUdpReaderAlreadyStarted;
            self.read_thread = try grt.std.Thread.spawn(spawn_config, readLoop, .{self});
        }

        pub fn startTimer(self: *Self, spawn_config: grt.std.Thread.SpawnConfig) !void {
            if (self.closed.load(.acquire)) return error.RuntimeEngineClosed;
            if (self.timer != null) return error.RuntimeTimerAlreadyStarted;

            const timer_impl = try TimerImpl.init(self.allocator, TimerCallback.call, self, spawn_config);
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
                self.conn.close();
                read_thread.join();
                self.read_thread = null;
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
                    return;
                };
            }
        }

        fn readLoop(self: *Self) void {
            while (!self.closed.load(.acquire)) {
                const packet = self.noise.getInboundPacket() catch |err| {
                    self.on_error.handle(err);
                    return;
                };
                errdefer packet.deinit();

                const result = self.conn.readFrom(packet.bufRef()) catch |err| {
                    packet.deinit();
                    if (self.closed.load(.acquire)) break;
                    self.on_error.handle(err);
                    return;
                };
                packet.len = result.bytes_read;
                packet.remote_endpoint = result.addr;

                const send_result = self.input.send(.{ .udp_inbound = packet }) catch |err| {
                    packet.deinit();
                    _ = self.stats.dropped_packets.fetchAdd(1, .monotonic);
                    self.on_error.handle(err);
                    return;
                };
                if (!send_result.ok) {
                    packet.deinit();
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
                else => {},
            };

            if (self.closed.load(.acquire) and input != .close) return error.RuntimeEngineClosed;
            switch (input) {
                .udp_inbound => |packet| {
                    var inbound_delivered = false;
                    var callback = NoiseCallback{
                        .runtime = self,
                        .inbound_delivered = &inbound_delivered,
                    };
                    self.noise.drive(.{ .inbound_packet = packet }, callback.callback()) catch |err| {
                        if (!inbound_delivered) packet.deinit();
                        return err;
                    };
                    if (inbound_delivered) return;
                    switch (packet.state) {
                        .consumed => packet.deinit(),
                        .service_delivered => {},
                        else => return error.InvalidInboundPacketState,
                    }
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
                .open_stream => {},
                .write_stream => {},
                .close_conn => |remote_static| {
                    var service_callback = ServiceCallback{ .runtime = self };
                    try self.service.drive(.{ .close_conn = remote_static }, service_callback.callback());
                    return;
                },
            }

            const packet = try self.noise.getOutboundPacket();
            errdefer packet.deinit();
            packet.remote_static = switch (input) {
                .write_direct => |request| request.remote_static,
                .open_stream => |request| request.remote_static,
                .write_stream => |request| request.remote_static,
                else => unreachable,
            };

            switch (input) {
                .write_direct => |request| {
                    const buffer = packet.transportPlaintextBufRef();
                    if (buffer.len < request.payload.len + 1) return error.BufferTooSmall;
                    @memcpy(buffer[1..][0..request.payload.len], request.payload);
                    packet.len = request.payload.len + 1;
                    packet.service_data = .{ .direct = .{
                        .protocol = request.protocol,
                        .payload = buffer[1..][0..request.payload.len],
                    } };
                },
                .open_stream => |request| {
                    packet.len = 0;
                    packet.service_data = .{ .open_stream = .{
                        .service = request.service,
                    } };
                },
                .write_stream => |request| {
                    const buffer = packet.transportPlaintextBufRef();
                    if (buffer.len < request.payload.len) return error.BufferTooSmall;
                    @memcpy(buffer[0..request.payload.len], request.payload);
                    packet.len = request.payload.len;
                    packet.service_data = .{ .write_stream = .{
                        .service = request.service,
                        .stream = request.stream,
                        .payload = buffer[0..request.payload.len],
                    } };
                },
                else => unreachable,
            }
            var callback = ServiceCallback{ .runtime = self };
            try self.service.drive(.{ .outbound = packet }, callback.callback());
        }

        fn updateTickDeadline(self: *Self, deadline: glib.time.instant.Time) void {
            if (self.tick_deadline != null and deadline >= self.tick_deadline.?) return;
            self.tick_deadline = deadline;
            if (self.timer) |timer| timer.reset(deadline);
        }

        fn drainAcceptedConns(self: *Self) void {
            while (true) {
                const result = self.accept.recvTimeout(0) catch break;
                if (!result.ok) break;
                result.value.deinit();
            }
        }

        const NoiseCallback = struct {
            runtime: *Self,
            inbound_delivered: ?*bool = null,

            fn callback(self: *@This()) NoiseEngineType.Callback {
                return .{ .ctx = self, .call = call };
            }

            fn call(ctx: *anyopaque, output: NoiseEngineType.DriveOutput) !void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                switch (output) {
                    .outbound => |packet| {
                        defer packet.deinit();
                        if (packet.state != .ready_to_send) {
                            try PacketOutbound.encrypt(grt, cipher_kind, packet);
                        }
                        const bytes = packet.bytes();
                        const written = try self.runtime.conn.writeTo(bytes, packet.remote_endpoint);
                        if (written != bytes.len) return error.ShortUdpWrite;
                        _ = self.runtime.stats.udp_tx_packets.fetchAdd(1, .monotonic);
                    },
                    .inbound => |packet| {
                        switch (packet.state) {
                            .prepared => {
                                try PacketInbound.decrtpy(grt, cipher_kind, packet);
                                var noise_callback = NoiseCallback{
                                    .runtime = self.runtime,
                                    .inbound_delivered = self.inbound_delivered,
                                };
                                return self.runtime.noise.drive(.{ .inbound_packet = packet }, noise_callback.callback());
                            },
                            .ready_to_consume, .consumed => {
                                var service_callback = ServiceCallback{
                                    .runtime = self.runtime,
                                    .inbound_delivered = self.inbound_delivered,
                                };
                                return self.runtime.service.drive(.{ .inbound = packet }, service_callback.callback());
                            },
                            .initial,
                            .service_delivered,
                            .decrypt_failed,
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
            inbound_delivered: ?*bool = null,

            fn callback(self: *@This()) ServiceEngine.Callback {
                return .{ .ctx = self, .call = call };
            }

            fn call(ctx: *anyopaque, output: ServiceEngine.DriveOutput) !void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                switch (output) {
                    .peer_port => |peer_port| {
                        const conn_impl = try self.runtime.allocator.create(ConnImpl);
                        errdefer conn_impl.deinit();
                        conn_impl.* = .{
                            .runtime = self.runtime,
                            .peer_port = peer_port,
                        };
                        const send_result = try self.runtime.accept.send(Conn.init(conn_impl));
                        if (!send_result.ok) {
                            _ = self.runtime.stats.dropped_packets.fetchAdd(1, .monotonic);
                            return error.RuntimeAcceptChannelClosed;
                        }
                        _ = self.runtime.stats.active_peers.fetchAdd(1, .monotonic);
                    },
                    .inbound_delivered => {
                        if (self.inbound_delivered) |delivered| delivered.* = true;
                    },
                    .outbound => |packet| {
                        var noise_callback = NoiseCallback{ .runtime = self.runtime };
                        return self.runtime.noise.drive(.{ .send_data = packet }, noise_callback.callback());
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

            pub fn close(self: *@This()) !void {
                if (!self.closed) {
                    self.closed = true;
                    _ = self.runtime.stats.active_peers.fetchSub(1, .monotonic);
                    const send_result = try self.runtime.input.send(.{ .close_conn = self.peer_port.remote_static });
                    if (!send_result.ok) return error.RuntimeChannelClosed;
                }
            }

            pub fn deinit(self: *@This()) void {
                self.close() catch {};
                self.runtime.allocator.destroy(self);
            }

            pub fn localStatic(self: *@This()) NoiseKey {
                return self.runtime.local_static;
            }

            pub fn remoteStatic(self: *@This()) NoiseKey {
                return self.peer_port.remote_static;
            }

            fn readPacket(packet: *PacketInbound, buf: []u8) !Conn.ReadResult {
                defer packet.deinit();

                const service_data = packet.service_data orelse return error.PayloadNotParsed;
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
