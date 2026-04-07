const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");
const testing_api = dep.testing;

const bench = @import("../common.zig");
const peer = net_pkg.peer;
const core_pkg = net_pkg.core;
const noise_pkg = net_pkg.noise;

fn Helpers(comptime lib: type) type {
    const ContextApi = dep.context.make(lib);
    const Net = dep.net.make(lib);
    const PacketConn = dep.net.PacketConn;
    const Noise = noise_pkg.make(lib);
    const Core = core_pkg.make(lib);
    const Peer = peer.make(Core);

    return struct {
        pub const client_count: usize = 4;
        pub const default_timeout_ns: i64 = 8 * lib.time.ns_per_s;
        pub const pump_timeout_ns: i64 = 20 * lib.time.ns_per_ms;

        pub const LocalAddr = struct {
            storage: PacketConn.AddrStorage = [_]u8{0} ** @sizeOf(PacketConn.AddrStorage),
            len: u32 = 0,
        };

        pub const Cluster = struct {
            allocator: dep.embed.mem.Allocator,
            ctx_api: ContextApi,
            server_key: Noise.KeyPair,
            server_listener: *Peer.Listener,
            server_addr: LocalAddr,
            clients: [client_count]Client,
            client_init_count: usize = 0,
            accepted: [client_count]?*Peer.Conn = [_]?*Peer.Conn{null} ** client_count,
            accepted_count: usize = 0,

            const Self = @This();

            const Client = struct {
                key_pair: Noise.KeyPair,
                listener: *Peer.Listener,
                conn: ?*Peer.Conn = null,

                fn deinit(self: *Client) void {
                    if (self.conn) |handle| handle.deinit();
                    self.listener.deinit();
                    self.* = undefined;
                }
            };

            const DialTask = struct {
                allocator: dep.embed.mem.Allocator,
                listener: *Peer.Listener,
                server_key: noise_pkg.Key,
                server_addr: LocalAddr,
                conn: ?*Peer.Conn = null,
                err: ?anyerror = null,

                fn run(self: *DialTask) void {
                    var ctx_api = ContextApi.init(self.allocator) catch |err| {
                        self.err = err;
                        return;
                    };
                    defer ctx_api.deinit();

                    var ctx = ctx_api.withTimeout(ctx_api.background(), default_timeout_ns) catch |err| {
                        self.err = err;
                        return;
                    };
                    defer ctx.deinit();

                    self.conn = self.listener.dialContext(
                        ctx,
                        self.server_key,
                        @ptrCast(&self.server_addr.storage),
                        self.server_addr.len,
                    ) catch |err| {
                        self.err = err;
                        return;
                    };
                }
            };

            pub fn init(allocator: dep.embed.mem.Allocator) !Self {
                var ctx_api = try ContextApi.init(allocator);
                errdefer ctx_api.deinit();

                const server_key = try Noise.KeyPair.fromPrivate(
                    noise_pkg.Key.fromBytes([_]u8{51} ** noise_pkg.Key.key_size),
                );

                const server_packet = try Net.listenPacket(.{
                    .allocator = allocator,
                    .address = dep.net.netip.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
                });
                errdefer server_packet.deinit();

                const server_addr = try localSockAddr(server_packet);
                const server_listener = try Peer.Listener.listen(
                    allocator,
                    server_packet,
                    server_key,
                    .{
                        .allow_unknown = true,
                        .service_config = .{
                            .on_new_service = allowAllServices,
                        },
                    },
                );
                errdefer server_listener.deinit();

                var self = Self{
                    .allocator = allocator,
                    .ctx_api = ctx_api,
                    .server_key = server_key,
                    .server_listener = server_listener,
                    .server_addr = server_addr,
                    .clients = undefined,
                };
                errdefer self.deinit();

                var index: usize = 0;
                while (index < client_count) : (index += 1) {
                    self.clients[index] = try initClient(allocator, @intCast(index));
                    self.client_init_count += 1;
                }
                return self;
            }

            pub fn deinit(self: *Self) void {
                var accepted_index: usize = 0;
                while (accepted_index < client_count) : (accepted_index += 1) {
                    if (self.accepted[accepted_index]) |handle| handle.deinit();
                }
                var client_index: usize = 0;
                while (client_index < self.client_init_count) : (client_index += 1) {
                    self.clients[client_index].deinit();
                }
                self.server_listener.deinit();
                self.ctx_api.deinit();
                self.* = undefined;
            }

            pub fn establishAll(self: *Self) !void {
                var tasks: [client_count]DialTask = undefined;
                var threads: [client_count]lib.Thread = undefined;
                var started: usize = 0;
            errdefer {
                var cleanup_index: usize = 0;
                while (cleanup_index < started) : (cleanup_index += 1) {
                    if (tasks[cleanup_index].conn) |handle| handle.deinit();
                }
            }
                errdefer {
                    var join_index: usize = 0;
                    while (join_index < started) : (join_index += 1) {
                        threads[join_index].join();
                    }
                }

                for (&self.clients, 0..) |*client, index| {
                    tasks[index] = .{
                        .allocator = self.allocator,
                        .listener = client.listener,
                        .server_key = self.server_key.public,
                        .server_addr = self.server_addr,
                    };
                    threads[index] = try lib.Thread.spawn(.{}, DialTask.run, .{&tasks[index]});
                    started += 1;
                }

                var accept_index: usize = 0;
                while (accept_index < client_count) : (accept_index += 1) {
                    var ctx = try self.ctx_api.withTimeout(self.ctx_api.background(), default_timeout_ns);
                    defer ctx.deinit();
                    const accepted = try self.server_listener.acceptContext(ctx);
                    const client_index = self.clientIndexForKey(accepted.publicKey()) orelse {
                        accepted.deinit();
                        return error.TestUnexpectedResult;
                    };
                    if (self.accepted[client_index] != null) {
                        accepted.deinit();
                        return error.TestUnexpectedResult;
                    }
                    self.accepted[client_index] = accepted;
                    self.accepted_count += 1;
                }

                var join_index: usize = 0;
                while (join_index < started) : (join_index += 1) {
                    threads[join_index].join();
                }
                for (&self.clients, 0..) |*client, index| {
                    if (tasks[index].err) |err| return err;
                    client.conn = tasks[index].conn orelse return error.TestUnexpectedResult;
                    tasks[index].conn = null;
                }
            }

            pub fn drive(self: *Self, rounds: usize) !void {
                var round: usize = 0;
                while (round < rounds) : (round += 1) {
                    try self.pumpServer();
                    try self.pumpClients();
                    try (try self.server_listener.udpHandle()).tick();
                    for (&self.clients) |*client| {
                        try (try client.listener.udpHandle()).tick();
                    }
                    try self.pumpServer();
                    try self.pumpClients();
                    lib.Thread.sleep(5 * lib.time.ns_per_ms);
                }
            }

            pub fn clientConn(self: *Self, index: usize) !*Peer.Conn {
                if (index >= client_count) return error.TestUnexpectedResult;
                return self.clients[index].conn orelse error.TestUnexpectedResult;
            }

            pub fn serverConn(self: *Self, index: usize) !*Peer.Conn {
                if (index >= client_count) return error.TestUnexpectedResult;
                return self.accepted[index] orelse error.TestUnexpectedResult;
            }

            pub fn waitForServerEvent(
                self: *Self,
                index: usize,
                allocator: dep.embed.mem.Allocator,
                max_rounds: usize,
            ) !peer.Event {
                var round: usize = 0;
                while (round < max_rounds) : (round += 1) {
                    const event = (try self.serverConn(index)).readEvent(allocator) catch |err| {
                        if (err == core_pkg.Error.QueueEmpty) {
                            try self.drive(1);
                            continue;
                        }
                        return err;
                    };
                    return event;
                }
                return error.TimedOut;
            }

            fn pumpServer(self: *Self) !void {
                try self.pumpListener(self.server_listener);
            }

            fn pumpClients(self: *Self) !void {
                for (&self.clients) |*client| {
                    try self.pumpListener(client.listener);
                }
            }

            fn pumpListener(self: *Self, listener: *Peer.Listener) !void {
                var ctx = try self.ctx_api.withTimeout(self.ctx_api.background(), pump_timeout_ns);
                defer ctx.deinit();
                _ = (try listener.udpHandle()).pumpContext(ctx) catch |err| switch (err) {
                    error.TimedOut, error.DeadlineExceeded => return,
                    else => return err,
                };
            }

            fn clientIndexForKey(self: *Self, key: noise_pkg.Key) ?usize {
                for (self.clients[0..self.client_init_count], 0..) |client, index| {
                    if (client.key_pair.public.eql(key)) return index;
                }
                return null;
            }
        };

        fn initClient(allocator: dep.embed.mem.Allocator, index: u8) !Cluster.Client {
            const key_pair = try Noise.KeyPair.fromPrivate(
                noise_pkg.Key.fromBytes([_]u8{71 + index} ** noise_pkg.Key.key_size),
            );
            const packet = try Net.listenPacket(.{
                .allocator = allocator,
                .address = dep.net.netip.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
            });
            const listener = Peer.Listener.listen(
                allocator,
                packet,
                key_pair,
                .{
                    .allow_unknown = false,
                    .service_config = .{
                        .on_new_service = allowAllServices,
                    },
                },
            ) catch |err| {
                packet.deinit();
                return err;
            };
            return .{
                .key_pair = key_pair,
                .listener = listener,
            };
        }

        fn localSockAddr(packet: PacketConn) !LocalAddr {
            const udp_impl = try packet.as(Net.UdpConn);
            var bound: lib.posix.sockaddr.storage = undefined;
            var bound_len: lib.posix.socklen_t = @sizeOf(lib.posix.sockaddr.storage);
            try lib.posix.getsockname(udp_impl.fd, @ptrCast(&bound), &bound_len);

            var result = LocalAddr{};
            result.len = @intCast(bound_len);
            const copy_len = @min(@as(usize, result.len), @sizeOf(PacketConn.AddrStorage));
            @memcpy(result.storage[0..copy_len], @as([*]const u8, @ptrCast(&bound))[0..copy_len]);
            return result;
        }

        fn allowAllServices(_: noise_pkg.Key, _: u64) bool {
            return true;
        }
    };
}

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            runConcurrentDialAcceptRate(lib, allocator) catch |err| {
                t.logErrorf("benchmark/peer/concurrent_dial_accept_cycle_rate failed: {}", .{err});
                return false;
            };
            runConcurrentEventTransferRate(lib, allocator) catch |err| {
                t.logErrorf("benchmark/peer/concurrent_event_transfer_rate failed: {}", .{err});
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

fn runConcurrentDialAcceptRate(comptime lib: type, allocator: dep.embed.mem.Allocator) !void {
    const Helper = Helpers(lib);
    const CountingAllocator = bench.CountingAllocator(lib);
    const config: bench.Config = .{
        .warmup = 1,
        .iterations = 4,
    };

    const State = struct {
        bench_allocator: dep.embed.mem.Allocator,
        sink: usize = 0,
    };

    var counting = CountingAllocator.init(allocator);
    var state = State{
        .bench_allocator = counting.allocator(),
    };

    var warmup: usize = 0;
    while (warmup < config.warmup) : (warmup += 1) {
        try runDialAcceptIteration(Helper, &state);
    }
    counting.reset();
    state.sink = 0;

    const start_ns = lib.time.nanoTimestamp();
    var iteration: usize = 0;
    while (iteration < config.iterations) : (iteration += 1) {
        try runDialAcceptIteration(Helper, &state);
    }
    const elapsed_ns: u64 = @intCast(lib.time.nanoTimestamp() - start_ns);
    lib.mem.doNotOptimizeAway(state.sink);

    // This benchmark measures end-to-end connection churn, including fixture
    // setup and teardown around the concurrent dial/accept burst.
    bench.print(lib, "peer.real_udp.concurrent_dial_accept_cycle_rate", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .alloc_calls_total = counting.stats.alloc_calls + counting.stats.resize_calls + counting.stats.remap_calls,
        .alloc_bytes_total = counting.stats.bytes_allocated,
        .peak_live_bytes = counting.stats.peak_live_bytes,
        .extra_name = "peers",
        .extra_value = Helper.client_count,
    });
}

fn runDialAcceptIteration(comptime Helper: type, state: anytype) !void {
    var cluster = try Helper.Cluster.init(state.bench_allocator);
    defer cluster.deinit();
    try cluster.establishAll();
    state.sink +%= Helper.client_count;
}

fn runConcurrentEventTransferRate(comptime lib: type, allocator: dep.embed.mem.Allocator) !void {
    const Helper = Helpers(lib);
    const CountingAllocator = bench.CountingAllocator(lib);
    const config: bench.Config = .{
        .warmup = 2,
        .iterations = 12,
    };
    const events = [_]peer.Event{
        .{ .name = "bench", .data = "{\"kind\":\"concurrent\",\"peer\":0}" },
        .{ .name = "bench", .data = "{\"kind\":\"concurrent\",\"peer\":1}" },
        .{ .name = "bench", .data = "{\"kind\":\"concurrent\",\"peer\":2}" },
        .{ .name = "bench", .data = "{\"kind\":\"concurrent\",\"peer\":3}" },
    };

    var payload_bytes_per_op: usize = 0;
    for (events) |event| {
        const encoded = try peer.encodeEvent(allocator, event);
        payload_bytes_per_op += encoded.len;
        allocator.free(encoded);
    }

    var cluster = try Helper.Cluster.init(allocator);
    defer cluster.deinit();
    try cluster.establishAll();

    const State = struct {
        cluster: *Helper.Cluster,
        bench_allocator: dep.embed.mem.Allocator,
        events: [Helper.client_count]peer.Event,
        sink: usize = 0,
    };

    var counting = CountingAllocator.init(allocator);
    var state = State{
        .cluster = &cluster,
        .bench_allocator = counting.allocator(),
        .events = events,
    };

    var warmup: usize = 0;
    while (warmup < config.warmup) : (warmup += 1) {
        try runConcurrentEventIteration(Helper, &state);
    }
    counting.reset();
    state.sink = 0;

    const start_ns = lib.time.nanoTimestamp();
    var iteration: usize = 0;
    while (iteration < config.iterations) : (iteration += 1) {
        try runConcurrentEventIteration(Helper, &state);
    }
    const elapsed_ns: u64 = @intCast(lib.time.nanoTimestamp() - start_ns);
    lib.mem.doNotOptimizeAway(state.sink);

    bench.print(lib, "peer.real_udp.concurrent_event_transfer_rate", config, elapsed_ns, .{
        .tier = .smoke,
        .impairment = bench.no_impairment,
        .payload_bytes_per_op = payload_bytes_per_op,
        .copy_bytes_per_op = payload_bytes_per_op,
        .alloc_calls_total = counting.stats.alloc_calls + counting.stats.resize_calls + counting.stats.remap_calls,
        .alloc_bytes_total = counting.stats.bytes_allocated,
        .peak_live_bytes = counting.stats.peak_live_bytes,
        .extra_name = "peers",
        .extra_value = Helper.client_count,
    });
}

fn runConcurrentEventIteration(comptime Helper: type, state: anytype) !void {
    var index: usize = 0;
    while (index < Helper.client_count) : (index += 1) {
        try (try state.cluster.clientConn(index)).sendEvent(state.bench_allocator, state.events[index]);
    }
    index = 0;
    while (index < Helper.client_count) : (index += 1) {
        var received = try state.cluster.waitForServerEvent(index, state.bench_allocator, 256);
        defer received.deinit(state.bench_allocator);
        if (!dep.embed.mem.eql(u8, received.name, state.events[index].name)) return error.TestUnexpectedResult;
        if (received.data == null) return error.TestUnexpectedResult;
        if (!dep.embed.mem.eql(u8, received.data.?, state.events[index].data.?)) return error.TestUnexpectedResult;
        state.sink +%= received.name.len;
        state.sink +%= received.data.?.len;
    }
}
