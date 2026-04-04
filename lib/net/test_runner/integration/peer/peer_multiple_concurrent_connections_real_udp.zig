const dep = @import("dep");
const net_pkg = @import("net");
const testing_api = dep.testing;

const core_pkg = net_pkg.core;
const noise_pkg = net_pkg.noise;

fn Helpers(comptime lib: type) type {
    const ContextApi = dep.context.make(lib);
    const Net = dep.net.make(lib);
    const PacketConn = dep.net.PacketConn;
    const Noise = noise_pkg.make(lib);
    const Core = core_pkg.make(lib);
    const Peer = net_pkg.peer.make(Core);

    return struct {
        const client_count = 3;

        const LocalAddr = struct {
            storage: PacketConn.AddrStorage = [_]u8{0} ** @sizeOf(PacketConn.AddrStorage),
            len: u32 = 0,
        };

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

        const AcceptTask = struct {
            ctx_api: *ContextApi,
            listener: *Peer.Listener,
            conn: ?*Peer.Conn = null,
            err: ?anyerror = null,

            fn run(self: *AcceptTask) void {
                var ctx = self.ctx_api.withTimeout(self.ctx_api.background(), 8 * lib.time.ns_per_s) catch |err| {
                    self.err = err;
                    return;
                };
                defer ctx.deinit();

                self.conn = self.listener.acceptContext(ctx) catch |err| {
                    self.err = err;
                    return;
                };
            }
        };

        pub fn runCase(allocator: dep.embed.mem.Allocator, testing_impl: anytype) !void {
            var ctx_api = try ContextApi.init(allocator);
            defer ctx_api.deinit();

            const server_key = try Noise.KeyPair.fromPrivate(
                noise_pkg.Key.fromBytes([_]u8{51} ** noise_pkg.Key.key_size),
            );

            const server_packet = try Net.listenPacket(.{
                .allocator = allocator,
                .address = dep.net.netip.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
            });
            const server_addr = localSockAddr(server_packet) catch |err| {
                server_packet.deinit();
                return err;
            };

            const server_listener = Peer.Listener.listen(
                allocator,
                server_packet,
                server_key,
                .{
                    .allow_unknown = true,
                    .service_config = .{
                        .on_new_service = allowAllServices,
                    },
                },
            ) catch |err| {
                server_packet.deinit();
                return err;
            };
            defer server_listener.deinit();

            var clients: [client_count]Client = undefined;
            var initialized_clients: usize = 0;
            while (initialized_clients < client_count) : (initialized_clients += 1) {
                clients[initialized_clients] = try initClient(allocator, @intCast(initialized_clients));
            }
            defer {
                var index: usize = 0;
                while (index < initialized_clients) : (index += 1) {
                    clients[index].deinit();
                }
            }
            try testing_impl.expect(!server_key.public.eql(clients[0].key_pair.public));
            try testing_impl.expect(!server_key.public.eql(clients[1].key_pair.public));
            try testing_impl.expect(!server_key.public.eql(clients[2].key_pair.public));
            try testing_impl.expect(!clients[0].key_pair.public.eql(clients[1].key_pair.public));
            try testing_impl.expect(!clients[0].key_pair.public.eql(clients[2].key_pair.public));
            try testing_impl.expect(!clients[1].key_pair.public.eql(clients[2].key_pair.public));

            var accepted_keys: [client_count]noise_pkg.Key = undefined;
            var accepted_conns: [client_count]*Peer.Conn = undefined;
            var accepted_count: usize = 0;
            defer {
                var index: usize = 0;
                while (index < accepted_count) : (index += 1) {
                    accepted_conns[index].deinit();
                }
            }

            for (&clients, 0..) |*client, index| {
                var accept_task = AcceptTask{
                    .ctx_api = &ctx_api,
                    .listener = server_listener,
                };
                var accept_thread = try lib.Thread.spawn(.{}, AcceptTask.run, .{&accept_task});
                var accept_joined = false;
                errdefer if (!accept_joined) accept_thread.join();

                var ctx = try ctx_api.withTimeout(ctx_api.background(), 8 * lib.time.ns_per_s);
                defer ctx.deinit();

                client.conn = client.listener.dialContext(
                    ctx,
                    server_key.public,
                    @ptrCast(&server_addr.storage),
                    server_addr.len,
                ) catch |err| return switch (index) {
                    0 => mapTimeout(err, error.Client0DialFailed),
                    1 => mapTimeout(err, error.Client1DialFailed),
                    2 => mapTimeout(err, error.Client2DialFailed),
                    else => err,
                };

                accept_thread.join();
                accept_joined = true;
                if (accept_task.err) |err| return switch (index) {
                    0 => mapTimeout(err, error.Accept0Failed),
                    1 => mapTimeout(err, error.Accept1Failed),
                    2 => mapTimeout(err, error.Accept2Failed),
                    else => err,
                };
                accepted_conns[index] = accept_task.conn orelse return error.TestUnexpectedResult;
                accepted_keys[index] = accepted_conns[index].publicKey();
                accepted_count += 1;
                try testing_impl.expect(client.conn.?.publicKey().eql(server_key.public));
            }

            for (accepted_keys, 0..) |accepted_key, index| {
                try testing_impl.expect(keyInClients(&clients, accepted_key));
                var other: usize = 0;
                while (other < client_count) : (other += 1) {
                    if (other == index) continue;
                    try testing_impl.expect(!accepted_key.eql(accepted_keys[other]));
                }
            }

            try testing_impl.expectError(core_pkg.Error.QueueEmpty, server_listener.accept());
        }

        fn initClient(allocator: dep.embed.mem.Allocator, index: u8) !Client {
            const private_key = noise_pkg.Key.fromBytes(
                [_]u8{71 + index} ** noise_pkg.Key.key_size,
            );
            const key_pair = try Noise.KeyPair.fromPrivate(private_key);

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

        fn keyInClients(clients: *const [client_count]Client, key: noise_pkg.Key) bool {
            for (clients) |client| {
                if (client.key_pair.public.eql(key)) return true;
            }
            return false;
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

        fn mapTimeout(err: anyerror, fallback: anyerror) anyerror {
            return switch (err) {
                error.DeadlineExceeded, error.TimedOut => fallback,
                else => err,
            };
        }
    };
}

pub fn make(comptime lib: type) testing_api.TestRunner {
    const testing = lib.testing;
    const Helper = Helpers(lib);

    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            Helper.runCase(allocator, testing) catch |err| {
                t.logErrorf("integration/net/peer_multiple_concurrent_connections_real_udp failed: {}", .{err});
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
