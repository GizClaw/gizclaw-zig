const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");
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

                var ctx = ctx_api.withTimeout(ctx_api.background(), 8 * lib.time.ns_per_s) catch |err| {
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

            var accepted_conns: [client_count]?*Peer.Conn = [_]?*Peer.Conn{null} ** client_count;
            defer {
                for (accepted_conns) |maybe_conn| {
                    if (maybe_conn) |handle| handle.deinit();
                }
            }

            var dial_tasks: [client_count]DialTask = undefined;
            var dial_threads: [client_count]lib.Thread = undefined;
            var started: usize = 0;
            errdefer {
                var cleanup_index: usize = 0;
                while (cleanup_index < started) : (cleanup_index += 1) {
                    if (dial_tasks[cleanup_index].conn) |handle| handle.deinit();
                }
            }
            errdefer {
                var join_index: usize = 0;
                while (join_index < started) : (join_index += 1) {
                    dial_threads[join_index].join();
                }
            }

            for (&clients, 0..) |*client, index| {
                dial_tasks[index] = .{
                    .allocator = allocator,
                    .listener = client.listener,
                    .server_key = server_key.public,
                    .server_addr = server_addr,
                };
                dial_threads[index] = try lib.Thread.spawn(.{}, DialTask.run, .{&dial_tasks[index]});
                started += 1;
            }

            var accept_count: usize = 0;
            while (accept_count < client_count) : (accept_count += 1) {
                var ctx = try ctx_api.withTimeout(ctx_api.background(), 8 * lib.time.ns_per_s);
                defer ctx.deinit();
                const accepted = server_listener.acceptContext(ctx) catch |err| {
                    return switch (accept_count) {
                        0 => mapTimeout(err, error.Accept0Failed),
                        1 => mapTimeout(err, error.Accept1Failed),
                        2 => mapTimeout(err, error.Accept2Failed),
                        else => err,
                    };
                };
                const client_index = clientIndexForKey(&clients, accepted.publicKey()) orelse {
                    accepted.deinit();
                    return error.TestUnexpectedResult;
                };
                if (accepted_conns[client_index] != null) {
                    accepted.deinit();
                    return error.TestUnexpectedResult;
                }
                accepted_conns[client_index] = accepted;
            }

            var join_index: usize = 0;
            while (join_index < started) : (join_index += 1) {
                dial_threads[join_index].join();
            }
            for (&clients, 0..) |*client, index| {
                if (dial_tasks[index].err) |err| return switch (index) {
                    0 => mapTimeout(err, error.Client0DialFailed),
                    1 => mapTimeout(err, error.Client1DialFailed),
                    2 => mapTimeout(err, error.Client2DialFailed),
                    else => err,
                };
                client.conn = dial_tasks[index].conn orelse return error.TestUnexpectedResult;
                dial_tasks[index].conn = null;
                try testing_impl.expect(client.conn.?.publicKey().eql(server_key.public));
                const accepted = accepted_conns[index] orelse return error.TestUnexpectedResult;
                try testing_impl.expect(accepted.publicKey().eql(clients[index].key_pair.public));
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

        fn clientIndexForKey(clients: *const [client_count]Client, key: noise_pkg.Key) ?usize {
            for (clients, 0..) |client, index| {
                if (client.key_pair.public.eql(key)) return index;
            }
            return null;
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
