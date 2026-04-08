const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");
const bench = @import("../common.zig");

const CoreFile = net_pkg.core;
const KcpFile = net_pkg.kcp;
const PeerFile = net_pkg.peer;

const RealUdpHarnessFile = @import("real_udp_harness.zig");

// Wrap the benchmark UDP harness with peer.Listener / peer.Conn helpers.
// The network path stays real loopback sockets while preserving the
// non-blocking benchmark drive loop from the lower-level harness.
pub fn make(comptime lib: type) type {
    const ContextApi = dep.context.make(lib);
    const Core = CoreFile.make(lib);
    const Kcp = KcpFile.make(CoreFile);
    const Peer = PeerFile.make(Core);
    const BaseHarness = RealUdpHarnessFile.make(lib);

    return struct {
        allocator: dep.embed.mem.Allocator,
        base: *BaseHarness,
        client_listener: *Peer.Listener,
        server_listener: *Peer.Listener,
        client_conn: ?*Peer.Conn = null,
        server_conn: ?*Peer.Conn = null,

        const Self = @This();

        const Side = enum {
            client,
            server,
        };

        pub const Options = struct {
            enable_kcp: bool = false,
            allow_all_services: bool = true,
            drop_first_client_write: bool = false,
            client_impairment: bench.ImpairmentProfile = bench.no_impairment,
            server_impairment: bench.ImpairmentProfile = bench.no_impairment,
            kcp_accept_backlog: usize = 0,
            kcp_max_active_streams: usize = 0,
        };

        const AcceptTask = struct {
            allocator: dep.embed.mem.Allocator,
            listener: *Peer.Listener,
            conn: ?*Peer.Conn = null,
            err: ?anyerror = null,

            fn run(self: *AcceptTask) void {
                var ctx_api = ContextApi.init(self.allocator) catch |err| {
                    self.err = err;
                    return;
                };
                defer ctx_api.deinit();

                var ctx = ctx_api.withTimeout(ctx_api.background(), BaseHarness.default_timeout_ns) catch |err| {
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

        const CoreAcceptTask = struct {
            allocator: dep.embed.mem.Allocator,
            udp: *Core.UDP,
            conn: ?*Core.Conn = null,
            err: ?anyerror = null,

            fn run(self: *CoreAcceptTask) void {
                var ctx_api = ContextApi.init(self.allocator) catch |err| {
                    self.err = err;
                    return;
                };
                defer ctx_api.deinit();

                var ctx = ctx_api.withTimeout(ctx_api.background(), BaseHarness.default_timeout_ns) catch |err| {
                    self.err = err;
                    return;
                };
                defer ctx.deinit();

                self.conn = self.udp.acceptContext(ctx) catch |err| {
                    self.err = err;
                    return;
                };
            }
        };

        pub fn init(allocator: dep.embed.mem.Allocator, options: Options) !Self {
            const base = try allocator.create(BaseHarness);
            errdefer allocator.destroy(base);
            base.* = try BaseHarness.init(allocator, .{
                .enable_kcp = options.enable_kcp,
                .allow_all_services = options.allow_all_services,
                .drop_first_client_write = options.drop_first_client_write,
                .client_impairment = options.client_impairment,
                .server_impairment = options.server_impairment,
                .kcp_accept_backlog = options.kcp_accept_backlog,
                .kcp_max_active_streams = options.kcp_max_active_streams,
            });
            errdefer base.deinit();

            const server_listener = try Peer.Listener.init(allocator, &base.server_udp, false);
            errdefer server_listener.deinit();
            const client_listener = try Peer.Listener.init(allocator, &base.client_udp, false);
            errdefer client_listener.deinit();

            return .{
                .allocator = allocator,
                .base = base,
                .client_listener = client_listener,
                .server_listener = server_listener,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.client_conn) |handle| handle.deinit();
            if (self.server_conn) |handle| handle.deinit();
            self.client_listener.deinit();
            self.server_listener.deinit();
            self.base.deinit();
            self.allocator.destroy(self.base);
            self.* = undefined;
        }

        pub fn dialAndAccept(self: *Self) !void {
            const server_addr = try self.base.currentServerAddr();

            var accept_task = AcceptTask{
                .allocator = self.allocator,
                .listener = self.server_listener,
            };
            var accept_thread = try lib.Thread.spawn(.{}, AcceptTask.run, .{&accept_task});
            errdefer accept_thread.join();

            var ctx = try self.base.ctx_api.withTimeout(self.base.ctx_api.background(), BaseHarness.default_timeout_ns);
            defer ctx.deinit();

            self.client_conn = try self.client_listener.dialContext(
                ctx,
                self.base.server_static.public,
                @ptrCast(&server_addr.storage),
                server_addr.len,
            );

            accept_thread.join();
            if (accept_task.err) |err| return err;
            self.server_conn = accept_task.conn orelse return error.TestUnexpectedResult;
        }

        pub fn reconnectClient(self: *Self) !*Peer.Conn {
            var accept_task = CoreAcceptTask{
                .allocator = self.allocator,
                .udp = try self.server_listener.udpHandle(),
            };
            var accept_thread = try lib.Thread.spawn(.{}, CoreAcceptTask.run, .{&accept_task});
            errdefer accept_thread.join();

            var ctx = try self.base.ctx_api.withTimeout(self.base.ctx_api.background(), BaseHarness.default_timeout_ns);
            defer ctx.deinit();
            const handle = try self.client_listener.connectContext(ctx, self.base.server_static.public);

            accept_thread.join();
            if (accept_task.err) |err| return err;
            if (accept_task.conn == null) return error.TestUnexpectedResult;
            return handle;
        }

        pub fn secondClientHandle(self: *Self) !*Peer.Conn {
            return try self.client_listener.peer(self.base.server_static.public);
        }

        pub fn secondServerHandle(self: *Self) !*Peer.Conn {
            return try self.server_listener.peer(self.base.client_static.public);
        }

        pub fn drive(self: *Self, rounds: usize) !void {
            try self.base.drive(rounds);
        }

        pub fn flushClientWrites(self: *Self) !void {
            try self.base.flushClientWrites();
        }

        pub fn flushServerWrites(self: *Self) !void {
            try self.base.flushServerWrites();
        }

        pub fn closeClientUDP(self: *Self) !void {
            (try self.client_listener.udpHandle()).close();
        }

        pub fn closeServerUDP(self: *Self) !void {
            (try self.server_listener.udpHandle()).close();
        }

        pub fn waitForServerEvent(
            self: *Self,
            allocator: dep.embed.mem.Allocator,
            max_rounds: usize,
        ) !Peer.Event {
            return try self.waitForEvent(.server, allocator, max_rounds);
        }

        pub fn waitForClientEvent(
            self: *Self,
            allocator: dep.embed.mem.Allocator,
            max_rounds: usize,
        ) !Peer.Event {
            return try self.waitForEvent(.client, allocator, max_rounds);
        }

        pub fn waitForServerOpusFrame(
            self: *Self,
            allocator: dep.embed.mem.Allocator,
            max_rounds: usize,
        ) !Peer.StampedOpusFrame {
            return try self.waitForOpusFrame(.server, allocator, max_rounds);
        }

        pub fn waitForClientOpusFrame(
            self: *Self,
            allocator: dep.embed.mem.Allocator,
            max_rounds: usize,
        ) !Peer.StampedOpusFrame {
            return try self.waitForOpusFrame(.client, allocator, max_rounds);
        }

        pub fn waitForAcceptedServerRPC(self: *Self, max_rounds: usize) !*Peer.Stream {
            return try self.waitForAcceptedService(.server, Peer.ServicePublic, max_rounds);
        }

        pub fn waitForAcceptedClientRPC(self: *Self, max_rounds: usize) !*Peer.Stream {
            return try self.waitForAcceptedService(.client, Peer.ServicePublic, max_rounds);
        }

        pub fn waitForAcceptedServerService(
            self: *Self,
            service_id: u64,
            max_rounds: usize,
        ) !*Peer.Stream {
            return try self.waitForAcceptedService(.server, service_id, max_rounds);
        }

        pub fn waitForAcceptedClientService(
            self: *Self,
            service_id: u64,
            max_rounds: usize,
        ) !*Peer.Stream {
            return try self.waitForAcceptedService(.client, service_id, max_rounds);
        }

        pub fn waitForStreamRead(
            self: *Self,
            stream: *Peer.Stream,
            out: []u8,
            max_rounds: usize,
        ) !usize {
            var round: usize = 0;
            while (round < max_rounds) : (round += 1) {
                const n = stream.read(out) catch |err| {
                    if (err == Kcp.Error.NoData) {
                        try self.drive(1);
                        continue;
                    }
                    return err;
                };
                return n;
            }
            return error.TimedOut;
        }

        pub fn clientConn(self: *Self) !*Peer.Conn {
            if (self.client_conn) |handle| return handle;
            return error.TestUnexpectedResult;
        }

        pub fn serverConn(self: *Self) !*Peer.Conn {
            if (self.server_conn) |handle| return handle;
            return error.TestUnexpectedResult;
        }

        fn waitForEvent(
            self: *Self,
            side: Side,
            allocator: dep.embed.mem.Allocator,
            max_rounds: usize,
        ) !Peer.Event {
            var round: usize = 0;
            while (round < max_rounds) : (round += 1) {
                const event = (try self.conn(side)).readEvent(allocator) catch |err| {
                    if (err == CoreFile.Error.QueueEmpty) {
                        try self.drive(1);
                        continue;
                    }
                    return err;
                };
                return event;
            }
            return error.TimedOut;
        }

        fn waitForOpusFrame(
            self: *Self,
            side: Side,
            allocator: dep.embed.mem.Allocator,
            max_rounds: usize,
        ) !Peer.StampedOpusFrame {
            var round: usize = 0;
            while (round < max_rounds) : (round += 1) {
                const frame = (try self.conn(side)).readOpusFrame(allocator) catch |err| {
                    if (err == CoreFile.Error.QueueEmpty) {
                        try self.drive(1);
                        continue;
                    }
                    return err;
                };
                return frame;
            }
            return error.TimedOut;
        }

        fn waitForAcceptedService(
            self: *Self,
            side: Side,
            service_id: u64,
            max_rounds: usize,
        ) !*Peer.Stream {
            var round: usize = 0;
            while (round < max_rounds) : (round += 1) {
                const stream = (try self.conn(side)).acceptService(service_id) catch |err| {
                    if (err == KcpFile.Error.AcceptQueueEmpty) {
                        try self.drive(1);
                        continue;
                    }
                    return err;
                };
                return stream;
            }
            return error.TimedOut;
        }

        fn conn(self: *Self, side: Side) !*Peer.Conn {
            return switch (side) {
                .client => try self.clientConn(),
                .server => try self.serverConn(),
            };
        }
    };
}
