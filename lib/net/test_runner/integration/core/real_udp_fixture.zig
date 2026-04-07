const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");
const bench = @import("../../benchmark/common.zig");

const noise = net_pkg.noise;
const CoreFile = net_pkg.core;
const KcpFile = net_pkg.kcp;

pub fn make(comptime lib: type) type {
    const ContextApi = dep.context.make(lib);
    const Net = dep.net.make(lib);
    const Noise = noise.make(lib);
    const Core = CoreFile.make(lib);
    const Kcp = KcpFile.make(CoreFile);
    const PacketConn = dep.net.PacketConn;
    const UdpType = Core.UDP;

    return struct {
        allocator: dep.embed.mem.Allocator,
        ctx_api: ContextApi,
        client_static: Noise.KeyPair,
        server_static: Noise.KeyPair,
        client_wrapper: *SwitchablePacketConn,
        server_wrapper: *SwitchablePacketConn,
        client_udp: UdpType,
        server_udp: UdpType,
        kcp_factory: ?*Kcp.Adapter.Factory = null,

        const Self = @This();

        pub const service_id: u64 = 7;
        pub const default_timeout_ns: i64 = 8 * lib.time.ns_per_s;
        pub const pump_timeout_ns: i64 = 20 * lib.time.ns_per_ms;

        pub const LocalAddr = struct {
            storage: PacketConn.AddrStorage = [_]u8{0} ** @sizeOf(PacketConn.AddrStorage),
            len: u32 = 0,
        };

        pub const DirectReadResult = struct {
            protocol_byte: u8,
            n: usize,
        };

        pub const Options = struct {
            enable_kcp: bool = false,
            drop_first_client_write: bool = false,
            allow_all_services: bool = true,
            client_impairment: bench.ImpairmentProfile = bench.no_impairment,
            server_impairment: bench.ImpairmentProfile = bench.no_impairment,
            kcp_accept_backlog: usize = 0,
            kcp_max_active_streams: usize = 0,
        };

        const AcceptTask = struct {
            allocator: dep.embed.mem.Allocator,
            udp: *UdpType,
            conn: ?*Core.Conn = null,
            err: ?anyerror = null,

            fn run(self: *AcceptTask) void {
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
                self.conn = self.udp.acceptContext(ctx) catch |err| {
                    self.err = err;
                    return;
                };
            }
        };

        const SwitchablePacketConn = struct {
            allocator: dep.embed.mem.Allocator,
            active: PacketConn,
            retired: ?PacketConn = null,
            drop_first_write: bool = false,
            read_timeout_ms: ?u32 = null,
            write_timeout_ms: ?u32 = null,
            write_count: usize = 0,
            impairment: bench.ImpairmentProfile = bench.no_impairment,
            drop_burst_remaining: usize = 0,
            delayed_packet: ?DelayedPacket = null,
            teardown_requested: bool = false,

            const DelayedPacket = struct {
                payload: [noise.MaxPacketSize]u8 = undefined,
                payload_len: usize,
                addr: PacketConn.AddrStorage = [_]u8{0} ** @sizeOf(PacketConn.AddrStorage),
                addr_len: u32,
            };

            fn init(allocator: dep.embed.mem.Allocator, active: PacketConn) !*SwitchablePacketConn {
                const self = try allocator.create(SwitchablePacketConn);
                self.* = .{
                    .allocator = allocator,
                    .active = active,
                };
                return self;
            }

            fn switchTo(self: *SwitchablePacketConn, next: PacketConn) void {
                if (self.retired) |packet| packet.deinit();
                self.retired = self.active;
                self.active = next;
                self.active.setReadTimeout(self.read_timeout_ms);
                self.active.setWriteTimeout(self.write_timeout_ms);
            }

            fn setImpairment(self: *SwitchablePacketConn, impairment: bench.ImpairmentProfile) void {
                self.impairment = impairment;
                self.drop_burst_remaining = 0;
                self.delayed_packet = null;
            }

            fn localSockAddr(self: *SwitchablePacketConn) !LocalAddr {
                const udp_impl = try self.active.as(Net.UdpConn);
                var bound: lib.posix.sockaddr.storage = undefined;
                var bound_len: lib.posix.socklen_t = @sizeOf(lib.posix.sockaddr.storage);
                try lib.posix.getsockname(udp_impl.fd, @ptrCast(&bound), &bound_len);

                var result = LocalAddr{};
                result.len = @intCast(bound_len);
                const copy_len = @min(@as(usize, result.len), @sizeOf(PacketConn.AddrStorage));
                @memcpy(result.storage[0..copy_len], @as([*]const u8, @ptrCast(&bound))[0..copy_len]);
                return result;
            }

            pub fn readFrom(self: *SwitchablePacketConn, buf: []u8) PacketConn.ReadFromError!PacketConn.ReadFromResult {
                self.active.setReadTimeout(self.read_timeout_ms);
                return self.active.readFrom(buf);
            }

            pub fn writeTo(
                self: *SwitchablePacketConn,
                buf: []const u8,
                addr: [*]const u8,
                addr_len: u32,
            ) PacketConn.WriteToError!usize {
                self.write_count += 1;
                if (self.drop_first_write) {
                    self.drop_first_write = false;
                    return buf.len;
                }
                const should_drop = self.shouldDropCurrent();
                const should_reorder = self.shouldReorderCurrent();

                if (self.delayed_packet != null) {
                    if (!should_drop) {
                        try self.sendActive(buf, addr, addr_len);
                        try self.maybeDuplicateActive(buf, addr, addr_len);
                    }
                    try self.flush();
                    return buf.len;
                }

                if (should_drop) return buf.len;
                if (should_reorder) {
                    try self.storeDelayed(buf, addr, addr_len);
                    return buf.len;
                }

                try self.sendActive(buf, addr, addr_len);
                try self.maybeDuplicateActive(buf, addr, addr_len);
                return buf.len;
            }

            pub fn close(self: *SwitchablePacketConn) void {
                self.active.close();
                if (self.retired) |packet| packet.close();
            }

            pub fn deinit(self: *SwitchablePacketConn) void {
                if (self.teardown_requested) return;
                self.teardown_requested = true;
                // PacketConn calls this hook during UDP teardown, so owner-side
                // heap release stays in finalize().
                self.close();
            }

            pub fn setReadTimeout(self: *SwitchablePacketConn, ms: ?u32) void {
                self.read_timeout_ms = ms;
                self.active.setReadTimeout(ms);
            }

            pub fn setWriteTimeout(self: *SwitchablePacketConn, ms: ?u32) void {
                self.write_timeout_ms = ms;
                self.active.setWriteTimeout(ms);
            }

            pub fn flush(self: *SwitchablePacketConn) PacketConn.WriteToError!void {
                if (self.delayed_packet) |packet| {
                    try self.sendActive(packet.payload[0..packet.payload_len], @ptrCast(&packet.addr), packet.addr_len);
                    self.delayed_packet = null;
                }
            }

            fn sendActive(
                self: *SwitchablePacketConn,
                buf: []const u8,
                addr: [*]const u8,
                addr_len: u32,
            ) PacketConn.WriteToError!void {
                self.active.setWriteTimeout(self.write_timeout_ms);
                _ = try self.active.writeTo(buf, addr, addr_len);
            }

            fn maybeDuplicateActive(
                self: *SwitchablePacketConn,
                buf: []const u8,
                addr: [*]const u8,
                addr_len: u32,
            ) PacketConn.WriteToError!void {
                if (!self.shouldDuplicateCurrent()) return;

                const burst = if (self.impairment.burst_len == 0) 1 else self.impairment.burst_len;
                var copy_index: usize = 0;
                while (copy_index < burst) : (copy_index += 1) {
                    try self.sendActive(buf, addr, addr_len);
                }
            }

            fn storeDelayed(
                self: *SwitchablePacketConn,
                buf: []const u8,
                addr: [*]const u8,
                addr_len: u32,
            ) PacketConn.WriteToError!void {
                if (buf.len > noise.MaxPacketSize) return error.MessageTooLong;

                var owned = DelayedPacket{
                    .payload_len = buf.len,
                    .addr_len = addr_len,
                };
                @memcpy(owned.payload[0..buf.len], buf);
                const addr_len_usize: usize = @intCast(addr_len);
                @memcpy(owned.addr[0..addr_len_usize], addr[0..addr_len_usize]);
                self.delayed_packet = owned;
            }

            fn shouldDropCurrent(self: *SwitchablePacketConn) bool {
                if (self.drop_burst_remaining != 0) {
                    self.drop_burst_remaining -= 1;
                    return true;
                }
                if (!percentHit(self.write_count, self.impairment.loss_pct)) return false;
                if (self.impairment.burst_len > 1) {
                    self.drop_burst_remaining = self.impairment.burst_len - 1;
                }
                return true;
            }

            fn shouldReorderCurrent(self: *SwitchablePacketConn) bool {
                return self.impairment.reorder_pct != 0 and percentHit(self.write_count, self.impairment.reorder_pct);
            }

            fn shouldDuplicateCurrent(self: *SwitchablePacketConn) bool {
                return self.impairment.duplicate_pct != 0 and percentHit(self.write_count, self.impairment.duplicate_pct);
            }

            fn percentHit(write_count: usize, pct: u8) bool {
                if (pct == 0 or write_count == 0) return false;
                const pct_usize: usize = pct;
                return ((write_count - 1) * pct_usize) / 100 != (write_count * pct_usize) / 100;
            }

            fn finalize(self: *SwitchablePacketConn) void {
                // The fixture owns the wrapper allocation and must call finalize()
                // after UDP deinit has triggered the PacketConn deinit hook.
                self.delayed_packet = null;
                self.active.deinit();
                if (self.retired) |packet| packet.deinit();
                const allocator = self.allocator;
                allocator.destroy(self);
            }
        };

        pub fn init(allocator: dep.embed.mem.Allocator, options: Options) !Self {
            var self: Self = undefined;
            self.allocator = allocator;
            self.ctx_api = try ContextApi.init(allocator);
            errdefer self.ctx_api.deinit();

            self.client_static = try Noise.KeyPair.fromPrivate(
                noise.Key.fromBytes([_]u8{ 24, 1, 0, 0 } ++ [_]u8{0} ** (noise.Key.key_size - 4)),
            );
            self.server_static = try Noise.KeyPair.fromPrivate(
                noise.Key.fromBytes([_]u8{ 40, 2, 0, 0 } ++ [_]u8{0} ** (noise.Key.key_size - 4)),
            );
            if (self.client_static.public.eql(self.server_static.public)) return error.TestUnexpectedResult;

            self.kcp_factory = null;
            if (options.enable_kcp) {
                const factory = try allocator.create(Kcp.Adapter.Factory);
                factory.* = .{};
                factory.config.mux.close_ack_timeout_ms = 50;
                factory.config.mux.interval = 1;
                if (options.kcp_accept_backlog != 0) {
                    factory.config.mux.accept_backlog = options.kcp_accept_backlog;
                }
                if (options.kcp_max_active_streams != 0) {
                    factory.config.mux.max_active_streams = options.kcp_max_active_streams;
                }
                self.kcp_factory = factory;
            }
            errdefer if (self.kcp_factory) |factory| allocator.destroy(factory);

            self.client_wrapper = try SwitchablePacketConn.init(
                allocator,
                try Net.listenPacket(.{
                    .allocator = allocator,
                    .address = dep.net.netip.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
                }),
            );
            errdefer self.client_wrapper.finalize();
            self.client_wrapper.drop_first_write = options.drop_first_client_write;
            self.client_wrapper.setImpairment(options.client_impairment);

            self.server_wrapper = try SwitchablePacketConn.init(
                allocator,
                try Net.listenPacket(.{
                    .allocator = allocator,
                    .address = dep.net.netip.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
                }),
            );
            errdefer self.server_wrapper.finalize();
            self.server_wrapper.setImpairment(options.server_impairment);

            var client_config: UdpType.Config = .{
                .allow_unknown = false,
                .service_config = if (options.allow_all_services)
                    .{
                        .on_new_service = allowAllServices,
                    }
                else
                    .{},
            };
            var server_config: UdpType.Config = .{
                .allow_unknown = true,
                .service_config = if (options.allow_all_services)
                    .{
                        .on_new_service = allowAllServices,
                    }
                else
                    .{},
            };
            if (self.kcp_factory) |factory| {
                client_config.service_config.stream_adapter_factory = factory.adapterFactory();
                server_config.service_config.stream_adapter_factory = factory.adapterFactory();
            }

            self.client_udp = try UdpType.init(
                allocator,
                PacketConn.init(self.client_wrapper),
                self.client_static,
                client_config,
            );
            errdefer self.client_udp.deinit();

            self.server_udp = try UdpType.init(
                allocator,
                PacketConn.init(self.server_wrapper),
                self.server_static,
                server_config,
            );
            errdefer self.server_udp.deinit();

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.client_udp.deinit();
            self.server_udp.deinit();
            self.client_wrapper.finalize();
            self.server_wrapper.finalize();
            if (self.kcp_factory) |factory| self.allocator.destroy(factory);
            self.ctx_api.deinit();
            self.* = undefined;
        }

        pub fn establish(self: *Self) !void {
            const server_addr = try self.server_wrapper.localSockAddr();
            try self.client_udp.setPeerEndpoint(
                self.server_static.public,
                @ptrCast(&server_addr.storage),
                server_addr.len,
            );

            var accept_task = AcceptTask{
                .allocator = self.allocator,
                .udp = &self.server_udp,
            };
            var accept_thread = try lib.Thread.spawn(.{}, AcceptTask.run, .{&accept_task});
            errdefer accept_thread.join();

            var ctx = try self.ctx_api.withTimeout(self.ctx_api.background(), default_timeout_ns);
            defer ctx.deinit();
            _ = try self.client_udp.connect(ctx, self.server_static.public);

            accept_thread.join();
            if (accept_task.err) |err| return err;
            if (accept_task.conn == null) return error.TestUnexpectedResult;
        }

        pub fn drive(self: *Self, rounds: usize) !void {
            var round: usize = 0;
            while (round < rounds) : (round += 1) {
                try self.flushClientWrites();
                try self.flushServerWrites();
                try self.pumpServer();
                try self.pumpClient();
                try self.client_udp.tick();
                try self.server_udp.tick();
                try self.flushClientWrites();
                try self.flushServerWrites();
                try self.pumpServer();
                try self.pumpClient();
                lib.Thread.sleep(5 * lib.time.ns_per_ms);
            }
        }

        pub fn flushClientWrites(self: *Self) !void {
            try self.client_wrapper.flush();
        }

        pub fn flushServerWrites(self: *Self) !void {
            try self.server_wrapper.flush();
        }

        pub fn pumpServer(self: *Self) !void {
            try self.pumpUdp(&self.server_udp);
        }

        pub fn pumpClient(self: *Self) !void {
            try self.pumpUdp(&self.client_udp);
        }

        pub fn currentClientAddr(self: *Self) !LocalAddr {
            return try self.client_wrapper.localSockAddr();
        }

        pub fn currentServerAddr(self: *Self) !LocalAddr {
            return try self.server_wrapper.localSockAddr();
        }

        pub fn switchClientSocket(self: *Self) !LocalAddr {
            const next = try Net.listenPacket(.{
                .allocator = self.allocator,
                .address = dep.net.netip.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
            });
            self.client_wrapper.switchTo(next);
            return try self.client_wrapper.localSockAddr();
        }

        pub fn waitForServerDirect(
            self: *Self,
            out: []u8,
            max_rounds: usize,
        ) !DirectReadResult {
            var round: usize = 0;
            while (round < max_rounds) : (round += 1) {
                const result = self.server_udp.read(self.client_static.public, out) catch |err| {
                    if (err == CoreFile.Error.QueueEmpty) {
                        try self.drive(1);
                        continue;
                    }
                    return err;
                };
                return .{
                    .protocol_byte = result.protocol_byte,
                    .n = result.n,
                };
            }
            return error.TimedOut;
        }

        pub fn waitForAcceptedServerStream(self: *Self, max_rounds: usize) !u64 {
            var round: usize = 0;
            while (round < max_rounds) : (round += 1) {
                const mux = self.server_udp.serviceMux(self.client_static.public) orelse {
                    try self.pumpServer();
                    try self.pumpClient();
                    continue;
                };
                const stream_id = mux.acceptStream(service_id) catch |err| {
                    if (err == error.AcceptQueueEmpty) {
                        try self.pumpServer();
                        try self.pumpClient();
                        continue;
                    }
                    return err;
                };
                return stream_id;
            }
            return error.TimedOut;
        }

        pub fn waitForServerStreamData(
            self: *Self,
            stream_id: u64,
            out: []u8,
            max_rounds: usize,
        ) !usize {
            var round: usize = 0;
            while (round < max_rounds) : (round += 1) {
                const n = self.server_udp.recvStreamData(self.client_static.public, service_id, stream_id, out) catch |err| {
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

        pub fn waitForClientStreamData(
            self: *Self,
            stream_id: u64,
            out: []u8,
            max_rounds: usize,
        ) !usize {
            var round: usize = 0;
            while (round < max_rounds) : (round += 1) {
                const n = self.client_udp.recvStreamData(self.server_static.public, service_id, stream_id, out) catch |err| {
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

        pub fn waitForServerEndpoint(self: *Self, expected: LocalAddr, max_rounds: usize) !LocalAddr {
            var round: usize = 0;
            while (round < max_rounds) : (round += 1) {
                if (self.server_udp.peerInfo(self.client_static.public)) |info| {
                    if (info.has_endpoint and addrEquals(
                        .{
                            .storage = info.endpoint.addr,
                            .len = info.endpoint.len,
                        },
                        expected,
                    )) {
                        return .{
                            .storage = info.endpoint.addr,
                            .len = info.endpoint.len,
                        };
                    }
                }
                try self.drive(1);
            }
            return error.TimedOut;
        }

        fn pumpUdp(self: *Self, udp: *UdpType) !void {
            var ctx = try self.ctx_api.withTimeout(self.ctx_api.background(), pump_timeout_ns);
            defer ctx.deinit();
            _ = udp.pumpContext(ctx) catch |err| switch (err) {
                error.TimedOut, error.DeadlineExceeded => return,
                else => return err,
            };
        }

        fn addrEquals(a: LocalAddr, b: LocalAddr) bool {
            if (a.len != b.len) return false;
            const n: usize = @intCast(a.len);
            return dep.embed.mem.eql(u8, a.storage[0..n], b.storage[0..n]);
        }
    };
}

fn allowAllServices(_: noise.Key, _: u64) bool {
    return true;
}
