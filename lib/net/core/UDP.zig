const dep = @import("dep");
const noise = @import("../noise.zig");

const consts = @import("consts.zig");
const errors = @import("errors.zig");
const HostFile = @import("Host.zig");
const KeyMapFile = @import("KeyMap.zig");
const protocol = @import("protocol.zig");
const ServiceMuxFile = @import("ServiceMux.zig");
const ConnFile = @import("Conn.zig");

// Single-threaded: callers must serialize all UDP access.
pub fn make(comptime lib: type, comptime Noise: type) type {
    const Context = dep.context.Context;
    const PacketConn = dep.net.PacketConn;
    const HostType = HostFile.make(lib, Noise);
    const ConnType = ConnFile.make(Noise);
    const KeyPair = Noise.KeyPair;
    const ServiceMuxType = ServiceMuxFile.make(lib, Noise);

    return struct {
        allocator: dep.embed.mem.Allocator,
        packet_conn: PacketConn,
        local_static: KeyPair,
        host: HostType,
        endpoints: KeyMapFile.make(Endpoint),
        peer_runtime: KeyMapFile.make(PeerRuntime),
        pending_sends: KeyMapFile.make(PendingSendQueue),
        pending_send_queue_size: usize,
        ready: AcceptQueue,
        read_buf: []u8,
        plaintext_buf: []u8,
        ciphertext_buf: []u8,
        wire_buf: []u8,
        on_peer_event: ?PeerEventHook,
        rx_bytes: u64 = 0,
        tx_bytes: u64 = 0,
        endpoint_update_count: u64 = 0,
        last_seen_ms: u64 = 0,
        last_endpoint_update_ms: u64 = 0,
        closed: bool = false,

        const Self = @This();

        pub const PeerEvent = struct {
            peer: noise.Key,
            state: HostFile.PeerState,
        };

        pub const EndpointSnapshot = struct {
            addr: PacketConn.AddrStorage = [_]u8{0} ** @sizeOf(PacketConn.AddrStorage),
            len: u32 = 0,
        };

        pub const HostInfo = struct {
            peer_count: usize,
            rx_bytes: u64,
            tx_bytes: u64,
            endpoint_updates: u64,
            last_seen_ms: u64,
            last_endpoint_update_ms: u64,
        };

        pub const PeerInfo = struct {
            peer: noise.Key,
            state: HostFile.PeerState,
            has_endpoint: bool,
            endpoint: EndpointSnapshot = .{},
            rx_bytes: u64,
            tx_bytes: u64,
            last_seen_ms: u64,
            last_endpoint_update_ms: u64,
        };

        pub const PeerEventHook = struct {
            ctx: *anyopaque,
            emit: *const fn (ctx: *anyopaque, event: PeerEvent) void,
        };

        pub const Config = struct {
            allow_unknown: bool = false,
            accept_queue_size: usize = consts.default_accept_queue_size,
            pending_send_queue_size: usize = consts.default_pending_send_queue_size,
            service_config: ServiceMuxFile.Config = .{},
            on_peer_event: ?PeerEventHook = null,
        };

        pub const SendResult = union(enum) {
            queued,
            sent: usize,
        };

        const Endpoint = struct {
            addr: PacketConn.AddrStorage = [_]u8{0} ** @sizeOf(PacketConn.AddrStorage),
            len: u32 = 0,
            updated_ms: u64 = 0,
        };

        const PeerRuntime = struct {
            rx_bytes: u64 = 0,
            tx_bytes: u64 = 0,
            last_seen_ms: u64 = 0,
        };

        const PendingKind = enum {
            direct,
            stream,
        };

        const PendingSend = struct {
            kind: PendingKind,
            service: u64,
            protocol_byte: u8,
            payload: []u8,
        };

        const PendingSendQueue = struct {
            allocator: dep.embed.mem.Allocator,
            slots: []Slot,
            head: usize = 0,
            tail: usize = 0,
            len: usize = 0,

            const Slot = struct {
                used: bool = false,
                value: PendingSend = undefined,
            };

            fn init(allocator: dep.embed.mem.Allocator, capacity: usize) !PendingSendQueue {
                const slots = try allocator.alloc(Slot, @max(capacity, 1));
                for (slots) |*slot| slot.* = .{};
                return .{
                    .allocator = allocator,
                    .slots = slots,
                };
            }

            fn deinit(self: *PendingSendQueue) void {
                while (self.pop()) |pending| {
                    self.allocator.free(pending.payload);
                }
                self.allocator.free(self.slots);
                self.slots = &.{};
                self.head = 0;
                self.tail = 0;
                self.len = 0;
            }

            fn pushCopy(
                self: *PendingSendQueue,
                kind: PendingKind,
                service: u64,
                protocol_byte: u8,
                payload: []const u8,
            ) !void {
                if (self.len == self.slots.len) return errors.Error.QueueFull;
                const owned = try self.allocator.alloc(u8, payload.len);
                errdefer self.allocator.free(owned);
                @memcpy(owned, payload);
                self.slots[self.tail] = .{
                    .used = true,
                    .value = .{
                        .kind = kind,
                        .service = service,
                        .protocol_byte = protocol_byte,
                        .payload = owned,
                    },
                };
                self.tail = (self.tail + 1) % self.slots.len;
                self.len += 1;
            }

            fn peek(self: *PendingSendQueue) ?*const PendingSend {
                if (self.len == 0) return null;
                return &self.slots[self.head].value;
            }

            fn pop(self: *PendingSendQueue) ?PendingSend {
                if (self.len == 0) return null;
                const slot = &self.slots[self.head];
                const pending = slot.value;
                slot.* = .{};
                self.head = (self.head + 1) % self.slots.len;
                self.len -= 1;
                return pending;
            }
        };

        const AcceptQueue = struct {
            slots: []noise.Key,
            head: usize = 0,
            tail: usize = 0,
            len: usize = 0,

            fn init(allocator: dep.embed.mem.Allocator, capacity: usize) !AcceptQueue {
                return .{
                    .slots = try allocator.alloc(noise.Key, @max(capacity, 1)),
                };
            }

            fn deinit(self: *AcceptQueue, allocator: dep.embed.mem.Allocator) void {
                allocator.free(self.slots);
                self.slots = &.{};
                self.head = 0;
                self.tail = 0;
                self.len = 0;
            }

            fn push(self: *AcceptQueue, remote_pk: noise.Key) !void {
                if (self.len == self.slots.len) return errors.Error.QueueFull;
                self.slots[self.tail] = remote_pk;
                self.tail = (self.tail + 1) % self.slots.len;
                self.len += 1;
            }

            fn pop(self: *AcceptQueue) ?noise.Key {
                if (self.len == 0) return null;
                const remote_pk = self.slots[self.head];
                self.head = (self.head + 1) % self.slots.len;
                self.len -= 1;
                return remote_pk;
            }
        };

        pub fn init(
            allocator: dep.embed.mem.Allocator,
            packet_conn: PacketConn,
            local_static: KeyPair,
            config: Config,
        ) !Self {
            const packet_size = noise.Message.max_packet_size;
            return .{
                .allocator = allocator,
                .packet_conn = packet_conn,
                .local_static = local_static,
                .host = try HostType.init(allocator, local_static, config.allow_unknown, config.service_config),
                .endpoints = try KeyMapFile.make(Endpoint).init(allocator, 8),
                .peer_runtime = try KeyMapFile.make(PeerRuntime).init(allocator, 8),
                .pending_sends = try KeyMapFile.make(PendingSendQueue).init(allocator, 8),
                .pending_send_queue_size = config.pending_send_queue_size,
                .ready = try AcceptQueue.init(allocator, config.accept_queue_size),
                .read_buf = try allocator.alloc(u8, packet_size),
                .plaintext_buf = try allocator.alloc(u8, packet_size),
                .ciphertext_buf = try allocator.alloc(u8, packet_size),
                .wire_buf = try allocator.alloc(u8, packet_size),
                .on_peer_event = config.on_peer_event,
            };
        }

        pub fn deinit(self: *Self) void {
            self.closed = true;
            self.packet_conn.deinit();
            self.host.deinit();
            self.clearPendingSendQueues();
            self.pending_sends.deinit();
            self.peer_runtime.deinit();
            self.endpoints.deinit();
            self.ready.deinit(self.allocator);
            self.allocator.free(self.read_buf);
            self.allocator.free(self.plaintext_buf);
            self.allocator.free(self.ciphertext_buf);
            self.allocator.free(self.wire_buf);
            self.read_buf = &.{};
            self.plaintext_buf = &.{};
            self.ciphertext_buf = &.{};
            self.wire_buf = &.{};
        }

        pub fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;
            self.packet_conn.close();
        }

        pub fn registerPeer(self: *Self, remote_pk: noise.Key) !void {
            if (self.closed) return errors.Error.Closed;
            self.ensureServiceMuxHooks();
            try self.host.registerPeer(remote_pk);
            _ = try self.ensurePeerRuntime(remote_pk);
        }

        pub fn connection(self: *Self, remote_pk: noise.Key) ?*ConnType {
            return self.host.connection(remote_pk);
        }

        pub fn serviceMux(self: *Self, remote_pk: noise.Key) ?*ServiceMuxType {
            self.ensureServiceMuxHooks();
            return self.host.serviceMux(remote_pk);
        }

        pub fn setPeerEndpoint(self: *Self, remote_pk: noise.Key, addr: [*]const u8, addr_len: u32) !void {
            if (self.closed) return errors.Error.Closed;
            if (addr_len == 0) return errors.Error.NoEndpoint;
            self.ensureServiceMuxHooks();
            try self.host.registerPeer(remote_pk);
            _ = try self.ensurePeerRuntime(remote_pk);
            _ = try self.storeEndpoint(remote_pk, addr, addr_len, nowMs());
        }

        pub fn connectTo(
            self: *Self,
            ctx: Context,
            remote_pk: noise.Key,
            addr: [*]const u8,
            addr_len: u32,
        ) !*ConnType {
            try self.setPeerEndpoint(remote_pk, addr, addr_len);
            return try self.connect(ctx, remote_pk);
        }

        pub fn connect(self: *Self, ctx: Context, remote_pk: noise.Key) !*ConnType {
            if (self.closed) return errors.Error.Closed;
            self.ensureServiceMuxHooks();
            const endpoint = self.endpoints.get(remote_pk) orelse return errors.Error.NoEndpoint;

            const wire_n = try self.host.beginDial(remote_pk, self.wire_buf, nowMs());
            self.emitPeerEvent(remote_pk, .connecting);
            _ = try self.writePacket(self.wire_buf[0..wire_n], @ptrCast(&endpoint.addr), endpoint.len, remote_pk);
            if (self.host.peerState(remote_pk) == .failed) return errors.Error.HandshakeFailed;
            if (self.connection(remote_pk)) |conn_ptr| {
                if (conn_ptr.state() == .established) {
                    try self.flushPendingSends(remote_pk);
                    return conn_ptr;
                }
            }

            while (true) {
                if (contextCause(ctx)) |cause| return cause;
                const conn_ptr = self.connection(remote_pk) orelse return errors.Error.PeerNotFound;
                if (conn_ptr.state() == .established) {
                    try self.flushPendingSends(remote_pk);
                    return conn_ptr;
                }

                const wait_ms = self.nextDialWaitMs(ctx, conn_ptr) catch |err| switch (err) {
                    error.TimedOut => {
                        const retry_n = (self.host.pollDialRetry(remote_pk, self.wire_buf, nowMs()) catch |poll_err| {
                            if (poll_err == errors.Error.HandshakeTimeout) {
                                self.emitPeerEvent(remote_pk, .failed);
                            }
                            return poll_err;
                        }) orelse continue;
                        const retry_endpoint = self.endpoints.get(remote_pk) orelse return errors.Error.NoEndpoint;
                        _ = try self.writePacket(self.wire_buf[0..retry_n], @ptrCast(&retry_endpoint.addr), retry_endpoint.len, remote_pk);
                        continue;
                    },
                    else => return err,
                };

                _ = self.readAndHandle(ctx, wait_ms) catch |err| switch (err) {
                    error.TimedOut => {
                        const retry_n = (self.host.pollDialRetry(remote_pk, self.wire_buf, nowMs()) catch |poll_err| {
                            if (poll_err == errors.Error.HandshakeTimeout) {
                                self.emitPeerEvent(remote_pk, .failed);
                            }
                            return poll_err;
                        }) orelse continue;
                        const retry_endpoint = self.endpoints.get(remote_pk) orelse return errors.Error.NoEndpoint;
                        _ = try self.writePacket(self.wire_buf[0..retry_n], @ptrCast(&retry_endpoint.addr), retry_endpoint.len, remote_pk);
                        continue;
                    },
                    else => {
                        if (self.host.peerState(remote_pk) == .failed) return errors.Error.HandshakeFailed;
                        return err;
                    },
                };
            }
        }

        pub fn accept(self: *Self) !*ConnType {
            if (self.closed) return errors.Error.Closed;
            const remote_pk = self.ready.pop() orelse return errors.Error.AcceptQueueEmpty;
            errdefer self.ready.push(remote_pk) catch {};
            try self.flushPendingSends(remote_pk);
            return self.host.connection(remote_pk) orelse errors.Error.PeerNotFound;
        }

        pub fn acceptContext(self: *Self, ctx: Context) !*ConnType {
            if (self.closed) return errors.Error.Closed;
            while (true) {
                if (self.ready.pop()) |remote_pk| {
                    errdefer self.ready.push(remote_pk) catch {};
                    try self.flushPendingSends(remote_pk);
                    return self.host.connection(remote_pk) orelse errors.Error.PeerNotFound;
                }
                _ = try self.readAndHandle(ctx, null);
            }
        }

        pub fn pumpContext(self: *Self, ctx: Context) !HostFile.Route {
            return try self.readAndHandle(ctx, null);
        }

        pub fn tick(self: *Self) !void {
            if (self.closed) return errors.Error.Closed;
            try self.tickAt(nowMs());
        }

        pub fn writeDirect(self: *Self, remote_pk: noise.Key, protocol_byte: u8, payload: []const u8) !SendResult {
            if (self.closed) return errors.Error.Closed;
            try protocol.validate(protocol_byte);
            if (protocol.isStream(protocol_byte)) {
                return if (protocol_byte == protocol.rpc)
                    errors.Error.RPCMustUseStream
                else
                    errors.Error.HTTPMustUseStream;
            }
            if (self.endpoints.get(remote_pk) == null) return errors.Error.NoEndpoint;
            if (try self.canSendImmediately(remote_pk)) {
                try self.flushPendingSends(remote_pk);
                return .{ .sent = try self.sendDirectNow(remote_pk, protocol_byte, payload) };
            }
            try self.queuePendingSend(remote_pk, .direct, 0, protocol_byte, payload);
            return .queued;
        }

        pub fn writeStream(self: *Self, remote_pk: noise.Key, service: u64, protocol_byte: u8, payload: []const u8) !SendResult {
            if (self.closed) return errors.Error.Closed;
            if (!protocol.isStream(protocol_byte)) return errors.Error.UnsupportedProtocol;
            if (self.endpoints.get(remote_pk) == null) return errors.Error.NoEndpoint;
            if (try self.canSendImmediately(remote_pk)) {
                try self.flushPendingSends(remote_pk);
                return .{ .sent = try self.sendStreamNow(remote_pk, service, protocol_byte, payload) };
            }
            try self.queuePendingSend(remote_pk, .stream, service, protocol_byte, payload);
            return .queued;
        }

        pub fn read(self: *Self, remote_pk: noise.Key, out: []u8) !HostType.ReadResult {
            if (self.closed) return errors.Error.Closed;
            return self.host.read(remote_pk, out);
        }

        pub fn readServiceProtocol(
            self: *Self,
            remote_pk: noise.Key,
            service: u64,
            protocol_byte: u8,
            out: []u8,
        ) !usize {
            if (self.closed) return errors.Error.Closed;
            return self.host.readServiceProtocol(remote_pk, service, protocol_byte, out);
        }

        pub fn sendStreamData(
            self: *Self,
            remote_pk: noise.Key,
            service: u64,
            stream_id: u64,
            payload: []const u8,
        ) !usize {
            if (self.closed) return errors.Error.Closed;
            return try self.host.sendMuxStream(remote_pk, service, stream_id, payload, nowMs());
        }

        pub fn recvStreamData(
            self: *Self,
            remote_pk: noise.Key,
            service: u64,
            stream_id: u64,
            out: []u8,
        ) !usize {
            if (self.closed) return errors.Error.Closed;
            return try self.host.recvMuxStream(remote_pk, service, stream_id, out);
        }

        pub fn closeStream(
            self: *Self,
            remote_pk: noise.Key,
            service: u64,
            stream_id: u64,
        ) !void {
            if (self.closed) return errors.Error.Closed;
            try self.host.closeMuxStream(remote_pk, service, stream_id, nowMs());
        }

        pub fn hostInfo(self: *const Self) HostInfo {
            return .{
                .peer_count = self.host.peerCount(),
                .rx_bytes = self.rx_bytes,
                .tx_bytes = self.tx_bytes,
                .endpoint_updates = self.endpoint_update_count,
                .last_seen_ms = self.last_seen_ms,
                .last_endpoint_update_ms = self.last_endpoint_update_ms,
            };
        }

        pub fn peerInfo(self: *const Self, remote_pk: noise.Key) ?PeerInfo {
            const state = self.host.peerState(remote_pk) orelse return null;
            const runtime = self.peer_runtime.get(remote_pk) orelse PeerRuntime{};
            const endpoint = self.endpoints.get(remote_pk);
            return .{
                .peer = remote_pk,
                .state = state,
                .has_endpoint = endpoint != null,
                .endpoint = if (endpoint) |value|
                    .{
                        .addr = value.addr,
                        .len = value.len,
                    }
                else
                    .{},
                .rx_bytes = runtime.rx_bytes,
                .tx_bytes = runtime.tx_bytes,
                .last_seen_ms = runtime.last_seen_ms,
                .last_endpoint_update_ms = if (endpoint) |value| value.updated_ms else 0,
            };
        }

        fn readAndHandle(self: *Self, ctx: Context, timeout_hint_ms: ?u32) !HostFile.Route {
            if (self.closed) return errors.Error.Closed;
            if (contextCause(ctx)) |cause| return cause;

            const timeout_ms = try effectiveReadTimeoutMs(ctx, timeout_hint_ms);
            self.packet_conn.setReadTimeout(timeout_ms);
            defer self.packet_conn.setReadTimeout(null);

            const recv = self.packet_conn.readFrom(self.read_buf) catch |err| switch (err) {
                error.Closed => {
                    self.closed = true;
                    return errors.Error.Closed;
                },
                error.TimedOut => {
                    if (contextCause(ctx)) |cause| return cause;
                    return error.TimedOut;
                },
                else => return err,
            };

            return try self.handleDatagram(
                self.read_buf[0..recv.bytes_read],
                @ptrCast(&recv.addr),
                recv.addr_len,
                nowMs(),
            );
        }

        fn handleDatagram(
            self: *Self,
            data: []const u8,
            from_addr: [*]const u8,
            from_addr_len: u32,
            now_ms: u64,
        ) !HostFile.Route {
            self.ensureServiceMuxHooks();
            self.rx_bytes += data.len;
            const result = self.host.handlePacketResult(data, self.plaintext_buf, self.wire_buf, now_ms);
            if (result.authenticated_peer) |remote_pk| {
                try self.noteAuthenticatedPeer(remote_pk, data.len, now_ms);
                _ = try self.storeEndpoint(remote_pk, from_addr, from_addr_len, now_ms);
            }
            if (result.peer_state_transition) |transition| {
                self.emitPeerEvent(transition.peer, transition.state);
            }

            switch (result.route) {
                .none => {},
                .response => |response| {
                    try self.ready.push(response.peer);
                    _ = try self.writePacket(self.wire_buf[0..response.n], from_addr, from_addr_len, response.peer);
                },
                .direct => {},
            }
            if (result.err) |err| return err;
            return result.route;
        }

        fn storeEndpoint(self: *Self, remote_pk: noise.Key, addr: [*]const u8, addr_len: u32, now_ms: u64) !bool {
            if (addr_len == 0) return false;
            const runtime = try self.ensurePeerRuntime(remote_pk);
            _ = runtime;
            if (self.endpoints.getPtr(remote_pk)) |existing| {
                if (existing.len == addr_len and dep.embed.mem.eql(u8, existing.addr[0..addr_len], addr[0..addr_len])) {
                    return false;
                }
            }
            var endpoint = Endpoint{
                .len = addr_len,
                .updated_ms = now_ms,
            };
            @memcpy(endpoint.addr[0..addr_len], addr[0..addr_len]);
            _ = try self.endpoints.put(remote_pk, endpoint);
            self.endpoint_update_count += 1;
            self.last_endpoint_update_ms = now_ms;
            return true;
        }

        fn canSendImmediately(self: *Self, remote_pk: noise.Key) !bool {
            const conn_ptr = self.connection(remote_pk) orelse return false;
            return conn_ptr.state() == .established;
        }

        fn queuePendingSend(
            self: *Self,
            remote_pk: noise.Key,
            kind: PendingKind,
            service: u64,
            protocol_byte: u8,
            payload: []const u8,
        ) !void {
            _ = self.endpoints.get(remote_pk) orelse return errors.Error.NoEndpoint;
            const queue = try self.getOrCreatePendingQueue(remote_pk);
            try queue.pushCopy(kind, service, protocol_byte, payload);
        }

        fn flushPendingSends(self: *Self, remote_pk: noise.Key) !void {
            const endpoint = self.endpoints.get(remote_pk) orelse return;
            const queue = self.pending_sends.getPtr(remote_pk) orelse return;
            while (queue.peek()) |pending| {
                const wire_n = switch (pending.kind) {
                    .direct => try self.host.sendDirect(
                        remote_pk,
                        pending.protocol_byte,
                        pending.payload,
                        self.plaintext_buf,
                        self.ciphertext_buf,
                        self.wire_buf,
                        nowMs(),
                    ),
                    .stream => try self.host.sendStream(
                        remote_pk,
                        pending.service,
                        pending.protocol_byte,
                        pending.payload,
                        self.plaintext_buf,
                        self.ciphertext_buf,
                        self.wire_buf,
                        nowMs(),
                    ),
                };
                _ = try self.writePacket(self.wire_buf[0..wire_n], @ptrCast(&endpoint.addr), endpoint.len, remote_pk);
                const flushed = queue.pop().?;
                self.allocator.free(flushed.payload);
            }
            if (queue.len == 0) {
                var emptied = self.pending_sends.remove(remote_pk).?;
                emptied.deinit();
            }
        }

        fn getOrCreatePendingQueue(self: *Self, remote_pk: noise.Key) !*PendingSendQueue {
            if (self.pending_sends.getPtr(remote_pk)) |queue| return queue;
            var queue = try PendingSendQueue.init(self.allocator, self.pending_send_queue_size);
            errdefer queue.deinit();
            _ = try self.pending_sends.put(remote_pk, queue);
            return self.pending_sends.getPtr(remote_pk).?;
        }

        fn clearPendingSendQueues(self: *Self) void {
            for (self.pending_sends.slots) |*slot| {
                if (slot.state != .full) continue;
                slot.value.deinit();
            }
        }

        fn sendDirectNow(self: *Self, remote_pk: noise.Key, protocol_byte: u8, payload: []const u8) !usize {
            const endpoint = self.endpoints.get(remote_pk) orelse return errors.Error.NoEndpoint;
            const wire_n = try self.host.sendDirect(
                remote_pk,
                protocol_byte,
                payload,
                self.plaintext_buf,
                self.ciphertext_buf,
                self.wire_buf,
                nowMs(),
            );
            _ = try self.writePacket(self.wire_buf[0..wire_n], @ptrCast(&endpoint.addr), endpoint.len, remote_pk);
            return wire_n;
        }

        fn sendStreamNow(self: *Self, remote_pk: noise.Key, service: u64, protocol_byte: u8, payload: []const u8) !usize {
            const endpoint = self.endpoints.get(remote_pk) orelse return errors.Error.NoEndpoint;
            const wire_n = try self.host.sendStream(
                remote_pk,
                service,
                protocol_byte,
                payload,
                self.plaintext_buf,
                self.ciphertext_buf,
                self.wire_buf,
                nowMs(),
            );
            _ = try self.writePacket(self.wire_buf[0..wire_n], @ptrCast(&endpoint.addr), endpoint.len, remote_pk);
            return wire_n;
        }

        fn pendingSendLen(self: *const Self, remote_pk: noise.Key) usize {
            const queue = self.pending_sends.getPtrConst(remote_pk) orelse return 0;
            return queue.len;
        }

        pub fn testPendingSendLen(self: *const Self, remote_pk: noise.Key) usize {
            return self.pendingSendLen(remote_pk);
        }

        pub fn testTickAt(self: *Self, now_ms: u64) !void {
            return self.tickAt(now_ms);
        }

        fn tickAt(self: *Self, now_ms: u64) !void {
            self.ensureServiceMuxHooks();
            try self.host.tick(now_ms);
        }

        pub fn testHandleDatagram(
            self: *Self,
            data: []const u8,
            from_addr: [*]const u8,
            from_addr_len: u32,
            now_ms: u64,
        ) !HostFile.Route {
            return self.handleDatagram(data, from_addr, from_addr_len, now_ms);
        }

        pub fn testEmitPeerEvent(self: *Self, remote_pk: noise.Key, state: HostFile.PeerState) void {
            self.emitPeerEvent(remote_pk, state);
        }

        fn nextDialWaitMs(self: *const Self, ctx: Context, conn_ptr: *const ConnType) !?u32 {
            _ = self;
            if (contextCause(ctx)) |cause| return cause;
            const sent_ms = conn_ptr.last_handshake_sent_ms;
            if (sent_ms == 0) return errors.Error.HandshakeIncomplete;

            const now_ms = nowMs();
            const elapsed_ms = now_ms -| sent_ms;
            if (elapsed_ms >= consts.rekey_timeout_ms) return error.TimedOut;
            return try effectiveReadTimeoutMs(ctx, @intCast(consts.rekey_timeout_ms - elapsed_ms));
        }

        fn effectiveReadTimeoutMs(ctx: Context, timeout_hint_ms: ?u32) !?u32 {
            if (contextCause(ctx)) |cause| return cause;

            var remaining_ms: ?u64 = if (timeout_hint_ms) |ms| ms else null;
            if (ctx.deadline()) |deadline_ns| {
                const now_ns = lib.time.nanoTimestamp();
                if (deadline_ns <= now_ns) return Context.DeadlineExceeded;

                const remaining_ns = deadline_ns - now_ns;
                var ctx_remaining_ms: u64 = @intCast(@divFloor(remaining_ns, lib.time.ns_per_ms));
                if (ctx_remaining_ms == 0) ctx_remaining_ms = 1;
                remaining_ms = if (remaining_ms) |value|
                    @min(value, ctx_remaining_ms)
                else
                    ctx_remaining_ms;
            }

            if (remaining_ms) |value| {
                if (value == 0) return error.TimedOut;
                return @intCast(@min(value, @as(u64, @intCast(dep.embed.math.maxInt(u32)))));
            }
            return null;
        }

        fn nowMs() u64 {
            return @intCast(lib.time.milliTimestamp());
        }

        fn ensurePeerRuntime(self: *Self, remote_pk: noise.Key) !*PeerRuntime {
            if (self.peer_runtime.getPtr(remote_pk)) |runtime| return runtime;
            _ = try self.peer_runtime.put(remote_pk, .{});
            return self.peer_runtime.getPtr(remote_pk).?;
        }

        fn ensureServiceMuxHooks(self: *Self) void {
            self.host.service_config.output = serviceMuxOutputHook(Self, self);
        }

        fn noteAuthenticatedPeer(self: *Self, remote_pk: noise.Key, bytes: usize, now_ms: u64) !void {
            const runtime = try self.ensurePeerRuntime(remote_pk);
            runtime.rx_bytes += bytes;
            runtime.last_seen_ms = now_ms;
            self.last_seen_ms = now_ms;
        }

        fn emitPeerEvent(self: *Self, remote_pk: noise.Key, state: HostFile.PeerState) void {
            if (self.on_peer_event) |hook| {
                hook.emit(hook.ctx, .{
                    .peer = remote_pk,
                    .state = state,
                });
            }
        }

        fn writePacket(
            self: *Self,
            data: []const u8,
            addr: [*]const u8,
            addr_len: u32,
            remote_pk: noise.Key,
        ) !usize {
            const written = self.packet_conn.writeTo(data, addr, addr_len) catch |err| switch (err) {
                error.Closed => {
                    self.closed = true;
                    return errors.Error.Closed;
                },
                else => return err,
            };
            self.tx_bytes += written;
            const runtime = try self.ensurePeerRuntime(remote_pk);
            runtime.tx_bytes += written;
            return written;
        }

        fn contextCause(ctx: Context) ?anyerror {
            if (ctx.err()) |cause| return cause;
            if (ctx.deadline()) |deadline_ns| {
                if (deadline_ns <= lib.time.nanoTimestamp()) return Context.DeadlineExceeded;
            }
            return null;
        }
    };
}

fn serviceMuxOutputHook(comptime UdpType: type, udp: *UdpType) ServiceMuxFile.Output {
    return .{
        .ctx = udp,
        .write = serviceMuxOutputWrite(UdpType),
    };
}

fn serviceMuxOutputWrite(
    comptime UdpType: type,
) *const fn (
    ctx: *anyopaque,
    peer: noise.Key,
    service: u64,
    protocol_byte: u8,
    data: []const u8,
) anyerror!void {
    return struct {
        fn write(ctx: *anyopaque, peer: noise.Key, service: u64, protocol_byte: u8, data: []const u8) !void {
            const udp: *UdpType = @ptrCast(@alignCast(ctx));
            if (protocol.isStream(protocol_byte)) {
                _ = try udp.sendStreamNow(peer, service, protocol_byte, data);
                return;
            }
            _ = try udp.sendDirectNow(peer, protocol_byte, data);
        }
    }.write;
}
