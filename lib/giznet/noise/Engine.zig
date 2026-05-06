const glib = @import("glib");
const AddrPort = glib.net.netip.AddrPort;

const Cipher = @import("Cipher.zig");
const HandshakeType = @import("Handshake.zig");
const Key = @import("Key.zig");
const KeyPair = @import("KeyPair.zig");
const Message = @import("Message.zig");
const packet = @import("../packet.zig");
const PeerType = @import("Peer.zig");
const PeerTableType = @import("PeerTable.zig");
const SessionType = @import("Session.zig");

const Engine = @This();

pub const default_rekey_after_time: glib.time.duration.Duration = 120 * glib.time.duration.Second;
pub const default_reject_after_time: glib.time.duration.Duration = 180 * glib.time.duration.Second;
pub const default_rekey_timeout: glib.time.duration.Duration = 5 * glib.time.duration.Second;
pub const default_keepalive_timeout: glib.time.duration.Duration = 10 * glib.time.duration.Second;
pub const default_handshake_attempt: glib.time.duration.Duration = 90 * glib.time.duration.Second;
pub const default_offline_timeout: glib.time.duration.Duration = 180 * glib.time.duration.Second;
pub const default_session_cleanup: glib.time.duration.Duration = 180 * glib.time.duration.Second;
pub const default_rekey_after_messages: u64 = 1 << 20;
pub const default_reject_after_messages: u64 = (1 << 20) + (1 << 12);

pub const Config = struct {
    max_peers: usize = 8,
    max_pending: usize = 8,
    rekey_after_time: glib.time.duration.Duration = default_rekey_after_time,
    reject_after_time: glib.time.duration.Duration = default_reject_after_time,
    rekey_timeout: glib.time.duration.Duration = default_rekey_timeout,
    keepalive_timeout: glib.time.duration.Duration = default_keepalive_timeout,
    handshake_attempt: glib.time.duration.Duration = default_handshake_attempt,
    offline_timeout: glib.time.duration.Duration = default_offline_timeout,
    session_cleanup: glib.time.duration.Duration = default_session_cleanup,
    rekey_after_messages: u64 = default_rekey_after_messages,
    reject_after_messages: u64 = default_reject_after_messages,
};

pub const DriveOutput = union(enum) {
    outbound: *packet.Outbound,
    inbound: *packet.Inbound,
    established: Key,
    offline: Key,
    next_tick_deadline: glib.time.instant.Time,
};

pub const InitiateHandshake = struct {
    remote_key: Key,
    remote_endpoint: AddrPort,
    keepalive_interval: ?glib.time.duration.Duration = null,
};

pub const DriveInput = union(enum) {
    inbound_packet: *packet.Inbound,
    send_data: *packet.Outbound,
    initiate_handshake: InitiateHandshake,
    tick: void,
};

pub const Stats = struct {
    peer_count: usize = 0,
    pending_handshake_count: usize = 0,
    session_count: usize = 0,
    latest_handshake: ?glib.time.instant.Time = null,
    transfer_rx: u64 = 0,
    transfer_tx: u64 = 0,
};

pub const Callback = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, result: DriveOutput) anyerror!void,

    pub fn handle(self: Callback, result: DriveOutput) !void {
        try self.call(self.ctx, result);
    }
};

pub fn make(
    comptime grt: type,
    comptime packet_size_capacity: usize,
    comptime cipher_kind: Cipher.Kind,
) type {
    const Order = grt.std.math.Order;
    const Handshake = HandshakeType.make(grt, cipher_kind);
    const Peer = PeerType.make(grt, cipher_kind);
    const PeerTable = PeerTableType.make(grt, cipher_kind);
    const Session = SessionType.make(grt, packet_size_capacity, cipher_kind);
    const TimerTreapKey = struct {
        due: glib.time.instant.Time,
        peer_key: Key,
    };
    const TimerTreap = grt.std.Treap(TimerTreapKey, struct {
        fn compare(a: TimerTreapKey, b: TimerTreapKey) Order {
            if (a.due < b.due) return .lt;
            if (a.due > b.due) return .gt;

            var index: usize = 0;
            while (index < a.peer_key.bytes.len) : (index += 1) {
                if (a.peer_key.bytes[index] < b.peer_key.bytes[index]) return .lt;
                if (a.peer_key.bytes[index] > b.peer_key.bytes[index]) return .gt;
            }
            return .eq;
        }
    }.compare);

    return struct {
        allocator: grt.std.mem.Allocator,
        local_static: KeyPair,
        config: Engine.Config,
        peers: PeerTable,
        inbound_pool: packet.Inbound.Pool,
        outbound_pool: packet.Outbound.Pool,
        next_session_index: u32 = 1,
        timer_treap: TimerTreap = .{},
        timer_slots: []TimerSlot = &.{},
        stats: Engine.Stats = .{},

        const Self = @This();
        const TimerSlot = struct {
            peer_key: Key = .{},
            bound: bool = false,
            inserted: bool = false,
            node: TimerTreap.Node = undefined,
        };

        pub fn init(
            allocator: grt.std.mem.Allocator,
            local_static: KeyPair,
            config: Engine.Config,
            packet_pools: packet.Pools,
        ) !Self {
            const normalized_config = Engine.normalizeConfig(config);
            var timer_slots: []TimerSlot = &[_]TimerSlot{};
            if (normalized_config.max_peers != 0) {
                timer_slots = try allocator.alloc(TimerSlot, normalized_config.max_peers);
            }
            errdefer if (timer_slots.len != 0) allocator.free(timer_slots);
            for (timer_slots) |*slot| slot.* = .{};

            return .{
                .allocator = allocator,
                .local_static = local_static,
                .config = normalized_config,
                .peers = PeerTable.init(allocator, normalized_config.max_peers, .{
                    .keepalive_timeout = normalized_config.keepalive_timeout,
                    .rekey_after_time = normalized_config.rekey_after_time,
                    .rekey_timeout = normalized_config.rekey_timeout,
                    .handshake_attempt = normalized_config.handshake_attempt,
                    .offline_timeout = normalized_config.offline_timeout,
                    .session_cleanup = normalized_config.session_cleanup,
                    .rekey_after_messages = normalized_config.rekey_after_messages,
                }),
                .inbound_pool = packet_pools.inbound,
                .outbound_pool = packet_pools.outbound,
                .timer_slots = timer_slots,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.timer_slots.len != 0) self.allocator.free(self.timer_slots);
            self.timer_slots = &.{};
            self.peers.deinit();
        }

        /// Single engine drive entrypoint.
        ///
        /// Contract shape:
        /// - must be called on the engine thread
        /// - accepts one explicit drive input
        /// - successful drive calls run `tick()` afterwards
        /// - failed drive actions return early and do not advance timers
        /// - `.inbound_packet` is implemented
        /// - `.send_data` emits a prepared outbound transport pkt and
        ///   leaves encryption to the caller
        /// - `.initiate_handshake` emits a ready-to-send handshake pkt
        /// - `.tick` is a no-op input that exists only to drive the shared
        ///   timer tail
        pub fn drive(
            self: *Self,
            input: Engine.DriveInput,
            on_result: Engine.Callback,
        ) !void {
            defer {
                self.stats.peer_count = self.peers.count();
                self.stats.pending_handshake_count = self.peers.pendingCount();
                self.stats.session_count = self.peers.sessionCount();
            }

            try switch (input) {
                .inbound_packet => |pkt| inbound: {
                    if (pkt.state == .initial) {
                        self.stats.transfer_rx +%= @as(u64, @intCast(pkt.len));
                    }

                    break :inbound switch (pkt.state) {
                        .initial => self.triageInbound(pkt, on_result),
                        .ready_to_consume => self.consumeInbound(pkt, on_result),

                        .prepared => error.InboundPacketRequiresDecrypt,
                        .consumed => error.InboundPacketConsumed,
                        .service_delivered => error.InboundPacketConsumed,
                        .decrypt_failed => error.InboundPacketDecryptFailed,
                        .consume_failed => error.InboundPacketConsumeFailed,
                    };
                },
                .send_data => |request| self.createDataOutbound(request, on_result),
                .initiate_handshake => |request| self.createInitiateHandshakeOutbound(request, on_result),
                .tick => {},
            };

            try self.tick(on_result);
        }

        /// Drive timer-based engine progress using the current time.
        ///
        /// Shape only for now:
        /// - must be called on the engine thread
        /// - may emit outbound packets, establishment notifications, and the
        ///   next required tick timestamp
        pub fn tick(
            self: *Self,
            on_result: Engine.Callback,
        ) !void {
            const now_time = Self.instantNow();

            while (self.timer_treap.getMin()) |node| {
                if (node.key.due > now_time) break;
                try self.tickNode(node, now_time, on_result);
            }

            if (self.timer_treap.getMin()) |node| {
                try self.emitEvent(on_result, .{ .next_tick_deadline = node.key.due });
            }
        }

        fn triageInbound(
            self: *Self,
            pkt: *packet.Inbound,
            on_result: Engine.Callback,
        ) !void {
            const kind = try inferInboundKind(pkt);

            return switch (kind) {
                .handshake => self.consumeInbound(pkt, on_result),
                .transport => self.prepareTransport(pkt, on_result),
                .unknown => error.InvalidInboundPacketKind,
            };
        }

        fn prepareTransport(
            self: *Self,
            pkt: *packet.Inbound,
            on_result: Engine.Callback,
        ) !void {
            const transport = Message.parseTransportMessage(pkt.bytes()) catch return error.InvalidTransportPacket;
            const peer = self.peers.findBySessionIndex(transport.receiver_index) orelse return error.SessionNotFound;
            const session = peer.sessionByLocalIndex(transport.receiver_index) orelse return error.SessionNotFound;

            pkt.state = .prepared;
            pkt.remote_static = peer.key;
            pkt.session_key = session.recvKey();
            pkt.local_session_index = session.localIndex();
            pkt.remote_session_index = session.remoteIndex();
            pkt.counter = transport.counter;

            try self.emitEvent(on_result, .{ .inbound = pkt });
        }

        fn consumeInbound(
            self: *Self,
            pkt: *packet.Inbound,
            on_result: Engine.Callback,
        ) !void {
            errdefer pkt.state = .consume_failed;

            return switch (pkt.kind) {
                .handshake => self.consumeHandshake(pkt, on_result),
                .transport => self.consumeTransport(pkt, on_result),
                .unknown => error.InvalidInboundPacketKind,
            };
        }

        fn consumeHandshake(
            self: *Self,
            pkt: *packet.Inbound,
            on_result: Engine.Callback,
        ) !void {
            return switch (try Handshake.parseMessageType(pkt.bytes())) {
                .init => {
                    const outbound = try self.consumeInit(pkt, on_result);
                    errdefer outbound.deinit();
                    try self.emitEvent(on_result, .{ .outbound = outbound });
                    pkt.deinit();
                },
                .response => try self.consumeResponse(pkt, on_result),
            };
        }

        fn consumeInit(
            self: *Self,
            pkt: *packet.Inbound,
            on_result: Engine.Callback,
        ) !*packet.Outbound {
            const outbound_packet = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer outbound_packet.deinit();

            var handshake = Handshake.readInit(self.local_static, pkt.bytes()) catch return error.InvalidHandshakeMessage;
            const peer_key = handshake.peerKey();
            const peer = try self.peers.getOrCreate(peer_key);

            const responder_session_index = try self.allocateSessionIndex();
            const written = try handshake.writeResponse(responder_session_index, outbound_packet.bufRef());
            const material = try handshake.sessionMaterial();
            const now_time = Self.instantNow();
            const endpoint = pkt.remote_endpoint;
            const session = Session.init(.{
                .local_index = responder_session_index,
                .remote_index = handshake.remoteSessionIndex(),
                .peer_key = peer_key,
                .endpoint = endpoint,
                .send_key = material.server_to_client,
                .recv_key = material.client_to_server,
                .timeout = self.config.reject_after_time,
                .now = now_time,
            });

            self.stats.latest_handshake = now_time;
            peer.establish(self.local_static.public, endpoint, session, false, now_time);
            peer.updateTimers(now_time, 0);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            try self.emitEvent(on_result, .{ .established = peer_key });

            outbound_packet.len = written;
            outbound_packet.kind = .handshake;
            outbound_packet.remote_endpoint = endpoint;
            outbound_packet.remote_static = peer_key;
            outbound_packet.state = .ready_to_send;

            pkt.state = .consumed;
            return outbound_packet;
        }

        fn consumeResponse(
            self: *Self,
            pkt: *packet.Inbound,
            on_result: Engine.Callback,
        ) !void {
            const response = try Handshake.parseResponse(pkt.bytes());
            const peer = self.peers.findPendingHandshakeByLocalSessionIndex(response.initiator_session_index) orelse return error.HandshakeNotFound;
            const pending_handshake = if (peer.pending_handshake) |*pending_handshake| pending_handshake else return error.HandshakeNotFound;

            var handshake = pending_handshake.handshake;
            try handshake.readResponse(pkt.bytes());
            const material = try handshake.sessionMaterial();

            const now_time = Self.instantNow();
            const endpoint = pkt.remote_endpoint;
            const session = Session.init(.{
                .local_index = handshake.localSessionIndex(),
                .remote_index = handshake.remoteSessionIndex(),
                .peer_key = peer.key,
                .endpoint = endpoint,
                .send_key = material.client_to_server,
                .recv_key = material.server_to_client,
                .timeout = self.config.reject_after_time,
                .now = now_time,
            });

            self.stats.latest_handshake = now_time;
            peer.establish(self.local_static.public, endpoint, session, true, now_time);
            peer.updateTimers(now_time, 0);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            try self.emitEvent(on_result, .{ .established = peer.key });

            pkt.state = .consumed;
            pkt.deinit();
        }

        fn consumeTransport(
            self: *Self,
            pkt: *packet.Inbound,
            on_result: Engine.Callback,
        ) !void {
            if (pkt.state != .ready_to_consume) return error.InboundPacketRequiresDecrypt;

            const peer = self.peers.findBySessionIndex(pkt.local_session_index) orelse return error.SessionNotFound;
            if (!peer.key.eql(pkt.remote_static)) return error.PeerMismatch;

            const session = peer.sessionByLocalIndex(pkt.local_session_index) orelse return error.SessionNotFound;
            if (session.remoteIndex() != pkt.remote_session_index) return error.SessionIndexMismatch;

            const now_time = Self.instantNow();
            try session.commitRecv(pkt.counter, now_time);
            peer.endpoint = pkt.remote_endpoint;
            peer.last_received = now_time;
            peer.markOnline(now_time);
            if (peer.current) |*current| current.setEndpoint(peer.endpoint);
            if (peer.previous) |*previous| previous.setEndpoint(peer.endpoint);
            peer.updateTimers(now_time, 1);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");

            pkt.state = .consumed;
            if (pkt.len != 0) {
                try self.emitEvent(on_result, .{ .inbound = pkt });
            } else {
                pkt.deinit();
            }
        }

        fn inferInboundKind(pkt: *packet.Inbound) !packet.Inbound.Kind {
            const kind: packet.Inbound.Kind = switch (try Message.getMessageType(pkt.bytes())) {
                Message.MessageTypeHandshakeInit,
                Message.MessageTypeHandshakeResp,
                => .handshake,
                Message.MessageTypeTransport => .transport,
                else => return error.InvalidInboundPacketKind,
            };

            pkt.kind = kind;
            return kind;
        }

        fn allocateSessionIndex(self: *Self) !u32 {
            const current = self.next_session_index;
            if (current == 0) return error.SessionIndexExhausted;
            self.next_session_index +%= 1;
            if (self.next_session_index == 0) self.next_session_index = 1;
            return current;
        }

        fn createDataOutbound(
            self: *Self,
            pkt: *packet.Outbound,
            on_result: Engine.Callback,
        ) !void {
            pkt.state = .prepared;
            pkt.kind = .transport;
            if (pkt.transportPlaintextBufRef().len < pkt.len) return error.BufferTooSmall;

            const peer = self.peers.get(pkt.remote_static) orelse return error.SessionNotFound;
            const session = if (peer.current) |*session| session else return error.SessionNotFound;
            const sent = Self.instantNow();
            const counter = try session.claimSendCounter(sent);

            pkt.remote_endpoint = session.endpointValue();
            pkt.remote_static = peer.key;
            pkt.session_key = session.sendKey();
            pkt.remote_session_index = session.remoteIndex();
            pkt.counter = counter;

            peer.last_sent = sent;
            peer.updateTimers(sent, 1);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            try self.emitEvent(on_result, .{ .outbound = pkt });
        }

        fn createInitiateHandshakeOutbound(
            self: *Self,
            request: Engine.InitiateHandshake,
            on_result: Engine.Callback,
        ) !void {
            const peer = try self.peers.getOrCreate(request.remote_key);
            if (peer.pending_handshake != null) return error.HandshakeInProgress;
            if (self.peers.pendingCount() >= self.config.max_pending) return error.PendingHandshakeLimitReached;

            const pkt = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();
            try self.startPendingHandshake(peer, request.remote_endpoint, request.keepalive_interval, Self.instantNow(), pkt);
            try self.emitEvent(on_result, .{ .outbound = pkt });
        }

        fn tickNode(
            self: *Self,
            node: *TimerTreap.Node,
            now: glib.time.instant.Time,
            on_result: Engine.Callback,
        ) !void {
            const peer_key = node.key.peer_key;
            var entry = self.timer_treap.getEntryForExisting(node);
            entry.set(null);
            if (self.findTimerSlot(peer_key)) |slot| slot.inserted = false;
            const peer = self.peers.get(peer_key) orelse return;
            var send_keepalive = false;
            var begin_rekey = false;
            var retry_handshake: ?u32 = null;
            var expire_handshake: ?u32 = null;
            var mark_offline = false;

            if (peer.current) |*current| {
                if (current.sendNonce() >= self.config.reject_after_messages or current.recvMaxNonce() >= self.config.reject_after_messages) {
                    current.markExpired();
                }
            }
            if (peer.previous) |*previous| {
                if (previous.sendNonce() >= self.config.reject_after_messages or previous.recvMaxNonce() >= self.config.reject_after_messages) {
                    previous.markExpired();
                }
            }

            peer.updateTimers(now, 0);
            while (peer.timers.nextDue(now)) |kind| {
                switch (kind) {
                    .keepalive_deadline => {
                        peer.timers.set(.keepalive_deadline, null);
                        send_keepalive = true;
                    },
                    .persistent_keepalive_deadline => {
                        peer.timers.set(.persistent_keepalive_deadline, null);
                        send_keepalive = true;
                    },
                    .rekey_deadline => {
                        peer.timers.set(.rekey_deadline, null);
                        if (peer.pending_handshake == null and peer.current != null and peer.is_initiator) {
                            peer.rekey_triggered = true;
                            peer.rekey_requested = false;
                            begin_rekey = true;
                        }
                    },
                    .handshake_retry_deadline => {
                        peer.timers.set(.handshake_retry_deadline, null);
                        if (peer.pending_handshake) |pending_handshake| {
                            retry_handshake = pending_handshake.local_session_index;
                        }
                    },
                    .handshake_deadline => {
                        peer.timers.set(.handshake_deadline, null);
                        if (peer.pending_handshake) |pending_handshake| {
                            expire_handshake = pending_handshake.local_session_index;
                        }
                    },
                    .offline_deadline => {
                        peer.timers.set(.offline_deadline, null);
                        mark_offline = true;
                    },
                    .cleanup_deadline => {
                        peer.timers.set(.cleanup_deadline, null);
                        peer.previous = null;
                    },
                }
            }

            if (mark_offline) {
                peer.markOffline();
                peer.updateTimers(now, 0);
                try self.emitEvent(on_result, .{ .offline = peer.key });
            } else {
                if (send_keepalive) {
                    try self.emitKeepalive(peer.key, on_result);
                }
                if (begin_rekey) {
                    try self.emitBeginRekey(peer.key, on_result);
                }
                if (retry_handshake) |local_session_index| {
                    try self.emitRetryHandshake(local_session_index, on_result);
                }
                if (expire_handshake) |local_session_index| {
                    self.expirePendingHandshake(local_session_index);
                }
            }

            if (!self.removeIdlePeer(peer.key)) {
                self.syncPeerTimerEntry(peer) catch @panic("OOM");
            }
        }

        fn emitKeepalive(self: *Self, peer_key: Key, on_result: Engine.Callback) !void {
            const pkt = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();
            const peer = self.peers.get(peer_key) orelse return error.SessionNotFound;
            const session = if (peer.current) |*session| session else return error.SessionNotFound;
            const sent = Self.instantNow();
            const counter = try session.claimSendCounter(sent);
            pkt.len = 0;
            pkt.state = .prepared;
            pkt.kind = .transport;
            pkt.remote_endpoint = session.endpointValue();
            pkt.remote_static = peer.key;
            pkt.session_key = session.sendKey();
            pkt.remote_session_index = session.remoteIndex();
            pkt.counter = counter;
            peer.last_sent = sent;
            peer.updateTimers(sent, 1);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            try self.emitEvent(on_result, .{ .outbound = pkt });
        }

        fn startPendingHandshake(
            self: *Self,
            peer: *Peer,
            endpoint: AddrPort,
            keepalive_interval: ?glib.time.duration.Duration,
            now: glib.time.instant.Time,
            pkt: *packet.Outbound,
        ) !void {
            const local_session_index = try self.allocateSessionIndex();
            var handshake = try Handshake.initInitiator(self.local_static, peer.key, local_session_index);
            const written = try handshake.writeInit(pkt.bufRef());

            peer.startPendingHandshake(self.local_static.public, endpoint, local_session_index, handshake, keepalive_interval, now);
            peer.updateTimers(now, 0);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            pkt.len = written;
            pkt.kind = .handshake;
            pkt.remote_endpoint = endpoint;
            pkt.remote_static = peer.key;
            pkt.state = .ready_to_send;
        }

        fn emitBeginRekey(self: *Self, peer_key: Key, on_result: Engine.Callback) !void {
            const peer = self.peers.get(peer_key) orelse return;
            if (peer.pending_handshake != null) return;

            const pkt = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();
            try self.startPendingHandshake(peer, peer.endpoint, peer.keepalive_interval, Self.instantNow(), pkt);
            try self.emitEvent(on_result, .{ .outbound = pkt });
        }

        fn emitRetryHandshake(self: *Self, local_session_index: u32, on_result: Engine.Callback) !void {
            const peer = self.peers.findPendingHandshakeByLocalSessionIndex(local_session_index) orelse return;
            const pending_handshake = if (peer.pending_handshake) |pending_handshake| pending_handshake else return;

            const pkt = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer pkt.deinit();
            peer.clearPendingHandshake();
            try self.startPendingHandshake(peer, pending_handshake.endpoint, peer.keepalive_interval, Self.instantNow(), pkt);
            try self.emitEvent(on_result, .{ .outbound = pkt });
        }

        fn expirePendingHandshake(self: *Self, local_session_index: u32) void {
            const peer = self.peers.findPendingHandshakeByLocalSessionIndex(local_session_index) orelse return;
            peer.clearPendingHandshake();
            peer.rekey_triggered = false;
            peer.rekey_requested = false;
            _ = self.removeIdlePeer(peer.key);
        }

        fn removeIdlePeer(self: *Self, peer_key: Key) bool {
            if (!self.peers.removeIdle(peer_key)) return false;
            _ = self.releaseTimerSlot(peer_key);
            return true;
        }

        fn releaseTimerSlot(self: *Self, peer_key: Key) bool {
            const slot = self.findTimerSlot(peer_key) orelse return false;
            _ = self.deactivateTimerSlot(peer_key);
            slot.* = .{};
            return true;
        }

        fn deactivateTimerSlot(self: *Self, peer_key: Key) bool {
            const slot = self.findTimerSlot(peer_key) orelse return false;
            if (!slot.inserted) return false;

            var entry = self.timer_treap.getEntryForExisting(&slot.node);
            entry.set(null);
            slot.inserted = false;
            return true;
        }

        fn syncPeerTimerEntry(self: *Self, peer: *Peer) !void {
            const slot = try self.getOrBindTimerSlot(peer.key);
            if (slot.inserted) {
                var existing = self.timer_treap.getEntryForExisting(&slot.node);
                existing.set(null);
                slot.inserted = false;
            }
            const due = peer.timers.earliest() orelse return;

            var entry = self.timer_treap.getEntryFor(.{
                .due = due,
                .peer_key = peer.key,
            });
            entry.set(&slot.node);
            slot.inserted = true;
        }

        fn findTimerSlot(self: *Self, peer_key: Key) ?*TimerSlot {
            for (self.timer_slots) |*slot| {
                if (slot.bound and slot.peer_key.eql(peer_key)) return slot;
            }
            return null;
        }

        fn getOrBindTimerSlot(self: *Self, peer_key: Key) !*TimerSlot {
            if (self.findTimerSlot(peer_key)) |slot| return slot;
            for (self.timer_slots) |*slot| {
                if (slot.bound) continue;
                slot.* = .{
                    .peer_key = peer_key,
                    .bound = true,
                };
                return slot;
            }
            return error.TimerSlotExhausted;
        }

        fn emitEvent(
            self: *Self,
            on_result: Engine.Callback,
            event: Engine.DriveOutput,
        ) !void {
            const outbound_transfer_len: ?u64 = switch (event) {
                .outbound => |pkt| if (pkt.kind == .handshake or pkt.state == .ready_to_send)
                    @as(u64, @intCast(pkt.len))
                else
                    null,
                else => null,
            };

            try on_result.handle(event);

            if (outbound_transfer_len) |len| self.stats.transfer_tx +%= len;
        }

        pub fn instantNow() glib.time.instant.Time {
            return grt.time.instant.now();
        }
    };
}

fn normalizeConfig(config: Config) Config {
    var normalized = config;
    normalized.rekey_after_time = nonNegativeDuration(normalized.rekey_after_time);
    normalized.reject_after_time = nonNegativeDuration(normalized.reject_after_time);
    normalized.rekey_timeout = nonNegativeDuration(normalized.rekey_timeout);
    normalized.keepalive_timeout = nonNegativeDuration(normalized.keepalive_timeout);
    normalized.handshake_attempt = nonNegativeDuration(normalized.handshake_attempt);
    normalized.offline_timeout = nonNegativeDuration(normalized.offline_timeout);
    normalized.session_cleanup = nonNegativeDuration(normalized.session_cleanup);
    return normalized;
}

fn nonNegativeDuration(duration: glib.time.duration.Duration) glib.time.duration.Duration {
    return @max(duration, 0);
}

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    const testing_api = glib.testing;
    const giznet = @import("../../giznet.zig");

    const Cases = struct {
        fn TestEngine(comptime EngineType: type, comptime packet_size: usize) type {
            return struct {
                inbound_pool: packet.Inbound.Pool,
                outbound_pool: packet.Outbound.Pool,
                engine: EngineType,

                const Self = @This();

                pub fn init(
                    allocator: glib.std.mem.Allocator,
                    local_static: KeyPair,
                    config: Engine.Config,
                ) !Self {
                    const inbound_pool = try packet.Inbound.initPool(grt, allocator, packet_size);
                    errdefer inbound_pool.deinit();

                    const outbound_pool = try packet.Outbound.initPool(grt, allocator, packet_size);
                    errdefer outbound_pool.deinit();

                    const engine = try EngineType.init(allocator, local_static, config, .{
                        .inbound = inbound_pool,
                        .outbound = outbound_pool,
                    });
                    errdefer engine.deinit();

                    return .{
                        .inbound_pool = inbound_pool,
                        .outbound_pool = outbound_pool,
                        .engine = engine,
                    };
                }

                pub fn deinit(self: *Self) void {
                    self.engine.deinit();
                    self.outbound_pool.deinit();
                    self.inbound_pool.deinit();
                }

                pub fn allocInboundPacket(self: *Self) !*packet.Inbound {
                    return self.inbound_pool.get() orelse error.OutOfMemory;
                }

                pub fn allocOutboundPacket(self: *Self) !*packet.Outbound {
                    return self.outbound_pool.get() orelse error.OutOfMemory;
                }
            };
        }

        fn offlineDeadlineMarksPeerOffline(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runOfflineDeadlineFlow();
        }

        fn passiveKeepaliveEmitsEmptyTransport(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runPassiveKeepaliveFlow();
        }

        fn initiateHandshakeConfiguresPersistentKeepalive(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runInitiateHandshakeKeepaliveConfigFlow();
        }

        fn persistentKeepaliveEmitsEmptyTransport(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runPersistentKeepaliveFlow();
        }

        fn negativeDurationsNormalizeToImmediate(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runNegativeDurationNormalizationFlow();
        }

        fn outboundCallbackErrorLeavesCallerPacketOwned(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runOutboundCallbackErrorOwnershipFlow();
        }

        fn transportCallbackErrorLeavesInboundOwned(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runTransportCallbackErrorOwnershipFlow();
        }

        fn emptyTransportSuccessConsumesInbound(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runEmptyTransportSuccessOwnershipFlow();
        }

        fn chachaRekeyTransfer10KiB(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runRekeyAfterMessagesFlow(.chacha_poly);
        }

        fn aesRekeyTransfer10KiB(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runRekeyAfterMessagesFlow(.aes_256_gcm);
        }

        fn plaintextRekeyTransfer10KiB(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            _ = allocator;
            try runRekeyAfterMessagesFlow(.plaintext);
        }

        fn runOfflineDeadlineFlow() !void {
            const any_lib = grt;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const Session = SessionType.make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2901);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2902);
            const remote_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52102);

            var engine_harness = try TestEngine(EngineType, packet_size).init(grt.std.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .offline_timeout = 0,
            });
            defer engine_harness.deinit();
            const engine = &engine_harness.engine;

            const now = EngineType.instantNow();
            const peer = try engine.peers.getOrCreate(remote_pair.public);
            peer.establish(local_pair.public, remote_endpoint, makeSession(
                Session,
                remote_pair.public,
                remote_endpoint,
                11,
                12,
                0x11,
                0x22,
                engine.config.reject_after_time,
                now,
            ), true, now);
            peer.last_sent = now;
            peer.last_received = now;
            peer.updateTimers(now, 0);
            try engine.syncPeerTimerEntry(peer);

            const CallbackState = struct {
                expected_remote_key: Key,
                offline_count: usize = 0,
                next_tick_events: usize = 0,

                fn callback(self: *@This()) Engine.Callback {
                    return .{
                        .ctx = self,
                        .call = callbackFn,
                    };
                }

                fn callbackFn(ctx: *anyopaque, result: Engine.DriveOutput) anyerror!void {
                    const self: *@This() = @ptrCast(@alignCast(ctx));
                    switch (result) {
                        .offline => |remote_key| {
                            try grt.std.testing.expect(remote_key.eql(self.expected_remote_key));
                            self.offline_count += 1;
                        },
                        .outbound => |pkt| {
                            pkt.deinit();
                            return error.UnexpectedOutbound;
                        },
                        .inbound => |pkt| {
                            pkt.deinit();
                            return error.UnexpectedInbound;
                        },
                        .established => return error.UnexpectedEstablished,
                        .next_tick_deadline => |_| self.next_tick_events += 1,
                    }
                }
            };

            var callback_state: CallbackState = .{
                .expected_remote_key = remote_pair.public,
            };
            try engine.drive(.{ .tick = {} }, callback_state.callback());

            try grt.std.testing.expectEqual(@as(usize, 1), callback_state.offline_count);
            try grt.std.testing.expect(peer.is_offline);
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), peer.offline_deadline);
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), peer.timers.get(.offline_deadline));
        }

        fn runPassiveKeepaliveFlow() !void {
            const any_lib = grt;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const Session = SessionType.make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2911);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2912);
            const remote_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52112);

            var engine_harness = try TestEngine(EngineType, packet_size).init(grt.std.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .keepalive_timeout = 0,
                .offline_timeout = 10 * glib.time.duration.Second,
            });
            defer engine_harness.deinit();
            const engine = &engine_harness.engine;

            const receive_now = blk: {
                const start_now = EngineType.instantNow();
                var current_now = start_now;
                while (current_now == start_now) {
                    current_now = EngineType.instantNow();
                }
                break :blk current_now;
            };

            const peer = try engine.peers.getOrCreate(remote_pair.public);
            peer.establish(local_pair.public, remote_endpoint, makeSession(
                Session,
                remote_pair.public,
                remote_endpoint,
                21,
                22,
                0x33,
                0x44,
                engine.config.reject_after_time,
                receive_now,
            ), false, receive_now);
            peer.last_sent = glib.time.instant.add(receive_now, -glib.time.duration.NanoSecond);
            peer.last_received = receive_now;
            peer.updateTimers(receive_now, 0);
            try engine.syncPeerTimerEntry(peer);

            const CallbackState = struct {
                keepalive_packet: ?*packet.Outbound = null,
                next_tick_events: usize = 0,

                fn callback(self: *@This()) Engine.Callback {
                    return .{
                        .ctx = self,
                        .call = callbackFn,
                    };
                }

                fn callbackFn(ctx: *anyopaque, result: Engine.DriveOutput) anyerror!void {
                    const self: *@This() = @ptrCast(@alignCast(ctx));
                    switch (result) {
                        .outbound => |pkt| {
                            if (self.keepalive_packet != null) {
                                pkt.deinit();
                                return error.UnexpectedMultipleOutbounds;
                            }
                            self.keepalive_packet = pkt;
                        },
                        .inbound => |pkt| {
                            pkt.deinit();
                            return error.UnexpectedInbound;
                        },
                        .established => return error.UnexpectedEstablished,
                        .offline => return error.UnexpectedOffline,
                        .next_tick_deadline => |_| self.next_tick_events += 1,
                    }
                }
            };

            var callback_state: CallbackState = .{};
            try engine.drive(.{ .tick = {} }, callback_state.callback());

            const keepalive_packet = callback_state.keepalive_packet orelse return error.MissingKeepalivePacket;
            defer keepalive_packet.deinit();

            try grt.std.testing.expectEqual(packet.Outbound.Kind.transport, keepalive_packet.kind);
            try grt.std.testing.expectEqual(packet.Outbound.State.prepared, keepalive_packet.state);
            try grt.std.testing.expectEqual(@as(usize, 0), keepalive_packet.len);
            try grt.std.testing.expect(keepalive_packet.remote_static.eql(remote_pair.public));
            try grt.std.testing.expect(giznet.eqlAddrPort(keepalive_packet.remote_endpoint, remote_endpoint));
        }

        fn runInitiateHandshakeKeepaliveConfigFlow() !void {
            const any_lib = grt;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2916);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2917);
            const remote_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52116);

            var engine_harness = try TestEngine(EngineType, packet_size).init(grt.std.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
            });
            defer engine_harness.deinit();
            const engine = &engine_harness.engine;

            const CallbackState = struct {
                outbound_packet: ?*packet.Outbound = null,

                fn callback(self: *@This()) Engine.Callback {
                    return .{
                        .ctx = self,
                        .call = callbackFn,
                    };
                }

                fn callbackFn(ctx: *anyopaque, result: Engine.DriveOutput) anyerror!void {
                    const self: *@This() = @ptrCast(@alignCast(ctx));
                    switch (result) {
                        .outbound => |pkt| {
                            if (self.outbound_packet != null) {
                                pkt.deinit();
                                return error.UnexpectedMultipleOutbounds;
                            }
                            self.outbound_packet = pkt;
                        },
                        .inbound => |pkt| {
                            pkt.deinit();
                            return error.UnexpectedInbound;
                        },
                        .established => return error.UnexpectedEstablished,
                        .offline => return error.UnexpectedOffline,
                        .next_tick_deadline => |_| {},
                    }
                }
            };

            var callback_state: CallbackState = .{};
            try engine.drive(.{
                .initiate_handshake = .{
                    .remote_key = remote_pair.public,
                    .remote_endpoint = remote_endpoint,
                    .keepalive_interval = 17 * glib.time.duration.MilliSecond,
                },
            }, callback_state.callback());

            const outbound_packet = callback_state.outbound_packet orelse return error.MissingHandshakePacket;
            defer outbound_packet.deinit();

            const peer = engine.peers.get(remote_pair.public) orelse return error.MissingPeer;
            try grt.std.testing.expect(peer.pending_handshake != null);
            try grt.std.testing.expect(peer.persistent_keepalive);
            try grt.std.testing.expectEqual(@as(?glib.time.duration.Duration, 17 * glib.time.duration.MilliSecond), peer.keepalive_interval);
            try grt.std.testing.expectEqual(packet.Outbound.Kind.handshake, outbound_packet.kind);
            try grt.std.testing.expectEqual(packet.Outbound.State.ready_to_send, outbound_packet.state);
            try grt.std.testing.expect(outbound_packet.remote_static.eql(remote_pair.public));
            try grt.std.testing.expect(giznet.eqlAddrPort(outbound_packet.remote_endpoint, remote_endpoint));
        }

        fn runPersistentKeepaliveFlow() !void {
            const any_lib = grt;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const Session = SessionType.make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2921);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2922);
            const remote_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52122);

            var engine_harness = try TestEngine(EngineType, packet_size).init(grt.std.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .offline_timeout = 10 * glib.time.duration.Second,
            });
            defer engine_harness.deinit();
            const engine = &engine_harness.engine;

            const sent_now = blk: {
                const start_now = EngineType.instantNow();
                var current_now = start_now;
                while (current_now == start_now) {
                    current_now = EngineType.instantNow();
                }
                break :blk current_now;
            };

            const peer = try engine.peers.getOrCreate(remote_pair.public);
            peer.establish(local_pair.public, remote_endpoint, makeSession(
                Session,
                remote_pair.public,
                remote_endpoint,
                31,
                32,
                0x55,
                0x66,
                engine.config.reject_after_time,
                sent_now,
            ), true, sent_now);
            peer.last_sent = sent_now;
            peer.last_received = sent_now;
            peer.persistent_keepalive = true;
            peer.keepalive_interval = glib.time.duration.NanoSecond;
            peer.updateTimers(sent_now, 0);
            try engine.syncPeerTimerEntry(peer);

            const CallbackState = struct {
                keepalive_packet: ?*packet.Outbound = null,
                next_tick_events: usize = 0,

                fn callback(self: *@This()) Engine.Callback {
                    return .{
                        .ctx = self,
                        .call = callbackFn,
                    };
                }

                fn callbackFn(ctx: *anyopaque, result: Engine.DriveOutput) anyerror!void {
                    const self: *@This() = @ptrCast(@alignCast(ctx));
                    switch (result) {
                        .outbound => |pkt| {
                            if (self.keepalive_packet != null) {
                                pkt.deinit();
                                return error.UnexpectedMultipleOutbounds;
                            }
                            self.keepalive_packet = pkt;
                        },
                        .inbound => |pkt| {
                            pkt.deinit();
                            return error.UnexpectedInbound;
                        },
                        .established => return error.UnexpectedEstablished,
                        .offline => return error.UnexpectedOffline,
                        .next_tick_deadline => |_| self.next_tick_events += 1,
                    }
                }
            };

            var callback_state: CallbackState = .{};
            while (callback_state.keepalive_packet == null) {
                try engine.drive(.{ .tick = {} }, callback_state.callback());
            }

            const keepalive_packet = callback_state.keepalive_packet orelse return error.MissingKeepalivePacket;
            defer keepalive_packet.deinit();

            try grt.std.testing.expectEqual(packet.Outbound.Kind.transport, keepalive_packet.kind);
            try grt.std.testing.expectEqual(packet.Outbound.State.prepared, keepalive_packet.state);
            try grt.std.testing.expectEqual(@as(usize, 0), keepalive_packet.len);
            try grt.std.testing.expect(keepalive_packet.remote_static.eql(remote_pair.public));
            try grt.std.testing.expect(giznet.eqlAddrPort(keepalive_packet.remote_endpoint, remote_endpoint));
        }

        fn runNegativeDurationNormalizationFlow() !void {
            const any_lib = grt;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2926);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2927);

            var engine_harness = try TestEngine(EngineType, packet_size).init(grt.std.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .rekey_after_time = -1,
                .reject_after_time = -1,
                .rekey_timeout = -1,
                .keepalive_timeout = -1,
                .handshake_attempt = -1,
                .offline_timeout = -1,
                .session_cleanup = -1,
            });
            defer engine_harness.deinit();
            const engine = &engine_harness.engine;

            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), engine.config.rekey_after_time);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), engine.config.reject_after_time);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), engine.config.rekey_timeout);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), engine.config.keepalive_timeout);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), engine.config.handshake_attempt);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), engine.config.offline_timeout);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), engine.config.session_cleanup);

            const peer = try engine.peers.getOrCreate(remote_pair.public);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), peer.timer_config.rekey_after_time);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), peer.timer_config.offline_timeout);
        }

        fn runOutboundCallbackErrorOwnershipFlow() !void {
            const any_lib = grt;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const Session = SessionType.make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2931);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2932);
            const remote_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52132);

            var engine_harness = try TestEngine(EngineType, packet_size).init(grt.std.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
            });
            defer engine_harness.deinit();
            const engine = &engine_harness.engine;

            const now = EngineType.instantNow();
            const peer = try engine.peers.getOrCreate(remote_pair.public);
            peer.establish(local_pair.public, remote_endpoint, makeSession(
                Session,
                remote_pair.public,
                remote_endpoint,
                41,
                42,
                0x77,
                0x88,
                engine.config.reject_after_time,
                now,
            ), true, now);

            const pkt = try engine_harness.allocOutboundPacket();
            errdefer pkt.deinit();
            pkt.remote_static = remote_pair.public;
            const payload = "owned on error";
            if (pkt.transportPlaintextBufRef().len < payload.len) return error.BufferTooSmall;
            @memcpy(pkt.transportPlaintextBufRef()[0..payload.len], payload);
            pkt.len = payload.len;

            var callback_state: OwnershipCallbackState = .{ .fail_outbound = true };
            try grt.std.testing.expectError(
                error.InjectOutboundFailure,
                engine.drive(.{ .send_data = pkt }, callback_state.callback()),
            );
            pkt.deinit();
        }

        fn runTransportCallbackErrorOwnershipFlow() !void {
            const any_lib = grt;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const Session = SessionType.make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2933);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2934);
            const remote_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52134);

            var engine_harness = try TestEngine(EngineType, packet_size).init(grt.std.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
            });
            defer engine_harness.deinit();
            const engine = &engine_harness.engine;

            try installEstablishedPeer(EngineType, Session, engine, local_pair.public, remote_pair.public, remote_endpoint, 51, 52);

            const pkt = try makeReadyTransportInbound(&engine_harness, remote_pair.public, remote_endpoint, 51, 52, 0, "emit then fail");
            defer pkt.deinit();

            var callback_state: OwnershipCallbackState = .{ .fail_inbound = true };
            try grt.std.testing.expectError(
                error.InjectInboundFailure,
                engine.drive(.{ .inbound_packet = pkt }, callback_state.callback()),
            );
        }

        fn runEmptyTransportSuccessOwnershipFlow() !void {
            const any_lib = grt;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const Session = SessionType.make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2935);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2936);
            const remote_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52136);

            var engine_harness = try TestEngine(EngineType, packet_size).init(grt.std.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
            });
            defer engine_harness.deinit();
            const engine = &engine_harness.engine;

            try installEstablishedPeer(EngineType, Session, engine, local_pair.public, remote_pair.public, remote_endpoint, 61, 62);

            const pkt = try makeReadyTransportInbound(&engine_harness, remote_pair.public, remote_endpoint, 61, 62, 0, "");
            var callback_state: OwnershipCallbackState = .{};
            try engine.drive(.{ .inbound_packet = pkt }, callback_state.callback());
            try grt.std.testing.expectEqual(@as(usize, 0), callback_state.inbound_count);
        }

        fn runRekeyAfterMessagesFlow(comptime cipher_kind: Cipher.Kind) !void {
            const any_lib = grt;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const EngineHarness = TestEngine(EngineType, packet_size);
            const payload_size: usize = 1024;
            const total_transfer_bytes: usize = 10 * 1024;
            const total_packet_count: usize = total_transfer_bytes / payload_size;
            const trigger_message_count: usize = 4;
            const no_rekey_after_time: glib.time.duration.Duration = 365 * glib.time.duration.Day;

            try grt.std.testing.expectEqual(@as(usize, 0), total_transfer_bytes % payload_size);

            const initiator_pair = giznet.noise.KeyPair.seed(any_lib, 1901);
            const responder_pair = giznet.noise.KeyPair.seed(any_lib, 1902);
            const initiator_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52001);
            const responder_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52002);

            var initiator_harness = try EngineHarness.init(grt.std.testing.allocator, initiator_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .rekey_after_messages = trigger_message_count,
                .rekey_after_time = no_rekey_after_time,
            });
            defer initiator_harness.deinit();

            var responder_harness = try EngineHarness.init(grt.std.testing.allocator, responder_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .rekey_after_messages = trigger_message_count,
                .rekey_after_time = no_rekey_after_time,
            });
            defer responder_harness.deinit();
            const initiator = &initiator_harness.engine;
            const responder = &responder_harness.engine;

            const Side = enum {
                initiator,
                responder,
            };

            const CallbackCtx = struct {
                harness_ptr: *anyopaque,
                side: Side,
            };

            const Harness = struct {
                initiator: *EngineHarness,
                responder: *EngineHarness,
                initiator_key: Key,
                responder_key: Key,
                initiator_endpoint: AddrPort,
                responder_endpoint: AddrPort,
                received_packets: usize = 0,
                received_bytes: usize = 0,
                established_events: usize = 0,
                offline_events: usize = 0,
                next_tick_events: usize = 0,
                initiator_callback_ctx: ?*CallbackCtx = null,
                responder_callback_ctx: ?*CallbackCtx = null,

                fn callback(self: *@This(), side: Side) Engine.Callback {
                    const ctx = switch (side) {
                        .initiator => self.initiator_callback_ctx orelse unreachable,
                        .responder => self.responder_callback_ctx orelse unreachable,
                    };
                    return .{
                        .ctx = ctx,
                        .call = callbackFn,
                    };
                }

                fn callbackFn(ctx: *anyopaque, result: Engine.DriveOutput) anyerror!void {
                    const callback_ctx: *CallbackCtx = @ptrCast(@alignCast(ctx));
                    const harness: *@This() = @ptrCast(@alignCast(callback_ctx.harness_ptr));
                    try harness.handleResult(callback_ctx.side, result);
                }

                fn handleResult(self: *@This(), side: Side, result: Engine.DriveOutput) !void {
                    switch (result) {
                        .outbound => |pkt| try self.handleOutbound(side, pkt),
                        .inbound => |pkt| try self.handleInbound(side, pkt),
                        .established => |remote_key| try self.handleEstablished(side, remote_key),
                        .offline => |remote_key| try self.handleOffline(side, remote_key),
                        .next_tick_deadline => |_| self.next_tick_events += 1,
                    }
                }

                fn handleOutbound(self: *@This(), side: Side, outbound: *packet.Outbound) !void {
                    const target_side = opposite(side);
                    const target_engine = self.engineHarness(target_side);
                    const remote_endpoint = self.endpoint(side);

                    if (outbound.state == .prepared) {
                        try packet.Outbound.encrypt(any_lib, cipher_kind, outbound);
                    }

                    const inbound = try target_engine.allocInboundPacket();
                    errdefer inbound.deinit();
                    if (inbound.bufRef().len < outbound.len) return error.BufferTooSmall;

                    @memcpy(inbound.bufRef()[0..outbound.len], outbound.bytes());
                    inbound.len = outbound.len;
                    inbound.remote_endpoint = remote_endpoint;

                    try target_engine.engine.drive(.{ .inbound_packet = inbound }, self.callback(target_side));
                    outbound.deinit();
                }

                fn handleInbound(self: *@This(), side: Side, inbound: *packet.Inbound) !void {
                    switch (inbound.state) {
                        .prepared => {
                            try packet.Inbound.decrtpy(any_lib, cipher_kind, inbound);
                            try self.engine(side).drive(.{ .inbound_packet = inbound }, self.callback(side));
                        },
                        .consumed => {
                            try self.verifyConsumedInbound(side, inbound);
                            inbound.deinit();
                        },
                        else => return error.UnexpectedInboundPacketState,
                    }
                }

                fn handleEstablished(self: *@This(), side: Side, remote_key: Key) !void {
                    self.established_events += 1;
                    switch (side) {
                        .initiator => try grt.std.testing.expect(remote_key.eql(self.responder_key)),
                        .responder => try grt.std.testing.expect(remote_key.eql(self.initiator_key)),
                    }
                }

                fn handleOffline(self: *@This(), side: Side, remote_key: Key) !void {
                    _ = side;
                    _ = remote_key;
                    self.offline_events += 1;
                }

                fn verifyConsumedInbound(self: *@This(), side: Side, inbound: *packet.Inbound) !void {
                    if (side != .responder) return error.UnexpectedInboundOnInitiator;

                    var expected_payload: [payload_size]u8 = undefined;
                    fillPayload(self.received_packets, expected_payload[0..]);

                    try grt.std.testing.expectEqual(@as(usize, payload_size), inbound.len);
                    try grt.std.testing.expect(inbound.remote_static.eql(self.initiator_key));
                    try grt.std.testing.expect(giznet.eqlAddrPort(inbound.remote_endpoint, self.initiator_endpoint));
                    try grt.std.testing.expect(glib.std.mem.eql(u8, expected_payload[0..], inbound.bytes()));

                    self.received_packets += 1;
                    self.received_bytes += inbound.len;
                }

                fn engine(self: *@This(), side: Side) *EngineType {
                    return switch (side) {
                        .initiator => &self.initiator.engine,
                        .responder => &self.responder.engine,
                    };
                }

                fn engineHarness(self: *@This(), side: Side) *EngineHarness {
                    return switch (side) {
                        .initiator => self.initiator,
                        .responder => self.responder,
                    };
                }

                fn endpoint(self: *@This(), side: Side) AddrPort {
                    return switch (side) {
                        .initiator => self.initiator_endpoint,
                        .responder => self.responder_endpoint,
                    };
                }

                fn opposite(side: Side) Side {
                    return switch (side) {
                        .initiator => .responder,
                        .responder => .initiator,
                    };
                }

                fn fillPayload(chunk_index: usize, out: []u8) void {
                    for (out, 0..) |*byte, index| {
                        const value = (chunk_index * 17 + index * 31 + 7) % 251;
                        byte.* = @intCast(value);
                    }
                }

                fn sendFromInitiator(self: *@This(), chunk_index: usize) !void {
                    var packet_buffer: [payload_size]u8 = undefined;
                    fillPayload(chunk_index, packet_buffer[0..]);
                    const pkt = try self.initiator.allocOutboundPacket();
                    errdefer pkt.deinit();
                    if (pkt.transportPlaintextBufRef().len < packet_buffer.len) return error.BufferTooSmall;
                    @memcpy(pkt.transportPlaintextBufRef()[0..packet_buffer.len], packet_buffer[0..]);
                    pkt.len = packet_buffer.len;
                    pkt.remote_static = self.responder_key;
                    try self.initiator.engine.drive(.{
                        .send_data = pkt,
                    }, self.callback(.initiator));
                }
            };

            var harness: Harness = .{
                .initiator = &initiator_harness,
                .responder = &responder_harness,
                .initiator_key = initiator_pair.public,
                .responder_key = responder_pair.public,
                .initiator_endpoint = initiator_endpoint,
                .responder_endpoint = responder_endpoint,
            };
            var initiator_callback_ctx: CallbackCtx = .{
                .harness_ptr = &harness,
                .side = .initiator,
            };
            var responder_callback_ctx: CallbackCtx = .{
                .harness_ptr = &harness,
                .side = .responder,
            };
            harness.initiator_callback_ctx = &initiator_callback_ctx;
            harness.responder_callback_ctx = &responder_callback_ctx;

            try initiator.drive(.{
                .initiate_handshake = .{
                    .remote_key = responder_pair.public,
                    .remote_endpoint = responder_endpoint,
                },
            }, harness.callback(.initiator));

            try grt.std.testing.expectEqual(@as(usize, 2), harness.established_events);
            try grt.std.testing.expectEqual(@as(usize, 1), initiator.stats.session_count);
            try grt.std.testing.expectEqual(@as(usize, 1), responder.stats.session_count);

            const initiator_peer_before = initiator.peers.get(responder_pair.public) orelse return error.SessionNotFound;
            const responder_peer_before = responder.peers.get(initiator_pair.public) orelse return error.SessionNotFound;
            const initiator_old_current = initiator_peer_before.current orelse return error.SessionNotFound;
            const responder_old_current = responder_peer_before.current orelse return error.SessionNotFound;

            var chunk_index: usize = 0;
            while (chunk_index < trigger_message_count) : (chunk_index += 1) {
                try harness.sendFromInitiator(chunk_index);
            }

            var tick_round: usize = 0;
            while (harness.established_events < 4 and tick_round < 4) : (tick_round += 1) {
                try initiator.drive(.{ .tick = {} }, harness.callback(.initiator));
                try responder.drive(.{ .tick = {} }, harness.callback(.responder));
            }

            try grt.std.testing.expect(harness.established_events >= 4);
            try grt.std.testing.expectEqual(trigger_message_count, harness.received_packets);
            try grt.std.testing.expectEqual(trigger_message_count * payload_size, harness.received_bytes);
            try grt.std.testing.expectEqual(@as(usize, 2), initiator.stats.session_count);
            try grt.std.testing.expectEqual(@as(usize, 2), responder.stats.session_count);
            try grt.std.testing.expectEqual(@as(usize, 0), initiator.stats.pending_handshake_count);
            try grt.std.testing.expectEqual(@as(usize, 0), responder.stats.pending_handshake_count);

            const initiator_peer_after = initiator.peers.get(responder_pair.public) orelse return error.SessionNotFound;
            const responder_peer_after = responder.peers.get(initiator_pair.public) orelse return error.SessionNotFound;
            const initiator_current = initiator_peer_after.current orelse return error.SessionNotFound;
            const initiator_previous = initiator_peer_after.previous orelse return error.SessionNotFound;
            const responder_current = responder_peer_after.current orelse return error.SessionNotFound;
            const responder_previous = responder_peer_after.previous orelse return error.SessionNotFound;

            try grt.std.testing.expect(initiator_current.localIndex() != initiator_old_current.localIndex());
            try grt.std.testing.expectEqual(initiator_old_current.localIndex(), initiator_previous.localIndex());
            try grt.std.testing.expect(responder_current.localIndex() != responder_old_current.localIndex());
            try grt.std.testing.expectEqual(responder_old_current.localIndex(), responder_previous.localIndex());

            while (chunk_index < total_packet_count) : (chunk_index += 1) {
                try harness.sendFromInitiator(chunk_index);
            }
            try grt.std.testing.expectEqual(total_packet_count, harness.received_packets);
            try grt.std.testing.expectEqual(total_transfer_bytes, harness.received_bytes);
            try grt.std.testing.expect(harness.established_events >= 4);
        }

        const OwnershipCallbackState = struct {
            fail_outbound: bool = false,
            fail_inbound: bool = false,
            outbound_count: usize = 0,
            inbound_count: usize = 0,

            fn callback(self: *@This()) Engine.Callback {
                return .{ .ctx = self, .call = call };
            }

            fn call(ctx: *anyopaque, result: Engine.DriveOutput) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                switch (result) {
                    .outbound => |pkt| {
                        self.outbound_count += 1;
                        if (self.fail_outbound) return error.InjectOutboundFailure;
                        pkt.deinit();
                    },
                    .inbound => |pkt| {
                        self.inbound_count += 1;
                        if (self.fail_inbound) return error.InjectInboundFailure;
                        pkt.deinit();
                    },
                    .established => {},
                    .offline => {},
                    .next_tick_deadline => |_| {},
                }
            }
        };

        fn installEstablishedPeer(
            comptime EngineType: type,
            comptime Session: type,
            engine: *EngineType,
            local_key: Key,
            remote_key: Key,
            endpoint: AddrPort,
            local_index: u32,
            remote_index: u32,
        ) !void {
            const now = EngineType.instantNow();
            const peer = try engine.peers.getOrCreate(remote_key);
            peer.establish(local_key, endpoint, makeSession(
                Session,
                remote_key,
                endpoint,
                local_index,
                remote_index,
                0x99,
                0xaa,
                engine.config.reject_after_time,
                now,
            ), true, now);
        }

        fn makeReadyTransportInbound(
            engine_harness: anytype,
            remote_key: Key,
            endpoint: AddrPort,
            local_index: u32,
            remote_index: u32,
            counter: u64,
            payload: []const u8,
        ) !*packet.Inbound {
            const inbound = try engine_harness.allocInboundPacket();
            errdefer inbound.deinit();

            const plaintext = inbound.bufRef()[Message.TransportHeaderSize..];
            if (plaintext.len < payload.len) return error.BufferTooSmall;
            @memcpy(plaintext[0..payload.len], payload);
            inbound.len = payload.len;
            inbound.kind = .transport;
            inbound.state = .ready_to_consume;
            inbound.remote_static = remote_key;
            inbound.remote_endpoint = endpoint;
            inbound.local_session_index = local_index;
            inbound.remote_session_index = remote_index;
            inbound.counter = counter;
            return inbound;
        }

        fn makeSession(
            Session: type,
            peer_key: Key,
            endpoint: AddrPort,
            local_index: u32,
            remote_index: u32,
            send_fill: u8,
            recv_fill: u8,
            timeout: glib.time.duration.Duration,
            now: glib.time.instant.Time,
        ) Session {
            return Session.init(.{
                .local_index = local_index,
                .remote_index = remote_index,
                .peer_key = peer_key,
                .endpoint = endpoint,
                .send_key = giznet.noise.Key{ .bytes = [_]u8{send_fill} ** 32 },
                .recv_key = giznet.noise.Key{ .bytes = [_]u8{recv_fill} ** 32 },
                .timeout = timeout,
                .now = now,
            });
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: glib.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: glib.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run(
                "offline_deadline_marks_peer_offline",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.offlineDeadlineMarksPeerOffline),
            );
            t.run(
                "passive_keepalive_emits_empty_transport",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.passiveKeepaliveEmitsEmptyTransport),
            );
            t.run(
                "initiate_handshake_configures_persistent_keepalive",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.initiateHandshakeConfiguresPersistentKeepalive),
            );
            t.run(
                "persistent_keepalive_emits_empty_transport",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.persistentKeepaliveEmitsEmptyTransport),
            );
            t.run(
                "negative_durations_normalize_to_immediate",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.negativeDurationsNormalizeToImmediate),
            );
            t.run(
                "outbound_callback_error_leaves_caller_packet_owned",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.outboundCallbackErrorLeavesCallerPacketOwned),
            );
            t.run(
                "transport_callback_error_leaves_inbound_owned",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.transportCallbackErrorLeavesInboundOwned),
            );
            t.run(
                "empty_transport_success_consumes_inbound",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.emptyTransportSuccessConsumesInbound),
            );
            t.run(
                "chacha_poly_rekey_transfer_10KiB",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.chachaRekeyTransfer10KiB),
            );
            t.run(
                "aes_256_gcm_rekey_transfer_10KiB",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.aesRekeyTransfer10KiB),
            );
            t.run(
                "plaintext_rekey_transfer_10KiB",
                testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.plaintextRekeyTransfer10KiB),
            );
            return true;
        }

        pub fn deinit(self: *@This(), allocator: glib.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
