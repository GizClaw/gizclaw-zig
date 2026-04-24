const embed = @import("embed");
const std = embed.std;
const AddrPort = embed.net.netip.AddrPort;

const Cipher = @import("Cipher.zig");
const HandshakeType = @import("Handshake.zig");
const InboundPacket = @import("InboundPacket.zig");
const Key = @import("Key.zig");
const KeyPair = @import("KeyPair.zig");
const Message = @import("Message.zig");
const OutboundPacket = @import("OutboundPacket.zig");
const PeerType = @import("Peer.zig");
const PeerTableType = @import("PeerTable.zig");
const SessionType = @import("Session.zig");

const Engine = @This();

pub const default_rekey_after_time_ms: u64 = 120_000;
pub const default_reject_after_time_ms: u64 = 180_000;
pub const default_rekey_timeout_ms: u64 = 5_000;
pub const default_keepalive_timeout_ms: u64 = 10_000;
pub const default_keepalive_interval_ms: ?u64 = null;
pub const default_handshake_attempt_ms: u64 = 90_000;
pub const default_offline_timeout_ms: u64 = 180_000;
pub const default_session_cleanup_ms: u64 = 180_000;
pub const default_rekey_after_messages: u64 = 1 << 20;
pub const default_reject_after_messages: u64 = (1 << 20) + (1 << 12);

pub const Config = struct {
    max_peers: usize = 8,
    max_pending: usize = 8,
    rekey_after_time_ms: u64 = default_rekey_after_time_ms,
    reject_after_time_ms: u64 = default_reject_after_time_ms,
    rekey_timeout_ms: u64 = default_rekey_timeout_ms,
    keepalive_timeout_ms: u64 = default_keepalive_timeout_ms,
    keepalive_interval_ms: ?u64 = default_keepalive_interval_ms,
    handshake_attempt_ms: u64 = default_handshake_attempt_ms,
    offline_timeout_ms: u64 = default_offline_timeout_ms,
    session_cleanup_ms: u64 = default_session_cleanup_ms,
    rekey_after_messages: u64 = default_rekey_after_messages,
    reject_after_messages: u64 = default_reject_after_messages,
};

pub const DriveOutput = union(enum) {
    outbound: *OutboundPacket,
    inbound: *InboundPacket,
    established: Key,
    offline: Key,
    next_tick_ms: u64,
};

pub const InitiateHandshake = struct {
    remote_key: Key,
    remote_endpoint: AddrPort,
};

pub const SendData = struct {
    remote_key: Key,
    payload: []u8,
};

pub const DriveInput = union(enum) {
    inbound_packet: *InboundPacket,
    send_data: SendData,
    initiate_handshake: InitiateHandshake,
    tick: void,
};

pub const Stats = struct {
    peer_count: usize = 0,
    pending_handshake_count: usize = 0,
    session_count: usize = 0,
    latest_handshake_ms: ?u64 = null,
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
    comptime lib: type,
    comptime packet_size_capacity: usize,
    comptime cipher_kind: Cipher.Kind,
) type {
    const Order = std.math.Order;
    const Handshake = HandshakeType.make(lib, cipher_kind);
    const Peer = PeerType.make(lib, cipher_kind);
    const PeerTable = PeerTableType.make(lib, cipher_kind);
    const Session = SessionType.make(lib, packet_size_capacity, cipher_kind);
    const TimerTreapKey = struct {
        due_ms: u64,
        peer_key: Key,
    };
    const TimerTreap = std.Treap(TimerTreapKey, struct {
        fn compare(a: TimerTreapKey, b: TimerTreapKey) Order {
            if (a.due_ms < b.due_ms) return .lt;
            if (a.due_ms > b.due_ms) return .gt;

            var index: usize = 0;
            while (index < a.peer_key.bytes.len) : (index += 1) {
                if (a.peer_key.bytes[index] < b.peer_key.bytes[index]) return .lt;
                if (a.peer_key.bytes[index] > b.peer_key.bytes[index]) return .gt;
            }
            return .eq;
        }
    }.compare);

    return struct {
        var started: ?lib.time.Instant = null;

        allocator: std.mem.Allocator,
        local_static: KeyPair,
        config: Engine.Config,
        peers: PeerTable,
        inbound_pool: InboundPacket.Pool,
        outbound_pool: OutboundPacket.Pool,
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
            allocator: std.mem.Allocator,
            local_static: KeyPair,
            config: Engine.Config,
        ) !Self {
            var timer_slots: []TimerSlot = &[_]TimerSlot{};
            if (config.max_peers != 0) {
                timer_slots = try allocator.alloc(TimerSlot, config.max_peers);
            }
            errdefer if (timer_slots.len != 0) allocator.free(timer_slots);
            for (timer_slots) |*slot| slot.* = .{};

            const inbound_pool = try InboundPacket.initPool(lib, allocator, packet_size_capacity);
            errdefer inbound_pool.deinit();

            const outbound_pool = try OutboundPacket.initPool(lib, allocator, packet_size_capacity);
            errdefer outbound_pool.deinit();

            return .{
                .allocator = allocator,
                .local_static = local_static,
                .config = config,
                .peers = PeerTable.init(allocator, config.max_peers, .{
                    .keepalive_timeout_ms = config.keepalive_timeout_ms,
                    .keepalive_interval_ms = config.keepalive_interval_ms,
                    .rekey_after_time_ms = config.rekey_after_time_ms,
                    .rekey_timeout_ms = config.rekey_timeout_ms,
                    .handshake_attempt_ms = config.handshake_attempt_ms,
                    .offline_timeout_ms = config.offline_timeout_ms,
                    .session_cleanup_ms = config.session_cleanup_ms,
                    .rekey_after_messages = config.rekey_after_messages,
                }),
                .inbound_pool = inbound_pool,
                .outbound_pool = outbound_pool,
                .timer_slots = timer_slots,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.timer_slots.len != 0) self.allocator.free(self.timer_slots);
            self.timer_slots = &.{};
            self.peers.deinit();
            self.inbound_pool.deinit();
            self.outbound_pool.deinit();
        }

        /// Acquire an engine-owned inbound packet in `.initial` state.
        ///
        /// The caller is expected to fill:
        /// - `packet.len`
        /// - `packet.bufRef()[0..len]`
        /// - `packet.remote_endpoint`
        ///
        /// before calling `drive()`.
        pub fn getInboundPacket(self: *Self) !*InboundPacket {
            return self.inbound_pool.get() orelse error.OutOfMemory;
        }

        /// Single engine drive entrypoint.
        ///
        /// Contract shape:
        /// - must be called on the engine thread
        /// - accepts one explicit drive input
        /// - successful drive calls run `tick()` afterwards
        /// - failed drive actions return early and do not advance timers
        /// - `.inbound_packet` is implemented
        /// - `.send_data` emits a prepared outbound transport packet and
        ///   leaves encryption to the caller
        /// - `.initiate_handshake` emits a ready-to-send handshake packet
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
                .inbound_packet => |packet| inbound: {
                    if (packet.state == .initial) {
                        self.stats.transfer_rx +%= @as(u64, @intCast(packet.len));
                    }

                    break :inbound switch (packet.state) {
                        .initial => self.triageInbound(packet, on_result),
                        .ready_to_consume => self.consumeInbound(packet, on_result),

                        .prepared => error.InboundPacketRequiresDecrypt,
                        .consumed => error.InboundPacketConsumed,
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
            const now_ms = nowMs();

            while (self.timer_treap.getMin()) |node| {
                if (node.key.due_ms > now_ms) break;
                try self.tickNode(node, now_ms, on_result);
            }

            if (self.timer_treap.getMin()) |node| {
                try self.emitEvent(on_result, .{ .next_tick_ms = node.key.due_ms });
            }
        }

        fn triageInbound(
            self: *Self,
            packet: *InboundPacket,
            on_result: Engine.Callback,
        ) !void {
            const kind = try inferInboundKind(packet);

            return switch (kind) {
                .handshake => self.consumeInbound(packet, on_result),
                .transport => self.prepareTransport(packet, on_result),
                .unknown => error.InvalidInboundPacketKind,
            };
        }

        fn prepareTransport(
            self: *Self,
            packet: *InboundPacket,
            on_result: Engine.Callback,
        ) !void {
            const transport = Message.parseTransportMessage(packet.bytes()) catch return error.InvalidTransportPacket;
            const peer = self.peers.findBySessionIndex(transport.receiver_index) orelse return error.SessionNotFound;
            const session = peer.sessionByLocalIndex(transport.receiver_index) orelse return error.SessionNotFound;

            packet.state = .prepared;
            packet.remote_static = peer.key;
            packet.session_key = session.recvKey();
            packet.local_session_index = session.localIndex();
            packet.remote_session_index = session.remoteIndex();
            packet.counter = transport.counter;

            try self.emitEvent(on_result, .{ .inbound = packet });
        }

        fn consumeInbound(
            self: *Self,
            packet: *InboundPacket,
            on_result: Engine.Callback,
        ) !void {
            errdefer packet.state = .consume_failed;

            return switch (packet.kind) {
                .handshake => self.consumeHandshake(packet, on_result),
                .transport => self.consumeTransport(packet, on_result),
                .unknown => error.InvalidInboundPacketKind,
            };
        }

        fn consumeHandshake(
            self: *Self,
            packet: *InboundPacket,
            on_result: Engine.Callback,
        ) !void {
            return switch (try Handshake.parseMessageType(packet.bytes())) {
                .init => {
                    const outbound = try self.consumeInit(packet, on_result);
                    try self.emitEvent(on_result, .{ .outbound = outbound });
                },
                .response => try self.consumeResponse(packet, on_result),
            };
        }

        fn consumeInit(
            self: *Self,
            packet: *InboundPacket,
            on_result: Engine.Callback,
        ) !*OutboundPacket {
            const outbound_packet = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer outbound_packet.deinit();

            var handshake = Handshake.readInit(self.local_static, packet.bytes()) catch return error.InvalidHandshakeMessage;
            const peer_key = handshake.peerKey();
            const peer = try self.peers.getOrCreate(peer_key);

            const responder_session_index = try self.allocateSessionIndex();
            const written = try handshake.writeResponse(responder_session_index, outbound_packet.bufRef());
            const material = try handshake.sessionMaterial();
            const now_ms = nowMs();
            const endpoint = packet.remote_endpoint;
            const session = Session.init(.{
                .local_index = responder_session_index,
                .remote_index = handshake.remoteSessionIndex(),
                .peer_key = peer_key,
                .endpoint = endpoint,
                .send_key = material.server_to_client,
                .recv_key = material.client_to_server,
                .timeout_ms = self.config.reject_after_time_ms,
                .now_ms = now_ms,
            });

            self.stats.latest_handshake_ms = now_ms;
            peer.establish(self.local_static.public, endpoint, session, false, now_ms);
            peer.updateTimers(now_ms, 0);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            try self.emitEvent(on_result, .{ .established = peer_key });

            outbound_packet.len = written;
            outbound_packet.kind = .handshake;
            outbound_packet.remote_endpoint = endpoint;
            outbound_packet.remote_static = peer_key;
            outbound_packet.state = .ready_to_send;

            packet.state = .consumed;
            return outbound_packet;
        }

        fn consumeResponse(
            self: *Self,
            packet: *InboundPacket,
            on_result: Engine.Callback,
        ) !void {
            const response = try Handshake.parseResponse(packet.bytes());
            const peer = self.peers.findPendingHandshakeByLocalSessionIndex(response.initiator_session_index) orelse return error.HandshakeNotFound;
            const pending_handshake = if (peer.pending_handshake) |*pending_handshake| pending_handshake else return error.HandshakeNotFound;

            var handshake = pending_handshake.handshake;
            try handshake.readResponse(packet.bytes());
            const material = try handshake.sessionMaterial();

            const now_ms = nowMs();
            const endpoint = packet.remote_endpoint;
            const session = Session.init(.{
                .local_index = handshake.localSessionIndex(),
                .remote_index = handshake.remoteSessionIndex(),
                .peer_key = peer.key,
                .endpoint = endpoint,
                .send_key = material.client_to_server,
                .recv_key = material.server_to_client,
                .timeout_ms = self.config.reject_after_time_ms,
                .now_ms = now_ms,
            });

            self.stats.latest_handshake_ms = now_ms;
            peer.establish(self.local_static.public, endpoint, session, true, now_ms);
            peer.updateTimers(now_ms, 0);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            try self.emitEvent(on_result, .{ .established = peer.key });

            packet.state = .consumed;
        }

        fn consumeTransport(
            self: *Self,
            packet: *InboundPacket,
            on_result: Engine.Callback,
        ) !void {
            if (packet.state != .ready_to_consume) return error.InboundPacketRequiresDecrypt;

            const peer = self.peers.findBySessionIndex(packet.local_session_index) orelse return error.SessionNotFound;
            if (!peer.key.eql(packet.remote_static)) return error.PeerMismatch;

            const session = peer.sessionByLocalIndex(packet.local_session_index) orelse return error.SessionNotFound;
            if (session.remoteIndex() != packet.remote_session_index) return error.SessionIndexMismatch;

            const now_ms = nowMs();
            try session.commitRecv(packet.counter, now_ms);
            peer.endpoint = packet.remote_endpoint;
            peer.last_received_ms = now_ms;
            peer.markOnline(now_ms);
            if (peer.current) |*current| current.setEndpoint(peer.endpoint);
            if (peer.previous) |*previous| previous.setEndpoint(peer.endpoint);
            peer.updateTimers(now_ms, 1);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");

            packet.state = .consumed;
            if (packet.len != 0) {
                try self.emitEvent(on_result, .{ .inbound = packet });
            }
        }

        fn inferInboundKind(packet: *InboundPacket) !InboundPacket.Kind {
            const kind: InboundPacket.Kind = switch (try Message.getMessageType(packet.bytes())) {
                Message.MessageTypeHandshakeInit,
                Message.MessageTypeHandshakeResp,
                => .handshake,
                Message.MessageTypeTransport => .transport,
                else => return error.InvalidInboundPacketKind,
            };

            packet.kind = kind;
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
            request: Engine.SendData,
            on_result: Engine.Callback,
        ) !void {
            const packet = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();

            packet.state = .prepared;
            packet.kind = .transport;
            if (packet.transportPlaintextBufRef().len < request.payload.len) return error.BufferTooSmall;
            @memcpy(packet.transportPlaintextBufRef()[0..request.payload.len], request.payload);

            const peer = self.peers.get(request.remote_key) orelse return error.SessionNotFound;
            const session = if (peer.current) |*session| session else return error.SessionNotFound;
            const sent_ms = nowMs();
            const counter = try session.claimSendCounter(sent_ms);

            packet.len = request.payload.len;
            packet.remote_endpoint = session.endpointValue();
            packet.remote_static = peer.key;
            packet.session_key = session.sendKey();
            packet.remote_session_index = session.remoteIndex();
            packet.counter = counter;

            peer.last_sent_ms = sent_ms;
            peer.updateTimers(sent_ms, 1);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            try self.emitEvent(on_result, .{ .outbound = packet });
        }

        fn createInitiateHandshakeOutbound(
            self: *Self,
            request: Engine.InitiateHandshake,
            on_result: Engine.Callback,
        ) !void {
            const peer = try self.peers.getOrCreate(request.remote_key);
            if (peer.pending_handshake != null) return error.HandshakeInProgress;
            if (self.peers.pendingCount() >= self.config.max_pending) return error.PendingHandshakeLimitReached;

            const packet = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();
            try self.startPendingHandshake(peer, request.remote_endpoint, nowMs(), packet);
            try self.emitEvent(on_result, .{ .outbound = packet });
        }

        fn tickNode(
            self: *Self,
            node: *TimerTreap.Node,
            now_ms: u64,
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

            peer.updateTimers(now_ms, 0);
            while (peer.timers.nextDue(now_ms)) |kind| {
                switch (kind) {
                    .keepalive_deadline => {
                        peer.timers.set(.keepalive_deadline, null);
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
                peer.updateTimers(now_ms, 0);
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
            const packet = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();
            const peer = self.peers.get(peer_key) orelse return error.SessionNotFound;
            const session = if (peer.current) |*session| session else return error.SessionNotFound;
            const sent_ms = nowMs();
            const counter = try session.claimSendCounter(sent_ms);
            packet.len = 0;
            packet.state = .prepared;
            packet.kind = .transport;
            packet.remote_endpoint = session.endpointValue();
            packet.remote_static = peer.key;
            packet.session_key = session.sendKey();
            packet.remote_session_index = session.remoteIndex();
            packet.counter = counter;
            peer.last_sent_ms = sent_ms;
            peer.updateTimers(sent_ms, 1);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            try self.emitEvent(on_result, .{ .outbound = packet });
        }

        fn startPendingHandshake(
            self: *Self,
            peer: *Peer,
            endpoint: AddrPort,
            now_ms: u64,
            packet: *OutboundPacket,
        ) !void {
            const local_session_index = try self.allocateSessionIndex();
            var handshake = try Handshake.initInitiator(self.local_static, peer.key, local_session_index);
            const written = try handshake.writeInit(packet.bufRef());

            peer.startPendingHandshake(self.local_static.public, endpoint, local_session_index, handshake, now_ms);
            peer.updateTimers(now_ms, 0);
            self.syncPeerTimerEntry(peer) catch @panic("OOM");
            packet.len = written;
            packet.kind = .handshake;
            packet.remote_endpoint = endpoint;
            packet.remote_static = peer.key;
            packet.state = .ready_to_send;
        }

        fn emitBeginRekey(self: *Self, peer_key: Key, on_result: Engine.Callback) !void {
            const peer = self.peers.get(peer_key) orelse return;
            if (peer.pending_handshake != null) return;

            const packet = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();
            try self.startPendingHandshake(peer, peer.endpoint, nowMs(), packet);
            try self.emitEvent(on_result, .{ .outbound = packet });
        }

        fn emitRetryHandshake(self: *Self, local_session_index: u32, on_result: Engine.Callback) !void {
            const peer = self.peers.findPendingHandshakeByLocalSessionIndex(local_session_index) orelse return;
            const pending_handshake = if (peer.pending_handshake) |pending_handshake| pending_handshake else return;

            const packet = self.outbound_pool.get() orelse return error.OutOfMemory;
            errdefer packet.deinit();
            peer.clearPendingHandshake();
            try self.startPendingHandshake(peer, pending_handshake.endpoint, nowMs(), packet);
            try self.emitEvent(on_result, .{ .outbound = packet });
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
            const due_ms = peer.timers.earliest() orelse return;

            var entry = self.timer_treap.getEntryFor(.{
                .due_ms = due_ms,
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
            try on_result.handle(event);

            switch (event) {
                .outbound => |packet| {
                    if (packet.kind == .handshake or packet.state == .ready_to_send) {
                        self.stats.transfer_tx +%= @as(u64, @intCast(packet.len));
                    }
                },
                .inbound => |_| {},
                .established => {},
                .offline => {},
                .next_tick_ms => {},
            }
        }

        fn nowMs() u64 {
            const now = lib.time.Instant.now() catch @panic("noise.Engine requires lib.time.Instant");
            if (started == null) {
                started = now;
                return 0;
            }
            return now.since(started.?) / lib.time.ns_per_ms;
        }
    };
}

pub fn TestRunner(comptime lib: type) embed.testing.TestRunner {
    const testing_api = embed.testing;
    const giznet = @import("../../giznet.zig");

    const Cases = struct {
        fn offlineDeadlineMarksPeerOffline(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            try runOfflineDeadlineFlow();
        }

        fn passiveKeepaliveEmitsEmptyTransport(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            try runPassiveKeepaliveFlow();
        }

        fn chachaRekeyTransfer10KiB(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            try runRekeyAfterMessagesFlow(.chacha_poly);
        }

        fn aesRekeyTransfer10KiB(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            try runRekeyAfterMessagesFlow(.aes_256_gcm);
        }

        fn plaintextRekeyTransfer10KiB(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            try runRekeyAfterMessagesFlow(.plaintext);
        }

        fn runOfflineDeadlineFlow() !void {
            const any_lib = lib;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const Session = SessionType.make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2901);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2902);
            const remote_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52102);

            var engine = try EngineType.init(any_lib.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .offline_timeout_ms = 0,
            });
            defer engine.deinit();

            const now_ms = EngineType.nowMs();
            const peer = try engine.peers.getOrCreate(remote_pair.public);
            peer.establish(local_pair.public, remote_endpoint, makeSession(
                Session,
                remote_pair.public,
                remote_endpoint,
                11,
                12,
                0x11,
                0x22,
                engine.config.reject_after_time_ms,
                now_ms,
            ), true, now_ms);
            peer.last_sent_ms = now_ms;
            peer.last_received_ms = now_ms;
            peer.updateTimers(now_ms, 0);
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
                            try any_lib.testing.expect(remote_key.eql(self.expected_remote_key));
                            self.offline_count += 1;
                        },
                        .outbound => |packet| {
                            packet.deinit();
                            return error.UnexpectedOutbound;
                        },
                        .inbound => |packet| {
                            packet.deinit();
                            return error.UnexpectedInbound;
                        },
                        .established => return error.UnexpectedEstablished,
                        .next_tick_ms => |_| self.next_tick_events += 1,
                    }
                }
            };

            var callback_state: CallbackState = .{
                .expected_remote_key = remote_pair.public,
            };
            try engine.drive(.{ .tick = {} }, callback_state.callback());

            try any_lib.testing.expectEqual(@as(usize, 1), callback_state.offline_count);
            try any_lib.testing.expect(peer.is_offline);
            try any_lib.testing.expectEqual(@as(?u64, null), peer.offline_deadline_ms);
            try any_lib.testing.expectEqual(@as(?u64, null), peer.timers.get(.offline_deadline));
        }

        fn runPassiveKeepaliveFlow() !void {
            const any_lib = lib;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const cipher_kind = Cipher.default_kind;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const Session = SessionType.make(any_lib, packet_size, cipher_kind);

            const local_pair = giznet.noise.KeyPair.seed(any_lib, 2911);
            const remote_pair = giznet.noise.KeyPair.seed(any_lib, 2912);
            const remote_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52112);

            var engine = try EngineType.init(any_lib.testing.allocator, local_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .keepalive_timeout_ms = 0,
                .offline_timeout_ms = 10_000,
            });
            defer engine.deinit();

            const receive_now = blk: {
                const start_now = EngineType.nowMs();
                var current_now = start_now;
                while (current_now == start_now) {
                    current_now = EngineType.nowMs();
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
                engine.config.reject_after_time_ms,
                receive_now,
            ), false, receive_now);
            peer.last_sent_ms = receive_now - 1;
            peer.last_received_ms = receive_now;
            peer.updateTimers(receive_now, 0);
            try engine.syncPeerTimerEntry(peer);

            const CallbackState = struct {
                keepalive_packet: ?*OutboundPacket = null,
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
                        .outbound => |packet| {
                            if (self.keepalive_packet != null) {
                                packet.deinit();
                                return error.UnexpectedMultipleOutbounds;
                            }
                            self.keepalive_packet = packet;
                        },
                        .inbound => |packet| {
                            packet.deinit();
                            return error.UnexpectedInbound;
                        },
                        .established => return error.UnexpectedEstablished,
                        .offline => return error.UnexpectedOffline,
                        .next_tick_ms => |_| self.next_tick_events += 1,
                    }
                }
            };

            var callback_state: CallbackState = .{};
            try engine.drive(.{ .tick = {} }, callback_state.callback());

            const packet = callback_state.keepalive_packet orelse return error.MissingKeepalivePacket;
            defer packet.deinit();

            try any_lib.testing.expectEqual(OutboundPacket.Kind.transport, packet.kind);
            try any_lib.testing.expectEqual(OutboundPacket.State.prepared, packet.state);
            try any_lib.testing.expectEqual(@as(usize, 0), packet.len);
            try any_lib.testing.expect(packet.remote_static.eql(remote_pair.public));
            try any_lib.testing.expect(giznet.eqlAddrPort(packet.remote_endpoint, remote_endpoint));
        }

        fn runRekeyAfterMessagesFlow(comptime cipher_kind: Cipher.Kind) !void {
            const any_lib = lib;
            const packet_size = SessionType.legacy_packet_size_capacity;
            const EngineType = make(any_lib, packet_size, cipher_kind);
            const payload_size: usize = 1024;
            const total_transfer_bytes: usize = 10 * 1024;
            const total_packet_count: usize = total_transfer_bytes / payload_size;
            const trigger_message_count: usize = 4;
            const no_rekey_after_time_ms: u64 = 365 * 24 * 60 * 60 * 1000;

            try any_lib.testing.expectEqual(@as(usize, 0), total_transfer_bytes % payload_size);

            const initiator_pair = giznet.noise.KeyPair.seed(any_lib, 1901);
            const responder_pair = giznet.noise.KeyPair.seed(any_lib, 1902);
            const initiator_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52001);
            const responder_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 52002);

            var initiator = try EngineType.init(any_lib.testing.allocator, initiator_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .rekey_after_messages = trigger_message_count,
                .rekey_after_time_ms = no_rekey_after_time_ms,
            });
            defer initiator.deinit();

            var responder = try EngineType.init(any_lib.testing.allocator, responder_pair, .{
                .max_peers = 1,
                .max_pending = 1,
                .rekey_after_messages = trigger_message_count,
                .rekey_after_time_ms = no_rekey_after_time_ms,
            });
            defer responder.deinit();

            const Side = enum {
                initiator,
                responder,
            };

            const CallbackCtx = struct {
                harness_ptr: *anyopaque,
                side: Side,
            };

            const Harness = struct {
                initiator: *EngineType,
                responder: *EngineType,
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
                        .outbound => |packet| try self.handleOutbound(side, packet),
                        .inbound => |packet| try self.handleInbound(side, packet),
                        .established => |remote_key| try self.handleEstablished(side, remote_key),
                        .offline => |remote_key| try self.handleOffline(side, remote_key),
                        .next_tick_ms => |_| self.next_tick_events += 1,
                    }
                }

                fn handleOutbound(self: *@This(), side: Side, packet: *OutboundPacket) !void {
                    const target_side = opposite(side);
                    const target_engine = self.engine(target_side);
                    const remote_endpoint = self.endpoint(side);

                    if (packet.state == .prepared) {
                        try OutboundPacket.encrypt(any_lib, cipher_kind, packet);
                    }

                    const inbound = try target_engine.getInboundPacket();
                    if (inbound.bufRef().len < packet.len) return error.BufferTooSmall;

                    @memcpy(inbound.bufRef()[0..packet.len], packet.bytes());
                    inbound.len = packet.len;
                    inbound.remote_endpoint = remote_endpoint;

                    try target_engine.drive(.{ .inbound_packet = inbound }, self.callback(target_side));
                    packet.deinit();
                    if (inbound.state != .initial) {
                        inbound.deinit();
                    }
                }

                fn handleInbound(self: *@This(), side: Side, packet: *InboundPacket) !void {
                    switch (packet.state) {
                        .prepared => {
                            try InboundPacket.decrtpy(any_lib, cipher_kind, packet);
                            try self.engine(side).drive(.{ .inbound_packet = packet }, self.callback(side));
                        },
                        .consumed => {
                            try self.verifyConsumedInbound(side, packet);
                            packet.deinit();
                        },
                        else => return error.UnexpectedInboundPacketState,
                    }
                }

                fn handleEstablished(self: *@This(), side: Side, remote_key: Key) !void {
                    self.established_events += 1;
                    switch (side) {
                        .initiator => try any_lib.testing.expect(remote_key.eql(self.responder_key)),
                        .responder => try any_lib.testing.expect(remote_key.eql(self.initiator_key)),
                    }
                }

                fn handleOffline(self: *@This(), side: Side, remote_key: Key) !void {
                    _ = side;
                    _ = remote_key;
                    self.offline_events += 1;
                }

                fn verifyConsumedInbound(self: *@This(), side: Side, packet: *InboundPacket) !void {
                    if (side != .responder) return error.UnexpectedInboundOnInitiator;

                    var expected_payload: [payload_size]u8 = undefined;
                    fillPayload(self.received_packets, expected_payload[0..]);

                    try any_lib.testing.expectEqual(@as(usize, payload_size), packet.len);
                    try any_lib.testing.expect(packet.remote_static.eql(self.initiator_key));
                    try any_lib.testing.expect(giznet.eqlAddrPort(packet.remote_endpoint, self.initiator_endpoint));
                    try any_lib.testing.expect(std.mem.eql(u8, expected_payload[0..], packet.bytes()));

                    self.received_packets += 1;
                    self.received_bytes += packet.len;
                }

                fn engine(self: *@This(), side: Side) *EngineType {
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
                    try self.initiator.drive(.{
                        .send_data = .{
                            .remote_key = self.responder_key,
                            .payload = packet_buffer[0..],
                        },
                    }, self.callback(.initiator));
                }
            };

            var harness: Harness = .{
                .initiator = &initiator,
                .responder = &responder,
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

            try any_lib.testing.expectEqual(@as(usize, 2), harness.established_events);
            try any_lib.testing.expectEqual(@as(usize, 1), initiator.stats.session_count);
            try any_lib.testing.expectEqual(@as(usize, 1), responder.stats.session_count);

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

            try any_lib.testing.expect(harness.established_events >= 4);
            try any_lib.testing.expectEqual(trigger_message_count, harness.received_packets);
            try any_lib.testing.expectEqual(trigger_message_count * payload_size, harness.received_bytes);
            try any_lib.testing.expectEqual(@as(usize, 2), initiator.stats.session_count);
            try any_lib.testing.expectEqual(@as(usize, 2), responder.stats.session_count);
            try any_lib.testing.expectEqual(@as(usize, 0), initiator.stats.pending_handshake_count);
            try any_lib.testing.expectEqual(@as(usize, 0), responder.stats.pending_handshake_count);

            const initiator_peer_after = initiator.peers.get(responder_pair.public) orelse return error.SessionNotFound;
            const responder_peer_after = responder.peers.get(initiator_pair.public) orelse return error.SessionNotFound;
            const initiator_current = initiator_peer_after.current orelse return error.SessionNotFound;
            const initiator_previous = initiator_peer_after.previous orelse return error.SessionNotFound;
            const responder_current = responder_peer_after.current orelse return error.SessionNotFound;
            const responder_previous = responder_peer_after.previous orelse return error.SessionNotFound;

            try any_lib.testing.expect(initiator_current.localIndex() != initiator_old_current.localIndex());
            try any_lib.testing.expectEqual(initiator_old_current.localIndex(), initiator_previous.localIndex());
            try any_lib.testing.expect(responder_current.localIndex() != responder_old_current.localIndex());
            try any_lib.testing.expectEqual(responder_old_current.localIndex(), responder_previous.localIndex());

            while (chunk_index < total_packet_count) : (chunk_index += 1) {
                try harness.sendFromInitiator(chunk_index);
            }
            try any_lib.testing.expectEqual(total_packet_count, harness.received_packets);
            try any_lib.testing.expectEqual(total_transfer_bytes, harness.received_bytes);
            try any_lib.testing.expect(harness.established_events >= 4);
        }

        fn makeSession(
            Session: type,
            peer_key: Key,
            endpoint: AddrPort,
            local_index: u32,
            remote_index: u32,
            send_fill: u8,
            recv_fill: u8,
            timeout_ms: u64,
            now_ms: u64,
        ) Session {
            return Session.init(.{
                .local_index = local_index,
                .remote_index = remote_index,
                .peer_key = peer_key,
                .endpoint = endpoint,
                .send_key = giznet.noise.Key{ .bytes = [_]u8{send_fill} ** 32 },
                .recv_key = giznet.noise.Key{ .bytes = [_]u8{recv_fill} ** 32 },
                .timeout_ms = timeout_ms,
                .now_ms = now_ms,
            });
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run(
                "offline_deadline_marks_peer_offline",
                testing_api.TestRunner.fromFn(lib, 512 * 1024, Cases.offlineDeadlineMarksPeerOffline),
            );
            t.run(
                "passive_keepalive_emits_empty_transport",
                testing_api.TestRunner.fromFn(lib, 512 * 1024, Cases.passiveKeepaliveEmitsEmptyTransport),
            );
            t.run(
                "chacha_poly_rekey_transfer_10KiB",
                testing_api.TestRunner.fromFn(lib, 512 * 1024, Cases.chachaRekeyTransfer10KiB),
            );
            t.run(
                "aes_256_gcm_rekey_transfer_10KiB",
                testing_api.TestRunner.fromFn(lib, 512 * 1024, Cases.aesRekeyTransfer10KiB),
            );
            t.run(
                "plaintext_rekey_transfer_10KiB",
                testing_api.TestRunner.fromFn(lib, 512 * 1024, Cases.plaintextRekeyTransfer10KiB),
            );
            return true;
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
