const dep = @import("dep");
const mem = dep.embed.mem;
const noise = @import("../noise.zig");

const ConnFile = @import("Conn.zig");
const consts = @import("consts.zig");
const errors = @import("errors.zig");
const protocol = @import("protocol.zig");
const ServiceMuxFile = @import("ServiceMux.zig");
const KeyMapFile = @import("KeyMap.zig");
const UIntMapFile = @import("UIntMap.zig");

// Single-threaded: callers must serialize all Host access.
pub const PeerState = enum {
    new,
    connecting,
    established,
    failed,
};

pub const Route = union(enum) {
    none,
    response: struct {
        n: usize,
        peer: noise.Key,
    },
    direct: struct {
        peer: noise.Key,
        // Direct packets always stay on the default lane today.
        service: u64,
        protocol_byte: u8,
        // This slice aliases the caller-provided plaintext buffer.
        payload: []const u8,
    },
};

pub const PeerStateTransition = struct {
    peer: noise.Key,
    state: PeerState,
};

pub const PacketResult = struct {
    route: Route = .none,
    authenticated_peer: ?noise.Key = null,
    peer_state_transition: ?PeerStateTransition = null,
    err: ?anyerror = null,
};

pub fn make(comptime lib: type, comptime Noise: type) type {
    const ConnType = ConnFile.make(Noise);
    const KeyPair = Noise.KeyPair;
    const ServiceMuxType = ServiceMuxFile.make(lib, Noise);

    return struct {
        pub const ReadResult = ServiceMuxType.ReadResult;

        allocator: mem.Allocator,
        local_static: KeyPair,
        allow_unknown: bool,
        service_config: ServiceMuxFile.Config,
        peers_by_key: KeyMapFile.make(*Peer),
        peers_by_index: UIntMapFile.make(u32, *Peer),
        pending_by_index: UIntMapFile.make(u32, *Peer),
        next_index: u32 = 1,

        const Self = @This();
        const Peer = struct {
            key: noise.Key,
            conn: ConnType,
            mux: ServiceMuxType,
            state: PeerState = .new,
        };

        pub fn init(
            allocator: mem.Allocator,
            local_static: KeyPair,
            allow_unknown: bool,
            service_config: ServiceMuxFile.Config,
        ) !Self {
            return .{
                .allocator = allocator,
                .local_static = local_static,
                .allow_unknown = allow_unknown,
                .service_config = service_config,
                .peers_by_key = try KeyMapFile.make(*Peer).init(allocator, 8),
                .peers_by_index = try UIntMapFile.make(u32, *Peer).init(allocator, 8),
                .pending_by_index = try UIntMapFile.make(u32, *Peer).init(allocator, 8),
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.peers_by_key.slots) |slot| {
                if (slot.state != .full) continue;
                slot.value.mux.deinit();
                self.allocator.destroy(slot.value);
            }
            self.pending_by_index.deinit();
            self.peers_by_index.deinit();
            self.peers_by_key.deinit();
        }

        pub fn registerPeer(self: *Self, remote_pk: noise.Key) !void {
            _ = try self.ensurePeer(remote_pk, true);
        }

        pub fn connection(self: *Self, remote_pk: noise.Key) ?*ConnType {
            const peer = self.getPeer(remote_pk) orelse return null;
            return &peer.conn;
        }

        pub fn serviceMux(self: *Self, remote_pk: noise.Key) ?*ServiceMuxType {
            const peer = self.getPeer(remote_pk) orelse return null;
            return &peer.mux;
        }

        pub fn peerState(self: *const Self, remote_pk: noise.Key) ?PeerState {
            const peer = self.peers_by_key.get(remote_pk) orelse return null;
            return peer.state;
        }

        pub fn tick(self: *Self, now_ms: u64) !void {
            var first_error: ?anyerror = null;
            for (self.peers_by_key.slots) |slot| {
                if (slot.state != .full) continue;
                slot.value.mux.tick(now_ms) catch |err| {
                    if (first_error == null) first_error = err;
                };
            }
            if (first_error) |err| return err;
        }

        pub fn beginDial(self: *Self, remote_pk: noise.Key, wire_out: []u8, now_ms: u64) !usize {
            var peer = try self.ensurePeer(remote_pk, true);
            try self.clearPeerIndexes(peer);
            peer.conn = ConnType.initInitiator(self.local_static, remote_pk, try self.allocateIndex());
            peer.state = .connecting;
            errdefer peer.state = .failed;
            const written = try peer.conn.beginHandshake(wire_out, now_ms);
            errdefer peer.conn.abortHandshakeAttempt();
            _ = try self.pending_by_index.put(peer.conn.localIndex(), peer);
            return written;
        }

        pub fn pollDialRetry(self: *Self, remote_pk: noise.Key, wire_out: []u8, now_ms: u64) !?usize {
            const peer = self.getPeer(remote_pk) orelse return errors.Error.PeerNotFound;
            if (peer.conn.state() == .closed) return errors.Error.ConnClosed;
            if (peer.conn.handshake == null) return null;
            if (peer.conn.handshake_attempt_start_ms != 0 and
                now_ms >= peer.conn.handshake_attempt_start_ms and
                now_ms - peer.conn.handshake_attempt_start_ms >= consts.rekey_attempt_time_ms)
            {
                peer.conn.abortHandshakeAttempt();
                peer.state = .failed;
                _ = self.pending_by_index.remove(peer.conn.localIndex());
                return errors.Error.HandshakeTimeout;
            }
            if (peer.conn.last_handshake_sent_ms == 0) return null;
            if (now_ms - peer.conn.last_handshake_sent_ms < consts.rekey_timeout_ms) return null;
            return try peer.conn.beginHandshake(wire_out, now_ms);
        }

        pub fn handlePacket(
            self: *Self,
            data: []const u8,
            plaintext_out: []u8,
            response_out: []u8,
            now_ms: u64,
        ) !Route {
            const result = self.handlePacketResult(data, plaintext_out, response_out, now_ms);
            if (result.err) |err| return err;
            return result.route;
        }

        pub fn sendDirect(
            self: *Self,
            remote_pk: noise.Key,
            protocol_byte: u8,
            payload: []const u8,
            plaintext_buf: []u8,
            ciphertext_buf: []u8,
            wire_out: []u8,
            now_ms: u64,
        ) !usize {
            const peer = self.getPeer(remote_pk) orelse return errors.Error.PeerNotFound;
            return peer.conn.send(protocol_byte, payload, plaintext_buf, ciphertext_buf, wire_out, now_ms);
        }

        pub fn sendStream(
            self: *Self,
            remote_pk: noise.Key,
            service: u64,
            protocol_byte: u8,
            payload: []const u8,
            plaintext_buf: []u8,
            ciphertext_buf: []u8,
            wire_out: []u8,
            now_ms: u64,
        ) !usize {
            if (!protocol.isStream(protocol_byte)) return errors.Error.UnsupportedProtocol;

            const peer = self.getPeer(remote_pk) orelse return errors.Error.PeerNotFound;
            const session = peer.conn.currentSession() orelse return errors.Error.NoSession;

            const prefix_len = noise.Varint.encode(plaintext_buf, service);
            if (plaintext_buf.len < prefix_len + payload.len) return errors.Error.BufferTooSmall;
            @memcpy(plaintext_buf[prefix_len .. prefix_len + payload.len], payload);

            var encoded_payload: [noise.Message.max_payload_size]u8 = undefined;
            const wrapped_len = try noise.Message.encodePayload(
                &encoded_payload,
                protocol_byte,
                plaintext_buf[0 .. prefix_len + payload.len],
            );
            const encrypted = try session.encrypt(encoded_payload[0..wrapped_len], ciphertext_buf);
            peer.conn.last_sent_ms = now_ms;
            return try noise.Message.buildTransportMessage(
                wire_out,
                session.remoteIndex(),
                encrypted.nonce,
                ciphertext_buf[0..encrypted.n],
            );
        }

        pub fn peerCount(self: *const Self) usize {
            return self.peers_by_key.count();
        }

        pub fn read(self: *Self, remote_pk: noise.Key, out: []u8) !ServiceMuxType.ReadResult {
            const peer = self.getPeer(remote_pk) orelse return errors.Error.PeerNotFound;
            return peer.mux.read(out);
        }

        pub fn readServiceProtocol(
            self: *Self,
            remote_pk: noise.Key,
            service: u64,
            protocol_byte: u8,
            out: []u8,
        ) !usize {
            const peer = self.getPeer(remote_pk) orelse return errors.Error.PeerNotFound;
            return peer.mux.readServiceProtocol(service, protocol_byte, out);
        }

        pub fn sendMuxStream(
            self: *Self,
            remote_pk: noise.Key,
            service: u64,
            stream_id: u64,
            payload: []const u8,
            now_ms: u64,
        ) !usize {
            const peer = self.getPeer(remote_pk) orelse return errors.Error.PeerNotFound;
            return peer.mux.sendStream(service, stream_id, payload, now_ms);
        }

        pub fn recvMuxStream(
            self: *Self,
            remote_pk: noise.Key,
            service: u64,
            stream_id: u64,
            out: []u8,
        ) !usize {
            const peer = self.getPeer(remote_pk) orelse return errors.Error.PeerNotFound;
            return peer.mux.recvStream(service, stream_id, out);
        }

        pub fn closeMuxStream(
            self: *Self,
            remote_pk: noise.Key,
            service: u64,
            stream_id: u64,
            now_ms: u64,
        ) !void {
            const peer = self.getPeer(remote_pk) orelse return errors.Error.PeerNotFound;
            try peer.mux.closeStream(service, stream_id, now_ms);
        }

        pub fn handlePacketResult(
            self: *Self,
            data: []const u8,
            plaintext_out: []u8,
            response_out: []u8,
            now_ms: u64,
        ) PacketResult {
            const message_type = noise.Message.getMessageType(data) catch |err| return .{ .err = err };
            return switch (message_type) {
                .handshake_init => self.handleHandshakeInitDetailed(data, response_out, now_ms),
                .handshake_resp => self.handleHandshakeRespDetailed(data, now_ms),
                .transport => self.handleTransportDetailed(data, plaintext_out, now_ms),
                else => .{},
            };
        }

        fn handleHandshakeInitDetailed(self: *Self, data: []const u8, response_out: []u8, now_ms: u64) PacketResult {
            const local_index = self.allocateIndex() catch |err| return .{ .err = err };
            var temp_conn = ConnType.initResponder(self.local_static, local_index);
            var response_buf: [noise.Message.handshake_resp_header_size + 64]u8 = undefined;
            const written = temp_conn.acceptHandshakeInit(data, &response_buf, now_ms) catch |err| return .{ .err = err };
            if (response_out.len < written) return .{ .err = errors.Error.BufferTooSmall };
            const remote_pk = temp_conn.remotePublicKey();

            var peer = if (self.getPeer(remote_pk)) |existing|
                existing
            else if (self.allow_unknown)
                self.createPeer(remote_pk, false) catch |err| return .{ .err = err }
            else
                return .{ .err = errors.Error.UnknownPeer };

            const previous_conn = peer.conn;
            const previous_state = peer.state;
            self.clearPeerIndexes(peer) catch |err| return .{ .err = err };
            errdefer {
                peer.conn = previous_conn;
                peer.state = previous_state;
                switch (previous_state) {
                    .established => if (previous_conn.localIndex() != 0) {
                        _ = self.peers_by_index.put(previous_conn.localIndex(), peer) catch {};
                    },
                    .connecting => if (previous_conn.localIndex() != 0 and previous_conn.handshake != null) {
                        _ = self.pending_by_index.put(previous_conn.localIndex(), peer) catch {};
                    },
                    else => {},
                }
            }
            peer.conn = temp_conn;
            peer.key = remote_pk;
            _ = self.peers_by_key.put(peer.key, peer) catch |err| return .{ .err = err };
            _ = self.peers_by_index.put(peer.conn.localIndex(), peer) catch |err| return .{ .err = err };
            peer.state = .established;
            @memcpy(response_out[0..written], response_buf[0..written]);
            return .{
                .route = .{ .response = .{ .n = written, .peer = remote_pk } },
                .authenticated_peer = remote_pk,
                .peer_state_transition = .{ .peer = remote_pk, .state = .established },
            };
        }

        fn handleHandshakeRespDetailed(self: *Self, data: []const u8, now_ms: u64) PacketResult {
            const resp = noise.Message.parseHandshakeResp(data) catch |err| return .{ .err = err };
            const peer = self.pending_by_index.get(resp.receiver_index) orelse return .{};
            peer.conn.handleHandshakeResponse(data, now_ms) catch |err| {
                _ = self.pending_by_index.remove(resp.receiver_index);
                peer.state = .failed;
                return .{
                    .peer_state_transition = .{ .peer = peer.key, .state = .failed },
                    .err = err,
                };
            };
            _ = self.peers_by_index.put(peer.conn.localIndex(), peer) catch |err| return .{
                .authenticated_peer = peer.key,
                .err = err,
            };
            _ = self.pending_by_index.remove(resp.receiver_index);
            peer.state = .established;
            return .{
                .authenticated_peer = peer.key,
                .peer_state_transition = .{ .peer = peer.key, .state = .established },
            };
        }

        fn handleTransportDetailed(self: *Self, data: []const u8, plaintext_out: []u8, now_ms: u64) PacketResult {
            const transport_msg = noise.Message.parseTransportMessage(data) catch |err| return .{ .err = err };
            const peer = self.peers_by_index.get(transport_msg.receiver_index) orelse return .{};
            const decrypted = peer.conn.decryptPayload(data, plaintext_out, now_ms) catch |err| return .{ .err = err };

            if (protocol.isStream(decrypted.protocol_byte)) {
                // Authenticated packets are consumed at the Noise layer; local
                // routing failures must be treated as drops, not retriable errors.
                const decoded_service = noise.Varint.decode(decrypted.payload) catch |err| return .{
                    .authenticated_peer = peer.key,
                    .err = err,
                };
                peer.mux.inputAt(
                    decoded_service.value,
                    decrypted.protocol_byte,
                    decrypted.payload[decoded_service.n..],
                    now_ms,
                ) catch |err| return .{
                    .authenticated_peer = peer.key,
                    .err = err,
                };
                return .{ .authenticated_peer = peer.key };
            }

            // Direct delivery wins over best-effort mux enqueue for the default
            // lane, so local queue pressure does not turn into a retriable error.
            peer.mux.inputAt(0, decrypted.protocol_byte, decrypted.payload, now_ms) catch {};
            return .{
                .route = .{
                    .direct = .{
                        .peer = peer.key,
                        .service = 0,
                        .protocol_byte = decrypted.protocol_byte,
                        .payload = decrypted.payload,
                    },
                },
                .authenticated_peer = peer.key,
            };
        }

        fn getPeer(self: *Self, remote_pk: noise.Key) ?*Peer {
            return self.peers_by_key.get(remote_pk);
        }

        fn ensurePeer(self: *Self, remote_pk: noise.Key, initiator: bool) !*Peer {
            if (self.getPeer(remote_pk)) |peer| return peer;

            return try self.createPeer(remote_pk, initiator);
        }

        fn createPeer(self: *Self, remote_pk: noise.Key, initiator: bool) !*Peer {
            const peer = try self.allocator.create(Peer);
            errdefer self.allocator.destroy(peer);
            var service_config = self.service_config;
            service_config.is_client = isKcpClient(self.local_static.public, remote_pk);
            peer.* = .{
                .key = remote_pk,
                .conn = if (initiator)
                    ConnType.initInitiator(self.local_static, remote_pk, 0)
                else
                    ConnType.initResponder(self.local_static, 0),
                .mux = try ServiceMuxType.init(self.allocator, remote_pk, service_config),
            };
            errdefer peer.mux.deinit();
            _ = try self.peers_by_key.put(remote_pk, peer);
            return peer;
        }

        fn clearPeerIndexes(self: *Self, peer: *Peer) !void {
            try self.removePeerFromIndexTable(&self.peers_by_index, peer);
            try self.removePeerFromIndexTable(&self.pending_by_index, peer);
        }

        fn removePeerFromIndexTable(self: *Self, table: *UIntMapFile.make(u32, *Peer), peer: *Peer) !void {
            const keys = try self.allocator.alloc(u32, table.count());
            defer self.allocator.free(keys);

            var count: usize = 0;
            for (table.slots) |slot| {
                if (slot.state != .full) continue;
                if (slot.value != peer) continue;
                keys[count] = slot.key;
                count += 1;
            }

            for (keys[0..count]) |key| {
                _ = table.remove(key);
            }
        }

        fn allocateIndex(self: *Self) !u32 {
            const start = self.next_index;
            while (true) {
                const candidate = self.next_index;
                self.next_index +%= 1;
                if (self.next_index == 0) self.next_index = 1;
                if (candidate == 0) continue;
                if (self.peers_by_index.get(candidate) == null and self.pending_by_index.get(candidate) == null) {
                    return candidate;
                }
                if (self.next_index == start) return errors.Error.NoFreeIndex;
            }
        }
    };
}

fn isKcpClient(local_pk: noise.Key, remote_pk: noise.Key) bool {
    for (local_pk.data, remote_pk.data) |lhs, rhs| {
        if (lhs < rhs) return true;
        if (lhs > rhs) return false;
    }
    return false;
}

