const embed = @import("embed");
const mem = embed.mem;
const noise = @import("noise");

const conn = @import("conn.zig");
const errors = @import("errors.zig");
const map = @import("map.zig");
const protocol = @import("protocol.zig");
const service_mux = @import("service_mux.zig");

// Single-threaded: callers must serialize all Host access.
pub const PeerState = enum {
    new,
    connecting,
    established,
    failed,
};

pub const Route = union(enum) {
    none,
    response: usize,
    direct: struct {
        peer: noise.Key,
        // Direct packets always stay on the default lane today.
        service: u64,
        protocol_byte: u8,
        // This slice aliases the caller-provided plaintext buffer.
        payload: []const u8,
    },
};

pub fn Host(comptime Noise: type) type {
    const ConnType = conn.Conn(Noise);
    const KeyPair = Noise.KeyPair;
    const ServiceMuxType = service_mux.ServiceMux(Noise);

    return struct {
        allocator: mem.Allocator,
        local_static: KeyPair,
        allow_unknown: bool,
        service_config: service_mux.Config,
        peers_by_key: map.KeyMap(*Peer),
        peers_by_index: map.UIntMap(u32, *Peer),
        pending_by_index: map.UIntMap(u32, *Peer),
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
            service_config: service_mux.Config,
        ) !Self {
            return .{
                .allocator = allocator,
                .local_static = local_static,
                .allow_unknown = allow_unknown,
                .service_config = service_config,
                .peers_by_key = try map.KeyMap(*Peer).init(allocator, 8),
                .peers_by_index = try map.UIntMap(u32, *Peer).init(allocator, 8),
                .pending_by_index = try map.UIntMap(u32, *Peer).init(allocator, 8),
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

        pub fn beginDial(self: *Self, remote_pk: noise.Key, wire_out: []u8, now_ms: u64) !usize {
            var peer = try self.ensurePeer(remote_pk, true);
            try self.clearPeerIndexes(peer);
            peer.conn = ConnType.initInitiator(self.local_static, remote_pk, try self.allocateIndex());
            peer.state = .connecting;
            errdefer peer.state = .failed;
            const written = try peer.conn.beginHandshake(wire_out, now_ms);
            _ = try self.pending_by_index.put(peer.conn.localIndex(), peer);
            return written;
        }

        pub fn handlePacket(
            self: *Self,
            data: []const u8,
            plaintext_out: []u8,
            response_out: []u8,
            now_ms: u64,
        ) !Route {
            const message_type = try noise.Message.getMessageType(data);
            return switch (message_type) {
                .handshake_init => self.handleHandshakeInit(data, response_out, now_ms),
                .handshake_resp => self.handleHandshakeResp(data, now_ms),
                .transport => self.handleTransport(data, plaintext_out, now_ms),
                else => .none,
            };
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
            const encrypted = try session.encrypt(encoded_payload[0..wrapped_len], ciphertext_buf, now_ms);
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

        fn handleHandshakeInit(self: *Self, data: []const u8, response_out: []u8, now_ms: u64) !Route {
            var temp_conn = ConnType.initResponder(self.local_static, try self.allocateIndex());
            var response_buf: [noise.Message.handshake_resp_header_size + 64]u8 = undefined;
            const written = try temp_conn.acceptHandshakeInit(data, &response_buf, now_ms);
            const remote_pk = temp_conn.remotePublicKey();

            var peer = if (self.getPeer(remote_pk)) |existing|
                existing
            else if (self.allow_unknown)
                try self.createPeer(remote_pk, false)
            else
                return errors.Error.UnknownPeer;

            try self.clearPeerIndexes(peer);
            peer.conn = temp_conn;
            peer.key = remote_pk;
            peer.state = .established;
            _ = try self.peers_by_key.put(peer.key, peer);
            _ = try self.peers_by_index.put(peer.conn.localIndex(), peer);
            if (response_out.len < written) return errors.Error.BufferTooSmall;
            @memcpy(response_out[0..written], response_buf[0..written]);
            return .{ .response = written };
        }

        fn handleHandshakeResp(self: *Self, data: []const u8, now_ms: u64) !Route {
            const resp = try noise.Message.parseHandshakeResp(data);
            const peer = self.pending_by_index.get(resp.receiver_index) orelse return .none;
            peer.conn.handleHandshakeResponse(data, now_ms) catch |err| {
                _ = self.pending_by_index.remove(resp.receiver_index);
                peer.state = .failed;
                return err;
            };
            try self.clearPeerIndexes(peer);
            peer.state = .established;
            _ = try self.peers_by_index.put(peer.conn.localIndex(), peer);
            return .none;
        }

        fn handleTransport(self: *Self, data: []const u8, plaintext_out: []u8, now_ms: u64) !Route {
            const transport_msg = try noise.Message.parseTransportMessage(data);
            const peer = self.peers_by_index.get(transport_msg.receiver_index) orelse return .none;
            const decrypted = try peer.conn.decryptPayload(data, plaintext_out, now_ms);

            if (protocol.isStream(decrypted.protocol_byte)) {
                // Authenticated packets are consumed at the Noise layer; local
                // routing failures must be treated as drops, not retriable errors.
                const decoded_service = noise.Varint.decode(decrypted.payload) catch return .none;
                peer.mux.input(
                    decoded_service.value,
                    decrypted.protocol_byte,
                    decrypted.payload[decoded_service.n..],
                ) catch return .none;
                return .none;
            }

            // Direct delivery wins over best-effort mux enqueue for the default
            // lane, so local queue pressure does not turn into a retriable error.
            peer.mux.input(0, decrypted.protocol_byte, decrypted.payload) catch {};
            return .{
                .direct = .{
                    .peer = peer.key,
                    .service = 0,
                    .protocol_byte = decrypted.protocol_byte,
                    .payload = decrypted.payload,
                },
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
            peer.* = .{
                .key = remote_pk,
                .conn = if (initiator)
                    ConnType.initInitiator(self.local_static, remote_pk, 0)
                else
                    ConnType.initResponder(self.local_static, 0),
                .mux = try ServiceMuxType.init(self.allocator, remote_pk, self.service_config),
            };
            errdefer peer.mux.deinit();
            _ = try self.peers_by_key.put(remote_pk, peer);
            return peer;
        }

        fn clearPeerIndexes(self: *Self, peer: *Peer) !void {
            try self.removePeerFromIndexTable(&self.peers_by_index, peer);
            try self.removePeerFromIndexTable(&self.pending_by_index, peer);
        }

        fn removePeerFromIndexTable(self: *Self, table: *map.UIntMap(u32, *Peer), peer: *Peer) !void {
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

pub fn testAll(comptime lib: type, testing: anytype, allocator: mem.Allocator) !void {
    const noise_mod = @import("noise");
    const Noise = noise_mod.make(noise_mod.LibAdapter.make(lib));
    const HostType = Host(Noise);

    const alice_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{9} ** noise.Key.key_size));
    const bob_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{10} ** noise.Key.key_size));

    var stream_capture = StreamCapture{};
    var client = try HostType.init(allocator, alice_static, false, .{
        .on_new_service = allowAllServices,
    });
    defer client.deinit();
    var server = try HostType.init(allocator, bob_static, true, .{
        .on_new_service = allowAllServices,
        .stream_adapter = streamCaptureAdapter(&stream_capture),
    });
    defer server.deinit();

    var init_wire: [128]u8 = undefined;
    const init_n = try client.beginDial(bob_static.public, &init_wire, 1);

    var plaintext: [128]u8 = undefined;
    var response_wire: [128]u8 = undefined;
    const response = try server.handlePacket(init_wire[0..init_n], &plaintext, &response_wire, 2);
    const response_n = response.response;
    _ = try client.handlePacket(response_wire[0..response_n], &plaintext, &response_wire, 3);

    try testing.expectEqual(@as(usize, 1), client.peerCount());
    try testing.expectEqual(@as(usize, 1), server.peerCount());

    var send_plaintext: [64]u8 = undefined;
    var send_ciphertext: [80]u8 = undefined;
    var send_wire: [96]u8 = undefined;
    const send_n = try client.sendDirect(
        bob_static.public,
        protocol.event,
        "host",
        &send_plaintext,
        &send_ciphertext,
        &send_wire,
        10,
    );
    const routed = try server.handlePacket(send_wire[0..send_n], &plaintext, &response_wire, 11);
    try testing.expectEqual(protocol.event, routed.direct.protocol_byte);
    try testing.expectEqualStrings("host", routed.direct.payload);

    var stream_plaintext: [64]u8 = undefined;
    const stream_n = try client.sendStream(
        bob_static.public,
        7,
        protocol.http,
        "ok",
        &stream_plaintext,
        &send_ciphertext,
        &send_wire,
        12,
    );
    try testing.expectEqual(@as(u64, 12), client.connection(bob_static.public).?.last_sent_ms);
    _ = try server.handlePacket(send_wire[0..stream_n], &plaintext, &response_wire, 13);
    try testing.expectEqual(@as(u64, 7), stream_capture.service);
    try testing.expectEqual(protocol.http, stream_capture.protocol_byte);
    try testing.expectEqualStrings("ok", stream_capture.payload[0..stream_capture.len]);

    var locked_server = try HostType.init(allocator, bob_static, false, .{
        .on_new_service = allowAllServices,
    });
    defer locked_server.deinit();
    try locked_server.registerPeer(alice_static.public);

    var stranger_static = try HostType.init(allocator, bob_static, false, .{
        .on_new_service = allowAllServices,
    });
    defer stranger_static.deinit();
    try testing.expectError(errors.Error.UnknownPeer, stranger_static.handlePacket(init_wire[0..init_n], &plaintext, &response_wire, 19));

    const init_again_n = try client.beginDial(bob_static.public, &init_wire, 20);
    const locked_response = try locked_server.handlePacket(init_wire[0..init_again_n], &plaintext, &response_wire, 21);
    try testing.expect(locked_response == .response);

    const second_wire_n = try client.beginDial(bob_static.public, &init_wire, 30);
    try testing.expect(client.pending_by_index.count() == 1);

    const bad_response_n = try server.handlePacket(init_wire[0..second_wire_n], &plaintext, &response_wire, 31);
    response_wire[bad_response_n.response - 1] ^= 1;
    try testing.expectError(error.AuthenticationFailed, client.handlePacket(response_wire[0..bad_response_n.response], &plaintext, &send_wire, 32));
    try testing.expect(client.pending_by_index.count() == 0);
}

fn allowAllServices(_: noise.Key, _: u64) bool {
    return true;
}

const StreamCapture = struct {
    service: u64 = 0,
    protocol_byte: u8 = 0,
    payload: [32]u8 = [_]u8{0} ** 32,
    len: usize = 0,
};

fn streamCaptureAdapter(ctx: *StreamCapture) service_mux.StreamAdapter {
    return .{
        .ctx = ctx,
        .input = streamCaptureInput,
    };
}

fn streamCaptureInput(ctx: *anyopaque, service: u64, protocol_byte: u8, data: []const u8) !void {
    const capture: *StreamCapture = @ptrCast(@alignCast(ctx));
    if (data.len > capture.payload.len) return errors.Error.BufferTooSmall;
    capture.service = service;
    capture.protocol_byte = protocol_byte;
    capture.len = data.len;
    @memcpy(capture.payload[0..data.len], data);
}
