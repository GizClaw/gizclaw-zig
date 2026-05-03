const glib = @import("glib");
const AddrPort = glib.net.netip.AddrPort;

const giznet = @import("../../../giznet.zig");
const Cipher = @import("../../noise/Cipher.zig");
const EngineType = @import("../../noise/Engine.zig");
const InboundPacket = @import("../../packet/Inbound.zig");
const Key = @import("../../noise/Key.zig");
const KeyPair = @import("../../noise/KeyPair.zig");
const OutboundPacket = @import("../../packet/Outbound.zig");
const SessionType = @import("../../noise/Session.zig");

const MultiPeerDirection = enum(u8) {
    left_to_right = 1,
    right_to_left = 2,
};

pub const SinglePeerReport = struct {
    bytes: usize,
    elapsed_ns: u64,
    bytes_per_second: u64,
    mbps: u64,
    received_packets: usize,
    received_bytes: usize,
    established_events: usize,
    rekey_count: usize,
    initiator_session_count: usize,
    responder_session_count: usize,
};

pub const MultiPeerReport = struct {
    peer_count: usize,
    payload_bytes_per_peer: usize,
    established_events: usize,
    rekey_count_per_relation: usize,
    left_hub_session_count: usize,
    right_hub_session_count: usize,
};

pub fn runSinglePeerTransfer(
    comptime grt: type,
    comptime cipher_kind: Cipher.Kind,
    comptime total_transfer_bytes: usize,
    comptime rekey_after_messages: u64,
) !SinglePeerReport {
    const payload_size: usize = 1024;
    const packet_size = SessionType.legacy_packet_size_capacity;
    const Engine = EngineType.make(grt, packet_size, cipher_kind);
    const EngineHarness = EngineWithPools(grt, Engine, packet_size);
    const rekey_after_messages_usize: usize = if (rekey_after_messages == glib.std.math.maxInt(u64))
        0
    else
        @intCast(rekey_after_messages);
    const chunk_count: usize = total_transfer_bytes / payload_size;
    const expected_rekey_count: usize = if (rekey_after_messages_usize == 0)
        0
    else
        chunk_count / rekey_after_messages_usize;
    const no_rekey_after_time: glib.time.duration.Duration = 365 * glib.time.duration.Day;

    try grt.std.testing.expectEqual(@as(usize, 0), total_transfer_bytes % payload_size);

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
        next_tick_events: usize = 0,
        initiator_callback_ctx: ?*CallbackCtx = null,
        responder_callback_ctx: ?*CallbackCtx = null,

        fn callback(self: *@This(), side: Side) EngineType.Callback {
            const ctx = switch (side) {
                .initiator => self.initiator_callback_ctx orelse unreachable,
                .responder => self.responder_callback_ctx orelse unreachable,
            };
            return .{
                .ctx = ctx,
                .call = callbackFn,
            };
        }

        fn callbackFn(ctx: *anyopaque, result: EngineType.DriveOutput) anyerror!void {
            const callback_ctx: *CallbackCtx = @ptrCast(@alignCast(ctx));
            const harness: *@This() = @ptrCast(@alignCast(callback_ctx.harness_ptr));
            try harness.handleResult(callback_ctx.side, result);
        }

        fn handleResult(self: *@This(), side: Side, result: EngineType.DriveOutput) !void {
            switch (result) {
                .outbound => |packet| try self.handleOutbound(side, packet),
                .inbound => |packet| try self.handleInbound(side, packet),
                .established => |remote_key| try self.handleEstablished(side, remote_key),
                .offline => return error.UnexpectedOffline,
                .next_tick_deadline => |_| self.next_tick_events += 1,
            }
        }

        fn handleOutbound(self: *@This(), side: Side, packet: *OutboundPacket) !void {
            const target_side = opposite(side);
            const target_engine = self.engineHarness(target_side);
            const remote_endpoint = self.endpoint(side);

            if (packet.state == .prepared) {
                try OutboundPacket.encrypt(grt, cipher_kind, packet);
            }

            const inbound = try target_engine.allocInboundPacket();
            errdefer inbound.deinit();
            if (inbound.bufRef().len < packet.len) return error.BufferTooSmall;

            @memcpy(inbound.bufRef()[0..packet.len], packet.bytes());
            inbound.len = packet.len;
            inbound.remote_endpoint = remote_endpoint;

            try target_engine.engine.drive(.{ .inbound_packet = inbound }, self.callback(target_side));
            packet.deinit();
        }

        fn handleInbound(self: *@This(), side: Side, packet: *InboundPacket) !void {
            switch (packet.state) {
                .prepared => {
                    try InboundPacket.decrtpy(grt, cipher_kind, packet);
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
                .initiator => try grt.std.testing.expect(remote_key.eql(self.responder_key)),
                .responder => try grt.std.testing.expect(remote_key.eql(self.initiator_key)),
            }
        }

        fn verifyConsumedInbound(self: *@This(), side: Side, packet: *InboundPacket) !void {
            if (side != .responder) return error.UnexpectedInboundOnInitiator;

            var expected_payload: [payload_size]u8 = undefined;
            fillSinglePeerPayload(self.received_packets, expected_payload[0..]);

            try grt.std.testing.expectEqual(@as(usize, payload_size), packet.len);
            try grt.std.testing.expect(packet.remote_static.eql(self.initiator_key));
            try grt.std.testing.expect(giznet.eqlAddrPort(packet.remote_endpoint, self.initiator_endpoint));
            try grt.std.testing.expect(glib.std.mem.eql(u8, expected_payload[0..], packet.bytes()));

            self.received_packets += 1;
            self.received_bytes += packet.len;
        }

        fn sendFromInitiator(self: *@This(), chunk_index: usize) !void {
            var packet_buffer: [payload_size]u8 = undefined;
            fillSinglePeerPayload(chunk_index, packet_buffer[0..]);
            const packet = try self.initiator.allocOutboundPacket();
            errdefer packet.deinit();
            if (packet.transportPlaintextBufRef().len < packet_buffer.len) return error.BufferTooSmall;
            @memcpy(packet.transportPlaintextBufRef()[0..packet_buffer.len], packet_buffer[0..]);
            packet.len = packet_buffer.len;
            packet.remote_static = self.responder_key;
            try self.initiator.engine.drive(.{
                .send_data = packet,
            }, self.callback(.initiator));
        }

        fn driveTicksUntilEstablished(self: *@This(), target_events: usize, max_rounds: usize) !void {
            var round: usize = 0;
            while (self.established_events < target_events and round < max_rounds) : (round += 1) {
                try self.initiator.engine.drive(.{ .tick = {} }, self.callback(.initiator));
                try self.responder.engine.drive(.{ .tick = {} }, self.callback(.responder));
            }
            try grt.std.testing.expectEqual(target_events, self.established_events);
        }

        fn engine(self: *@This(), side: Side) *Engine {
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
    };

    const initiator_pair = giznet.noise.KeyPair.seed(grt, 901);
    const responder_pair = giznet.noise.KeyPair.seed(grt, 902);
    const initiator_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 51001);
    const responder_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 51002);

    var initiator_harness = try EngineHarness.init(grt.std.testing.allocator, initiator_pair, .{
        .max_peers = 1,
        .max_pending = 1,
        .rekey_after_messages = rekey_after_messages,
        .rekey_after_time = no_rekey_after_time,
    });
    defer initiator_harness.deinit();

    var responder_harness = try EngineHarness.init(grt.std.testing.allocator, responder_pair, .{
        .max_peers = 1,
        .max_pending = 1,
        .rekey_after_messages = rekey_after_messages,
        .rekey_after_time = no_rekey_after_time,
    });
    defer responder_harness.deinit();

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

    const start_ns = grt.time.instant.now();
    try initiator_harness.engine.drive(.{
        .initiate_handshake = .{
            .remote_key = responder_pair.public,
            .remote_endpoint = responder_endpoint,
        },
    }, harness.callback(.initiator));
    try grt.std.testing.expectEqual(@as(usize, 2), harness.established_events);

    for (0..chunk_count) |chunk_index| {
        try harness.sendFromInitiator(chunk_index);
        if (rekey_after_messages_usize != 0 and (chunk_index + 1) % rekey_after_messages_usize == 0) {
            const completed_rekeys = (chunk_index + 1) / rekey_after_messages_usize;
            try harness.driveTicksUntilEstablished(2 * (1 + completed_rekeys), 8);
        }
    }
    const end_ns = grt.time.instant.now();

    try grt.std.testing.expectEqual(chunk_count, harness.received_packets);
    try grt.std.testing.expectEqual(total_transfer_bytes, harness.received_bytes);
    try grt.std.testing.expectEqual(2 * (1 + expected_rekey_count), harness.established_events);
    try grt.std.testing.expectEqual(if (expected_rekey_count == 0) @as(usize, 1) else @as(usize, 2), initiator_harness.engine.stats.session_count);
    try grt.std.testing.expectEqual(if (expected_rekey_count == 0) @as(usize, 1) else @as(usize, 2), responder_harness.engine.stats.session_count);
    try grt.std.testing.expectEqual(@as(usize, 0), initiator_harness.engine.stats.pending_handshake_count);
    try grt.std.testing.expectEqual(@as(usize, 0), responder_harness.engine.stats.pending_handshake_count);
    try grt.std.testing.expect(responder_harness.engine.stats.transfer_rx >= @as(u64, @intCast(total_transfer_bytes)));

    const elapsed_ns: u64 = @intCast(grt.time.instant.sub(end_ns, start_ns));
    const bytes_per_second = if (elapsed_ns == 0 or total_transfer_bytes == 0)
        0
    else
        @as(u64, @intCast((@as(u128, total_transfer_bytes) * @as(u128, grt.time.duration.Second)) / @as(u128, elapsed_ns)));
    return .{
        .bytes = total_transfer_bytes,
        .elapsed_ns = elapsed_ns,
        .bytes_per_second = bytes_per_second,
        .mbps = @divTrunc(bytes_per_second * 8, 1_000_000),
        .received_packets = harness.received_packets,
        .received_bytes = harness.received_bytes,
        .established_events = harness.established_events,
        .rekey_count = expected_rekey_count,
        .initiator_session_count = initiator_harness.engine.stats.session_count,
        .responder_session_count = responder_harness.engine.stats.session_count,
    };
}

pub fn runMultiPeerBidirectionalRekey(
    comptime grt: type,
    comptime cipher_kind: Cipher.Kind,
    comptime peer_count: usize,
    comptime total_transfer_bytes_per_peer: usize,
    comptime rekey_after_messages: u64,
) !MultiPeerReport {
    const payload_size: usize = 1024;
    const packet_size = SessionType.legacy_packet_size_capacity;
    const Engine = EngineType.make(grt, packet_size, cipher_kind);
    const EngineHarness = EngineWithPools(grt, Engine, packet_size);
    const rekey_after_messages_usize: usize = @intCast(rekey_after_messages);
    const packets_per_peer: usize = total_transfer_bytes_per_peer / payload_size;
    const expected_rekey_count_per_relation: usize = packets_per_peer / rekey_after_messages_usize;
    const no_rekey_after_time: glib.time.duration.Duration = 365 * glib.time.duration.Day;

    try grt.std.testing.expect(rekey_after_messages_usize != 0);
    try grt.std.testing.expectEqual(@as(usize, 0), total_transfer_bytes_per_peer % payload_size);

    const NodeKind = enum {
        left_hub,
        right_hub,
        left_leaf,
        right_leaf,
    };

    const NodeId = struct {
        kind: NodeKind,
        index: usize = 0,
    };

    const CallbackCtx = struct {
        harness_ptr: *anyopaque,
        node_id: NodeId,
    };

    const Harness = struct {
        left_hub: *EngineHarness,
        right_hub: *EngineHarness,
        left_hub_key: Key,
        right_hub_key: Key,
        left_hub_endpoint: AddrPort,
        right_hub_endpoint: AddrPort,
        left_leaves: *[peer_count]EngineHarness,
        right_leaves: *[peer_count]EngineHarness,
        left_leaf_pairs: *const [peer_count]KeyPair,
        right_leaf_pairs: *const [peer_count]KeyPair,
        left_leaf_endpoints: *const [peer_count]AddrPort,
        right_leaf_endpoints: *const [peer_count]AddrPort,
        established_events: usize = 0,
        next_tick_events: usize = 0,
        left_leaf_received_packets: [peer_count]usize = [_]usize{0} ** peer_count,
        right_leaf_received_packets: [peer_count]usize = [_]usize{0} ** peer_count,
        left_hub_callback_ctx: ?*CallbackCtx = null,
        right_hub_callback_ctx: ?*CallbackCtx = null,
        left_leaf_callback_ctxs: ?*[peer_count]CallbackCtx = null,
        right_leaf_callback_ctxs: ?*[peer_count]CallbackCtx = null,

        fn callback(self: *@This(), node_id: NodeId) EngineType.Callback {
            const ctx = switch (node_id.kind) {
                .left_hub => self.left_hub_callback_ctx orelse unreachable,
                .right_hub => self.right_hub_callback_ctx orelse unreachable,
                .left_leaf => &(self.left_leaf_callback_ctxs orelse unreachable)[node_id.index],
                .right_leaf => &(self.right_leaf_callback_ctxs orelse unreachable)[node_id.index],
            };
            return .{
                .ctx = ctx,
                .call = callbackFn,
            };
        }

        fn callbackFn(ctx: *anyopaque, result: EngineType.DriveOutput) anyerror!void {
            const callback_ctx: *CallbackCtx = @ptrCast(@alignCast(ctx));
            const harness: *@This() = @ptrCast(@alignCast(callback_ctx.harness_ptr));
            try harness.handleResult(callback_ctx.node_id, result);
        }

        fn handleResult(self: *@This(), source: NodeId, result: EngineType.DriveOutput) !void {
            switch (result) {
                .outbound => |packet| try self.handleOutbound(source, packet),
                .inbound => |packet| try self.handleInbound(source, packet),
                .established => |remote_key| try self.handleEstablished(source, remote_key),
                .offline => return error.UnexpectedOffline,
                .next_tick_deadline => |_| self.next_tick_events += 1,
            }
        }

        fn handleOutbound(self: *@This(), source: NodeId, packet: *OutboundPacket) !void {
            const target = try self.lookupNodeByEndpoint(packet.remote_endpoint);
            const target_engine = self.engineHarness(target);
            const remote_endpoint = self.endpoint(source);

            if (packet.state == .prepared) {
                try OutboundPacket.encrypt(grt, cipher_kind, packet);
            }

            const inbound = try target_engine.allocInboundPacket();
            errdefer inbound.deinit();
            if (inbound.bufRef().len < packet.len) return error.BufferTooSmall;
            @memcpy(inbound.bufRef()[0..packet.len], packet.bytes());
            inbound.len = packet.len;
            inbound.remote_endpoint = remote_endpoint;

            try target_engine.engine.drive(.{ .inbound_packet = inbound }, self.callback(target));
            packet.deinit();
        }

        fn handleInbound(self: *@This(), node_id: NodeId, packet: *InboundPacket) !void {
            switch (packet.state) {
                .prepared => {
                    try InboundPacket.decrtpy(grt, cipher_kind, packet);
                    try self.engine(node_id).drive(.{ .inbound_packet = packet }, self.callback(node_id));
                },
                .consumed => {
                    try self.verifyConsumedInbound(node_id, packet);
                    packet.deinit();
                },
                else => return error.UnexpectedInboundPacketState,
            }
        }

        fn handleEstablished(self: *@This(), node_id: NodeId, remote_key: Key) !void {
            self.established_events += 1;
            switch (node_id.kind) {
                .left_hub => try grt.std.testing.expect(self.containsKey(self.right_leaf_pairs, remote_key)),
                .right_hub => try grt.std.testing.expect(self.containsKey(self.left_leaf_pairs, remote_key)),
                .left_leaf => try grt.std.testing.expect(remote_key.eql(self.right_hub_key)),
                .right_leaf => try grt.std.testing.expect(remote_key.eql(self.left_hub_key)),
            }
        }

        fn verifyConsumedInbound(self: *@This(), node_id: NodeId, packet: *InboundPacket) !void {
            var expected_payload: [payload_size]u8 = undefined;

            switch (node_id.kind) {
                .right_leaf => {
                    const chunk_index = self.right_leaf_received_packets[node_id.index];
                    fillMultiPeerPayload(.left_to_right, node_id.index, chunk_index, expected_payload[0..]);
                    try grt.std.testing.expectEqual(@as(usize, payload_size), packet.len);
                    try grt.std.testing.expect(packet.remote_static.eql(self.left_hub_key));
                    try grt.std.testing.expect(giznet.eqlAddrPort(packet.remote_endpoint, self.left_hub_endpoint));
                    try grt.std.testing.expect(glib.std.mem.eql(u8, expected_payload[0..], packet.bytes()));
                    self.right_leaf_received_packets[node_id.index] += 1;
                },
                .left_leaf => {
                    const chunk_index = self.left_leaf_received_packets[node_id.index];
                    fillMultiPeerPayload(.right_to_left, node_id.index, chunk_index, expected_payload[0..]);
                    try grt.std.testing.expectEqual(@as(usize, payload_size), packet.len);
                    try grt.std.testing.expect(packet.remote_static.eql(self.right_hub_key));
                    try grt.std.testing.expect(giznet.eqlAddrPort(packet.remote_endpoint, self.right_hub_endpoint));
                    try grt.std.testing.expect(glib.std.mem.eql(u8, expected_payload[0..], packet.bytes()));
                    self.left_leaf_received_packets[node_id.index] += 1;
                },
                .left_hub, .right_hub => return error.UnexpectedInboundOnHub,
            }
        }

        fn engine(self: *@This(), node_id: NodeId) *Engine {
            return switch (node_id.kind) {
                .left_hub => &self.left_hub.engine,
                .right_hub => &self.right_hub.engine,
                .left_leaf => &self.left_leaves[node_id.index].engine,
                .right_leaf => &self.right_leaves[node_id.index].engine,
            };
        }

        fn engineHarness(self: *@This(), node_id: NodeId) *EngineHarness {
            return switch (node_id.kind) {
                .left_hub => self.left_hub,
                .right_hub => self.right_hub,
                .left_leaf => &self.left_leaves[node_id.index],
                .right_leaf => &self.right_leaves[node_id.index],
            };
        }

        fn endpoint(self: *@This(), node_id: NodeId) AddrPort {
            return switch (node_id.kind) {
                .left_hub => self.left_hub_endpoint,
                .right_hub => self.right_hub_endpoint,
                .left_leaf => self.left_leaf_endpoints[node_id.index],
                .right_leaf => self.right_leaf_endpoints[node_id.index],
            };
        }

        fn lookupNodeByEndpoint(self: *@This(), target_endpoint: AddrPort) !NodeId {
            if (giznet.eqlAddrPort(target_endpoint, self.left_hub_endpoint)) return .{ .kind = .left_hub };
            if (giznet.eqlAddrPort(target_endpoint, self.right_hub_endpoint)) return .{ .kind = .right_hub };

            for (self.left_leaf_endpoints, 0..) |candidate, index| {
                if (giznet.eqlAddrPort(target_endpoint, candidate)) return .{ .kind = .left_leaf, .index = index };
            }
            for (self.right_leaf_endpoints, 0..) |candidate, index| {
                if (giznet.eqlAddrPort(target_endpoint, candidate)) return .{ .kind = .right_leaf, .index = index };
            }
            return error.UnknownEndpoint;
        }

        fn containsKey(self: *@This(), keypairs: *const [peer_count]KeyPair, key: Key) bool {
            _ = self;
            for (keypairs.*) |pair| {
                if (pair.public.eql(key)) return true;
            }
            return false;
        }

        fn sendFromLeftHub(self: *@This(), peer_index: usize, chunk_index: usize) !void {
            var packet_buffer: [payload_size]u8 = undefined;
            fillMultiPeerPayload(.left_to_right, peer_index, chunk_index, packet_buffer[0..]);
            const packet = try self.left_hub.allocOutboundPacket();
            errdefer packet.deinit();
            if (packet.transportPlaintextBufRef().len < packet_buffer.len) return error.BufferTooSmall;
            @memcpy(packet.transportPlaintextBufRef()[0..packet_buffer.len], packet_buffer[0..]);
            packet.len = packet_buffer.len;
            packet.remote_static = self.right_leaf_pairs[peer_index].public;
            try self.left_hub.engine.drive(.{
                .send_data = packet,
            }, self.callback(.{ .kind = .left_hub }));
        }

        fn sendFromRightHub(self: *@This(), peer_index: usize, chunk_index: usize) !void {
            var packet_buffer: [payload_size]u8 = undefined;
            fillMultiPeerPayload(.right_to_left, peer_index, chunk_index, packet_buffer[0..]);
            const packet = try self.right_hub.allocOutboundPacket();
            errdefer packet.deinit();
            if (packet.transportPlaintextBufRef().len < packet_buffer.len) return error.BufferTooSmall;
            @memcpy(packet.transportPlaintextBufRef()[0..packet_buffer.len], packet_buffer[0..]);
            packet.len = packet_buffer.len;
            packet.remote_static = self.left_leaf_pairs[peer_index].public;
            try self.right_hub.engine.drive(.{
                .send_data = packet,
            }, self.callback(.{ .kind = .right_hub }));
        }

        fn driveAllTicksUntilEstablished(self: *@This(), target_events: usize, max_rounds: usize) !void {
            var round: usize = 0;
            while (self.established_events < target_events and round < max_rounds) : (round += 1) {
                try self.left_hub.engine.drive(.{ .tick = {} }, self.callback(.{ .kind = .left_hub }));
                try self.right_hub.engine.drive(.{ .tick = {} }, self.callback(.{ .kind = .right_hub }));
                for (0..peer_count) |index| {
                    try self.left_leaves[index].engine.drive(.{ .tick = {} }, self.callback(.{ .kind = .left_leaf, .index = index }));
                    try self.right_leaves[index].engine.drive(.{ .tick = {} }, self.callback(.{ .kind = .right_leaf, .index = index }));
                }
            }
            try grt.std.testing.expectEqual(target_events, self.established_events);
        }
    };

    const left_hub_pair = giznet.noise.KeyPair.seed(grt, 3001);
    const right_hub_pair = giznet.noise.KeyPair.seed(grt, 3002);
    const left_hub_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 53001);
    const right_hub_endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 53002);

    var left_hub_harness = try EngineHarness.init(grt.std.testing.allocator, left_hub_pair, .{
        .max_peers = peer_count,
        .max_pending = peer_count,
        .rekey_after_messages = rekey_after_messages,
        .rekey_after_time = no_rekey_after_time,
    });
    errdefer left_hub_harness.deinit();
    const left_hub = &left_hub_harness.engine;

    var right_hub_harness = try EngineHarness.init(grt.std.testing.allocator, right_hub_pair, .{
        .max_peers = peer_count,
        .max_pending = peer_count,
        .rekey_after_messages = rekey_after_messages,
        .rekey_after_time = no_rekey_after_time,
    });
    errdefer right_hub_harness.deinit();
    const right_hub = &right_hub_harness.engine;

    var left_leaf_pairs: [peer_count]KeyPair = undefined;
    var right_leaf_pairs: [peer_count]KeyPair = undefined;
    var left_leaf_endpoints: [peer_count]AddrPort = undefined;
    var right_leaf_endpoints: [peer_count]AddrPort = undefined;
    var left_leaves: [peer_count]EngineHarness = undefined;
    var right_leaves: [peer_count]EngineHarness = undefined;
    var left_leaf_init_count: usize = 0;
    var right_leaf_init_count: usize = 0;
    errdefer {
        var index: usize = 0;
        while (index < left_leaf_init_count) : (index += 1) left_leaves[index].deinit();
        index = 0;
        while (index < right_leaf_init_count) : (index += 1) right_leaves[index].deinit();
        right_hub_harness.deinit();
        left_hub_harness.deinit();
    }

    for (0..peer_count) |index| {
        left_leaf_pairs[index] = giznet.noise.KeyPair.seed(grt, @intCast(3100 + index));
        right_leaf_pairs[index] = giznet.noise.KeyPair.seed(grt, @intCast(3200 + index));
        left_leaf_endpoints[index] = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, @intCast(53100 + index));
        right_leaf_endpoints[index] = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, @intCast(53200 + index));

        left_leaves[index] = try EngineHarness.init(grt.std.testing.allocator, left_leaf_pairs[index], .{
            .max_peers = 1,
            .max_pending = 1,
            .rekey_after_messages = rekey_after_messages,
            .rekey_after_time = no_rekey_after_time,
        });
        left_leaf_init_count += 1;

        right_leaves[index] = try EngineHarness.init(grt.std.testing.allocator, right_leaf_pairs[index], .{
            .max_peers = 1,
            .max_pending = 1,
            .rekey_after_messages = rekey_after_messages,
            .rekey_after_time = no_rekey_after_time,
        });
        right_leaf_init_count += 1;
    }

    defer {
        for (&left_leaves) |*engine| engine.deinit();
        for (&right_leaves) |*engine| engine.deinit();
        right_hub_harness.deinit();
        left_hub_harness.deinit();
    }

    var harness: Harness = .{
        .left_hub = &left_hub_harness,
        .right_hub = &right_hub_harness,
        .left_hub_key = left_hub_pair.public,
        .right_hub_key = right_hub_pair.public,
        .left_hub_endpoint = left_hub_endpoint,
        .right_hub_endpoint = right_hub_endpoint,
        .left_leaves = &left_leaves,
        .right_leaves = &right_leaves,
        .left_leaf_pairs = &left_leaf_pairs,
        .right_leaf_pairs = &right_leaf_pairs,
        .left_leaf_endpoints = &left_leaf_endpoints,
        .right_leaf_endpoints = &right_leaf_endpoints,
    };
    var left_hub_callback_ctx: CallbackCtx = .{
        .harness_ptr = &harness,
        .node_id = .{ .kind = .left_hub },
    };
    var right_hub_callback_ctx: CallbackCtx = .{
        .harness_ptr = &harness,
        .node_id = .{ .kind = .right_hub },
    };
    var left_leaf_callback_ctxs: [peer_count]CallbackCtx = undefined;
    var right_leaf_callback_ctxs: [peer_count]CallbackCtx = undefined;
    for (0..peer_count) |index| {
        left_leaf_callback_ctxs[index] = .{
            .harness_ptr = &harness,
            .node_id = .{ .kind = .left_leaf, .index = index },
        };
        right_leaf_callback_ctxs[index] = .{
            .harness_ptr = &harness,
            .node_id = .{ .kind = .right_leaf, .index = index },
        };
    }
    harness.left_hub_callback_ctx = &left_hub_callback_ctx;
    harness.right_hub_callback_ctx = &right_hub_callback_ctx;
    harness.left_leaf_callback_ctxs = &left_leaf_callback_ctxs;
    harness.right_leaf_callback_ctxs = &right_leaf_callback_ctxs;

    for (0..peer_count) |index| {
        try left_hub.drive(.{
            .initiate_handshake = .{
                .remote_key = right_leaf_pairs[index].public,
                .remote_endpoint = right_leaf_endpoints[index],
            },
        }, harness.callback(.{ .kind = .left_hub }));
    }
    for (0..peer_count) |index| {
        try right_hub.drive(.{
            .initiate_handshake = .{
                .remote_key = left_leaf_pairs[index].public,
                .remote_endpoint = left_leaf_endpoints[index],
            },
        }, harness.callback(.{ .kind = .right_hub }));
    }

    try grt.std.testing.expectEqual(@as(usize, peer_count * 4), harness.established_events);
    try grt.std.testing.expectEqual(peer_count, left_hub.stats.peer_count);
    try grt.std.testing.expectEqual(peer_count, right_hub.stats.peer_count);
    try grt.std.testing.expectEqual(peer_count, left_hub.stats.session_count);
    try grt.std.testing.expectEqual(peer_count, right_hub.stats.session_count);

    for (0..packets_per_peer) |chunk_index| {
        for (0..peer_count) |peer_index| {
            try harness.sendFromLeftHub(peer_index, chunk_index);
        }
        for (0..peer_count) |peer_index| {
            try harness.sendFromRightHub(peer_index, chunk_index);
        }
        if ((chunk_index + 1) % rekey_after_messages_usize == 0) {
            const completed_rekeys = (chunk_index + 1) / rekey_after_messages_usize;
            try harness.driveAllTicksUntilEstablished(peer_count * 4 * (1 + completed_rekeys), 8);
        }
    }

    try grt.std.testing.expectEqual(peer_count * 4 * (1 + expected_rekey_count_per_relation), harness.established_events);
    try grt.std.testing.expectEqual(if (expected_rekey_count_per_relation == 0) peer_count else peer_count * 2, left_hub.stats.session_count);
    try grt.std.testing.expectEqual(if (expected_rekey_count_per_relation == 0) peer_count else peer_count * 2, right_hub.stats.session_count);

    for (0..peer_count) |index| {
        try grt.std.testing.expectEqual(packets_per_peer, harness.left_leaf_received_packets[index]);
        try grt.std.testing.expectEqual(packets_per_peer, harness.right_leaf_received_packets[index]);
        try grt.std.testing.expectEqual(if (expected_rekey_count_per_relation == 0) @as(usize, 1) else @as(usize, 2), left_leaves[index].engine.stats.session_count);
        try grt.std.testing.expectEqual(if (expected_rekey_count_per_relation == 0) @as(usize, 1) else @as(usize, 2), right_leaves[index].engine.stats.session_count);

        const left_leaf_peer = left_leaves[index].engine.peers.get(right_hub_pair.public) orelse return error.SessionNotFound;
        const right_leaf_peer = right_leaves[index].engine.peers.get(left_hub_pair.public) orelse return error.SessionNotFound;
        if (expected_rekey_count_per_relation == 0) {
            try grt.std.testing.expect(left_leaf_peer.current != null);
            try grt.std.testing.expect(right_leaf_peer.current != null);
        } else {
            try grt.std.testing.expect(left_leaf_peer.current != null and left_leaf_peer.previous != null);
            try grt.std.testing.expect(right_leaf_peer.current != null and right_leaf_peer.previous != null);
        }

        const left_hub_peer = left_hub.peers.get(right_leaf_pairs[index].public) orelse return error.SessionNotFound;
        const right_hub_peer = right_hub.peers.get(left_leaf_pairs[index].public) orelse return error.SessionNotFound;
        if (expected_rekey_count_per_relation == 0) {
            try grt.std.testing.expect(left_hub_peer.current != null);
            try grt.std.testing.expect(right_hub_peer.current != null);
        } else {
            try grt.std.testing.expect(left_hub_peer.current != null and left_hub_peer.previous != null);
            try grt.std.testing.expect(right_hub_peer.current != null and right_hub_peer.previous != null);
        }
    }

    return .{
        .peer_count = peer_count,
        .payload_bytes_per_peer = total_transfer_bytes_per_peer,
        .established_events = harness.established_events,
        .rekey_count_per_relation = expected_rekey_count_per_relation,
        .left_hub_session_count = left_hub.stats.session_count,
        .right_hub_session_count = right_hub.stats.session_count,
    };
}

fn EngineWithPools(
    comptime grt: type,
    comptime Engine: type,
    comptime packet_size: usize,
) type {
    return struct {
        inbound_pool: InboundPacket.Pool,
        outbound_pool: OutboundPacket.Pool,
        engine: Engine,

        const Self = @This();

        pub fn init(
            allocator: glib.std.mem.Allocator,
            local_static: KeyPair,
            config: EngineType.Config,
        ) !Self {
            const inbound_pool = try InboundPacket.initPool(grt, allocator, packet_size);
            errdefer inbound_pool.deinit();

            const outbound_pool = try OutboundPacket.initPool(grt, allocator, packet_size);
            errdefer outbound_pool.deinit();

            const engine = try Engine.init(allocator, local_static, config, .{
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

        pub fn allocInboundPacket(self: *Self) !*InboundPacket {
            return self.inbound_pool.get() orelse error.OutOfMemory;
        }

        pub fn allocOutboundPacket(self: *Self) !*OutboundPacket {
            return self.outbound_pool.get() orelse error.OutOfMemory;
        }
    };
}

fn fillSinglePeerPayload(chunk_index: usize, out: []u8) void {
    for (out, 0..) |*byte, index| {
        const value = (chunk_index * 17 + index * 31 + 7) % 251;
        byte.* = @intCast(value);
    }
}

fn fillMultiPeerPayload(direction: MultiPeerDirection, peer_index: usize, chunk_index: usize, out: []u8) void {
    for (out, 0..) |*byte, index| {
        const value = ((@intFromEnum(direction) * 53) + (peer_index * 17) + (chunk_index * 29) + (index * 31) + 7) % 251;
        byte.* = @intCast(value);
    }
}
