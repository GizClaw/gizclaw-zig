const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");
const errors = @import("../../../core/errors.zig");
const protocol = @import("../../../core/protocol.zig");
const HostFile = @import("../../../core/Host.zig");
const ConnFile = @import("../../../core/Conn.zig");
const ServiceMuxFile = @import("../../../core/ServiceMux.zig");
const UDPFile = @import("../../../core/UDP.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib, lib.testing, allocator) catch |err| {
                t.logErrorf("core/UDP failed: {}", .{err});
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

fn runCases(comptime lib: type, testing: anytype, allocator: dep.embed.mem.Allocator) !void {
    const ContextApi = dep.context.make(lib);
    const Noise = noise.make(lib);
    const Kcp = @import("../../../kcp.zig").make(@import("../../../core.zig"));
    const UdpType = UDPFile.make(lib, Noise);
    const PacketConn = dep.net.PacketConn;
    const direct_protocol: u8 = 0x03;

    const alice_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{12} ** noise.Key.key_size));
    const bob_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{13} ** noise.Key.key_size));
    const carol_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{14} ** noise.Key.key_size));

    var ctx_api = try ContextApi.init(allocator);
    defer ctx_api.deinit();

    var alice_pc = LinkedPacketConn(UdpType).init(1);
    var bob_pc = LinkedPacketConn(UdpType).init(2);
    const alice_packet = PacketConn.init(&alice_pc);
    const bob_packet = PacketConn.init(&bob_pc);

    var stream_capture = StreamCapture{};
    var alice_events = EventCapture(UdpType){};
    var bob_events = EventCapture(UdpType){};
    var alice_udp = try UdpType.init(allocator, alice_packet, alice_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
        .on_peer_event = eventCaptureHook(UdpType, &alice_events),
    });
    defer alice_udp.deinit();
    var bob_udp = try UdpType.init(allocator, bob_packet, bob_static, .{
        .allow_unknown = true,
        .service_config = .{
            .on_new_service = allowAllServices,
            .stream_adapter = streamCaptureAdapter(&stream_capture),
        },
        .on_peer_event = eventCaptureHook(UdpType, &bob_events),
    });
    defer bob_udp.deinit();

    alice_pc.peer_udp = &bob_udp;
    bob_pc.peer_udp = &alice_udp;

    var stale_bob_addr = bob_pc.local_addr;
    stale_bob_addr[0] = 99;
    try alice_udp.setPeerEndpoint(bob_static.public, @ptrCast(&stale_bob_addr), bob_pc.local_addr_len);
    const client_conn = try alice_udp.connect(ctx_api.background(), bob_static.public);
    const accepted = try bob_udp.accept();
    try testing.expectEqual(ConnFile.State.established, client_conn.state());
    try testing.expectEqual(ConnFile.State.established, accepted.state());
    try testing.expectEqual(@as(usize, 2), alice_events.len);
    try testing.expect(alice_events.events[0].peer.eql(bob_static.public));
    try testing.expectEqual(HostFile.PeerState.connecting, alice_events.events[0].state);
    try testing.expect(alice_events.events[1].peer.eql(bob_static.public));
    try testing.expectEqual(HostFile.PeerState.established, alice_events.events[1].state);
    try testing.expectEqual(@as(usize, 1), bob_events.len);
    try testing.expect(bob_events.events[0].peer.eql(alice_static.public));
    try testing.expectEqual(HostFile.PeerState.established, bob_events.events[0].state);

    const alice_info = alice_udp.peerInfo(bob_static.public).?;
    try testing.expect(alice_info.has_endpoint);
    try testing.expectEqual(bob_pc.local_addr_len, alice_info.endpoint.len);
    try testing.expectEqual(bob_pc.local_addr[0], alice_info.endpoint.addr[0]);
    try testing.expectEqual(HostFile.PeerState.established, alice_info.state);
    try testing.expect(alice_info.tx_bytes > 0);
    try testing.expect(alice_info.rx_bytes > 0);
    try testing.expect(alice_info.last_seen_ms > 0);
    try testing.expect(alice_info.last_endpoint_update_ms > 0);
    const alice_host_info = alice_udp.hostInfo();
    try testing.expectEqual(@as(usize, 1), alice_host_info.peer_count);
    try testing.expect(alice_host_info.tx_bytes > 0);
    try testing.expect(alice_host_info.rx_bytes > 0);
    try testing.expectEqual(@as(u64, 2), alice_host_info.endpoint_updates);

    const direct_result = try alice_udp.writeDirect(bob_static.public, direct_protocol, "udp");
    try testing.expect(direct_result == .sent);
    try testing.expect(direct_result.sent > 0);
    var direct_buf: [16]u8 = undefined;
    const direct = try bob_udp.read(alice_static.public, &direct_buf);
    try testing.expectEqual(direct_protocol, direct.protocol_byte);
    try testing.expectEqualStrings("udp", direct_buf[0..direct.n]);

    const stream_result = try alice_udp.writeStream(bob_static.public, 7, protocol.kcp, "ok");
    try testing.expect(stream_result == .sent);
    try testing.expect(stream_result.sent > 0);
    try testing.expectEqual(@as(u64, 7), stream_capture.service);
    try testing.expectEqual(protocol.kcp, stream_capture.protocol_byte);
    try testing.expectEqualStrings("ok", stream_capture.payload[0..stream_capture.len]);

    var kcp_factory = Kcp.Adapter.Factory{};
    var stream_client_pc = LinkedPacketConn(UdpType).init(15);
    var stream_server_pc = LinkedPacketConn(UdpType).init(16);
    const stream_client_packet = PacketConn.init(&stream_client_pc);
    const stream_server_packet = PacketConn.init(&stream_server_pc);
    var stream_client = try UdpType.init(allocator, stream_client_packet, alice_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
            .stream_adapter_factory = kcp_factory.adapterFactory(),
        },
    });
    defer stream_client.deinit();
    var stream_server = try UdpType.init(allocator, stream_server_packet, bob_static, .{
        .allow_unknown = true,
        .service_config = .{
            .on_new_service = allowAllServices,
            .stream_adapter_factory = kcp_factory.adapterFactory(),
        },
    });
    defer stream_server.deinit();
    stream_client_pc.peer_udp = &stream_server;
    stream_server_pc.peer_udp = &stream_client;
    try stream_client.setPeerEndpoint(bob_static.public, @ptrCast(&stream_server_pc.local_addr), stream_server_pc.local_addr_len);
    _ = try stream_client.connect(ctx_api.background(), bob_static.public);
    _ = try stream_server.accept();

    const client_stream_mux = stream_client.serviceMux(bob_static.public).?;
    const server_stream_mux = stream_server.serviceMux(alice_static.public).?;
    const opened_stream = try client_stream_mux.openStream(4);
    try testing.expectEqual(@as(u64, 1), opened_stream);
    const accepted_stream = try server_stream_mux.acceptStream(4);
    try testing.expectEqual(opened_stream, accepted_stream);

    var stream_buf: [32]u8 = undefined;
    _ = try stream_client.sendStreamData(bob_static.public, 4, opened_stream, "ping");
    try testing.expectError(Kcp.Error.NoData, stream_server.recvStreamData(alice_static.public, 4, accepted_stream, &stream_buf));
    var stream_ticks: usize = 0;
    while (stream_ticks < 8) : (stream_ticks += 1) {
        try stream_client.testTickAt(nextFakeNowMs());
        try stream_server.testTickAt(nextFakeNowMs());
    }
    const ping_n = try stream_server.recvStreamData(alice_static.public, 4, accepted_stream, &stream_buf);
    try testing.expectEqualStrings("ping", stream_buf[0..ping_n]);

    _ = try stream_server.sendStreamData(alice_static.public, 4, accepted_stream, "pong");
    stream_ticks = 0;
    while (stream_ticks < 8) : (stream_ticks += 1) {
        try stream_server.testTickAt(nextFakeNowMs());
        try stream_client.testTickAt(nextFakeNowMs());
    }
    const pong_n = try stream_client.recvStreamData(bob_static.public, 4, opened_stream, &stream_buf);
    try testing.expectEqualStrings("pong", stream_buf[0..pong_n]);

    const server_opened = try server_stream_mux.openStream(6);
    try testing.expectEqual(@as(u64, 0), server_opened);
    const client_accepted = try client_stream_mux.acceptStream(6);
    try testing.expectEqual(server_opened, client_accepted);

    try stream_client.closeStream(bob_static.public, 4, opened_stream);
    try testing.expectEqual(@as(usize, 1), client_stream_mux.numStreams());
    try testing.expectEqual(@as(usize, 1), server_stream_mux.numStreams());
    try stream_client.testTickAt(nextFakeNowMs());
    try stream_server.testTickAt(nextFakeNowMs());
    try testing.expectEqual(@as(usize, 1), client_stream_mux.numStreams());
    try testing.expectEqual(@as(usize, 1), server_stream_mux.numStreams());

    const bob_endpoint_updates_before = bob_udp.hostInfo().endpoint_updates;
    alice_pc.local_addr[0] = 21;
    const roaming_stream = try alice_udp.writeStream(bob_static.public, 8, protocol.kcp, "roam");
    try testing.expect(roaming_stream == .sent);
    const bob_roamed = bob_udp.peerInfo(alice_static.public).?;
    try testing.expect(bob_roamed.has_endpoint);
    try testing.expectEqual(alice_pc.local_addr[0], bob_roamed.endpoint.addr[0]);
    try testing.expectEqual(bob_endpoint_updates_before + 1, bob_udp.hostInfo().endpoint_updates);

    const bob_endpoint_updates_after_roam = bob_udp.hostInfo().endpoint_updates;
    const same_endpoint_stream = try alice_udp.writeStream(bob_static.public, 8, protocol.kcp, "same");
    try testing.expect(same_endpoint_stream == .sent);
    try testing.expectEqual(bob_endpoint_updates_after_roam, bob_udp.hostInfo().endpoint_updates);

    var queued_client_pc = LinkedPacketConn(UdpType).init(7);
    var queued_server_pc = LinkedPacketConn(UdpType).init(8);
    const queued_client_packet = PacketConn.init(&queued_client_pc);
    const queued_server_packet = PacketConn.init(&queued_server_pc);
    var queued_stream_capture = StreamCapture{};
    var queued_client = try UdpType.init(allocator, queued_client_packet, alice_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer queued_client.deinit();
    var queued_server = try UdpType.init(allocator, queued_server_packet, bob_static, .{
        .allow_unknown = true,
        .service_config = .{
            .on_new_service = allowAllServices,
            .stream_adapter = streamCaptureAdapter(&queued_stream_capture),
        },
    });
    defer queued_server.deinit();
    queued_client_pc.peer_udp = &queued_server;
    queued_server_pc.peer_udp = &queued_client;
    try queued_client.setPeerEndpoint(bob_static.public, @ptrCast(&queued_server_pc.local_addr), queued_server_pc.local_addr_len);

    const queued_direct_a = try queued_client.writeDirect(bob_static.public, direct_protocol, "one");
    const queued_direct_b = try queued_client.writeDirect(bob_static.public, direct_protocol, "two");
    const queued_stream = try queued_client.writeStream(bob_static.public, 9, protocol.kcp, "qq");
    try testing.expect(queued_direct_a == .queued);
    try testing.expect(queued_direct_b == .queued);
    try testing.expect(queued_stream == .queued);
    try testing.expectEqual(@as(usize, 3), queued_client.testPendingSendLen(bob_static.public));
    try testing.expectEqual(@as(usize, 0), queued_client_pc.write_count);

    const queued_conn = try queued_client.connect(ctx_api.background(), bob_static.public);
    const queued_accepted = try queued_server.accept();
    try testing.expectEqual(ConnFile.State.established, queued_conn.state());
    try testing.expectEqual(ConnFile.State.established, queued_accepted.state());
    try testing.expectEqual(@as(usize, 0), queued_client.testPendingSendLen(bob_static.public));

    var queued_buf: [16]u8 = undefined;
    const queued_read_a = try queued_server.read(alice_static.public, &queued_buf);
    try testing.expectEqual(direct_protocol, queued_read_a.protocol_byte);
    try testing.expectEqualStrings("one", queued_buf[0..queued_read_a.n]);
    const queued_read_b = try queued_server.read(alice_static.public, &queued_buf);
    try testing.expectEqual(direct_protocol, queued_read_b.protocol_byte);
    try testing.expectEqualStrings("two", queued_buf[0..queued_read_b.n]);
    try testing.expectEqual(@as(u64, 9), queued_stream_capture.service);
    try testing.expectEqual(protocol.kcp, queued_stream_capture.protocol_byte);
    try testing.expectEqualStrings("qq", queued_stream_capture.payload[0..queued_stream_capture.len]);

    var full_client_pc = LinkedPacketConn(UdpType).init(9);
    const full_client_packet = PacketConn.init(&full_client_pc);
    var full_client = try UdpType.init(allocator, full_client_packet, alice_static, .{
        .allow_unknown = false,
        .pending_send_queue_size = 1,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer full_client.deinit();
    try full_client.setPeerEndpoint(bob_static.public, @ptrCast(&queued_server_pc.local_addr), queued_server_pc.local_addr_len);
    try testing.expect((try full_client.writeDirect(bob_static.public, direct_protocol, "x")) == .queued);
    try testing.expectError(errors.Error.QueueFull, full_client.writeDirect(bob_static.public, direct_protocol, "y"));

    var retry_client_pc = LinkedPacketConn(UdpType).init(3);
    retry_client_pc.drop_first = true;
    var retry_server_pc = LinkedPacketConn(UdpType).init(4);
    const retry_client_packet = PacketConn.init(&retry_client_pc);
    const retry_server_packet = PacketConn.init(&retry_server_pc);
    var retry_client = try UdpType.init(allocator, retry_client_packet, alice_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer retry_client.deinit();
    var retry_server = try UdpType.init(allocator, retry_server_packet, bob_static, .{
        .allow_unknown = true,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer retry_server.deinit();
    retry_client_pc.peer_udp = &retry_server;
    retry_server_pc.peer_udp = &retry_client;
    try retry_client.setPeerEndpoint(bob_static.public, @ptrCast(&retry_server_pc.local_addr), retry_server_pc.local_addr_len);
    _ = try retry_client.connect(ctx_api.background(), bob_static.public);
    try testing.expectEqual(@as(usize, 2), retry_client_pc.write_count);

    var no_endpoint_pc = LinkedPacketConn(UdpType).init(5);
    const no_endpoint_packet = PacketConn.init(&no_endpoint_pc);
    var no_endpoint_udp = try UdpType.init(allocator, no_endpoint_packet, carol_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer no_endpoint_udp.deinit();
    try testing.expectError(errors.Error.AcceptQueueEmpty, no_endpoint_udp.accept());
    try testing.expectError(error.TimedOut, no_endpoint_udp.pumpContext(ctx_api.background()));
    try testing.expectError(errors.Error.NoEndpoint, no_endpoint_udp.connect(ctx_api.background(), bob_static.public));

    var externally_closed_client_pc = LinkedPacketConn(UdpType).init(19);
    var externally_closed_server_pc = LinkedPacketConn(UdpType).init(20);
    externally_closed_client_pc.closed = true;
    const externally_closed_client_packet = PacketConn.init(&externally_closed_client_pc);
    const externally_closed_server_packet = PacketConn.init(&externally_closed_server_pc);
    var externally_closed_client = try UdpType.init(allocator, externally_closed_client_packet, alice_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer externally_closed_client.deinit();
    var externally_closed_server = try UdpType.init(allocator, externally_closed_server_packet, bob_static, .{
        .allow_unknown = true,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer externally_closed_server.deinit();
    externally_closed_client_pc.peer_udp = &externally_closed_server;
    externally_closed_server_pc.peer_udp = &externally_closed_client;
    try externally_closed_client.setPeerEndpoint(
        bob_static.public,
        @ptrCast(&externally_closed_server_pc.local_addr),
        externally_closed_server_pc.local_addr_len,
    );
    try testing.expectError(
        errors.Error.Closed,
        externally_closed_client.connect(ctx_api.background(), bob_static.public),
    );

    var closed_pc = LinkedPacketConn(UdpType).init(6);
    const closed_packet = PacketConn.init(&closed_pc);
    var closed_udp = try UdpType.init(allocator, closed_packet, carol_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer closed_udp.deinit();
    closed_udp.close();
    var closed_stream_buf: [1]u8 = undefined;
    var closed_direct_buf: [1]u8 = undefined;
    try testing.expectError(errors.Error.Closed, closed_udp.connect(ctx_api.background(), bob_static.public));
    try testing.expectError(errors.Error.Closed, closed_udp.accept());
    try testing.expectError(errors.Error.Closed, closed_udp.acceptContext(ctx_api.background()));
    try testing.expectError(errors.Error.Closed, closed_udp.pumpContext(ctx_api.background()));
    try testing.expectError(errors.Error.Closed, closed_udp.tick());
    try testing.expectError(errors.Error.Closed, closed_udp.registerPeer(bob_static.public));
    try testing.expectError(errors.Error.Closed, closed_udp.setPeerEndpoint(bob_static.public, @ptrCast(&closed_pc.local_addr), closed_pc.local_addr_len));
    try testing.expectError(errors.Error.Closed, closed_udp.read(bob_static.public, &closed_direct_buf));
    try testing.expectError(errors.Error.Closed, closed_udp.readServiceProtocol(bob_static.public, 0, direct_protocol, &closed_direct_buf));
    try testing.expectError(errors.Error.Closed, closed_udp.writeDirect(bob_static.public, direct_protocol, "x"));
    try testing.expectError(errors.Error.Closed, closed_udp.writeStream(bob_static.public, 1, protocol.kcp, "x"));
    try testing.expectError(errors.Error.Closed, closed_udp.sendStreamData(bob_static.public, 1, 1, "x"));
    try testing.expectError(errors.Error.Closed, closed_udp.recvStreamData(bob_static.public, 1, 1, &closed_stream_buf));
    try testing.expectError(errors.Error.Closed, closed_udp.closeStream(bob_static.public, 1, 1));

    var teardown_pc = LinkedPacketConn(UdpType).init(22);
    const teardown_packet = PacketConn.init(&teardown_pc);
    var teardown_udp = try UdpType.init(allocator, teardown_packet, carol_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    teardown_udp.close();
    teardown_udp.deinit();
    try testing.expectEqual(@as(usize, 1), teardown_pc.deinit_count);

    var connect_failure_client_pc = LinkedPacketConn(UdpType).init(17);
    var connect_failure_server_pc = LinkedPacketConn(UdpType).init(18);
    connect_failure_server_pc.mutate_first_outbound = true;
    connect_failure_server_pc.ignore_peer_errors = true;
    const connect_failure_client_packet = PacketConn.init(&connect_failure_client_pc);
    const connect_failure_server_packet = PacketConn.init(&connect_failure_server_pc);
    var connect_failure_events = EventCapture(UdpType){};
    var connect_failure_client = try UdpType.init(allocator, connect_failure_client_packet, alice_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
        .on_peer_event = eventCaptureHook(UdpType, &connect_failure_events),
    });
    defer connect_failure_client.deinit();
    var connect_failure_server = try UdpType.init(allocator, connect_failure_server_packet, bob_static, .{
        .allow_unknown = true,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer connect_failure_server.deinit();
    connect_failure_client_pc.peer_udp = &connect_failure_server;
    connect_failure_server_pc.peer_udp = &connect_failure_client;
    try connect_failure_client.setPeerEndpoint(
        bob_static.public,
        @ptrCast(&connect_failure_server_pc.local_addr),
        connect_failure_server_pc.local_addr_len,
    );
    try testing.expectError(
        errors.Error.HandshakeFailed,
        connect_failure_client.connect(ctx_api.background(), bob_static.public),
    );
    try testing.expectEqual(@as(usize, 2), connect_failure_events.len);
    try testing.expect(connect_failure_events.events[0].peer.eql(bob_static.public));
    try testing.expectEqual(HostFile.PeerState.connecting, connect_failure_events.events[0].state);
    try testing.expect(connect_failure_events.events[1].peer.eql(bob_static.public));
    try testing.expectEqual(HostFile.PeerState.failed, connect_failure_events.events[1].state);

    var failure_client_pc = LinkedPacketConn(UdpType).init(10);
    var failure_server_pc = LinkedPacketConn(UdpType).init(11);
    const failure_client_packet = PacketConn.init(&failure_client_pc);
    const failure_server_packet = PacketConn.init(&failure_server_pc);
    var failure_events = EventCapture(UdpType){};
    var failure_client = try UdpType.init(allocator, failure_client_packet, alice_static, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
        .on_peer_event = eventCaptureHook(UdpType, &failure_events),
    });
    defer failure_client.deinit();
    var failure_server = try UdpType.init(allocator, failure_server_packet, bob_static, .{
        .allow_unknown = true,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer failure_server.deinit();
    try failure_client.setPeerEndpoint(bob_static.public, @ptrCast(&failure_server_pc.local_addr), failure_server_pc.local_addr_len);

    const failure_init_n = try failure_client.host.beginDial(bob_static.public, failure_client.wire_buf, nextFakeNowMs());
    failure_client.testEmitPeerEvent(bob_static.public, .connecting);

    var failure_response: [128]u8 = undefined;
    const failure_result = failure_server.host.handlePacketResult(
        failure_client.wire_buf[0..failure_init_n],
        failure_server.plaintext_buf,
        &failure_response,
        nextFakeNowMs(),
    );
    if (failure_result.err) |err| return err;
    try testing.expect(failure_result.route == .response);
    const failure_response_n = failure_result.route.response.n;
    failure_response[failure_response_n - 1] ^= 1;

    try testing.expectError(
        error.AuthenticationFailed,
        failure_client.testHandleDatagram(
            failure_response[0..failure_response_n],
            @ptrCast(&failure_server_pc.local_addr),
            failure_server_pc.local_addr_len,
            nextFakeNowMs(),
        ),
    );
    try testing.expectEqual(@as(usize, 2), failure_events.len);
    try testing.expect(failure_events.events[0].peer.eql(bob_static.public));
    try testing.expectEqual(HostFile.PeerState.connecting, failure_events.events[0].state);
    try testing.expect(failure_events.events[1].peer.eql(bob_static.public));
    try testing.expectEqual(HostFile.PeerState.failed, failure_events.events[1].state);
    try testing.expectEqual(HostFile.PeerState.failed, failure_client.peerInfo(bob_static.public).?.state);
}

fn LinkedPacketConn(comptime UdpType: type) type {
    const PacketConn = dep.net.PacketConn;
    return struct {
        peer_udp: ?*UdpType = null,
        local_addr: PacketConn.AddrStorage = [_]u8{0} ** @sizeOf(PacketConn.AddrStorage),
        local_addr_len: u32 = 1,
        read_timeout_ms: ?u32 = null,
        write_timeout_ms: ?u32 = null,
        write_count: usize = 0,
        drop_first: bool = false,
        closed: bool = false,
        deinit_count: usize = 0,
        mutate_first_outbound: bool = false,
        ignore_peer_errors: bool = false,
        mutate_buf: [noise.Message.max_packet_size]u8 = undefined,

        const Self = @This();

        fn init(tag: u8) Self {
            var value = Self{};
            value.local_addr[0] = tag;
            return value;
        }

        pub fn readFrom(self: *Self, _: []u8) PacketConn.ReadFromError!PacketConn.ReadFromResult {
            if (self.closed) return error.Closed;
            return error.TimedOut;
        }

        pub fn writeTo(self: *Self, buf: []const u8, _: [*]const u8, _: u32) PacketConn.WriteToError!usize {
            if (self.closed) return error.Closed;
            self.write_count += 1;
            if (self.drop_first) {
                self.drop_first = false;
                return buf.len;
            }
            const peer_udp = self.peer_udp orelse return error.NetworkUnreachable;
            const delivered = if (self.mutate_first_outbound and buf.len > 0) blk: {
                self.mutate_first_outbound = false;
                if (buf.len > self.mutate_buf.len) return error.Unexpected;
                @memcpy(self.mutate_buf[0..buf.len], buf);
                self.mutate_buf[buf.len - 1] ^= 1;
                break :blk self.mutate_buf[0..buf.len];
            } else buf;
            _ = peer_udp.testHandleDatagram(delivered, @ptrCast(&self.local_addr), self.local_addr_len, nextFakeNowMs()) catch {
                if (self.ignore_peer_errors) {
                    return buf.len;
                }
                return error.Unexpected;
            };
            return buf.len;
        }

        pub fn close(self: *Self) void {
            self.closed = true;
        }

        pub fn deinit(self: *Self) void {
            self.closed = true;
            self.deinit_count += 1;
        }

        pub fn setReadTimeout(self: *Self, ms: ?u32) void {
            self.read_timeout_ms = ms;
        }

        pub fn setWriteTimeout(self: *Self, ms: ?u32) void {
            self.write_timeout_ms = ms;
        }
    };
}

var fake_now_ms: u64 = 1_000;

fn nextFakeNowMs() u64 {
    fake_now_ms += 1;
    return fake_now_ms;
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

fn streamCaptureAdapter(ctx: *StreamCapture) ServiceMuxFile.StreamAdapter {
    return .{
        .ctx = ctx,
        .input = streamCaptureInput,
    };
}

fn streamCaptureInput(ctx: *anyopaque, service: u64, protocol_byte: u8, data: []const u8, _: u64) !void {
    const capture: *StreamCapture = @ptrCast(@alignCast(ctx));
    if (data.len > capture.payload.len) return errors.Error.BufferTooSmall;
    capture.service = service;
    capture.protocol_byte = protocol_byte;
    capture.len = data.len;
    @memcpy(capture.payload[0..data.len], data);
}

fn EventCapture(comptime UdpType: type) type {
    return struct {
        events: [8]UdpType.PeerEvent = undefined,
        len: usize = 0,

        const Self = @This();

        fn push(self: *Self, event: UdpType.PeerEvent) void {
            if (self.len >= self.events.len) return;
            self.events[self.len] = event;
            self.len += 1;
        }
    };
}

fn eventCaptureHook(comptime UdpType: type, capture: *EventCapture(UdpType)) UdpType.PeerEventHook {
    return .{
        .ctx = capture,
        .emit = eventCaptureEmit(UdpType),
    };
}

fn eventCaptureEmit(comptime UdpType: type) *const fn (ctx: *anyopaque, event: UdpType.PeerEvent) void {
    return struct {
        fn emit(ctx: *anyopaque, event: UdpType.PeerEvent) void {
            const capture: *EventCapture(UdpType) = @ptrCast(@alignCast(ctx));
            capture.push(event);
        }
    }.emit;
}
