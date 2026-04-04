const dep = @import("dep");
const noise_pkg = @import("../../../noise.zig");
const testing_api = dep.testing;

const core = @import("../../../core.zig");
const peer = @import("../../../peer.zig");
const fixture = @import("fixture.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib, lib.testing, allocator) catch |err| {
                t.logErrorf("peer/Listener failed: {}", .{err});
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
    const Noise = noise_pkg.make(lib);
    const Core = core.make(lib);
    const Peer = peer.make(Core);
    const FixtureType = fixture.Fixture(lib);
    const PacketConn = dep.net.PacketConn;
    const ContextApi = dep.context.make(lib);
    const Helpers = struct {
        fn deinitAfterClientListener(pair: *FixtureType) void {
            pair.server_conn.deinit();
            pair.client_conn.deinit();
            pair.server_listener.deinit();
            pair.server_udp.deinit();
            pair.client_udp.deinit();
            pair.allocator.destroy(pair.server_udp);
            pair.allocator.destroy(pair.client_udp);
            pair.allocator.destroy(pair.server_pc);
            pair.allocator.destroy(pair.client_pc);
            pair.allocator.destroy(pair.clock_ms);
            pair.ctx_api.deinit();
        }
    };

    var invalid = Peer.Listener{};
    try testing.expectError(peer.Error.NilListener, invalid.accept());
    try testing.expectError(peer.Error.NilListener, invalid.peer(noise_pkg.Key.zero));
    try testing.expectError(peer.Error.NilListener, invalid.close());

    var pair = try FixtureType.init(allocator);
    defer pair.deinit();

    var server_peer = try pair.server_listener.peer(pair.client_key.public);
    defer server_peer.deinit();
    try testing.expect(server_peer.publicKey().eql(pair.client_key.public));

    try testing.expectError(core.Error.PeerNotFound, pair.server_listener.peer(noise_pkg.Key.zero));

    try pair.server_listener.close();
    try testing.expectError(peer.Error.Closed, pair.server_listener.accept());

    var pair2 = try FixtureType.init(allocator);
    defer pair2.deinit();
    var reconnect_handle = try pair2.client_listener.connectContext(pair2.ctx_api.background(), pair2.server_key.public);
    defer reconnect_handle.deinit();
    try testing.expectError(core.Error.QueueEmpty, pair2.server_listener.accept());

    var pair3 = try FixtureType.init(allocator);
    defer pair3.deinit();
    try pair3.server_conn.close();
    var peer_handle = try pair3.server_listener.peer(pair3.client_key.public);
    defer peer_handle.deinit();
    var reconnect_handle2 = try pair3.client_listener.connectContext(pair3.ctx_api.background(), pair3.server_key.public);
    defer reconnect_handle2.deinit();
    try testing.expectError(core.Error.QueueEmpty, pair3.server_listener.accept());
    try peer_handle.close();

    {
        var pair4 = try FixtureType.init(allocator);
        defer Helpers.deinitAfterClientListener(&pair4);

        var retained = try pair4.client_listener.peer(pair4.server_key.public);
        defer retained.deinit();

        pair4.client_listener.deinit();

        try testing.expectError(core.Error.Closed, retained.openRPC());
    }

    {
        var pair5 = try FixtureType.init(allocator);
        defer Helpers.deinitAfterClientListener(&pair5);

        var client_stream = try pair5.client_conn.openRPC();
        defer client_stream.deinit();
        var server_stream = try pair5.server_conn.acceptRPC();
        defer server_stream.deinit();

        pair5.client_listener.deinit();

        try testing.expectError(core.Error.Closed, client_stream.write("after-listener-deinit"));
    }

    var ctx_api = try ContextApi.init(allocator);
    defer ctx_api.deinit();
    const key = try Noise.KeyPair.fromPrivate(
        noise_pkg.Key.fromBytes([_]u8{81} ** noise_pkg.Key.key_size),
    );
    var packet = EmptyPacketConn{};
    var udp = try Core.UDP.init(allocator, PacketConn.init(&packet), key, .{
        .allow_unknown = false,
        .service_config = .{
            .on_new_service = allowAllServices,
        },
    });
    defer udp.deinit();
    var listener = try Peer.Listener.init(allocator, &udp, false);
    defer listener.deinit();

    const peer_events = try listener.peerEvents();
    try testing.expectEqual(@as(usize, 64), peer_events.capacity());
    var index: usize = 0;
    while (index < 64) : (index += 1) {
        try testing.expect(try listener.testEnqueuePeerEvent(.{
            .peer = noise_pkg.Key.fromBytes(keyBytes(@intCast(index + 1))),
            .state = .established,
        }));
    }
    try testing.expect(!(try listener.testEnqueuePeerEvent(.{
        .peer = noise_pkg.Key.fromBytes(keyBytes(200)),
        .state = .established,
    })));
    try testing.expectEqual(@as(usize, 64), peer_events.count());

    const first = peer_events.pop().?;
    try testing.expect(first.peer.eql(noise_pkg.Key.fromBytes(keyBytes(1))));
    while (peer_events.pop() != null) {}

    try testing.expectError(core.Error.QueueEmpty, listener.accept());
    _ = try listener.testEnqueuePeerEvent(.{
        .peer = noise_pkg.Key.fromBytes(keyBytes(9)),
        .state = .connecting,
    });
    _ = try listener.testEnqueuePeerEvent(.{
        .peer = noise_pkg.Key.fromBytes(keyBytes(10)),
        .state = .established,
    });
    var accepted = try listener.accept();
    defer accepted.deinit();
    try testing.expect(accepted.publicKey().eql(noise_pkg.Key.fromBytes(keyBytes(10))));
    try accepted.close();

    const remote = noise_pkg.Key.fromBytes(keyBytes(77));
    try testing.expectEqual(@as(usize, 0), try listener.testKnownCount());
    try testing.expectError(
        error.NetworkUnreachable,
        listener.dialContext(ctx_api.background(), remote, @ptrCast(&packet.addr), 1),
    );
    try testing.expectEqual(@as(usize, 0), try listener.testKnownCount());
}

const EmptyPacketConn = struct {
    const PacketConn = dep.net.PacketConn;

    addr: PacketConn.AddrStorage = [_]u8{1} ** @sizeOf(PacketConn.AddrStorage),
    read_timeout_ms: ?u32 = null,
    write_timeout_ms: ?u32 = null,
    closed: bool = false,

    pub fn readFrom(self: *EmptyPacketConn, _: []u8) PacketConn.ReadFromError!PacketConn.ReadFromResult {
        if (self.closed) return error.Closed;
        return error.TimedOut;
    }

    pub fn writeTo(self: *EmptyPacketConn, _: []const u8, _: [*]const u8, _: u32) PacketConn.WriteToError!usize {
        if (self.closed) return error.Closed;
        return error.NetworkUnreachable;
    }

    pub fn close(self: *EmptyPacketConn) void {
        self.closed = true;
    }

    pub fn deinit(self: *EmptyPacketConn) void {
        self.closed = true;
    }

    pub fn setReadTimeout(self: *EmptyPacketConn, ms: ?u32) void {
        self.read_timeout_ms = ms;
    }

    pub fn setWriteTimeout(self: *EmptyPacketConn, ms: ?u32) void {
        self.write_timeout_ms = ms;
    }
};

fn allowAllServices(_: noise_pkg.Key, _: u64) bool {
    return true;
}

fn keyBytes(tag: u8) [noise_pkg.Key.key_size]u8 {
    return [_]u8{tag} ** noise_pkg.Key.key_size;
}
