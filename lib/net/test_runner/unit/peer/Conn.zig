const dep = @import("dep");
const noise = @import("../../../noise.zig");
const testing_api = dep.testing;

const core = @import("../../../core.zig");
const peer = @import("../../../peer.zig");
const SharedRefFile = @import("../../../peer/SharedRef.zig");
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
                t.logErrorf("peer/Conn failed: {}", .{err});
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
    const FixtureType = fixture.Fixture(lib);
    const Peer = peer.make(core.make(lib));
    const direct_protocol: u8 = 0x03;
    const rpc_service: u64 = 4;
    const extra_service: u64 = 1;

    var invalid = Peer.Conn{ .remote_pk = noise.Key.zero };
    var invalid_buf: [8]u8 = undefined;
    try testing.expectError(peer.Error.NilConn, invalid.openService(rpc_service));
    try testing.expectError(peer.Error.NilConn, invalid.acceptService(rpc_service));
    try testing.expectError(peer.Error.NilConn, invalid.write(direct_protocol, "x"));
    try testing.expectError(peer.Error.NilConn, invalid.read(&invalid_buf));
    try testing.expectError(peer.Error.NilConn, invalid.close());

    {
        var pair = try FixtureType.init(allocator);
        defer pair.deinit();

        _ = try pair.client_conn.write(direct_protocol, "hello");
        var buf: [32]u8 = undefined;
        const got = try pair.server_conn.read(&buf);
        try testing.expectEqual(direct_protocol, got.protocol_byte);
        try testing.expectEqualStrings("hello", buf[0..got.n]);
    }

    {
        var pair = try FixtureType.init(allocator);
        defer pair.deinit();

        var client_stream = try pair.client_conn.openService(rpc_service);
        defer client_stream.deinit();
        var server_stream = try pair.server_conn.acceptService(rpc_service);
        defer server_stream.deinit();
        _ = try client_stream.write("ping");
        try pair.drive(16);
        var buf: [16]u8 = undefined;
        const ping_n = try server_stream.read(&buf);
        try testing.expectEqualStrings("ping", buf[0..ping_n]);
        _ = try server_stream.write("pong");
        try pair.drive(16);
        const pong_n = try client_stream.read(&buf);
        try testing.expectEqualStrings("pong", buf[0..pong_n]);
    }

    {
        var pair = try FixtureType.init(allocator);
        defer pair.deinit();

        var client_admin = try pair.client_conn.openService(extra_service);
        defer client_admin.deinit();
        var server_admin = try pair.server_conn.acceptService(extra_service);
        defer server_admin.deinit();
        _ = try client_admin.write("adm");
        try pair.drive(16);
        var buf: [16]u8 = undefined;
        const admin_n = try server_admin.read(&buf);
        try testing.expectEqualStrings("adm", buf[0..admin_n]);
    }

    {
        var pair = try FixtureType.initWithServices(allocator, false);
        defer pair.deinit();

        try testing.expectError(core.Error.ServiceRejected, pair.client_conn.openService(extra_service));
        try testing.expectError(core.Error.ServiceRejected, pair.server_conn.acceptService(extra_service));
    }

    {
        var pair = try FixtureType.init(allocator);
        defer pair.deinit();

        var second_handle = try pair.client_listener.peer(pair.server_key.public);
        defer second_handle.deinit();
        try pair.client_conn.close();
        var still_open_buf: [32]u8 = undefined;
        try testing.expectError(peer.Error.ConnClosed, pair.client_conn.openService(rpc_service));
        try testing.expectError(peer.Error.ConnClosed, pair.client_conn.write(direct_protocol, "x"));
        _ = try second_handle.write(direct_protocol, "still-open");
        const still_open = try pair.server_conn.read(&still_open_buf);
        try testing.expectEqual(direct_protocol, still_open.protocol_byte);
        try testing.expectEqualStrings("still-open", still_open_buf[0..still_open.n]);
    }

    {
        const FakePeer = peer.make(FakeCore);
        const FakeSharedRef = SharedRefFile.make(FakeCore);
        var client_udp = FakeCore.UDP{};
        var server_udp = FakeCore.UDP{};
        client_udp.peer = &server_udp;
        server_udp.peer = &client_udp;

        var client_conn = try FakePeer.Conn.init(allocator, fakeShared(FakeSharedRef, &client_udp), noise.Key.zero, null);
        defer client_conn.deinit();
        var server_conn = try FakePeer.Conn.init(allocator, fakeShared(FakeSharedRef, &server_udp), noise.Key.zero, null);
        defer server_conn.deinit();
        var held_stream = try client_conn.openService(rpc_service);
        defer held_stream.deinit();
        var accepted_stream = try server_conn.acceptService(rpc_service);
        defer accepted_stream.deinit();

        _ = try held_stream.write("x");
        var buf: [16]u8 = undefined;
        const primed_n = try accepted_stream.read(&buf);
        try testing.expectEqualStrings("x", buf[0..primed_n]);

        try client_conn.close();
        _ = try held_stream.write("y");
        const held_n = try accepted_stream.read(&buf);
        try testing.expectEqualStrings("y", buf[0..held_n]);
    }

    {
        var pair = try FixtureType.init(allocator);
        defer pair.deinit();

        pair.client_udp.close();
        try testing.expectError(core.Error.Closed, pair.client_conn.openService(rpc_service));
        try testing.expectError(core.Error.Closed, pair.client_conn.write(direct_protocol, "x"));
        try pair.client_conn.close();
        try testing.expectError(peer.Error.ConnClosed, pair.client_conn.openService(rpc_service));
    }
}

fn fakeShared(comptime SharedRef: type, udp: *FakeCore.UDP) SharedRef {
    return .{
        .ctx = udp,
        .retain = struct {
            fn retain(_: *anyopaque) void {}
        }.retain,
        .release = struct {
            fn release(_: *anyopaque) void {}
        }.release,
        .udp = struct {
            fn getUDP(ctx: *anyopaque) *FakeCore.UDP {
                return @ptrCast(@alignCast(ctx));
            }
        }.getUDP,
    };
}

const FakeCore = struct {
    const FakeState = enum { established };

    pub const ServiceMux = struct {
        pub const ReadResult = struct {
            protocol_byte: u8,
            n: usize,
        };

        pub fn openStream(_: *ServiceMux, _: u64) !u64 {
            return 1;
        }

        pub fn acceptStream(_: *ServiceMux, _: u64) !u64 {
            return 1;
        }

        pub fn closeService(_: *ServiceMux, _: u64) !void {}

        pub fn stopAcceptingService(_: *ServiceMux, _: u64) !void {}

        pub fn read(_: *ServiceMux, _: []u8) !ReadResult {
            return error.QueueEmpty;
        }

        pub fn write(_: *ServiceMux, _: u8, payload: []const u8) !usize {
            return payload.len;
        }
    };

    pub const UDP = struct {
        pub const PeerEvent = struct {
            peer: noise.Key,
            state: FakeState,
        };

        pub const PeerInfo = struct {
            state: FakeState,
        };

        peer: ?*UDP = null,
        mux: ServiceMux = .{},
        inbox: [64]u8 = [_]u8{0} ** 64,
        inbox_len: usize = 0,
        closed: bool = false,

        pub fn serviceMux(self: *UDP, _: noise.Key) ?*ServiceMux {
            return &self.mux;
        }

        pub fn peerInfo(_: *UDP, _: noise.Key) ?PeerInfo {
            return .{ .state = .established };
        }

        pub fn sendStreamData(self: *UDP, _: noise.Key, _: u64, _: u64, payload: []const u8) !usize {
            const peer_udp = self.peer orelse return error.NoData;
            @memcpy(peer_udp.inbox[0..payload.len], payload);
            peer_udp.inbox_len = payload.len;
            return payload.len;
        }

        pub fn recvStreamData(self: *UDP, _: noise.Key, _: u64, _: u64, out: []u8) !usize {
            if (self.inbox_len == 0) return error.NoData;
            @memcpy(out[0..self.inbox_len], self.inbox[0..self.inbox_len]);
            const n = self.inbox_len;
            self.inbox_len = 0;
            return n;
        }

        pub fn closeStream(_: *UDP, _: noise.Key, _: u64, _: u64) !void {}
    };
};
