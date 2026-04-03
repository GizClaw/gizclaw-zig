const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");
const Conn = @import("../../../core/Conn.zig");
const consts = @import("../../../core/consts.zig");
const errors = @import("../../../core/errors.zig");
const DialerFile = @import("../../../core/Dialer.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib, lib.testing, allocator) catch |err| {
                t.logErrorf("core/Dialer failed: {}", .{err});
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

fn runCases(comptime lib: type, testing: anytype, allocator: lib.mem.Allocator) !void {
    const ContextApi = dep.context.make(lib);
    const Noise = noise.make(lib);
    const DialerType = DialerFile.make(lib, Noise);
    const ConnType = Conn.make(Noise);
    const PacketConn = dep.net.PacketConn;

    const alice_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{5} ** noise.Key.key_size));
    const bob_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{6} ** noise.Key.key_size));

    var dialer = DialerType.init(alice_static, bob_static.public, 11);
    var init_wire: [128]u8 = undefined;
    _ = try dialer.start(&init_wire, 100);
    try testing.expect((try dialer.pollRetry(&init_wire, 101)) == null);

    var retry_wire: [128]u8 = undefined;
    const retry_n = (try dialer.pollRetry(&retry_wire, 100 + consts.rekey_timeout_ms + 1)).?;
    try testing.expect(retry_n > 0);

    var successful_dialer = DialerType.init(alice_static, bob_static.public, 12);
    var responder = ConnType.initResponder(bob_static, 21);
    const init_n = try successful_dialer.start(&init_wire, 200);

    var resp_wire: [128]u8 = undefined;
    const resp_n = try responder.acceptHandshakeInit(init_wire[0..init_n], &resp_wire, 200);
    try successful_dialer.handleResponse(resp_wire[0..resp_n], 201);
    try testing.expectEqual(Conn.State.established, successful_dialer.connection().state());
    try testing.expect((try successful_dialer.pollRetry(&retry_wire, 201 + consts.rekey_attempt_time_ms + 1)) == null);

    _ = try successful_dialer.connection().beginHandshake(&init_wire, 300);
    try testing.expect((try successful_dialer.pollRetry(&retry_wire, 300 + consts.rekey_timeout_ms + 1)) != null);
    try testing.expectError(errors.Error.HandshakeTimeout, successful_dialer.pollRetry(&retry_wire, 300 + consts.rekey_attempt_time_ms + 1));
    try testing.expect((try successful_dialer.pollRetry(&retry_wire, 300 + consts.rekey_attempt_time_ms + 2)) == null);

    const remote_addr: PacketConn.AddrStorage = [_]u8{0xaa} ** @sizeOf(PacketConn.AddrStorage);
    const remote_addr_len: u32 = 16;

    {
        var ctx_api = try ContextApi.init(allocator);
        defer ctx_api.deinit();

        var responder_ctx = ResponderScript(ConnType){ .responder = ConnType.initResponder(bob_static, 31) };
        var packet_conn = FakePacketConn(ConnType).init(&responder_ctx, responderWrite(ConnType));
        const packet = PacketConn.init(&packet_conn);

        var transport_dialer = DialerType.init(alice_static, bob_static.public, 30);
        try transport_dialer.dialContext(
            ctx_api.background(),
            packet,
            @ptrCast(&remote_addr),
            remote_addr_len,
        );
        try testing.expectEqual(Conn.State.established, transport_dialer.connection().state());
        try testing.expectEqual(@as(usize, 1), packet_conn.write_count);
    }

    {
        var ctx_api = try ContextApi.init(allocator);
        defer ctx_api.deinit();

        var retry_ctx = RetryScript(ConnType){ .responder = ConnType.initResponder(bob_static, 41) };
        var packet_conn = FakePacketConn(ConnType).init(&retry_ctx, retryingResponderWrite(ConnType));
        const packet = PacketConn.init(&packet_conn);

        var retrying_dialer = DialerType.init(alice_static, bob_static.public, 40);
        try retrying_dialer.dialContext(
            ctx_api.background(),
            packet,
            @ptrCast(&remote_addr),
            remote_addr_len,
        );
        try testing.expectEqual(@as(usize, 2), packet_conn.write_count);
        try testing.expect(!lib.mem.eql(u8, packet_conn.writes[0].data[0..packet_conn.writes[0].len], packet_conn.writes[1].data[0..packet_conn.writes[1].len]));
        try testing.expectEqual(@as(?u32, null), packet_conn.read_timeout_ms);
    }

    {
        var ctx_api = try ContextApi.init(allocator);
        defer ctx_api.deinit();

        var filter_ctx = FilterScript(ConnType){ .responder = ConnType.initResponder(bob_static, 51) };
        var packet_conn = FakePacketConn(ConnType).init(&filter_ctx, filterWrite(ConnType));
        const packet = PacketConn.init(&packet_conn);

        var filtered_dialer = DialerType.init(alice_static, bob_static.public, 50);
        try filtered_dialer.dialContext(
            ctx_api.background(),
            packet,
            @ptrCast(&remote_addr),
            remote_addr_len,
        );
        try testing.expectEqual(Conn.State.established, filtered_dialer.connection().state());
    }

    {
        var ctx_api = try ContextApi.init(allocator);
        defer ctx_api.deinit();

        var malformed_ctx = MalformedScript{};
        var packet_conn = FakePacketConn(ConnType).init(&malformed_ctx, malformedWrite(ConnType));
        const packet = PacketConn.init(&packet_conn);

        var malformed_dialer = DialerType.init(alice_static, bob_static.public, 60);
        try testing.expectError(
            noise.MessageError.TooShort,
            malformed_dialer.dialContext(
                ctx_api.background(),
                packet,
                @ptrCast(&remote_addr),
                remote_addr_len,
            ),
        );
    }

    {
        var ctx_api = try ContextApi.init(allocator);
        defer ctx_api.deinit();

        var cancel_ctx = try ctx_api.withCancel(ctx_api.background());
        defer cancel_ctx.deinit();
        cancel_ctx.cancel();

        var packet_conn = FakePacketConn(ConnType).init(null, null);
        const packet = PacketConn.init(&packet_conn);

        var canceled_dialer = DialerType.init(alice_static, bob_static.public, 70);
        try testing.expectError(
            error.Canceled,
            canceled_dialer.dialContext(
                cancel_ctx,
                packet,
                @ptrCast(&remote_addr),
                remote_addr_len,
            ),
        );
        try testing.expectEqual(@as(usize, 0), packet_conn.write_count);
    }
}

fn ResponderScript(comptime ConnType: type) type {
    return struct {
        responder: ConnType,
    };
}

fn RetryScript(comptime ConnType: type) type {
    return struct {
        responder: ConnType,
        dropped_first: bool = false,
    };
}

fn FilterScript(comptime ConnType: type) type {
    return struct {
        responder: ConnType,
    };
}

const MalformedScript = struct {};

fn FakePacketConn(comptime ConnType: type) type {
    _ = ConnType;
    const PacketConn = dep.net.PacketConn;
    return struct {
        const Self = @This();
        const max_packets = 4;
        const max_packet_len = 128;

        pub const Packet = struct {
            len: usize,
            data: [max_packet_len]u8,
            addr: PacketConn.AddrStorage,
            addr_len: u32,
        };

        pub const OnWriteFn = *const fn (ctx: ?*anyopaque, packet_conn: *anyopaque, data: []const u8, addr: []const u8) anyerror!void;

        on_write_ctx: ?*anyopaque,
        on_write: ?OnWriteFn,
        queued: [max_packets]Packet = undefined,
        queued_len: usize = 0,
        read_index: usize = 0,
        writes: [max_packets]Packet = undefined,
        write_count: usize = 0,
        read_timeout_ms: ?u32 = null,
        write_timeout_ms: ?u32 = null,
        closed: bool = false,

        fn init(on_write_ctx: ?*anyopaque, on_write: ?OnWriteFn) Self {
            return .{
                .on_write_ctx = on_write_ctx,
                .on_write = on_write,
            };
        }

        pub fn readFrom(self: *Self, buf: []u8) PacketConn.ReadFromError!PacketConn.ReadFromResult {
            if (self.closed) return error.Closed;
            if (self.read_index >= self.queued_len) return error.TimedOut;

            const packet = self.queued[self.read_index];
            self.read_index += 1;
            @memcpy(buf[0..packet.len], packet.data[0..packet.len]);
            return .{
                .bytes_read = packet.len,
                .addr = packet.addr,
                .addr_len = packet.addr_len,
            };
        }

        pub fn writeTo(self: *Self, buf: []const u8, addr: [*]const u8, addr_len: u32) PacketConn.WriteToError!usize {
            if (self.closed) return error.Closed;
            if (self.write_count >= self.writes.len) return error.Unexpected;
            if (buf.len > max_packet_len) return error.MessageTooLong;

            self.writes[self.write_count] = .{
                .len = buf.len,
                .data = undefined,
                .addr = @splat(0),
                .addr_len = addr_len,
            };
            @memcpy(self.writes[self.write_count].data[0..buf.len], buf);
            @memcpy(self.writes[self.write_count].addr[0..addr_len], addr[0..addr_len]);
            self.write_count += 1;

            if (self.on_write) |callback| {
                callback(self.on_write_ctx, self, buf, addr[0..addr_len]) catch return error.Unexpected;
            }
            return buf.len;
        }

        pub fn close(self: *Self) void {
            self.closed = true;
        }

        pub fn deinit(self: *Self) void {
            self.closed = true;
        }

        pub fn setReadTimeout(self: *Self, ms: ?u32) void {
            self.read_timeout_ms = ms;
        }

        pub fn setWriteTimeout(self: *Self, ms: ?u32) void {
            self.write_timeout_ms = ms;
        }

        fn queuePacket(self: *Self, data: []const u8, addr: []const u8) !void {
            if (self.queued_len >= self.queued.len) return error.Unexpected;
            if (data.len > max_packet_len) return error.Unexpected;
            if (addr.len > @sizeOf(PacketConn.AddrStorage)) return error.Unexpected;

            self.queued[self.queued_len] = .{
                .len = data.len,
                .data = undefined,
                .addr = @splat(0),
                .addr_len = @intCast(addr.len),
            };
            @memcpy(self.queued[self.queued_len].data[0..data.len], data);
            @memcpy(self.queued[self.queued_len].addr[0..addr.len], addr);
            self.queued_len += 1;
        }
    };
}

fn responderWrite(comptime ConnType: type) FakePacketConn(ConnType).OnWriteFn {
    return struct {
        fn call(ctx: ?*anyopaque, packet_conn: *anyopaque, data: []const u8, addr: []const u8) !void {
            const typed_ctx = ctx orelse return error.Unexpected;
            const responder_ctx: *ResponderScript(ConnType) = @ptrCast(@alignCast(typed_ctx));
            const self: *FakePacketConn(ConnType) = @ptrCast(@alignCast(packet_conn));
            var response: [128]u8 = undefined;
            const response_n = try responder_ctx.responder.acceptHandshakeInit(data, &response, 400);
            try self.queuePacket(response[0..response_n], addr);
        }
    }.call;
}

fn retryingResponderWrite(comptime ConnType: type) FakePacketConn(ConnType).OnWriteFn {
    return struct {
        fn call(ctx: ?*anyopaque, packet_conn: *anyopaque, data: []const u8, addr: []const u8) !void {
            const typed_ctx = ctx orelse return error.Unexpected;
            const responder_ctx: *RetryScript(ConnType) = @ptrCast(@alignCast(typed_ctx));
            const self: *FakePacketConn(ConnType) = @ptrCast(@alignCast(packet_conn));
            if (!responder_ctx.dropped_first) {
                responder_ctx.dropped_first = true;
                return;
            }

            var response: [128]u8 = undefined;
            const response_n = try responder_ctx.responder.acceptHandshakeInit(data, &response, 500);
            try self.queuePacket(response[0..response_n], addr);
        }
    }.call;
}

fn filterWrite(comptime ConnType: type) FakePacketConn(ConnType).OnWriteFn {
    return struct {
        fn call(ctx: ?*anyopaque, packet_conn: *anyopaque, data: []const u8, addr: []const u8) !void {
            const typed_ctx = ctx orelse return error.Unexpected;
            const responder_ctx: *FilterScript(ConnType) = @ptrCast(@alignCast(typed_ctx));
            const self: *FakePacketConn(ConnType) = @ptrCast(@alignCast(packet_conn));

            var wrong_response: [noise.Message.min_handshake_resp_size]u8 = [_]u8{0} ** noise.Message.min_handshake_resp_size;
            wrong_response[0] = @intFromEnum(noise.MessageType.handshake_resp);
            const empty = [_]u8{0} ** noise.TagSize;
            _ = try noise.Message.buildHandshakeResp(
                &wrong_response,
                999,
                777,
                noise.Key.zero,
                &empty,
            );
            try self.queuePacket(&wrong_response, addr);

            var response: [128]u8 = undefined;
            const response_n = try responder_ctx.responder.acceptHandshakeInit(data, &response, 600);
            try self.queuePacket(response[0..response_n], addr);
        }
    }.call;
}

fn malformedWrite(comptime ConnType: type) FakePacketConn(ConnType).OnWriteFn {
    return struct {
        fn call(_: ?*anyopaque, packet_conn: *anyopaque, _: []const u8, addr: []const u8) !void {
            const self: *FakePacketConn(ConnType) = @ptrCast(@alignCast(packet_conn));
            const malformed = [_]u8{@intFromEnum(noise.MessageType.handshake_resp)};
            try self.queuePacket(&malformed, addr);
        }
    }.call;
}
