const Self = @This();

pub fn Addr(comptime Impl: type) type {
    comptime {
        _ = @as(*const fn (*const Impl) []const u8, &Impl.network);
        _ = @as(*const fn (*const Impl, []u8) []const u8, &Impl.stringify);
    }

    return Impl;
}

pub fn Transport(comptime Impl: type) type {
    comptime {
        _ = @as(*const fn (*Impl, []const u8, Impl.AddrType) anyerror!void, &Impl.sendTo);
        _ = @as(*const fn (*Impl, []u8) anyerror!Impl.RecvResult, &Impl.recvFrom);
        _ = @as(*const fn (*Impl) anyerror!void, &Impl.close);
        _ = @as(*const fn (*const Impl) Impl.AddrType, &Impl.localAddr);
        _ = @as(*const fn (*Impl, i64) anyerror!void, &Impl.setReadDeadlineMs);
        _ = @as(*const fn (*Impl, i64) anyerror!void, &Impl.setWriteDeadlineMs);
    }

    return Impl;
}

pub fn testAll(testing: anytype) !void {
    const MockAddr = struct {
        bytes: []const u8,

        pub fn network(_: *const @This()) []const u8 {
            return "mock";
        }

        pub fn stringify(self: *const @This(), buf: []u8) []const u8 {
            const len = @min(buf.len, self.bytes.len);
            @memcpy(buf[0..len], self.bytes[0..len]);
            return buf[0..len];
        }
    };

    const MockAddrType = Addr(MockAddr);
    const MockRecvResult = struct {
        n: usize,
        addr: MockAddrType,
    };

    const MockTransport = struct {
        pub const AddrType = MockAddrType;
        pub const RecvResult = MockRecvResult;

        local: MockAddr = .{ .bytes = "local" },
        closed: bool = false,

        pub fn sendTo(_: *@This(), _: []const u8, _: AddrType) !void {}

        pub fn recvFrom(_: *@This(), buf: []u8) !RecvResult {
            if (buf.len == 0) return error.EmptyBuffer;
            buf[0] = 0xaa;
            return .{ .n = 1, .addr = .{ .bytes = "remote" } };
        }

        pub fn close(self: *@This()) !void {
            self.closed = true;
        }

        pub fn localAddr(self: *const @This()) AddrType {
            return self.local;
        }

        pub fn setReadDeadlineMs(_: *@This(), _: i64) !void {}

        pub fn setWriteDeadlineMs(_: *@This(), _: i64) !void {}
    };

    const TransportType = Transport(MockTransport);
    var transport = TransportType{};
    var buf: [8]u8 = undefined;
    const recv = try transport.recvFrom(&buf);

    try testing.expectEqual(@as(usize, 1), recv.n);
    try testing.expectEqual(@as(u8, 0xaa), buf[0]);
    try testing.expectEqualStrings("mock", recv.addr.network());

    var addr_buf: [16]u8 = undefined;
    const text = transport.localAddr().stringify(&addr_buf);
    try testing.expectEqualStrings("local", text);

    try transport.close();
    try testing.expect(transport.closed);
}
