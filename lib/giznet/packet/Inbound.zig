const glib = @import("glib");
const Key = @import("../noise/Key.zig");
const Message = @import("../noise/Message.zig");
const Protocol = @import("../service/protocol.zig");
const Uvarint = @import("../service/Uvarint.zig");

const PoolType = glib.sync.Pool;
const AddrPort = glib.net.netip.AddrPort;

const Inbound = @This();

pub const State = enum {
    initial,
    consumed,
    service_delivered,
    consume_failed,
};

pub const Kind = enum {
    unknown,
    handshake,
    transport,
};

pub const ServiceData = union(enum) {
    direct: Direct,
    kcp: Kcp,
    close: void,
};

pub const Direct = struct {
    protocol: u8 = 0,
    payload: []u8 = &.{},
};

pub const Kcp = struct {
    service: u64 = 0,
    stream: u64 = 0,
    frame_type: u8 = 0,
    frame: []u8 = &.{},
    payload: []u8 = &.{},
};

pub const VTable = struct {
    bufRef: *const fn (ptr: *anyopaque) []u8,
};

pub const Pool = struct {
    ptr: *anyopaque,
    vtable: *const PoolVTable,

    pub const PoolVTable = struct {
        get: *const fn (ptr: *anyopaque) ?*Inbound,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn get(self: Pool) ?*Inbound {
        return self.vtable.get(self.ptr);
    }

    pub fn deinit(self: Pool) void {
        self.vtable.deinit(self.ptr);
    }
};

impl_ptr: ?*anyopaque = null,
vtable: ?*const VTable = null,
pool: ?PoolType = null,
len: usize = 0,
remote_endpoint: AddrPort = .{},
timestamp: glib.time.instant.Time = 0,
state: State = .initial,
kind: Kind = .unknown,
remote_static: Key = .{},
service_data: ?ServiceData = null,

fn init(self: *Inbound, pointer: anytype) *Inbound {
    const Ptr = @TypeOf(pointer);
    const info = @typeInfo(Ptr);
    if (info != .pointer or info.pointer.size != .one)
        @compileError("Inbound.init expects a single-item pointer");

    const Impl = info.pointer.child;
    if (!comptime @hasDecl(Impl, "bufRef"))
        @compileError("Inbound.init expects pointer type to expose `bufRef()`");

    const erased: *anyopaque = @ptrCast(@alignCast(pointer));

    const gen = struct {
        fn bufferRef(ptr: *anyopaque) []u8 {
            const impl: *Impl = @ptrCast(@alignCast(ptr));
            return impl.bufRef();
        }

        const vtable = VTable{
            .bufRef = bufferRef,
        };
    };

    self.* = .{};
    self.impl_ptr = erased;
    self.vtable = &gen.vtable;
    return self;
}

pub fn bufRef(self: *const Inbound) []u8 {
    const vtable = self.vtable orelse unreachable;
    const impl_ptr = self.impl_ptr orelse unreachable;
    return vtable.bufRef(impl_ptr);
}

pub fn bytes(self: *const Inbound) []u8 {
    const start = switch (self.kind) {
        .handshake, .unknown => 0,
        .transport => switch (self.state) {
            .consumed, .service_delivered, .consume_failed => Message.TransportHeaderSize,
            else => 0,
        },
    };
    return self.bufRef()[start..][0..self.len];
}

pub fn fullBuffer(self: *const Inbound) []u8 {
    return self.bufRef();
}

pub fn eql(self: *const Inbound, other: *const Inbound) bool {
    return self == other;
}

pub fn parseServiceData(self: *Inbound) !*Inbound {
    const data = self.bytes();
    if (data.len < 1) return error.PayloadTooShort;
    const payload = data[1..];
    switch (data[0]) {
        Protocol.ProtocolKCP => {
            const service = try Uvarint.read(payload);
            const mux_frame = payload[service.len..];
            if (mux_frame.len == 0) return error.InvalidServiceFrame;
            const frame_type = mux_frame[0];
            const frame_payload = mux_frame[1..];
            var stream: u64 = 0;
            var frame = frame_payload;
            var kcp_payload = frame_payload;
            switch (frame_type) {
                Protocol.KcpMuxFrameData => {
                    if (frame_payload.len < 4) return error.InvalidServiceFrame;
                    stream = glib.std.mem.readInt(u32, frame_payload[0..4], .little);
                },
                Protocol.KcpMuxFrameOpen,
                Protocol.KcpMuxFrameClose,
                Protocol.KcpMuxFrameCloseAck,
                => {
                    if (frame_payload.len < 4) return error.InvalidServiceFrame;
                    stream = glib.std.mem.readInt(u32, frame_payload[0..4], .little);
                    frame = frame_payload[4..];
                    kcp_payload = frame_payload[4..];
                },
                else => {},
            }
            self.service_data = .{ .kcp = .{
                .service = service.value,
                .stream = stream,
                .frame_type = frame_type,
                .frame = frame,
                .payload = kcp_payload,
            } };
        },
        Protocol.ProtocolConnCtrl => {
            self.service_data = .{ .close = {} };
        },
        else => |protocol| {
            self.service_data = .{ .direct = .{
                .protocol = protocol,
                .payload = payload,
            } };
        },
    }
    return self;
}

pub fn deinit(self: *Inbound) void {
    const pool = self.pool orelse unreachable;
    const impl_ptr = self.impl_ptr orelse unreachable;
    self.len = 0;
    self.remote_endpoint = .{};
    self.timestamp = 0;
    self.state = .initial;
    self.kind = .unknown;
    self.remote_static = .{};
    self.service_data = null;
    pool.put(impl_ptr);
}

fn make(comptime _: type, comptime packet_size: usize) type {
    return struct {
        buffer_storage: [packet_size]u8 = undefined,
        packet: Inbound = undefined,

        const Self = @This();
        fn bufRef(self: *Self) []u8 {
            return self.buffer_storage[0..];
        }

        const gen = struct {
            fn bufferRef(ptr: *anyopaque) []u8 {
                const self: *Self = @ptrCast(@alignCast(ptr));
                return self.bufRef();
            }

            const vtable = VTable{
                .bufRef = bufferRef,
            };
        };
    };
}

pub fn initPool(
    comptime grt: type,
    allocator: glib.std.mem.Allocator,
    comptime packet_size: usize,
) !Pool {
    const Impl = make(grt, packet_size);
    const ImplPool = PoolType.makeWithSync(grt.std, grt.sync, Impl);

    const PoolImpl = struct {
        allocator: glib.std.mem.Allocator,
        pool: ImplPool,

        pub fn getPacket(self: *@This()) ?*Inbound {
            const impl = self.pool.getTyped() orelse return null;
            const packet = impl.packet.init(impl);
            packet.pool = PoolType.init(&self.pool);
            return packet;
        }

        pub fn deinit(self: *@This()) void {
            self.pool.deinit();
            self.allocator.destroy(self);
        }
    };

    const impl = try allocator.create(PoolImpl);
    errdefer allocator.destroy(impl);
    impl.* = .{
        .allocator = allocator,
        .pool = ImplPool.init(allocator, struct {
            fn newImpl(_: ?*anyopaque, _: glib.std.mem.Allocator) ?Impl {
                return .{};
            }
        }.newImpl, null),
    };

    const gen = struct {
        fn getFn(ptr: *anyopaque) ?*Inbound {
            const self: *PoolImpl = @ptrCast(@alignCast(ptr));
            return self.getPacket();
        }

        fn deinitFn(ptr: *anyopaque) void {
            const self: *PoolImpl = @ptrCast(@alignCast(ptr));
            self.deinit();
        }

        const vtable = Pool.PoolVTable{
            .get = getFn,
            .deinit = deinitFn,
        };
    };

    return .{
        .ptr = impl,
        .vtable = &gen.vtable,
    };
}

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    const testing_api = glib.testing;

    const Runner = struct {
        pub fn init(self: *@This(), allocator: glib.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: glib.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryWrapperCase(grt) catch |err| {
                t.logErrorf("giznet/packet Inbound wrapper failed: {}", .{err});
                return false;
            };
            tryParseServicePayloadCase(grt) catch |err| {
                t.logErrorf("giznet/packet Inbound service parse failed: {}", .{err});
                return false;
            };
            tryParseKcpDataFrameCase(grt) catch |err| {
                t.logErrorf("giznet/packet Inbound kcp data parse failed: {}", .{err});
                return false;
            };
            tryParseKcpControlFrameCase(grt) catch |err| {
                t.logErrorf("giznet/packet Inbound kcp control parse failed: {}", .{err});
                return false;
            };
            tryRejectShortKcpConvCase(grt) catch |err| {
                t.logErrorf("giznet/packet Inbound short kcp conv rejection failed: {}", .{err});
                return false;
            };
            tryPoolReuseCase(grt) catch |err| {
                t.logErrorf("giznet/packet Inbound pool reuse failed: {}", .{err});
                return false;
            };
            tryPoolMultipleOutstandingCase(grt) catch |err| {
                t.logErrorf("giznet/packet Inbound pool multiple outstanding failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: glib.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryWrapperCase(comptime any_lib: type) !void {
            _ = any_lib;
            const Mock = struct {
                storage: [32]u8 = undefined,

                fn bufRef(self: *@This()) []u8 {
                    return self.storage[0..];
                }
            };

            var mock = Mock{};
            var packet_storage: Inbound = .{};
            const packet = packet_storage.init(&mock);
            const endpoint = AddrPort.from4(.{ 127, 0, 0, 1 }, 9001);

            const payload = [_]u8{ 7, 'h', 'e', 'l', 'l', 'o' };
            if (payload.len > packet.bufRef().len) return error.BufferTooSmall;
            @memcpy(packet.bufRef()[0..payload.len], payload[0..]);
            packet.len = payload.len;
            packet.remote_endpoint = endpoint;
            packet.timestamp = 77;
            packet.state = .initial;
            packet.kind = .unknown;
            packet.remote_static = .{};
            try grt.std.testing.expect(glib.std.mem.eql(u8, packet.bytes(), &[_]u8{ 7, 'h', 'e', 'l', 'l', 'o' }));
            try grt.std.testing.expect(glib.std.meta.eql(packet.remote_endpoint, endpoint));
            try grt.std.testing.expectEqual(@as(glib.time.instant.Time, 77), packet.timestamp);
            try grt.std.testing.expectEqual(State.initial, packet.state);
            try grt.std.testing.expectEqual(Kind.unknown, packet.kind);
            try grt.std.testing.expectEqual(@as(?ServiceData, null), packet.service_data);

            packet.state = .consumed;
            try grt.std.testing.expectEqual(State.consumed, packet.state);
        }

        fn tryParseServicePayloadCase(comptime any_lib: type) !void {
            var pool = try initPool(any_lib, grt.std.testing.allocator, 32);
            defer pool.deinit();

            const packet = pool.get() orelse return error.TestExpectedPacket;
            defer packet.deinit();

            const payload = [_]u8{ 9, 'p', 'i', 'n', 'g' };
            const plaintext = packet.bufRef()[Message.TransportHeaderSize..];
            @memcpy(plaintext[0..payload.len], payload[0..]);
            packet.len = payload.len;
            packet.kind = .transport;
            packet.state = .consumed;

            try grt.std.testing.expect((try packet.parseServiceData()) == packet);
            const direct = packet.service_data.?.direct;
            try grt.std.testing.expectEqual(@as(u8, 9), direct.protocol);
            try grt.std.testing.expectEqualStrings("ping", direct.payload);
        }

        fn tryParseKcpDataFrameCase(comptime any_lib: type) !void {
            var pool = try initPool(any_lib, grt.std.testing.allocator, 64);
            defer pool.deinit();

            const packet = pool.get() orelse return error.TestExpectedPacket;
            defer packet.deinit();

            const service: u64 = 300;
            const stream: u32 = 0x01020304;
            var payload: [32]u8 = undefined;
            payload[0] = Protocol.ProtocolKCP;
            const service_len = try Uvarint.write(service, payload[1..]);
            const frame_offset = 1 + service_len;
            payload[frame_offset] = Protocol.KcpMuxFrameData;
            glib.std.mem.writeInt(u32, payload[frame_offset + 1 ..][0..4], stream, .little);
            @memcpy(payload[frame_offset + 5 ..][0..3], &[_]u8{ 0xaa, 0xbb, 0xcc });
            const payload_len = frame_offset + 8;

            const plaintext = packet.bufRef()[Message.TransportHeaderSize..];
            @memcpy(plaintext[0..payload_len], payload[0..payload_len]);
            packet.len = payload_len;
            packet.kind = .transport;
            packet.state = .consumed;

            try grt.std.testing.expect((try packet.parseServiceData()) == packet);
            const kcp = packet.service_data.?.kcp;
            try grt.std.testing.expectEqual(service, kcp.service);
            try grt.std.testing.expectEqual(@as(u64, stream), kcp.stream);
            try grt.std.testing.expectEqual(Protocol.KcpMuxFrameData, kcp.frame_type);
            try grt.std.testing.expectEqualSlices(u8, payload[frame_offset + 1 .. payload_len], kcp.frame);
            try grt.std.testing.expectEqualSlices(u8, payload[frame_offset + 1 .. payload_len], kcp.payload);
        }

        fn tryParseKcpControlFrameCase(comptime any_lib: type) !void {
            var pool = try initPool(any_lib, grt.std.testing.allocator, 64);
            defer pool.deinit();

            const packet = pool.get() orelse return error.TestExpectedPacket;
            defer packet.deinit();

            const stream: u32 = 0x01020304;
            const payload = [_]u8{
                Protocol.ProtocolKCP,
                7,
                Protocol.KcpMuxFrameClose,
                0x04,
                0x03,
                0x02,
                0x01,
                0xee,
            };
            const plaintext = packet.bufRef()[Message.TransportHeaderSize..];
            @memcpy(plaintext[0..payload.len], payload[0..]);
            packet.len = payload.len;
            packet.kind = .transport;
            packet.state = .consumed;

            try grt.std.testing.expect((try packet.parseServiceData()) == packet);
            const kcp = packet.service_data.?.kcp;
            try grt.std.testing.expectEqual(@as(u64, 7), kcp.service);
            try grt.std.testing.expectEqual(@as(u64, stream), kcp.stream);
            try grt.std.testing.expectEqual(Protocol.KcpMuxFrameClose, kcp.frame_type);
            try grt.std.testing.expectEqualSlices(u8, &[_]u8{0xee}, kcp.frame);
            try grt.std.testing.expectEqualSlices(u8, &[_]u8{0xee}, kcp.payload);
        }

        fn tryRejectShortKcpConvCase(comptime any_lib: type) !void {
            var pool = try initPool(any_lib, grt.std.testing.allocator, 64);
            defer pool.deinit();

            const packet = pool.get() orelse return error.TestExpectedPacket;
            defer packet.deinit();

            const payload = [_]u8{
                Protocol.ProtocolKCP,
                7,
                Protocol.KcpMuxFrameData,
                0x04,
                0x03,
                0x02,
            };
            const plaintext = packet.bufRef()[Message.TransportHeaderSize..];
            @memcpy(plaintext[0..payload.len], payload[0..]);
            packet.len = payload.len;
            packet.kind = .transport;
            packet.state = .consumed;

            try grt.std.testing.expectError(error.InvalidServiceFrame, packet.parseServiceData());
        }

        fn tryPoolReuseCase(comptime any_lib: type) !void {
            var pool = try initPool(any_lib, grt.std.testing.allocator, 32);
            defer pool.deinit();

            const first = pool.get() orelse return error.TestExpectedFirstPacket;
            const endpoint = AddrPort.from4(.{ 127, 0, 0, 1 }, 9101);
            if ("ping".len > first.bufRef().len) return error.BufferTooSmall;
            @memcpy(first.bufRef()[0.."ping".len], "ping");
            first.len = "ping".len;
            first.remote_endpoint = endpoint;
            first.timestamp = 91;
            first.state = .initial;
            first.kind = .unknown;
            first.remote_static = .{};
            first.service_data = .{ .direct = .{ .protocol = 7, .payload = first.bufRef()[0..0] } };
            first.state = .consumed;
            first.deinit();

            const second = pool.get() orelse return error.TestExpectedSecondPacket;
            defer second.deinit();

            try grt.std.testing.expect(second.eql(first));
            try grt.std.testing.expectEqual(@as(usize, 0), second.bytes().len);
            try grt.std.testing.expect(glib.std.meta.eql(second.remote_endpoint, AddrPort{}));
            try grt.std.testing.expectEqual(State.initial, second.state);
            try grt.std.testing.expectEqual(Kind.unknown, second.kind);
            try grt.std.testing.expectEqual(@as(?ServiceData, null), second.service_data);
        }

        fn tryPoolMultipleOutstandingCase(comptime any_lib: type) !void {
            var pool = try initPool(any_lib, grt.std.testing.allocator, 16);
            defer pool.deinit();

            const first = pool.get() orelse return error.TestExpectedFirstPacket;
            defer first.deinit();

            const second = pool.get() orelse return error.TestExpectedSecondPacket;
            defer second.deinit();

            try grt.std.testing.expect(!first.eql(second));
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
