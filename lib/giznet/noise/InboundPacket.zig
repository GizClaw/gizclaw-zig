const glib = @import("glib");
const Cipher = @import("Cipher.zig");
const Key = @import("Key.zig");
const Message = @import("Message.zig");
const SessionType = @import("Session.zig");
const PoolType = glib.sync.Pool;
const AddrPort = glib.net.netip.AddrPort;
const legacy_packet_size_capacity = SessionType.legacy_packet_size_capacity;

const InboundPacket = @This();

pub const State = enum {
    initial,
    prepared,
    ready_to_consume,
    consumed,
    decrypt_failed,
    consume_failed,
};

pub const Kind = enum {
    unknown,
    handshake,
    transport,
};

pub const VTable = struct {
    bufRef: *const fn (ptr: *anyopaque) []u8,
};

pub const Pool = struct {
    ptr: *anyopaque,
    vtable: *const PoolVTable,

    pub const PoolVTable = struct {
        get: *const fn (ptr: *anyopaque) ?*InboundPacket,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn get(self: Pool) ?*InboundPacket {
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
timestamp_ms: u64 = 0,
state: State = .initial,
kind: Kind = .unknown,
remote_static: Key = .{},
session_key: Key = .{},
local_session_index: u32 = 0,
remote_session_index: u32 = 0,
counter: u64 = 0,

fn init(self: *InboundPacket, pointer: anytype) *InboundPacket {
    const Ptr = @TypeOf(pointer);
    const info = @typeInfo(Ptr);
    if (info != .pointer or info.pointer.size != .one)
        @compileError("InboundPacket.init expects a single-item pointer");

    const Impl = info.pointer.child;
    if (!comptime @hasDecl(Impl, "bufRef"))
        @compileError("InboundPacket.init expects pointer type to expose `bufRef()`");

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

pub fn bufRef(self: *const InboundPacket) []u8 {
    const vtable = self.vtable orelse unreachable;
    const impl_ptr = self.impl_ptr orelse unreachable;
    return vtable.bufRef(impl_ptr);
}

pub fn bytes(self: *const InboundPacket) []u8 {
    const start = switch (self.kind) {
        .handshake, .unknown => 0,
        .transport => switch (self.state) {
            .ready_to_consume, .consumed, .consume_failed => Message.TransportHeaderSize,
            else => 0,
        },
    };
    return self.bufRef()[start..][0..self.len];
}

pub fn fullBuffer(self: *const InboundPacket) []u8 {
    return self.bufRef();
}

pub fn eql(self: *const InboundPacket, other: *const InboundPacket) bool {
    return self == other;
}

pub fn decrtpy(comptime grt: type, comptime cipher_kind: Cipher.Kind, self: *InboundPacket) !void {
    const CipherSuite = Cipher.make(grt, cipher_kind);
    errdefer self.state = .decrypt_failed;
    const transport = Message.parseTransportMessage(self.fullBuffer()[0..self.len]) catch return error.InvalidTransportPacket;
    if (transport.receiver_index != self.local_session_index) return error.SessionIndexMismatch;
    if (transport.counter == glib.std.math.maxInt(u64)) return error.InvalidTransportPacket;

    const plaintext_len = transport.ciphertext.len - Message.tag_size;
    const plaintext = self.fullBuffer()[Message.TransportHeaderSize..];
    if (plaintext.len < plaintext_len) return error.BufferTooSmall;
    const session_key = self.session_key;
    const written = CipherSuite.decrypt(&session_key, transport.counter, transport.ciphertext, "", plaintext[0..plaintext_len]) catch |err| switch (err) {
        error.AuthenticationFailed => return error.AuthenticationFailed,
        else => return error.InvalidTransportPacket,
    };

    self.len = written;
    self.kind = .transport;
    self.state = .ready_to_consume;
}

pub fn deinit(self: *InboundPacket) void {
    const pool = self.pool orelse unreachable;
    const impl_ptr = self.impl_ptr orelse unreachable;
    self.len = 0;
    self.remote_endpoint = .{};
    self.timestamp_ms = 0;
    self.state = .initial;
    self.kind = .unknown;
    self.remote_static = .{};
    self.session_key = .{};
    self.local_session_index = 0;
    self.remote_session_index = 0;
    self.counter = 0;
    pool.put(impl_ptr);
}

fn make(comptime _: type, comptime packet_size: usize) type {
    return struct {
        buffer_storage: [packet_size]u8 = undefined,
        packet: InboundPacket = undefined,

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
    const ImplPool = PoolType.make(grt.std, Impl);

    const PoolImpl = struct {
        allocator: glib.std.mem.Allocator,
        pool: ImplPool,

        pub fn getPacket(self: *@This()) ?*InboundPacket {
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
        fn getFn(ptr: *anyopaque) ?*InboundPacket {
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

            tryDecryptTransportCase(grt) catch |err| {
                t.logErrorf("giznet/runtime InboundPacket decrypt transport failed: {}", .{err});
                return false;
            };
            tryWrapperCase(grt) catch |err| {
                t.logErrorf("giznet/runtime InboundPacket wrapper failed: {}", .{err});
                return false;
            };
            tryPoolReuseCase(grt) catch |err| {
                t.logErrorf("giznet/runtime InboundPacket pool reuse failed: {}", .{err});
                return false;
            };
            tryPoolMultipleOutstandingCase(grt) catch |err| {
                t.logErrorf("giznet/runtime InboundPacket pool multiple outstanding failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: glib.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryDecryptTransportCase(comptime any_lib: type) !void {
            const Session = SessionType.make(any_lib, legacy_packet_size_capacity, Cipher.default_kind);
            const CipherSuite = Cipher.make(any_lib, Cipher.default_kind);
            var pool = try initPool(any_lib, grt.std.testing.allocator, legacy_packet_size_capacity);
            defer pool.deinit();

            const packet = pool.get() orelse return error.TestExpectedPacket;
            defer packet.deinit();

            const endpoint = AddrPort.from4(.{ 127, 0, 0, 1 }, 9201);
            const session_key = Key{ .bytes = [_]u8{0x4b} ** 32 };
            const receiver_index: u32 = 77;
            const counter: u64 = 9;
            const payload = "decrypt me";

            var plaintext: [Session.max_plaintext_len]u8 = undefined;
            const plaintext_len = try Message.encodePayload(payload, plaintext[0..]);

            var ciphertext_storage: [Session.max_ciphertext_len]u8 = undefined;
            const cipher_len = CipherSuite.encrypt(
                &session_key,
                counter,
                plaintext[0..plaintext_len],
                "",
                ciphertext_storage[0..],
            );

            var wire: [legacy_packet_size_capacity]u8 = undefined;
            const wire_len = try Message.buildTransportMessage(
                receiver_index,
                counter,
                ciphertext_storage[0..cipher_len],
                wire[0..],
            );

            if (wire_len > packet.bufRef().len) return error.BufferTooSmall;
            @memcpy(packet.bufRef()[0..wire_len], wire[0..wire_len]);
            packet.len = wire_len;
            packet.remote_endpoint = endpoint;
            packet.timestamp_ms = 77;
            packet.state = .prepared;
            packet.kind = .unknown;
            packet.remote_static = .{};
            packet.session_key = .{};
            packet.local_session_index = 0;
            packet.remote_session_index = 0;
            packet.counter = 0;
            packet.remote_static = Key{ .bytes = [_]u8{0x2a} ** 32 };
            packet.session_key = session_key;
            packet.local_session_index = receiver_index;
            packet.remote_session_index = 88;
            packet.counter = counter;

            try InboundPacket.decrtpy(any_lib, Cipher.default_kind, packet);

            try grt.std.testing.expect(glib.std.mem.eql(u8, packet.bytes(), payload));
            try grt.std.testing.expectEqual(@as(usize, payload.len), packet.len);
            try grt.std.testing.expectEqual(counter, packet.counter);
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
            var packet_storage: InboundPacket = .{};
            const packet = packet_storage.init(&mock);
            const endpoint = AddrPort.from4(.{ 127, 0, 0, 1 }, 9001);

            const payload = [_]u8{ 7, 'h', 'e', 'l', 'l', 'o' };
            if (payload.len > packet.bufRef().len) return error.BufferTooSmall;
            @memcpy(packet.bufRef()[0..payload.len], payload[0..]);
            packet.len = payload.len;
            packet.remote_endpoint = endpoint;
            packet.timestamp_ms = 77;
            packet.state = .prepared;
            packet.kind = .unknown;
            packet.remote_static = .{};
            packet.session_key = .{};
            packet.local_session_index = 0;
            packet.remote_session_index = 0;
            packet.counter = 0;
            try grt.std.testing.expect(glib.std.mem.eql(u8, packet.bytes(), &[_]u8{ 7, 'h', 'e', 'l', 'l', 'o' }));
            try grt.std.testing.expect(glib.std.meta.eql(packet.remote_endpoint, endpoint));
            try grt.std.testing.expectEqual(@as(u64, 77), packet.timestamp_ms);
            try grt.std.testing.expectEqual(State.prepared, packet.state);
            try grt.std.testing.expectEqual(Kind.unknown, packet.kind);
            try grt.std.testing.expectEqual(@as(u32, 0), packet.local_session_index);
            try grt.std.testing.expectEqual(@as(u32, 0), packet.remote_session_index);
            try grt.std.testing.expectEqual(@as(u64, 0), packet.counter);

            packet.state = .consumed;
            packet.counter = 11;
            try grt.std.testing.expectEqual(State.consumed, packet.state);
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
            first.timestamp_ms = 91;
            first.state = .prepared;
            first.kind = .unknown;
            first.remote_static = .{};
            first.session_key = .{};
            first.local_session_index = 0;
            first.remote_session_index = 0;
            first.counter = 0;
            first.state = .consumed;
            first.counter = 17;
            first.deinit();

            const second = pool.get() orelse return error.TestExpectedSecondPacket;
            defer second.deinit();

            try grt.std.testing.expect(second.eql(first));
            try grt.std.testing.expectEqual(@as(usize, 0), second.bytes().len);
            try grt.std.testing.expect(glib.std.meta.eql(second.remote_endpoint, AddrPort{}));
            try grt.std.testing.expectEqual(State.initial, second.state);
            try grt.std.testing.expectEqual(Kind.unknown, second.kind);
            try grt.std.testing.expectEqual(@as(u64, 0), second.counter);
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
