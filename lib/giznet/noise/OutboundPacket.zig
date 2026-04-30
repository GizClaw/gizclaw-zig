const glib = @import("glib");
const Cipher = @import("Cipher.zig");
const Key = @import("Key.zig");
const Message = @import("Message.zig");
const SessionType = @import("Session.zig");
const PoolType = glib.sync.Pool;
const AddrPort = glib.net.netip.AddrPort;
const legacy_packet_size_capacity = SessionType.legacy_packet_size_capacity;

const OutboundPacket = @This();

pub const State = enum {
    initial,
    prepared,
    ready_to_send,
};

impl_ptr: ?*anyopaque = null,
vtable: ?*const VTable = null,
pool: ?PoolType = null,
len: usize = 0,
state: State = .initial,
kind: Kind = .transport,
remote_endpoint: AddrPort = .{},
remote_static: Key = .{},
session_key: Key = .{},
remote_session_index: u32 = 0,
counter: u64 = 0,

pub const Kind = enum {
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
        get: *const fn (ptr: *anyopaque) ?*OutboundPacket,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn get(self: Pool) ?*OutboundPacket {
        return self.vtable.get(self.ptr);
    }

    pub fn deinit(self: Pool) void {
        self.vtable.deinit(self.ptr);
    }
};

fn init(self: *OutboundPacket, pointer: anytype) *OutboundPacket {
    const Ptr = @TypeOf(pointer);
    const info = @typeInfo(Ptr);
    if (info != .pointer or info.pointer.size != .one)
        @compileError("OutboundPacket.init expects a single-item pointer");

    const Impl = info.pointer.child;
    if (!comptime @hasDecl(Impl, "bufRef"))
        @compileError("OutboundPacket.init expects pointer type to expose `bufRef()`");

    const erased: *anyopaque = @ptrCast(@alignCast(pointer));

    const Gen = struct {
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
    self.vtable = &Gen.vtable;
    return self;
}

pub fn bytes(self: *const OutboundPacket) []u8 {
    const start = switch (self.kind) {
        .handshake => 0,
        .transport => switch (self.state) {
            .prepared => Message.TransportHeaderSize,
            else => 0,
        },
    };
    return self.bufRef()[start..][0..self.len];
}

pub fn bufRef(self: *const OutboundPacket) []u8 {
    const vtable = self.vtable orelse unreachable;
    const impl_ptr = self.impl_ptr orelse unreachable;
    return vtable.bufRef(impl_ptr);
}

pub fn transportPlaintextBufRef(self: *const OutboundPacket) []u8 {
    return self.bufRef()[Message.TransportHeaderSize..];
}

pub fn eql(self: *const OutboundPacket, other: *const OutboundPacket) bool {
    return self == other;
}

pub fn encrypt(comptime grt: type, comptime cipher_kind: Cipher.Kind, self: *OutboundPacket) !void {
    const Session = SessionType.make(grt, legacy_packet_size_capacity, cipher_kind);
    const CipherSuite = Cipher.make(grt, cipher_kind);

    if (self.kind == .handshake) {
        self.state = .ready_to_send;
        return;
    }

    glib.std.debug.assert(self.kind == .transport);

    const buffer = self.bufRef();
    const plaintext = self.bytes();
    if (plaintext.len > Session.max_plaintext_len) return error.BufferTooSmall;
    const ciphertext = buffer[Session.outer_header_len..];
    if (ciphertext.len < plaintext.len + Session.tag_len) return error.BufferTooSmall;
    const cipher_len = CipherSuite.encrypt(
        &self.session_key,
        self.counter,
        plaintext,
        "",
        ciphertext,
    );
    const written = try Message.buildTransportMessage(
        self.remote_session_index,
        self.counter,
        ciphertext[0..cipher_len],
        buffer,
    );
    self.len = written;
    self.state = .ready_to_send;
}

pub fn deinit(self: *OutboundPacket) void {
    const pool = self.pool orelse unreachable;
    const impl_ptr = self.impl_ptr orelse unreachable;
    self.len = 0;
    self.state = .initial;
    self.kind = .transport;
    self.remote_endpoint = .{};
    self.remote_static = .{};
    self.session_key = .{};
    self.remote_session_index = 0;
    self.counter = 0;
    pool.put(impl_ptr);
}

fn make(comptime _: type, comptime packet_size: usize) type {
    return struct {
        buffer_storage: [packet_size]u8 = undefined,
        packet: OutboundPacket = undefined,

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

        pub fn getPacket(self: *@This()) ?*OutboundPacket {
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
        fn getFn(ptr: *anyopaque) ?*OutboundPacket {
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

            tryEncryptTransportCase(grt) catch |err| {
                t.logErrorf("giznet/runtime OutboundPacket encrypt transport failed: {}", .{err});
                return false;
            };
            tryPoolReuseCase(grt) catch |err| {
                t.logErrorf("giznet/runtime OutboundPacket pool reuse failed: {}", .{err});
                return false;
            };
            tryPoolMultipleOutstandingCase(grt) catch |err| {
                t.logErrorf("giznet/runtime OutboundPacket pool multiple outstanding failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: glib.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryEncryptTransportCase(comptime any_lib: type) !void {
            const Session = SessionType.make(any_lib, legacy_packet_size_capacity, Cipher.default_kind);
            const CipherSuite = Cipher.make(any_lib, Cipher.default_kind);
            var pool = try initPool(any_lib, grt.std.testing.allocator, legacy_packet_size_capacity);
            defer pool.deinit();

            const packet = pool.get() orelse return error.TestExpectedPacket;
            defer packet.deinit();

            const endpoint = AddrPort.from4(.{ 127, 0, 0, 1 }, 9301);
            const session_key = Key{ .bytes = [_]u8{0x5c} ** 32 };
            const remote_session_index: u32 = 91;
            const counter: u64 = 14;
            const payload = [_]u8{ 6, 'e', 'n', 'c', 'r', 'y', 'p', 't', ' ', 'm', 'e' };

            packet.state = .prepared;
            packet.kind = .transport;
            if (payload.len > packet.transportPlaintextBufRef().len) return error.BufferTooSmall;
            @memcpy(packet.transportPlaintextBufRef()[0..payload.len], payload[0..]);
            packet.len = payload.len;
            packet.remote_endpoint = endpoint;
            packet.remote_static = Key{ .bytes = [_]u8{0x7d} ** 32 };
            packet.session_key = session_key;
            packet.remote_session_index = remote_session_index;
            packet.counter = counter;

            try OutboundPacket.encrypt(any_lib, Cipher.default_kind, packet);

            try grt.std.testing.expectEqual(State.ready_to_send, packet.state);
            try grt.std.testing.expectEqual(Kind.transport, packet.kind);

            const transport = try Message.parseTransportMessage(packet.bytes());
            try grt.std.testing.expectEqual(remote_session_index, transport.receiver_index);
            try grt.std.testing.expectEqual(counter, transport.counter);

            var plaintext: [Session.max_plaintext_len]u8 = undefined;
            const written = try CipherSuite.decrypt(
                &session_key,
                counter,
                transport.ciphertext,
                "",
                plaintext[0..],
            );
            try grt.std.testing.expect(glib.std.mem.eql(u8, plaintext[0..written], payload[0..]));
        }

        fn tryPoolReuseCase(comptime any_lib: type) !void {
            var pool = try initPool(any_lib, grt.std.testing.allocator, 32);
            defer pool.deinit();

            const first = pool.get() orelse return error.TestExpectedFirstPacket;
            const endpoint = AddrPort.from4(.{ 127, 0, 0, 1 }, 9101);
            if ("ping".len > first.bufRef().len) return error.BufferTooSmall;
            @memcpy(first.bufRef()[0.."ping".len], "ping");
            first.len = "ping".len;
            first.state = .prepared;
            first.kind = .transport;
            first.remote_endpoint = endpoint;
            first.state = .ready_to_send;
            first.deinit();

            const second = pool.get() orelse return error.TestExpectedSecondPacket;
            defer second.deinit();

            try grt.std.testing.expect(second.eql(first));
            try grt.std.testing.expectEqual(@as(usize, 0), second.bytes().len);
            try grt.std.testing.expect(glib.std.meta.eql(second.remote_endpoint, AddrPort{}));
            try grt.std.testing.expectEqual(State.initial, second.state);
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
