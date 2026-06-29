const glib = @import("glib");
const Key = @import("giznet").Key;
const Message = @import("../noise/Message.zig");

const PoolType = glib.sync.Pool;
const AddrPort = glib.net.netip.AddrPort;

const Outbound = @This();

pub const State = enum {
    initial,
    ready_to_send,
};

pub const Kind = enum {
    handshake,
    transport,
};

pub const ServiceData = union(enum) {
    direct: Direct,
    open_stream: OpenStream,
    write_stream: WriteStream,
    close_stream: CloseStream,
};

pub const Direct = struct {
    protocol: u8 = 0,
    payload: []const u8 = &.{},
};

pub const OpenStream = struct {
    service: u64 = 0,
};

pub const WriteStream = struct {
    service: u64 = 0,
    stream: u64 = 0,
    payload: []const u8 = &.{},
};

pub const CloseStream = struct {
    service: u64 = 0,
    stream: u64 = 0,
};

impl_ptr: ?*anyopaque = null,
vtable: ?*const VTable = null,
pool: ?PoolType = null,
len: usize = 0,
state: State = .initial,
kind: Kind = .transport,
remote_endpoint: AddrPort = .{},
remote_static: Key = .{},
service_data: ?ServiceData = null,

pub const VTable = struct {
    bufRef: *const fn (ptr: *anyopaque) []u8,
};

pub const Pool = struct {
    ptr: *anyopaque,
    vtable: *const PoolVTable,

    pub const PoolVTable = struct {
        get: *const fn (ptr: *anyopaque) ?*Outbound,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn get(self: Pool) ?*Outbound {
        return self.vtable.get(self.ptr);
    }

    pub fn deinit(self: Pool) void {
        self.vtable.deinit(self.ptr);
    }
};

fn init(self: *Outbound, pointer: anytype) *Outbound {
    const Ptr = @TypeOf(pointer);
    const info = @typeInfo(Ptr);
    if (info != .pointer or info.pointer.size != .one)
        @compileError("Outbound.init expects a single-item pointer");

    const Impl = info.pointer.child;
    if (!comptime @hasDecl(Impl, "bufRef"))
        @compileError("Outbound.init expects pointer type to expose `bufRef()`");

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

pub fn bytes(self: *const Outbound) []u8 {
    return self.bufRef()[0..self.len];
}

pub fn bufRef(self: *const Outbound) []u8 {
    const vtable = self.vtable orelse unreachable;
    const impl_ptr = self.impl_ptr orelse unreachable;
    return vtable.bufRef(impl_ptr);
}

pub fn transportPlaintextBufRef(self: *const Outbound) []u8 {
    return self.bufRef()[Message.TransportHeaderSize..];
}

pub fn eql(self: *const Outbound, other: *const Outbound) bool {
    return self == other;
}

pub fn deinit(self: *Outbound) void {
    const pool = self.pool orelse unreachable;
    const impl_ptr = self.impl_ptr orelse unreachable;
    self.len = 0;
    self.state = .initial;
    self.kind = .transport;
    self.remote_endpoint = .{};
    self.remote_static = .{};
    self.service_data = null;
    pool.put(impl_ptr);
}

fn make(comptime _: type, comptime packet_size: usize) type {
    return struct {
        buffer_storage: [packet_size]u8 = undefined,
        packet: Outbound = undefined,

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

        pub fn getPacket(self: *@This()) ?*Outbound {
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
        fn getFn(ptr: *anyopaque) ?*Outbound {
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

            tryPoolReuseCase(grt) catch |err| {
                t.logErrorf("giznet/packet Outbound pool reuse failed: {}", .{err});
                return false;
            };
            tryPoolMultipleOutstandingCase(grt) catch |err| {
                t.logErrorf("giznet/packet Outbound pool multiple outstanding failed: {}", .{err});
                return false;
            };
            tryServiceDataResetCase(grt) catch |err| {
                t.logErrorf("giznet/packet Outbound service data reset failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: glib.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryPoolReuseCase(comptime any_lib: type) !void {
            var pool = try initPool(any_lib, grt.std.testing.allocator, 32);
            defer pool.deinit();

            const first = pool.get() orelse return error.TestExpectedFirstPacket;
            const endpoint = AddrPort.from4(.{ 127, 0, 0, 1 }, 9101);
            if ("ping".len > first.bufRef().len) return error.BufferTooSmall;
            @memcpy(first.bufRef()[0.."ping".len], "ping");
            first.len = "ping".len;
            first.state = .initial;
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

        fn tryServiceDataResetCase(comptime any_lib: type) !void {
            var pool = try initPool(any_lib, grt.std.testing.allocator, 32);
            defer pool.deinit();

            const first = pool.get() orelse return error.TestExpectedFirstPacket;
            first.remote_static = Key{ .bytes = [_]u8{0x34} ** 32 };
            first.service_data = .{ .direct = .{
                .protocol = 9,
                .payload = "hello",
            } };
            first.deinit();

            const second = pool.get() orelse return error.TestExpectedSecondPacket;
            defer second.deinit();

            try grt.std.testing.expect(second.eql(first));
            try grt.std.testing.expectEqual(@as(?ServiceData, null), second.service_data);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
