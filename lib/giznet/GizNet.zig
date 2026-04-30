//! Stable erased root handle for giznet backends.

const glib = @import("glib");
const Conn = @import("Conn.zig");
const DialOptions = @import("DialOptions.zig");

const GizNet = @This();

ptr: *anyopaque,
vtable: *const VTable,

pub const Stats = struct {
    active_peers: usize = 0,
    udp_rx_packets: u64 = 0,
    udp_tx_packets: u64 = 0,
    dropped_packets: u64 = 0,
    last_error: ?anyerror = null,
};

pub const DialError = anyerror;

pub const VTable = struct {
    dial: *const fn (ptr: *anyopaque, options: DialOptions) DialError!Conn,
    close: *const fn (ptr: *anyopaque) void,
    join: *const fn (ptr: *anyopaque) void,
    deinit: *const fn (ptr: *anyopaque) void,
    isClosed: *const fn (ptr: *anyopaque) bool,
    lastError: *const fn (ptr: *anyopaque) ?anyerror,
    stats: *const fn (ptr: *anyopaque) Stats,
};

pub fn dial(self: GizNet, options: DialOptions) DialError!Conn {
    return self.vtable.dial(self.ptr, options);
}

pub fn close(self: GizNet) void {
    self.vtable.close(self.ptr);
}

pub fn join(self: GizNet) void {
    self.vtable.join(self.ptr);
}

pub fn deinit(self: GizNet) void {
    self.vtable.deinit(self.ptr);
}

pub fn isClosed(self: GizNet) bool {
    return self.vtable.isClosed(self.ptr);
}

pub fn lastError(self: GizNet) ?anyerror {
    return self.vtable.lastError(self.ptr);
}

pub fn stats(self: GizNet) Stats {
    return self.vtable.stats(self.ptr);
}

pub fn make(comptime Runtime: type, comptime Config: type) type {
    return struct {
        pub const RuntimeType = Runtime;
        pub const ConfigType = Config;

        const OwnedGizNet = struct {
            allocator: glib.std.mem.Allocator,
            runtime: *Runtime,

            pub fn dial(self: *@This(), options: DialOptions) DialError!Conn {
                return self.runtime.dial(options);
            }

            pub fn close(self: *@This()) void {
                self.runtime.close();
            }

            pub fn join(self: *@This()) void {
                self.runtime.join();
            }

            pub fn deinit(self: *@This()) void {
                self.runtime.deinit();
                self.allocator.destroy(self);
            }

            pub fn isClosed(self: *@This()) bool {
                return self.runtime.isClosed();
            }

            pub fn lastError(self: *@This()) ?anyerror {
                return self.runtime.lastError();
            }

            pub fn stats(self: *@This()) Stats {
                return self.runtime.stats();
            }
        };

        pub fn init(allocator: glib.std.mem.Allocator, config: Config) !GizNet {
            const owned = try allocator.create(OwnedGizNet);
            errdefer allocator.destroy(owned);

            owned.* = .{
                .allocator = allocator,
                .runtime = try Runtime.init(allocator, config),
            };
            return GizNet.init(owned);
        }
    };
}

/// Wrap a pointer to any concrete giznet root backend.
pub fn init(ptr: anytype) GizNet {
    const Ptr = @TypeOf(ptr);
    const info = @typeInfo(Ptr);
    if (info != .pointer or info.pointer.size != .one or info.pointer.is_const) {
        @compileError("GizNet.init expects a mutable single-item pointer");
    }

    const Impl = info.pointer.child;

    const gen = struct {
        fn dialFn(raw_ptr: *anyopaque, options: DialOptions) DialError!Conn {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.dial(options);
        }

        fn closeFn(raw_ptr: *anyopaque) void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            self.close();
        }

        fn joinFn(raw_ptr: *anyopaque) void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            self.join();
        }

        fn deinitFn(raw_ptr: *anyopaque) void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            self.deinit();
        }

        fn isClosedFn(raw_ptr: *anyopaque) bool {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.isClosed();
        }

        fn lastErrorFn(raw_ptr: *anyopaque) ?anyerror {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.lastError();
        }

        fn statsFn(raw_ptr: *anyopaque) Stats {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.stats();
        }
    };

    const vtable = VTable{
        .dial = gen.dialFn,
        .close = gen.closeFn,
        .join = gen.joinFn,
        .deinit = gen.deinitFn,
        .isClosed = gen.isClosedFn,
        .lastError = gen.lastErrorFn,
        .stats = gen.statsFn,
    };

    return .{
        .ptr = ptr,
        .vtable = &vtable,
    };
}
