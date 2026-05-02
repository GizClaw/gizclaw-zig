//! Stable erased root handle for giznet backends.

const glib = @import("glib");

const Conn = @import("Conn.zig");
const DialOptions = @import("DialOptions.zig");
const Stats = @import("runtime/Stats.zig");

const GizNet = @This();

ptr: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    dial: *const fn (ptr: *anyopaque, options: DialOptions) anyerror!void,
    accept: *const fn (ptr: *anyopaque) anyerror!Conn,
    close: *const fn (ptr: *anyopaque) anyerror!void,
    join: *const fn (ptr: *anyopaque) void,
    deinit: *const fn (ptr: *anyopaque) void,
    stats: *const fn (ptr: *anyopaque) Stats.Snapshot,
};

pub fn dial(self: GizNet, options: DialOptions) anyerror!void {
    try self.vtable.dial(self.ptr, options);
}

pub fn accept(self: GizNet) !Conn {
    return self.vtable.accept(self.ptr);
}

pub fn close(self: GizNet) !void {
    try self.vtable.close(self.ptr);
}

pub fn join(self: GizNet) void {
    self.vtable.join(self.ptr);
}

pub fn deinit(self: GizNet) void {
    self.vtable.deinit(self.ptr);
}

pub fn stats(self: GizNet) Stats.Snapshot {
    return self.vtable.stats(self.ptr);
}

pub fn make(comptime grt: type, comptime RuntimeEngine: type, comptime RuntimeConfig: type) type {
    return struct {
        allocator: grt.std.mem.Allocator,
        runtime: *RuntimeEngine,

        const Self = @This();

        pub const UpConfig = struct {
            drive_spawn_config: grt.std.Thread.SpawnConfig = .{},
            read_spawn_config: grt.std.Thread.SpawnConfig = .{},
            timer_spawn_config: grt.std.Thread.SpawnConfig = .{},
        };

        pub fn init(
            allocator: grt.std.mem.Allocator,
            conn: grt.net.PacketConn,
            config: RuntimeConfig,
        ) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            const runtime = try allocator.create(RuntimeEngine);
            errdefer allocator.destroy(runtime);

            runtime.* = try RuntimeEngine.init(allocator, conn, config);
            errdefer runtime.deinit();

            self.* = .{
                .allocator = allocator,
                .runtime = runtime,
            };
            return self;
        }

        pub fn up(
            self: *Self,
            config: UpConfig,
        ) !GizNet {
            if (self.runtime.drive_thread != null) return error.GizNetAlreadyUp;

            errdefer {
                self.close() catch {};
                self.join();
            }

            try self.runtime.startDrive(config.drive_spawn_config);
            try self.runtime.startRead(config.read_spawn_config);
            try self.runtime.startTimer(config.timer_spawn_config);
            return GizNet.init(self);
        }

        pub fn dial(self: *Self, options: DialOptions) anyerror!void {
            if (self.runtime.drive_thread == null) return error.GizNetNotUp;
            const endpoint = options.endpoint orelse return error.MissingEndpoint;
            try self.runtime.initiatePeer(.{
                .remote_key = options.remote_key,
                .remote_endpoint = endpoint,
                .keepalive_interval = if (options.keepalive_ms) |ms|
                    @as(glib.time.duration.Duration, @intCast(ms)) * glib.time.duration.MilliSecond
                else
                    null,
            });
        }

        pub fn accept(self: *Self) !Conn {
            if (self.runtime.drive_thread == null) return error.GizNetNotUp;
            const result = try self.runtime.acceptConn();
            if (!result.ok) return error.RuntimeAcceptChannelClosed;
            return result.value;
        }

        pub fn acceptTimeout(self: *Self, timeout: glib.time.duration.Duration) !Conn {
            if (self.runtime.drive_thread == null) return error.GizNetNotUp;
            const result = try self.runtime.acceptConnTimeout(timeout);
            if (!result.ok) return error.RuntimeAcceptChannelClosed;
            return result.value;
        }

        pub fn close(self: *Self) !void {
            if (self.runtime.drive_thread == null) return;
            try self.runtime.close();
        }

        pub fn join(self: *Self) void {
            self.runtime.join();
        }

        pub fn deinit(self: *Self) void {
            self.close() catch {};
            self.join();
            self.runtime.deinit();
            self.allocator.destroy(self.runtime);
            self.allocator.destroy(self);
        }

        pub fn stats(self: *Self) Stats.Snapshot {
            return self.runtime.snapshotStats();
        }
    };
}

/// Wrap a pointer to any concrete giznet root backend.
fn init(ptr: anytype) GizNet {
    const Ptr = @TypeOf(ptr);
    const info = @typeInfo(Ptr);
    if (info != .pointer or info.pointer.size != .one or info.pointer.is_const) {
        @compileError("GizNet.init expects a mutable single-item pointer");
    }

    const Impl = info.pointer.child;

    const gen = struct {
        fn dialFn(raw_ptr: *anyopaque, options: DialOptions) anyerror!void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            try self.dial(options);
        }

        fn acceptFn(raw_ptr: *anyopaque) anyerror!Conn {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.accept();
        }

        fn closeFn(raw_ptr: *anyopaque) anyerror!void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            try self.close();
        }

        fn joinFn(raw_ptr: *anyopaque) void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            self.join();
        }

        fn deinitFn(raw_ptr: *anyopaque) void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            self.deinit();
        }

        fn statsFn(raw_ptr: *anyopaque) Stats.Snapshot {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.stats();
        }

        const vtable = VTable{
            .dial = dialFn,
            .accept = acceptFn,
            .close = closeFn,
            .join = joinFn,
            .deinit = deinitFn,
            .stats = statsFn,
        };
    };

    return .{
        .ptr = ptr,
        .vtable = &gen.vtable,
    };
}
