//! Stable erased peer-connection handle for giznet.

const Key = @import("noise/Key.zig");

const Conn = @This();

ptr: *anyopaque,
vtable: *const VTable,

pub const ReadResult = struct {
    protocol: u8,
    n: usize,
};

pub const VTable = struct {
    read: *const fn (ptr: *anyopaque, buf: []u8) anyerror!ReadResult,
    write: *const fn (ptr: *anyopaque, protocol: u8, payload: []const u8) anyerror!usize,
    close: *const fn (ptr: *anyopaque) anyerror!void,
    deinit: *const fn (ptr: *anyopaque) void,
    localStatic: *const fn (ptr: *anyopaque) Key,
    remoteStatic: *const fn (ptr: *anyopaque) Key,
};

pub fn read(self: Conn, buf: []u8) anyerror!ReadResult {
    return self.vtable.read(self.ptr, buf);
}

pub fn write(self: Conn, protocol: u8, payload: []const u8) anyerror!usize {
    return self.vtable.write(self.ptr, protocol, payload);
}

pub fn close(self: Conn) anyerror!void {
    return self.vtable.close(self.ptr);
}

pub fn deinit(self: Conn) void {
    self.vtable.deinit(self.ptr);
}

pub fn localStatic(self: Conn) Key {
    return self.vtable.localStatic(self.ptr);
}

pub fn remoteStatic(self: Conn) Key {
    return self.vtable.remoteStatic(self.ptr);
}

/// Wrap a pointer to any concrete giznet peer-connection backend.
pub fn init(ptr: anytype) Conn {
    const Ptr = @TypeOf(ptr);
    const info = @typeInfo(Ptr);
    if (info != .pointer or info.pointer.size != .one or info.pointer.is_const) {
        @compileError("Conn.init expects a mutable single-item pointer");
    }

    const Impl = info.pointer.child;

    const gen = struct {
        fn readFn(raw_ptr: *anyopaque, buf: []u8) anyerror!ReadResult {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.read(buf);
        }

        fn writeFn(raw_ptr: *anyopaque, protocol: u8, payload: []const u8) anyerror!usize {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.write(protocol, payload);
        }

        fn closeFn(raw_ptr: *anyopaque) anyerror!void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.close();
        }

        fn deinitFn(raw_ptr: *anyopaque) void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            self.deinit();
        }

        fn localStaticFn(raw_ptr: *anyopaque) Key {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.localStatic();
        }

        fn remoteStaticFn(raw_ptr: *anyopaque) Key {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.remoteStatic();
        }
    };

    const vtable = VTable{
        .read = gen.readFn,
        .write = gen.writeFn,
        .close = gen.closeFn,
        .deinit = gen.deinitFn,
        .localStatic = gen.localStaticFn,
        .remoteStatic = gen.remoteStaticFn,
    };

    return .{
        .ptr = ptr,
        .vtable = &vtable,
    };
}
