//! Stable erased stream handle for giznet.

const glib = @import("glib");

const Stream = @This();

ptr: *anyopaque,
vtable: *const VTable,
service: u64,
stream: u64,

pub const VTable = struct {
    read: *const fn (ptr: *anyopaque, buf: []u8) anyerror!usize,
    setReadDeadline: *const fn (ptr: *anyopaque, deadline: glib.time.instant.Time) anyerror!void,
    write: *const fn (ptr: *anyopaque, payload: []const u8) anyerror!usize,
    setWriteDeadline: *const fn (ptr: *anyopaque, deadline: glib.time.instant.Time) anyerror!void,
    close: *const fn (ptr: *anyopaque) anyerror!void,
    deinit: *const fn (ptr: *anyopaque) void,
};

pub fn read(self: Stream, buf: []u8) anyerror!usize {
    return self.vtable.read(self.ptr, buf);
}

pub fn setReadDeadline(self: Stream, deadline: glib.time.instant.Time) anyerror!void {
    try self.vtable.setReadDeadline(self.ptr, deadline);
}

pub fn write(self: Stream, payload: []const u8) anyerror!usize {
    return self.vtable.write(self.ptr, payload);
}

pub fn setWriteDeadline(self: Stream, deadline: glib.time.instant.Time) anyerror!void {
    try self.vtable.setWriteDeadline(self.ptr, deadline);
}

pub fn close(self: Stream) anyerror!void {
    try self.vtable.close(self.ptr);
}

pub fn deinit(self: Stream) void {
    self.vtable.deinit(self.ptr);
}

/// Wrap a pointer to any concrete giznet stream backend.
pub fn init(ptr: anytype, service_id: u64, stream_id: u64) Stream {
    const Ptr = @TypeOf(ptr);
    const info = @typeInfo(Ptr);
    if (info != .pointer or info.pointer.size != .one or info.pointer.is_const) {
        @compileError("Stream.init expects a mutable single-item pointer");
    }

    const Impl = info.pointer.child;

    const gen = struct {
        fn readFn(raw_ptr: *anyopaque, buf: []u8) anyerror!usize {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.read(buf);
        }

        fn setReadDeadlineFn(raw_ptr: *anyopaque, deadline: glib.time.instant.Time) anyerror!void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            try self.setReadDeadline(deadline);
        }

        fn writeFn(raw_ptr: *anyopaque, payload: []const u8) anyerror!usize {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.write(payload);
        }

        fn setWriteDeadlineFn(raw_ptr: *anyopaque, deadline: glib.time.instant.Time) anyerror!void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            try self.setWriteDeadline(deadline);
        }

        fn closeFn(raw_ptr: *anyopaque) anyerror!void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            return self.close();
        }

        fn deinitFn(raw_ptr: *anyopaque) void {
            const self: *Impl = @ptrCast(@alignCast(raw_ptr));
            self.deinit();
        }

        const vtable = VTable{
            .read = readFn,
            .setReadDeadline = setReadDeadlineFn,
            .write = writeFn,
            .setWriteDeadline = setWriteDeadlineFn,
            .close = closeFn,
            .deinit = deinitFn,
        };
    };

    return .{
        .ptr = ptr,
        .vtable = &gen.vtable,
        .service = service_id,
        .stream = stream_id,
    };
}
