//! StreamConn adapts a giznet KCP stream to `glib.net.Conn`.

const glib = @import("glib");

const Stream = @import("Stream.zig");

pub fn make(comptime grt: type) type {
    const Allocator = grt.std.mem.Allocator;
    const NetConn = grt.net.Conn;

    return struct {
        allocator: Allocator,
        stream: Stream,
        closed: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),

        const Self = @This();

        pub fn init(allocator: Allocator, stream: Stream) Allocator.Error!NetConn {
            const self = try allocator.create(Self);
            self.* = .{
                .allocator = allocator,
                .stream = stream,
            };
            return NetConn.init(self);
        }

        pub fn read(self: *Self, buf: []u8) NetConn.ReadError!usize {
            if (self.closed.load(.acquire)) return error.EndOfStream;
            if (buf.len == 0) return 0;
            return self.stream.read(buf) catch |err| switch (err) {
                error.StreamClosed,
                error.KcpStreamClosed,
                error.ConnClosed,
                => return error.EndOfStream,
                error.Timeout => return error.TimedOut,
                error.BufferTooSmall => return error.ShortRead,
                error.ConnectionReset => return error.ConnectionReset,
                error.ConnectionRefused => return error.ConnectionRefused,
                error.BrokenPipe => return error.BrokenPipe,
                else => return error.Unexpected,
            };
        }

        pub fn write(self: *Self, buf: []const u8) NetConn.WriteError!usize {
            if (self.closed.load(.acquire)) return error.BrokenPipe;
            if (buf.len == 0) return 0;
            return self.stream.write(buf) catch |err| switch (err) {
                error.StreamClosed,
                error.KcpStreamClosed,
                error.ConnClosed,
                => return error.BrokenPipe,
                error.Timeout => return error.TimedOut,
                error.ConnectionReset => return error.ConnectionReset,
                error.ConnectionRefused => return error.ConnectionRefused,
                error.BrokenPipe => return error.BrokenPipe,
                else => return error.Unexpected,
            };
        }

        pub fn close(self: *Self) void {
            if (self.closed.swap(true, .acq_rel)) return;
            self.stream.close() catch {};
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.stream.deinit();
            self.allocator.destroy(self);
        }

        pub fn setReadDeadline(self: *Self, deadline: ?glib.time.instant.Time) void {
            self.stream.setReadDeadline(deadline orelse 0) catch {};
        }

        pub fn setWriteDeadline(self: *Self, deadline: ?glib.time.instant.Time) void {
            self.stream.setWriteDeadline(deadline orelse 0) catch {};
        }
    };
}
