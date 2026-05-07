//! Listener adapts accepted giznet KCP streams to `glib.net.Listener`.

const glib = @import("glib");

const Conn = @import("Conn.zig");
const Stream = @import("Stream.zig");

pub fn make(comptime grt: type) type {
    const Allocator = grt.std.mem.Allocator;
    const NetConn = grt.net.Conn;
    const NetListener = grt.net.Listener;

    return struct {
        allocator: Allocator,
        conn: Conn,
        options: Options,
        closed: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),

        const Self = @This();

        pub const Options = struct {
            accept_poll_timeout: glib.time.duration.Duration = 50 * glib.time.duration.MilliSecond,
        };

        pub fn init(allocator: Allocator, conn: Conn) Self {
            return initOptions(allocator, conn, .{});
        }

        pub fn initOptions(allocator: Allocator, conn: Conn, options: Options) Self {
            return .{
                .allocator = allocator,
                .conn = conn,
                .options = options,
            };
        }

        pub fn listener(self: *Self) NetListener {
            return NetListener.init(self);
        }

        pub fn asNetListener(self: *Self) NetListener {
            return self.listener();
        }

        pub fn listen(self: *Self) NetListener.ListenError!void {
            _ = self;
        }

        pub fn accept(self: *Self) NetListener.AcceptError!NetConn {
            while (!self.closed.load(.acquire)) {
                const stream = self.conn.accept(self.options.accept_poll_timeout) catch |err| switch (err) {
                    error.Timeout => continue,
                    error.ConnClosed,
                    error.StreamClosed,
                    error.RuntimeChannelClosed,
                    error.RuntimeAcceptChannelClosed,
                    => return error.Closed,
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.Unexpected,
                };
                errdefer stream.deinit();

                if (self.closed.load(.acquire)) return error.Closed;

                const stream_conn = self.allocator.create(StreamConn) catch return error.OutOfMemory;
                stream_conn.* = .{
                    .allocator = self.allocator,
                    .stream = stream,
                };
                return NetConn.init(stream_conn);
            }
            return error.Closed;
        }

        pub fn close(self: *Self) void {
            self.closed.store(true, .release);
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.* = undefined;
        }

        const StreamConn = struct {
            allocator: Allocator,
            stream: Stream,
            closed: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),

            pub fn read(self: *StreamConn, buf: []u8) NetConn.ReadError!usize {
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

            pub fn write(self: *StreamConn, buf: []const u8) NetConn.WriteError!usize {
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

            pub fn close(self: *StreamConn) void {
                if (self.closed.swap(true, .acq_rel)) return;
                self.stream.close() catch {};
            }

            pub fn deinit(self: *StreamConn) void {
                self.stream.deinit();
                self.allocator.destroy(self);
            }

            pub fn setReadDeadline(self: *StreamConn, deadline: ?glib.time.instant.Time) void {
                self.stream.setReadDeadline(deadline orelse 0) catch {};
            }

            pub fn setWriteDeadline(self: *StreamConn, deadline: ?glib.time.instant.Time) void {
                self.stream.setWriteDeadline(deadline orelse 0) catch {};
            }
        };
    };
}
