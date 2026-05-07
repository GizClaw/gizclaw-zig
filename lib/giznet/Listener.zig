//! Listener adapts accepted giznet KCP streams to `glib.net.Listener`.

const glib = @import("glib");

const Conn = @import("Conn.zig");
const stream_conn_mod = @import("StreamConn.zig");

pub fn make(comptime grt: type) type {
    const Allocator = grt.std.mem.Allocator;
    const NetConn = grt.net.Conn;
    const NetListener = grt.net.Listener;
    const StreamConn = stream_conn_mod.make(grt);

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

                return StreamConn.init(self.allocator, stream) catch return error.OutOfMemory;
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
    };
}
