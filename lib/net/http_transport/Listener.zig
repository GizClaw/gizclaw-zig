const dep = @import("dep");
const bridge_errors = @import("errors.zig");
const StreamConnFile = @import("StreamConn.zig");

const mem = dep.embed.mem;
const net = dep.net;

pub fn make(comptime Peer: type) type {
    const StreamConn = StreamConnFile.make(Peer);

    return struct {
        allocator: mem.Allocator = undefined,
        conn: ?*Peer.Conn = null,
        service_id: u64 = 0,
        closed: bool = false,
        close_err: ?anyerror = null,

        const Self = @This();
        const Error = bridge_errors.Error;

        fn initOwned(allocator: mem.Allocator, conn: *Peer.Conn, service_id: u64) !*Self {
            const self = try allocator.create(Self);
            self.* = .{
                .allocator = allocator,
                .conn = conn,
                .service_id = service_id,
            };
            return self;
        }

        pub fn init(allocator: mem.Allocator, conn: *Peer.Conn, service_id: u64) !net.Listener {
            const self = try Self.initOwned(allocator, conn, service_id);
            return net.Listener.init(self);
        }

        pub fn listen(self: *Self) !void {
            if (self.conn == null) return Error.InvalidHandle;
            if (self.closed) return Error.ListenerClosed;
        }

        pub fn accept(self: *Self) net.Listener.AcceptError!net.Conn {
            if (self.conn == null) return bridge_errors.toListenerAcceptError(Error.InvalidHandle);
            if (self.closed) return error.Closed;

            const stream = self.conn.?.acceptService(self.service_id) catch |err| {
                if (self.closed or bridge_errors.isClosed(err)) return error.Closed;
                return bridge_errors.toListenerAcceptError(err);
            };
            return StreamConn.init(self.allocator, stream) catch return error.OutOfMemory;
        }

        pub fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;
            if (self.conn) |conn| {
                conn.stopAcceptingService(self.service_id) catch |err| {
                    self.close_err = err;
                };
            }
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            self.close();
            allocator.destroy(self);
        }

        pub fn service(self: *const Self) u64 {
            return self.service_id;
        }

        pub fn isClosed(self: *const Self) bool {
            return self.closed;
        }

        pub fn lastCloseError(self: *const Self) ?anyerror {
            return self.close_err;
        }

        pub fn peerConn(self: *Self) Error!*Peer.Conn {
            if (self.conn) |conn| return conn;
            return Error.InvalidHandle;
        }
    };
}
