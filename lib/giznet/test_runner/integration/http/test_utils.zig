const glib = @import("glib");

const giznet = @import("../../../../giznet.zig");

pub fn RecordingListener(comptime grt: type) type {
    const AcceptCount = grt.std.atomic.Value(usize);
    const StreamIds = grt.std.ArrayList(u64);

    return struct {
        allocator: grt.std.mem.Allocator,
        conn: giznet.Conn,
        count: *AcceptCount,
        stream_ids: *StreamIds,
        closed: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),

        pub fn init(
            allocator: grt.std.mem.Allocator,
            conn: giznet.Conn,
            count: *AcceptCount,
            stream_ids: *StreamIds,
        ) @This() {
            return .{
                .allocator = allocator,
                .conn = conn,
                .count = count,
                .stream_ids = stream_ids,
            };
        }

        pub fn listen(self: *@This()) grt.net.Listener.ListenError!void {
            _ = self;
        }

        pub fn accept(self: *@This()) grt.net.Listener.AcceptError!grt.net.Conn {
            while (!self.closed.load(.acquire)) {
                const stream = self.conn.accept(50 * glib.time.duration.MilliSecond) catch |err| switch (err) {
                    error.Timeout => continue,
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.Closed,
                };
                errdefer stream.deinit();
                self.stream_ids.append(self.allocator, stream.stream) catch return error.OutOfMemory;
                _ = self.count.fetchAdd(1, .acq_rel);
                return giznet.StreamConn.make(grt).init(self.allocator, stream) catch return error.OutOfMemory;
            }
            return error.Closed;
        }

        pub fn close(self: *@This()) void {
            self.closed.store(true, .release);
        }

        pub fn deinit(self: *@This()) void {
            self.close();
        }
    };
}

pub fn ChunkBody(comptime grt: type) type {
    _ = grt;
    return struct {
        chunks: []const []const u8,
        chunk_index: usize = 0,
        offset: usize = 0,
        closed: bool = false,

        pub fn read(self: *@This(), buf: []u8) anyerror!usize {
            if (self.closed or buf.len == 0) return 0;
            while (self.chunk_index < self.chunks.len) {
                const chunk = self.chunks[self.chunk_index];
                if (self.offset == chunk.len) {
                    self.chunk_index += 1;
                    self.offset = 0;
                    continue;
                }
                const remaining = chunk[self.offset..];
                const n = @min(buf.len, remaining.len);
                @memcpy(buf[0..n], remaining[0..n]);
                self.offset += n;
                return n;
            }
            return 0;
        }

        pub fn close(self: *@This()) void {
            self.closed = true;
        }
    };
}

pub fn readAllBody(body: anytype, buf: []u8) !usize {
    var reader = body;
    var total: usize = 0;
    while (true) {
        const n = try reader.read(buf[total..]);
        if (n == 0) return total;
        total += n;
        if (total == buf.len) return total;
    }
}

pub fn readAllRequestBody(req: anytype, buf: []u8) !usize {
    const body = req.body() orelse return 0;
    return readAllBody(body, buf);
}

pub fn ServerTask(comptime grt: type, comptime Server: type) type {
    return struct {
        pub fn run(server: *Server, listener: grt.net.Listener) void {
            server.serve(listener) catch {};
        }
    };
}
