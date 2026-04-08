const dep = @import("dep");
const errors = @import("errors.zig");

const mem = dep.embed.mem;
const net = dep.net;
const Thread = dep.embed_std.std.Thread;

const poll_interval_ns: u64 = dep.embed.time.ns_per_ms;
const default_read_storage_len: usize = 64 * 1024;

pub fn make(comptime Peer: type) type {
    return struct {
        allocator: mem.Allocator = undefined,
        stream: ?*Peer.Stream = null,
        closed: bool = false,
        read_timeout_ms: ?u32 = null,
        write_timeout_ms: ?u32 = null,
        close_err: ?anyerror = null,
        read_storage: []u8 = &.{},
        read_start: usize = 0,
        read_end: usize = 0,

        const Self = @This();

        fn initOwned(allocator: mem.Allocator, stream: *Peer.Stream) !*Self {
            const self = try allocator.create(Self);
            self.* = .{
                .allocator = allocator,
                .stream = stream,
            };
            return self;
        }

        pub fn init(allocator: mem.Allocator, stream: *Peer.Stream) !net.Conn {
            const self = try Self.initOwned(allocator, stream);
            return net.Conn.init(self);
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            const stream = self.stream;
            if (!self.closed) self.close();
            if (stream) |value| value.deinit();
            if (self.read_storage.len != 0) allocator.free(self.read_storage);
            allocator.destroy(self);
        }

        pub fn read(self: *Self, buf: []u8) net.Conn.ReadError!usize {
            if (self.stream == null) return errors.toConnReadError(error.InvalidHandle);
            if (self.closed) return errors.toConnReadError(error.StreamClosed);
            if (buf.len == 0) return 0;

            const started_ns = dep.embed_std.std.time.nanoTimestamp();
            while (true) {
                if (self.closed) return errors.toConnReadError(error.StreamClosed);
                if (self.read_start != self.read_end) {
                    const available = self.read_end - self.read_start;
                    const n = @min(buf.len, available);
                    @memcpy(buf[0..n], self.read_storage[self.read_start .. self.read_start + n]);
                    self.read_start += n;
                    if (self.read_start == self.read_end) {
                        self.read_start = 0;
                        self.read_end = 0;
                    }
                    return n;
                }

                self.fillReadBuffer(started_ns, buf.len) catch |err| return errors.toConnReadError(err);
            }
        }

        pub fn write(self: *Self, buf: []const u8) net.Conn.WriteError!usize {
            if (self.stream == null) return errors.toConnWriteError(error.InvalidHandle);
            if (self.closed) return errors.toConnWriteError(error.StreamClosed);

            const started_ns = dep.embed_std.std.time.nanoTimestamp();
            while (true) {
                if (self.closed) return errors.toConnWriteError(error.StreamClosed);
                return self.stream.?.write(buf) catch |err| switch (err) {
                    error.NoData => {
                        try self.waitForIO(self.write_timeout_ms, started_ns);
                        continue;
                    },
                    else => return errors.toConnWriteError(err),
                };
            }
        }

        pub fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;
            if (self.stream) |stream| {
                stream.close() catch |err| {
                    self.close_err = err;
                };
            }
        }

        pub fn setReadTimeout(self: *Self, ms: ?u32) void {
            // The current peer stream does not enforce timeouts. We keep the
            // requested value so higher layers can observe bridge-local policy
            // without pretending the lower layer already implements deadlines.
            self.read_timeout_ms = ms;
        }

        pub fn setWriteTimeout(self: *Self, ms: ?u32) void {
            // See `setReadTimeout()`: this stores adapter-local metadata only.
            self.write_timeout_ms = ms;
        }

        pub fn readTimeout(self: *const Self) ?u32 {
            return self.read_timeout_ms;
        }

        pub fn writeTimeout(self: *const Self) ?u32 {
            return self.write_timeout_ms;
        }

        pub fn lastCloseError(self: *const Self) ?anyerror {
            return self.close_err;
        }

        pub fn isClosed(self: *const Self) bool {
            return self.closed;
        }

        pub fn peerStream(self: *Self) Error!*Peer.Stream {
            if (self.stream) |stream| return stream;
            return errors.Error.InvalidHandle;
        }

        fn waitForIO(self: *Self, timeout_ms: ?u32, started_ns: i128) error{TimedOut}!void {
            _ = self;
            if (timeout_ms) |ms| {
                const deadline_ns = started_ns + @as(i128, ms) * dep.embed.time.ns_per_ms;
                if (dep.embed_std.std.time.nanoTimestamp() >= deadline_ns) return error.TimedOut;
            }
            Thread.sleep(poll_interval_ns);
        }

        fn fillReadBuffer(self: *Self, started_ns: i128, min_len: usize) !void {
            const initial_len = @max(default_read_storage_len, min_len);
            if (self.read_storage.len < initial_len) {
                self.read_storage = try self.ensureReadStorage(initial_len);
            }

            while (true) {
                const n = self.stream.?.read(self.read_storage) catch |err| switch (err) {
                    error.NoData => {
                        try self.waitForIO(self.read_timeout_ms, started_ns);
                        continue;
                    },
                    error.BufferTooSmall, error.FragmentIncomplete => {
                        self.read_storage = try self.ensureReadStorage(self.read_storage.len * 2);
                        continue;
                    },
                    else => return err,
                };
                self.read_start = 0;
                self.read_end = n;
                return;
            }
        }

        fn ensureReadStorage(self: *Self, new_len: usize) mem.Allocator.Error![]u8 {
            if (self.read_storage.len == 0) return try self.allocator.alloc(u8, new_len);
            return try self.allocator.realloc(self.read_storage, new_len);
        }

        const Error = errors.Error;
    };
}
