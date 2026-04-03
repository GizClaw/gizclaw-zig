const errors = @import("errors.zig");

pub fn make(comptime Mux: type) type {
    return struct {
        mux: *Mux,
        stream_id: u64,

        const Self = @This();

        pub fn id(self: *const Self) u64 {
            return self.stream_id;
        }

        pub fn read(self: *Self, out: []u8, now_ms: u64) !usize {
            return try self.mux.readStream(self.stream_id, out, now_ms);
        }

        pub fn write(self: *Self, payload: []const u8, now_ms: u64) !usize {
            return try self.mux.writeStream(self.stream_id, payload, now_ms);
        }

        pub fn close(self: *Self, now_ms: u64) !void {
            self.mux.closeStream(self.stream_id, now_ms) catch |err| switch (err) {
                errors.Error.StreamNotFound => return,
                else => return err,
            };
        }

        pub fn setReadDeadline(self: *Self, deadline_ms: ?u64) !void {
            try self.mux.setStreamReadDeadline(self.stream_id, deadline_ms);
        }

        pub fn setWriteDeadline(self: *Self, deadline_ms: ?u64) !void {
            try self.mux.setStreamWriteDeadline(self.stream_id, deadline_ms);
        }

        pub fn setDeadline(self: *Self, deadline_ms: ?u64) !void {
            try self.mux.setStreamDeadline(self.stream_id, deadline_ms);
        }
    };
}
