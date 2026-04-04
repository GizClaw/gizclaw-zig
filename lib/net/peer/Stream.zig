const dep = @import("dep");
const errors = @import("errors.zig");
const SharedRefFile = @import("SharedRef.zig");

pub fn make(comptime Core: type) type {
    const PeerEvent = Core.UDP.PeerEvent;
    const Key = @TypeOf(@as(PeerEvent, undefined).peer);
    const SharedRef = SharedRefFile.make(Core);

    return struct {
        allocator: dep.embed.mem.Allocator = undefined,
        shared: ?SharedRef = null,
        remote_pk: Key,
        service_id: u64,
        stream_id_value: u64,
        closed: bool = false,

        const Self = @This();

        pub fn init(
            allocator: dep.embed.mem.Allocator,
            shared: SharedRef,
            remote_pk: Key,
            service_id: u64,
            stream_id: u64,
        ) !*Self {
            const self = try allocator.create(Self);
            shared.retain(shared.ctx);
            self.* = .{
                .allocator = allocator,
                .shared = shared,
                .remote_pk = remote_pk,
                .service_id = service_id,
                .stream_id_value = stream_id,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            const shared = self.shared;
            // `deinit()` is a best-effort finalizer. Call `close()` first if the
            // caller needs the underlying stream-close error.
            if (!self.closed) self.close() catch {};
            if (shared) |ref| ref.release(ref.ctx);
            allocator.destroy(self);
        }

        pub fn read(self: *Self, out: []u8) !usize {
            const udp = try self.getUDP();
            return try udp.recvStreamData(self.remote_pk, self.service_id, self.stream_id_value, out);
        }

        pub fn write(self: *Self, payload: []const u8) !usize {
            const udp = try self.getUDP();
            return try udp.sendStreamData(self.remote_pk, self.service_id, self.stream_id_value, payload);
        }

        pub fn close(self: *Self) !void {
            const udp = try self.getUDP();
            try udp.closeStream(self.remote_pk, self.service_id, self.stream_id_value);
            self.closed = true;
        }

        pub fn service(self: Self) u64 {
            return self.service_id;
        }

        pub fn streamId(self: Self) u64 {
            return self.stream_id_value;
        }

        pub fn publicKey(self: Self) Key {
            return self.remote_pk;
        }

        fn getUDP(self: *Self) !*Core.UDP {
            if (self.shared == null) return errors.Error.InvalidHandle;
            if (self.closed) return errors.Error.StreamClosed;
            return self.shared.?.udp(self.shared.?.ctx);
        }
    };
}
