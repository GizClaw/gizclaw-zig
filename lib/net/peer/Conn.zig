const dep = @import("dep");
const core = @import("../core.zig");

const mem = dep.embed.mem;
const errors = @import("errors.zig");
const SharedRefFile = @import("SharedRef.zig");
const StreamFile = @import("Stream.zig");

pub fn make(comptime Core: type) type {
    const PeerEvent = Core.UDP.PeerEvent;
    const Key = @TypeOf(@as(PeerEvent, undefined).peer);
    const SharedRef = SharedRefFile.make(Core);
    const Stream = StreamFile.make(Core);

    return struct {
        allocator: mem.Allocator = undefined,
        shared: ?SharedRef = null,
        remote_pk: Key,
        release_hook: ?ReleaseHook = null,
        closed: bool = false,
        released_known: bool = false,

        const Self = @This();

        pub const ReleaseHook = struct {
            ctx: *anyopaque,
            release: *const fn (ctx: *anyopaque, remote_pk: Key) void,
        };

        pub fn init(
            allocator: mem.Allocator,
            shared: SharedRef,
            remote_pk: Key,
            release_hook: ?ReleaseHook,
        ) !*Self {
            const self = try allocator.create(Self);
            shared.retain(shared.ctx);
            self.* = .{
                .allocator = allocator,
                .shared = shared,
                .remote_pk = remote_pk,
                .release_hook = release_hook,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            const shared = self.shared;
            // `deinit()` is a best-effort finalizer. Call `close()` first if the
            // caller needs to observe the handle-local close result directly.
            if (!self.closed or !self.released_known) self.close() catch {};
            if (shared) |ref| ref.release(ref.ctx);
            allocator.destroy(self);
        }

        pub fn openService(self: *Self, service: u64) !*Stream {
            const service_mux = try self.serviceMux();
            const stream_id = try service_mux.openStream(service);
            return Stream.init(self.allocator, self.shared.?, self.remote_pk, service, stream_id);
        }

        pub fn acceptService(self: *Self, service: u64) !*Stream {
            const service_mux = try self.serviceMux();
            const stream_id = try service_mux.acceptStream(service);
            return Stream.init(self.allocator, self.shared.?, self.remote_pk, service, stream_id);
        }

        pub fn closeService(self: *Self, service: u64) !void {
            const service_mux = try self.serviceMux();
            try service_mux.closeService(service);
        }

        pub fn stopAcceptingService(self: *Self, service: u64) !void {
            const service_mux = try self.serviceMux();
            try service_mux.stopAcceptingService(service);
        }

        pub fn read(self: *Self, out: []u8) !Core.ServiceMux.ReadResult {
            const service_mux = try self.serviceMux();
            return try service_mux.read(out);
        }

        pub fn write(self: *Self, protocol_byte: u8, payload: []const u8) !usize {
            const service_mux = try self.serviceMux();
            return try service_mux.write(protocol_byte, payload);
        }

        pub fn close(self: *Self) !void {
            try self.validateHandle();
            self.closed = true;
            self.releaseKnown();
        }

        pub fn publicKey(self: Self) Key {
            return self.remote_pk;
        }

        fn getUDP(self: *Self) !*Core.UDP {
            try self.validateHandle();
            return self.shared.?.udp(self.shared.?.ctx);
        }

        fn validateHandle(self: *Self) !void {
            if (self.shared == null) return errors.Error.NilConn;
            if (self.closed) return errors.Error.ConnClosed;
        }

        fn releaseKnown(self: *Self) void {
            if (self.released_known) return;
            self.released_known = true;
            if (self.release_hook) |hook| hook.release(hook.ctx, self.remote_pk);
        }

        fn serviceMux(self: *Self) !*Core.ServiceMux {
            const udp = try self.getUDP();
            if (udp.serviceMux(self.remote_pk)) |service_mux| return service_mux;
            if (udp.peerInfo(self.remote_pk) == null) return core.Error.PeerNotFound;
            return core.Error.NoSession;
        }
    };
}
