const dep = @import("dep");
const core = @import("../core.zig");

const mem = dep.embed.mem;
const errors = @import("errors.zig");
const opus_frame = @import("opus_frame.zig");
const prologue = @import("prologue.zig");
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

        pub fn openRPC(self: *Self) !*Stream {
            return self.openService(prologue.ServicePublic);
        }

        pub fn acceptRPC(self: *Self) !*Stream {
            return self.acceptService(prologue.ServicePublic);
        }

        pub fn closeService(self: *Self, service: u64) !void {
            const service_mux = try self.serviceMux();
            try service_mux.closeService(service);
        }

        pub fn stopAcceptingService(self: *Self, service: u64) !void {
            const service_mux = try self.serviceMux();
            try service_mux.stopAcceptingService(service);
        }

        pub fn sendEvent(self: *Self, allocator: dep.embed.mem.Allocator, event: prologue.Event) !void {
            const udp = try self.getUDP();
            const payload = try prologue.encodeEvent(allocator, event);
            defer allocator.free(payload);
            _ = try udp.writeDirect(self.remote_pk, core.protocol.event, payload);
        }

        pub fn readEvent(self: *Self, allocator: dep.embed.mem.Allocator) !prologue.Event {
            const udp = try self.getUDP();
            var buf: [core.MaxPayloadSize]u8 = undefined;
            const n = try udp.readServiceProtocol(self.remote_pk, prologue.ServicePublic, core.protocol.event, &buf);
            return try prologue.decodeEvent(allocator, buf[0..n]);
        }

        pub fn sendOpusFrame(self: *Self, frame: opus_frame.StampedOpusFrame) !void {
            const udp = try self.getUDP();
            try frame.validate();
            _ = try udp.writeDirect(self.remote_pk, core.protocol.opus, frame.bytes);
        }

        pub fn readOpusFrame(self: *Self, allocator: dep.embed.mem.Allocator) !opus_frame.StampedOpusFrame {
            const udp = try self.getUDP();
            var buf: [core.MaxPayloadSize]u8 = undefined;
            const n = try udp.readServiceProtocol(self.remote_pk, prologue.ServicePublic, core.protocol.opus, &buf);
            return try opus_frame.parseStampedOpusFrame(allocator, buf[0..n]);
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
