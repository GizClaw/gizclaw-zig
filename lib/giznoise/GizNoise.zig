//! Owning Noise-backed giznet root implementation.

const glib = @import("glib");
const giznet = @import("giznet");

const runtime_ns = @import("runtime.zig");
const RuntimeEngine = @import("runtime/Engine.zig");
const NoiseCipher = @import("noise/Cipher.zig");

pub fn make(
    comptime grt: type,
    comptime packet_size_capacity: usize,
    comptime cipher_kind: NoiseCipher.Kind,
) type {
    const RuntimePackage = runtime_ns.make(grt, packet_size_capacity, cipher_kind);
    const RuntimeGizNet = RuntimePackage.GizNet;

    return struct {
        allocator: grt.std.mem.Allocator,
        packet_conn: ?grt.net.PacketConn = null,
        impl: ?*RuntimeGizNet = null,
        root: ?giznet.GizNet = null,
        allowed_peer_key: ?giznet.Key = null,

        const Self = @This();

        pub const Config = RuntimeEngine.Config;
        pub const OnError = RuntimeEngine.OnError;
        pub const UpConfig = RuntimeGizNet.UpConfig;

        pub const InitOptions = struct {
            allowed_peer_key: ?giznet.Key = null,
        };

        pub fn init(
            allocator: grt.std.mem.Allocator,
            packet_conn: grt.net.PacketConn,
            runtime_config: Config,
            up_config: UpConfig,
            options: InitOptions,
        ) !*Self {
            const self = try allocator.create(Self);

            self.* = .{
                .allocator = allocator,
                .packet_conn = packet_conn,
                .allowed_peer_key = options.allowed_peer_key,
            };
            errdefer self.deinit();

            var effective_config = runtime_config;
            if (options.allowed_peer_key != null) {
                effective_config.noise.peer_policy = .{
                    .ctx = self,
                    .allow = allowPeer,
                };
            }

            const impl = try RuntimeGizNet.init(allocator, packet_conn, effective_config);
            self.impl = impl;
            self.root = try impl.up(up_config);
            return self;
        }

        pub fn asGizNet(self: *Self) giznet.GizNet {
            return giznet.GizNet.init(self);
        }

        pub fn dial(self: *Self, options: giznet.DialOptions) !void {
            const root = self.root orelse return error.GizNoiseNotUp;
            try root.dial(options);
        }

        pub fn accept(self: *Self) !giznet.Conn {
            const root = self.root orelse return error.GizNoiseNotUp;
            return try root.accept();
        }

        pub fn acceptTimeout(self: *Self, timeout: glib.time.duration.Duration) !giznet.Conn {
            const root = self.root orelse return error.GizNoiseNotUp;
            return try root.acceptTimeout(timeout);
        }

        pub fn close(self: *Self) !void {
            if (self.root) |root| try root.close();
        }

        pub fn join(self: *Self) void {
            if (self.root) |root| root.join();
        }

        pub fn stats(self: *Self) giznet.Stats.Snapshot {
            const root = self.root orelse return .{};
            return root.stats();
        }

        pub fn deinit(self: *Self) void {
            if (self.root) |root| {
                root.deinit();
                self.root = null;
                self.impl = null;
            } else if (self.impl) |impl| {
                impl.deinit();
                self.impl = null;
            }
            if (self.packet_conn) |packet_conn| {
                packet_conn.close();
                packet_conn.deinit();
                self.packet_conn = null;
            }
            self.allocator.destroy(self);
        }

        fn allowPeer(ctx: ?*anyopaque, peer_key: giznet.Key) bool {
            const raw_ctx = ctx orelse return false;
            const self: *Self = @ptrCast(@alignCast(raw_ctx));
            const allowed = self.allowed_peer_key orelse return true;
            return peer_key.eql(allowed);
        }
    };
}
