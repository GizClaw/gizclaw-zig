const embed = @import("embed");
const std = embed.std;

const Cipher = @import("Cipher.zig");
const Key = @import("Key.zig");
const PeerType = @import("Peer.zig");

pub fn make(comptime lib: type, comptime cipher_kind: Cipher.Kind) type {
    const Peer = PeerType.make(lib, cipher_kind);

    return struct {
        allocator: std.mem.Allocator,
        max_peers: usize,
        timer_config: Peer.TimerConfig,
        items: []Peer = &.{},
        len: usize = 0,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, max_peers: usize, timer_config: Peer.TimerConfig) Self {
            return .{
                .allocator = allocator,
                .max_peers = max_peers,
                .timer_config = timer_config,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.items.len != 0) self.allocator.free(self.items);
            self.items = &.{};
            self.len = 0;
        }

        pub fn count(self: Self) usize {
            return self.len;
        }

        pub fn get(self: *Self, key: Key) ?*Peer {
            for (self.items[0..self.len]) |*peer| {
                if (peer.key.eql(key)) return peer;
            }
            return null;
        }

        pub fn getConst(self: *const Self, key: Key) ?*const Peer {
            for (self.items[0..self.len]) |*peer| {
                if (peer.key.eql(key)) return peer;
            }
            return null;
        }

        pub fn getOrCreate(self: *Self, key: Key) !*Peer {
            if (self.get(key)) |peer| return peer;
            if (self.len >= self.max_peers) return error.PeerLimitReached;
            try self.ensureCapacity(self.len + 1);
            self.items[self.len] = Peer.init(key, self.timer_config);
            self.len += 1;
            return &self.items[self.len - 1];
        }

        pub fn findPendingHandshakeByLocalSessionIndex(self: *Self, local_session_index: u32) ?*Peer {
            for (self.items[0..self.len]) |*peer| {
                if (peer.pending_handshake) |pending_handshake| {
                    const index = pending_handshake.local_session_index;
                    if (index == local_session_index) return peer;
                }
            }
            return null;
        }

        pub fn findBySessionIndex(self: *Self, local_session_index: u32) ?*Peer {
            for (self.items[0..self.len]) |*peer| {
                if (peer.sessionByLocalIndex(local_session_index) != null) return peer;
            }
            return null;
        }

        pub fn removeIdle(self: *Self, key: Key) bool {
            var index: usize = 0;
            while (index < self.len) : (index += 1) {
                if (!self.items[index].key.eql(key)) continue;
                if (!self.items[index].isCompletelyIdle()) return false;
                const last = self.len - 1;
                if (index != last) self.items[index] = self.items[last];
                self.len -= 1;
                return true;
            }
            return false;
        }

        pub fn pendingCount(self: *const Self) usize {
            var total: usize = 0;
            for (self.items[0..self.len]) |peer| {
                if (peer.pending_handshake != null) total += 1;
            }
            return total;
        }

        pub fn sessionCount(self: *const Self) usize {
            var total: usize = 0;
            for (self.items[0..self.len]) |peer| {
                if (peer.current != null) total += 1;
                if (peer.previous != null) total += 1;
            }
            return total;
        }

        fn ensureCapacity(self: *Self, needed: usize) !void {
            if (needed <= self.items.len) return;
            var next = if (self.items.len == 0) @as(usize, 4) else self.items.len * 2;
            while (next < needed) next *= 2;
            self.items = if (self.items.len == 0)
                try self.allocator.alloc(Peer, next)
            else
                try self.allocator.realloc(self.items, next);
        }
    };
}

pub fn testRunner(comptime lib: type) embed.testing.TestRunner {
    const testing_api = embed.testing;
    const giznet = @import("../../giznet.zig");

    const Runner = struct {
        pub fn init(self: *@This(), allocator: std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase(lib) catch |err| {
                t.logErrorf("giznet/noise PeerTable unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }

        fn tryCase(comptime any_lib: type) !void {
            const PeerTable = make(any_lib, Cipher.default_kind);
            const Handshake = @import("Handshake.zig").make(any_lib, Cipher.default_kind);
            const Session = @import("Session.zig").make(
                any_lib,
                @import("Session.zig").legacy_packet_size_capacity,
                Cipher.default_kind,
            );
            const key_a = giznet.noise.KeyPair.seed(any_lib, 51);
            const key_b = giznet.noise.KeyPair.seed(any_lib, 61);
            const key_c = giznet.noise.KeyPair.seed(any_lib, 71);
            const listener_pair = giznet.noise.KeyPair.seed(any_lib, 81);
            const endpoint = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 4010);

            var table = PeerTable.init(any_lib.testing.allocator, 2, .{
                .keepalive_timeout_ms = 10,
                .rekey_after_time_ms = 50,
                .rekey_timeout_ms = 5,
                .handshake_attempt_ms = 20,
                .session_cleanup_ms = 40,
                .rekey_after_messages = 8,
            });
            defer table.deinit();

            const peer_a = try table.getOrCreate(key_a.public);
            try any_lib.testing.expectEqual(@as(usize, 1), table.count());
            try any_lib.testing.expect(table.getConst(key_a.public) != null);
            _ = try table.getOrCreate(key_a.public);
            try any_lib.testing.expectEqual(@as(usize, 1), table.count());

            const peer_b = try table.getOrCreate(key_b.public);
            try any_lib.testing.expectEqual(@as(usize, 2), table.count());
            try any_lib.testing.expectError(error.PeerLimitReached, table.getOrCreate(key_c.public));

            const handshake = try Handshake.initInitiator(listener_pair, key_a.public, 91);
            peer_a.startPendingHandshake(listener_pair.public, endpoint, 91, handshake, 100);
            try any_lib.testing.expectEqual(@as(usize, 1), table.pendingCount());
            try any_lib.testing.expect(table.findPendingHandshakeByLocalSessionIndex(91) != null);
            try any_lib.testing.expect(!table.removeIdle(key_a.public));

            const session = makeSession(Session, key_b.public, endpoint, 5, 6, 0x55, 0x66);
            peer_b.establish(listener_pair.public, endpoint, session, false, 200);
            try any_lib.testing.expectEqual(@as(usize, 1), table.sessionCount());
            const by_session = table.findBySessionIndex(5) orelse return error.MissingPeer;
            try any_lib.testing.expect(by_session.key.eql(key_b.public));

            peer_a.clearPendingHandshake();
            try any_lib.testing.expect(table.removeIdle(key_a.public));
            try any_lib.testing.expectEqual(@as(usize, 1), table.count());
            try any_lib.testing.expect(table.get(key_a.public) == null);
        }

        fn makeSession(
            Session: type,
            peer_key: giznet.noise.Key,
            endpoint: giznet.AddrPort,
            local_index: u32,
            remote_index: u32,
            send_fill: u8,
            recv_fill: u8,
        ) Session {
            return Session.init(.{
                .local_index = local_index,
                .remote_index = remote_index,
                .peer_key = peer_key,
                .endpoint = endpoint,
                .send_key = giznet.noise.Key{ .bytes = [_]u8{send_fill} ** 32 },
                .recv_key = giznet.noise.Key{ .bytes = [_]u8{recv_fill} ** 32 },
            });
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
