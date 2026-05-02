const glib = @import("glib");

const Key = @import("../noise/Key.zig");
const PeerRoot = @import("Peer.zig");

pub fn make(comptime grt: type) type {
    const Peer = PeerRoot.make(grt);

    return struct {
        allocator: grt.std.mem.Allocator,
        peer_config: PeerRoot.Config,
        items: []Peer = &.{},
        len: usize = 0,

        const Self = @This();
        pub const PeerType = Peer;
        pub const GetOrCreateResult = struct {
            peer: *Peer,
            created: bool,
        };

        pub fn init(allocator: grt.std.mem.Allocator, peer_config: PeerRoot.Config) Self {
            return .{
                .allocator = allocator,
                .peer_config = peer_config,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.items[0..self.len]) |*peer| {
                peer.deinit();
            }
            if (self.items.len != 0) self.allocator.free(self.items);
            self.items = &.{};
            self.len = 0;
        }

        pub fn get(self: *Self, remote_static: Key) ?*Peer {
            for (self.items[0..self.len]) |*peer| {
                if (peer.remote_static.eql(remote_static)) return peer;
            }
            return null;
        }

        pub fn getOrCreate(self: *Self, remote_static: Key) !*Peer {
            return (try self.getOrCreateWithStatus(remote_static)).peer;
        }

        pub fn getOrCreateWithStatus(self: *Self, remote_static: Key) !GetOrCreateResult {
            if (self.get(remote_static)) |peer| return .{
                .peer = peer,
                .created = false,
            };

            try self.ensureCapacity(self.len + 1);
            self.items[self.len] = try Peer.init(self.allocator, remote_static, self.peer_config);
            self.len += 1;
            return .{
                .peer = &self.items[self.len - 1],
                .created = true,
            };
        }

        pub fn remove(self: *Self, remote_static: Key) bool {
            var index: usize = 0;
            while (index < self.len) : (index += 1) {
                if (!self.items[index].remote_static.eql(remote_static)) continue;

                self.items[index].deinit();
                const last = self.len - 1;
                if (index != last) self.items[index] = self.items[last];
                self.len -= 1;
                return true;
            }
            return false;
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

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    const testing_api = glib.testing;

    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase(grt) catch |err| {
                t.logErrorf("giznet/service PeerTable unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }

        fn tryCase(comptime any_lib: type) !void {
            _ = any_lib;

            const PeerTable = make(grt);
            var table = PeerTable.init(grt.std.testing.allocator, .{});
            defer table.deinit();

            const key = Key{ .bytes = [_]u8{0x42} ** 32 };
            const peer = try table.getOrCreate(key);
            try grt.std.testing.expect(peer.remote_static.eql(key));
            try grt.std.testing.expect(table.get(key) == peer);
            try grt.std.testing.expect(try table.getOrCreate(key) == peer);
            try grt.std.testing.expect(!(try table.getOrCreateWithStatus(key)).created);
            try grt.std.testing.expect(table.remove(key));
            try grt.std.testing.expect(table.get(key) == null);
            try grt.std.testing.expect(!table.remove(key));
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
