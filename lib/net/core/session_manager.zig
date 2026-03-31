const embed = @import("embed");
const mem = embed.mem;
const noise = @import("noise");

const errors = @import("errors.zig");
const map = @import("map.zig");

// Single-threaded: callers must serialize all SessionManager access.
pub fn SessionManager(comptime Noise: type) type {
    const Session = Noise.Session;

    return struct {
        allocator: mem.Allocator,
        by_index: map.UIntMap(u32, *Entry),
        by_pubkey: map.KeyMap(*Entry),
        next_index: u32 = 1,

        const Self = @This();
        const Entry = struct {
            session: *Session,
            owned: bool,
        };

        pub fn init(allocator: mem.Allocator) !Self {
            return .{
                .allocator = allocator,
                .by_index = try map.UIntMap(u32, *Entry).init(allocator, 8),
                .by_pubkey = try map.KeyMap(*Entry).init(allocator, 8),
            };
        }

        pub fn deinit(self: *Self) void {
            self.clear();
            self.by_pubkey.deinit();
            self.by_index.deinit();
        }

        pub fn createSession(
            self: *Self,
            remote_pk: noise.Key,
            send_key: noise.Key,
            recv_key: noise.Key,
            remote_index: u32,
            now_ms: u64,
        ) !*Session {
            const local_index = self.allocateIndex();
            if (local_index == 0) return errors.Error.NoFreeIndex;
            if (remote_index == 0) return errors.Error.InvalidReceiverIndex;

            const session = Session.init(.{
                .local_index = local_index,
                .remote_index = remote_index,
                .send_key = send_key,
                .recv_key = recv_key,
                .remote_pk = remote_pk,
                .now_ms = now_ms,
            });
            const owned = try self.allocator.create(Session);
            owned.* = session;
            return try self.registerOwnedSession(owned);
        }

        pub fn registerSession(self: *Self, session: *Session) !*Session {
            return try self.registerEntry(session, false);
        }

        fn registerOwnedSession(self: *Self, session: *Session) !*Session {
            return try self.registerEntry(session, true);
        }

        fn registerEntry(self: *Self, session: *Session, owned: bool) !*Session {
            const local_index = session.localIndex();
            const remote_pk = session.remotePublicKey();

            if (local_index == 0) return errors.Error.NoFreeIndex;
            if (self.by_index.get(local_index)) |existing| {
                if (!existing.session.remotePublicKey().eql(remote_pk)) {
                    return errors.Error.IndexInUse;
                }
            }

            const entry = try self.allocator.create(Entry);
            entry.* = .{
                .session = session,
                .owned = owned,
            };
            errdefer self.allocator.destroy(entry);

            const replaced = self.by_pubkey.get(remote_pk);
            const previous_index = if (replaced) |existing| existing.session.localIndex() else null;

            if (replaced) |existing| {
                _ = try self.by_pubkey.put(remote_pk, entry);
                errdefer _ = self.by_pubkey.put(remote_pk, existing) catch unreachable;
            } else {
                _ = try self.by_pubkey.put(remote_pk, entry);
                errdefer _ = self.by_pubkey.remove(remote_pk);
            }

            if (previous_index) |index| {
                if (index != local_index) {
                    _ = self.by_index.remove(index);
                    errdefer _ = self.by_index.put(index, replaced.?) catch unreachable;
                }
            }

            const replaced_index = try self.by_index.put(local_index, entry);
            errdefer {
                if (replaced_index) |previous| {
                    _ = self.by_index.put(local_index, previous) catch unreachable;
                } else {
                    _ = self.by_index.remove(local_index);
                }
            }

            if (replaced) |old_entry| {
                if (old_entry.owned) self.allocator.destroy(old_entry.session);
                self.allocator.destroy(old_entry);
            }

            return entry.session;
        }

        pub fn getByIndex(self: *Self, local_index: u32) ?*Session {
            const entry = self.by_index.get(local_index) orelse return null;
            return entry.session;
        }

        pub fn getByIndexConst(self: *const Self, local_index: u32) ?*const Session {
            const entry = self.by_index.get(local_index) orelse return null;
            return entry.session;
        }

        pub fn getByPublicKey(self: *Self, remote_pk: noise.Key) ?*Session {
            const entry = self.by_pubkey.get(remote_pk) orelse return null;
            return entry.session;
        }

        pub fn getByPublicKeyConst(self: *const Self, remote_pk: noise.Key) ?*const Session {
            const entry = self.by_pubkey.get(remote_pk) orelse return null;
            return entry.session;
        }

        pub fn removeByIndex(self: *Self, local_index: u32) bool {
            const entry = self.by_index.remove(local_index) orelse return false;
            _ = self.by_pubkey.remove(entry.session.remotePublicKey());
            if (entry.owned) self.allocator.destroy(entry.session);
            self.allocator.destroy(entry);
            return true;
        }

        pub fn removeByPublicKey(self: *Self, remote_pk: noise.Key) bool {
            const entry = self.by_pubkey.remove(remote_pk) orelse return false;
            _ = self.by_index.remove(entry.session.localIndex());
            if (entry.owned) self.allocator.destroy(entry.session);
            self.allocator.destroy(entry);
            return true;
        }

        pub fn expire(self: *Self, now_ms: u64) usize {
            var removed: usize = 0;

            const snapshot = self.localIndexSnapshot() catch return 0;
            defer self.allocator.free(snapshot);

            for (snapshot) |local_index| {
                const session = self.getByIndex(local_index) orelse continue;
                if (!session.isExpired(now_ms)) continue;
                if (self.removeByIndex(local_index)) removed += 1;
            }

            return removed;
        }

        pub fn count(self: *const Self) usize {
            return self.by_index.count();
        }

        pub fn clear(self: *Self) void {
            const snapshot = self.localIndexSnapshot() catch return;
            defer self.allocator.free(snapshot);

            for (snapshot) |local_index| {
                _ = self.removeByIndex(local_index);
            }
        }

        pub fn forEach(self: *Self, func: anytype) void {
            self.by_index.forEach(struct {
                fn call(local_index: u32, entry: **Entry) void {
                    _ = local_index;
                    func(entry.*.session);
                }
            }.call);
        }

        fn allocateIndex(self: *Self) u32 {
            const start = self.next_index;
            while (true) {
                const candidate = self.next_index;
                self.next_index +%= 1;
                if (self.next_index == 0) self.next_index = 1;

                if (candidate != 0 and self.by_index.get(candidate) == null) {
                    return candidate;
                }
                if (self.next_index == start) return 0;
            }
        }

        fn localIndexSnapshot(self: *Self) ![]u32 {
            const result = try self.allocator.alloc(u32, self.count());
            var index: usize = 0;
            for (self.by_index.slots) |slot| {
                if (slot.state != .full) continue;
                result[index] = slot.key;
                index += 1;
            }
            return result;
        }
    };
}

pub fn testAll(comptime lib: type, testing: anytype, allocator: mem.Allocator) !void {
    const noise_mod = @import("noise");
    const Noise = noise_mod.make(noise_mod.LibAdapter.make(lib));
    const Manager = SessionManager(Noise);

    var manager = try Manager.init(allocator);
    defer manager.deinit();

    const send_a = noise.Key.fromBytes([_]u8{1} ** noise.Key.key_size);
    const recv_a = noise.Key.fromBytes([_]u8{2} ** noise.Key.key_size);
    const pk_a = noise.Key.fromBytes([_]u8{3} ** noise.Key.key_size);
    const pk_b = noise.Key.fromBytes([_]u8{4} ** noise.Key.key_size);

    try testing.expectError(errors.Error.InvalidReceiverIndex, manager.createSession(pk_a, send_a, recv_a, 0, 9));

    const first = try manager.createSession(pk_a, send_a, recv_a, 41, 10);
    try testing.expect(first.localIndex() != 0);
    try testing.expectEqual(@as(usize, 1), manager.count());
    try testing.expect(manager.getByIndex(first.localIndex()) == first);
    try testing.expect(manager.getByPublicKey(pk_a) == first);
    try testing.expectEqual(@as(u32, 41), first.remoteIndex());

    const replaced = try manager.createSession(pk_a, recv_a, send_a, 42, 20);
    try testing.expectEqual(@as(usize, 1), manager.count());
    try testing.expect(manager.getByPublicKey(pk_a) == replaced);
    try testing.expect(manager.getByIndex(first.localIndex()) == null);

    const second = try manager.createSession(pk_b, send_a, recv_a, 43, 30);
    try testing.expectEqual(@as(usize, 2), manager.count());
    try testing.expect(manager.getByPublicKey(pk_b) == second);

    try testing.expect(manager.getByIndex(first.localIndex()) == null);

    const external = try allocator.create(Noise.Session);
    defer allocator.destroy(external);
    external.* = Noise.Session.init(.{
        .local_index = 99,
        .remote_index = 44,
        .send_key = send_a,
        .recv_key = recv_a,
        .remote_pk = noise.Key.fromBytes([_]u8{5} ** noise.Key.key_size),
        .now_ms = 40,
    });
    try testing.expect((try manager.registerSession(external)) == external);
    try testing.expect(manager.getByIndex(99) == external);

    const conflicting = try allocator.create(Noise.Session);
    defer allocator.destroy(conflicting);
    conflicting.* = Noise.Session.init(.{
        .local_index = second.localIndex(),
        .remote_index = 45,
        .send_key = send_a,
        .recv_key = recv_a,
        .remote_pk = noise.Key.fromBytes([_]u8{6} ** noise.Key.key_size),
        .now_ms = 41,
    });
    try testing.expectError(errors.Error.IndexInUse, manager.registerSession(conflicting));

    second.expire();
    try testing.expectEqual(@as(usize, 1), manager.expire(31));
    try testing.expectEqual(@as(usize, 2), manager.count());

    try testing.expect(manager.removeByPublicKey(pk_a));
    try testing.expectEqual(@as(usize, 1), manager.count());
    try testing.expect(manager.removeByIndex(99));
    try testing.expectEqual(@as(usize, 0), manager.count());
}
