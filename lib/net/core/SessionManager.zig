const dep = @import("dep");
const mem = dep.embed.mem;
const noise = @import("../noise.zig");

const errors = @import("errors.zig");
const KeyMapFile = @import("KeyMap.zig");
const UIntMapFile = @import("UIntMap.zig");

pub fn make(comptime lib: type, comptime Noise: type) type {
    const Session = Noise.Session;

    return struct {
        allocator: mem.Allocator,
        by_index: UIntMapFile.make(u32, *Entry),
        by_pubkey: KeyMapFile.make(*Entry),
        next_index: u32 = 1,
        guard: lib.Thread.RwLock = .{},
        worker_mutex: lib.Thread.Mutex = .{},
        worker_cond: lib.Thread.Condition = .{},
        worker_thread: ?lib.Thread = null,
        worker_stop: bool = false,
        worker_joining: bool = false,
        worker_interval_ms: u32 = 0,

        const Self = @This();
        const Entry = struct {
            session: *Session,
            owned: bool,
        };

        pub fn init(allocator: mem.Allocator) !Self {
            return .{
                .allocator = allocator,
                .by_index = try UIntMapFile.make(u32, *Entry).init(allocator, 8),
                .by_pubkey = try KeyMapFile.make(*Entry).init(allocator, 8),
            };
        }

        pub fn deinit(self: *Self) void {
            self.stopExpiryWorker();
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
        ) !*Session {
            if (remote_index == 0) return errors.Error.InvalidReceiverIndex;

            self.guard.lock();
            defer self.guard.unlock();

            const local_index = self.allocateIndexLocked();
            if (local_index == 0) return errors.Error.NoFreeIndex;

            const owned = try self.allocator.create(Session);
            errdefer self.allocator.destroy(owned);

            owned.* = Session.init(.{
                .local_index = local_index,
                .remote_index = remote_index,
                .send_key = send_key,
                .recv_key = recv_key,
                .remote_pk = remote_pk,
            });
            return try self.registerEntryLocked(owned, true);
        }

        pub fn registerSession(self: *Self, session: *Session) !*Session {
            self.guard.lock();
            defer self.guard.unlock();
            return try self.registerEntryLocked(session, false);
        }

        pub fn startExpiryWorker(self: *Self, interval_ms: u32) !void {
            const effective_interval_ms: u32 = @max(interval_ms, 1);
            self.worker_mutex.lock();
            defer self.worker_mutex.unlock();
            if (self.worker_thread != null) return errors.Error.ExpiryWorkerAlreadyRunning;

            self.worker_stop = false;
            self.worker_joining = false;
            self.worker_interval_ms = effective_interval_ms;
            self.worker_thread = try lib.Thread.spawn(.{}, expiryWorkerMain, .{self});
        }

        pub fn stopExpiryWorker(self: *Self) void {
            self.worker_mutex.lock();
            if (self.worker_thread == null or self.worker_joining) {
                self.worker_mutex.unlock();
                return;
            }
            self.worker_stop = true;
            self.worker_joining = true;
            self.worker_cond.broadcast();
            const thread = self.worker_thread.?;
            self.worker_mutex.unlock();

            thread.join();

            self.worker_mutex.lock();
            self.worker_thread = null;
            self.worker_stop = false;
            self.worker_joining = false;
            self.worker_interval_ms = 0;
            self.worker_mutex.unlock();
        }

        fn registerEntryLocked(self: *Self, session: *Session, owned: bool) !*Session {
            const local_index = session.localIndex();
            const remote_pk = session.remotePublicKey();

            if (local_index == 0) return errors.Error.NoFreeIndex;
            if (self.by_index.get(local_index) != null) return errors.Error.IndexInUse;

            const entry = try self.allocator.create(Entry);
            entry.* = .{
                .session = session,
                .owned = owned,
            };
            errdefer self.allocator.destroy(entry);

            const replaced = self.by_pubkey.get(remote_pk);
            const previous_index = if (replaced) |existing| existing.session.localIndex() else null;

            const replaced_index = try self.by_index.put(local_index, entry);
            if (replaced_index != null) unreachable;
            errdefer _ = self.by_index.remove(local_index);

            _ = try self.by_pubkey.put(remote_pk, entry);

            if (previous_index) |index| {
                _ = self.by_index.remove(index);
            }

            if (replaced) |old_entry| {
                self.destroyEntry(old_entry);
            }

            return entry.session;
        }

        pub fn getByIndex(self: *Self, local_index: u32) ?*Session {
            self.guard.lockShared();
            defer self.guard.unlockShared();
            const entry = self.by_index.get(local_index) orelse return null;
            return entry.session;
        }

        pub fn getByIndexConst(self: *const Self, local_index: u32) ?*const Session {
            @constCast(&self.guard).lockShared();
            defer @constCast(&self.guard).unlockShared();
            const entry = self.by_index.get(local_index) orelse return null;
            return entry.session;
        }

        pub fn getByPublicKey(self: *Self, remote_pk: noise.Key) ?*Session {
            self.guard.lockShared();
            defer self.guard.unlockShared();
            const entry = self.by_pubkey.get(remote_pk) orelse return null;
            return entry.session;
        }

        pub fn getByPublicKeyConst(self: *const Self, remote_pk: noise.Key) ?*const Session {
            @constCast(&self.guard).lockShared();
            defer @constCast(&self.guard).unlockShared();
            const entry = self.by_pubkey.get(remote_pk) orelse return null;
            return entry.session;
        }

        // Runs the callback while holding the manager's shared lock.
        // The callback must stay short and must not call SessionManager write APIs.
        pub fn withSessionByIndexLocked(self: *const Self, local_index: u32, ctx: anytype, func: anytype) bool {
            @constCast(&self.guard).lockShared();
            defer @constCast(&self.guard).unlockShared();

            const entry = self.by_index.get(local_index) orelse return false;
            func(ctx, entry.session);
            return true;
        }

        // Runs the callback while holding the manager's shared lock.
        // The callback must stay short and must not call SessionManager write APIs.
        pub fn withSessionByPublicKeyLocked(self: *const Self, remote_pk: noise.Key, ctx: anytype, func: anytype) bool {
            @constCast(&self.guard).lockShared();
            defer @constCast(&self.guard).unlockShared();

            const entry = self.by_pubkey.get(remote_pk) orelse return false;
            func(ctx, entry.session);
            return true;
        }

        pub fn removeByIndex(self: *Self, local_index: u32) bool {
            self.guard.lock();
            defer self.guard.unlock();
            return self.removeByIndexLocked(local_index);
        }

        pub fn removeByPublicKey(self: *Self, remote_pk: noise.Key) bool {
            self.guard.lock();
            defer self.guard.unlock();
            return self.removeByPublicKeyLocked(remote_pk);
        }

        pub fn expire(self: *Self) usize {
            self.guard.lock();
            defer self.guard.unlock();
            return self.expireLocked();
        }

        pub fn count(self: *const Self) usize {
            @constCast(&self.guard).lockShared();
            defer @constCast(&self.guard).unlockShared();
            return self.by_index.count();
        }

        pub fn clear(self: *Self) void {
            self.guard.lock();
            defer self.guard.unlock();
            self.clearLocked();
        }

        // Runs callbacks while holding the manager's shared lock.
        // Callbacks must not re-enter SessionManager write APIs.
        pub fn forEachLocked(self: *const Self, ctx: anytype, func: anytype) void {
            @constCast(&self.guard).lockShared();
            defer @constCast(&self.guard).unlockShared();
            self.by_index.forEach(struct {
                fn call(local_index: u32, entry: **Entry) void {
                    _ = local_index;
                    func(ctx, entry.*.session);
                }
            }.call);
        }

        pub fn localIndexSnapshot(self: *const Self) ![]u32 {
            @constCast(&self.guard).lockShared();
            defer @constCast(&self.guard).unlockShared();
            return try self.localIndexSnapshotLocked();
        }

        pub fn publicKeySnapshot(self: *const Self) ![]noise.Key {
            @constCast(&self.guard).lockShared();
            defer @constCast(&self.guard).unlockShared();
            return try self.publicKeySnapshotLocked();
        }

        fn removeByIndexLocked(self: *Self, local_index: u32) bool {
            const entry = self.by_index.remove(local_index) orelse return false;
            _ = self.by_pubkey.remove(entry.session.remotePublicKey());
            self.destroyEntry(entry);
            return true;
        }

        fn removeByPublicKeyLocked(self: *Self, remote_pk: noise.Key) bool {
            const entry = self.by_pubkey.remove(remote_pk) orelse return false;
            _ = self.by_index.remove(entry.session.localIndex());
            self.destroyEntry(entry);
            return true;
        }

        fn expireLocked(self: *Self) usize {
            var removed: usize = 0;
            expire_scan: while (true) {
                for (self.by_index.slots) |slot| {
                    if (slot.state != .full) continue;
                    if (!slot.value.session.isExpired()) continue;
                    if (self.removeByIndexLocked(slot.key)) removed += 1;
                    continue :expire_scan;
                }
                break;
            }

            return removed;
        }

        fn clearLocked(self: *Self) void {
            clear_scan: while (true) {
                for (self.by_index.slots) |slot| {
                    if (slot.state != .full) continue;
                    _ = self.removeByIndexLocked(slot.key);
                    continue :clear_scan;
                }
                break;
            }
        }

        fn destroyEntry(self: *Self, entry: *Entry) void {
            if (entry.owned) self.allocator.destroy(entry.session);
            self.allocator.destroy(entry);
        }

        fn allocateIndexLocked(self: *Self) u32 {
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

        fn localIndexSnapshotLocked(self: *const Self) ![]u32 {
            const result = try self.allocator.alloc(u32, self.by_index.count());
            var index: usize = 0;
            for (self.by_index.slots) |slot| {
                if (slot.state != .full) continue;
                result[index] = slot.key;
                index += 1;
            }
            return result;
        }

        fn publicKeySnapshotLocked(self: *const Self) ![]noise.Key {
            const result = try self.allocator.alloc(noise.Key, self.by_pubkey.count());
            var index: usize = 0;
            for (self.by_pubkey.slots) |slot| {
                if (slot.state != .full) continue;
                result[index] = slot.key;
                index += 1;
            }
            return result;
        }

        fn expiryWorkerMain(self: *Self) void {
            self.worker_mutex.lock();
            defer self.worker_mutex.unlock();

            while (!self.worker_stop) {
                const wait_ns = @as(u64, self.worker_interval_ms) * lib.time.ns_per_ms;
                self.worker_cond.timedWait(&self.worker_mutex, wait_ns) catch |err| switch (err) {
                    error.Timeout => {
                        self.worker_mutex.unlock();
                        _ = self.expire();
                        self.worker_mutex.lock();
                    },
                };
            }
        }
    };
}
