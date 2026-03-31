const embed = @import("embed");
const mem = embed.mem;
const noise = @import("noise");

fn mix64(value: u64) u64 {
    var hash = value;
    hash ^= hash >> 33;
    hash *%= 0xff51afd7ed558ccd;
    hash ^= hash >> 33;
    hash *%= 0xc4ceb9fe1a85ec53;
    hash ^= hash >> 33;
    return hash;
}

fn nextCapacity(min_capacity: usize) usize {
    var capacity: usize = 8;
    while (capacity < min_capacity) : (capacity *= 2) {}
    return capacity;
}

pub fn UIntMap(comptime K: type, comptime V: type) type {
    return struct {
        allocator: mem.Allocator,
        slots: []Slot,
        count_value: usize = 0,
        tombstones: usize = 0,

        const Self = @This();
        const State = enum(u2) {
            empty,
            full,
            tombstone,
        };
        const Slot = struct {
            state: State = .empty,
            key: K = 0,
            value: V = undefined,
        };

        pub fn init(allocator: mem.Allocator, requested_capacity: usize) !Self {
            const slots = try allocator.alloc(Slot, nextCapacity(requested_capacity));
            for (slots) |*slot| slot.* = .{};
            return .{
                .allocator = allocator,
                .slots = slots,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.slots);
            self.slots = &.{};
            self.count_value = 0;
            self.tombstones = 0;
        }

        pub fn clear(self: *Self) void {
            for (self.slots) |*slot| slot.state = .empty;
            self.count_value = 0;
            self.tombstones = 0;
        }

        pub fn count(self: *const Self) usize {
            return self.count_value;
        }

        pub fn getPtr(self: *Self, key: K) ?*V {
            const index = self.lookupIndex(key) orelse return null;
            return &self.slots[index].value;
        }

        pub fn get(self: *const Self, key: K) ?V {
            const index = self.lookupIndex(key) orelse return null;
            return self.slots[index].value;
        }

        pub fn getPtrConst(self: *const Self, key: K) ?*const V {
            const index = self.lookupIndex(key) orelse return null;
            return &self.slots[index].value;
        }

        pub fn put(self: *Self, key: K, value: V) !?V {
            try self.ensureCapacity();

            const insert_index, const found_index = self.findInsertSlot(key);
            if (found_index) |index| {
                const old = self.slots[index].value;
                self.slots[index].value = value;
                return old;
            }

            const slot = &self.slots[insert_index];
            if (slot.state == .tombstone) self.tombstones -= 1;
            slot.* = .{
                .state = .full,
                .key = key,
                .value = value,
            };
            self.count_value += 1;
            return null;
        }

        pub fn remove(self: *Self, key: K) ?V {
            const index = self.lookupIndex(key) orelse return null;
            const old = self.slots[index].value;
            self.slots[index].state = .tombstone;
            self.count_value -= 1;
            self.tombstones += 1;
            return old;
        }

        pub fn forEach(self: *Self, func: anytype) void {
            for (self.slots) |*slot| {
                if (slot.state != .full) continue;
                func(slot.key, &slot.value);
            }
        }

        fn lookupIndex(self: *const Self, key: K) ?usize {
            if (self.slots.len == 0) return null;

            var index = bucketForInt(self.slots.len, key);
            var probes: usize = 0;
            while (probes < self.slots.len) : (probes += 1) {
                const slot = self.slots[index];
                switch (slot.state) {
                    .empty => return null,
                    .full => if (slot.key == key) return index,
                    .tombstone => {},
                }
                index = (index + 1) & (self.slots.len - 1);
            }
            return null;
        }

        fn findInsertSlot(self: *const Self, key: K) struct { usize, ?usize } {
            var index = bucketForInt(self.slots.len, key);
            var first_tombstone: ?usize = null;
            var probes: usize = 0;
            while (probes < self.slots.len) : (probes += 1) {
                const slot = self.slots[index];
                switch (slot.state) {
                    .empty => return .{ first_tombstone orelse index, null },
                    .full => if (slot.key == key) return .{ index, index },
                    .tombstone => {
                        if (first_tombstone == null) first_tombstone = index;
                    },
                }
                index = (index + 1) & (self.slots.len - 1);
            }
            return .{ first_tombstone orelse 0, null };
        }

        fn ensureCapacity(self: *Self) !void {
            if ((self.count_value + self.tombstones + 1) * 4 < self.slots.len * 3) return;
            try self.rehash(if (self.slots.len == 0) 8 else self.slots.len * 2);
        }

        fn rehash(self: *Self, requested_capacity: usize) !void {
            const new_slots = try self.allocator.alloc(Slot, nextCapacity(requested_capacity));
            for (new_slots) |*slot| slot.* = .{};

            const old_slots = self.slots;
            self.slots = new_slots;
            self.count_value = 0;
            self.tombstones = 0;

            for (old_slots) |slot| {
                if (slot.state != .full) continue;
                self.insertWithoutResize(slot.key, slot.value);
            }

            self.allocator.free(old_slots);
        }

        fn insertWithoutResize(self: *Self, key: K, value: V) void {
            const insert_index, _ = self.findInsertSlot(key);
            const slot = &self.slots[insert_index];
            if (slot.state == .tombstone) self.tombstones -= 1;
            slot.* = .{
                .state = .full,
                .key = key,
                .value = value,
            };
            self.count_value += 1;
        }
    };
}

pub fn KeyMap(comptime V: type) type {
    return struct {
        allocator: mem.Allocator,
        slots: []Slot,
        count_value: usize = 0,
        tombstones: usize = 0,

        const Self = @This();
        const State = enum(u2) {
            empty,
            full,
            tombstone,
        };
        const Slot = struct {
            state: State = .empty,
            key: noise.Key = noise.Key.zero,
            value: V = undefined,
        };

        pub fn init(allocator: mem.Allocator, requested_capacity: usize) !Self {
            const slots = try allocator.alloc(Slot, nextCapacity(requested_capacity));
            for (slots) |*slot| slot.* = .{};
            return .{
                .allocator = allocator,
                .slots = slots,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.slots);
            self.slots = &.{};
            self.count_value = 0;
            self.tombstones = 0;
        }

        pub fn clear(self: *Self) void {
            for (self.slots) |*slot| slot.state = .empty;
            self.count_value = 0;
            self.tombstones = 0;
        }

        pub fn count(self: *const Self) usize {
            return self.count_value;
        }

        pub fn getPtr(self: *Self, key: noise.Key) ?*V {
            const index = self.lookupIndex(key) orelse return null;
            return &self.slots[index].value;
        }

        pub fn get(self: *const Self, key: noise.Key) ?V {
            const index = self.lookupIndex(key) orelse return null;
            return self.slots[index].value;
        }

        pub fn getPtrConst(self: *const Self, key: noise.Key) ?*const V {
            const index = self.lookupIndex(key) orelse return null;
            return &self.slots[index].value;
        }

        pub fn put(self: *Self, key: noise.Key, value: V) !?V {
            try self.ensureCapacity();

            const insert_index, const found_index = self.findInsertSlot(key);
            if (found_index) |index| {
                const old = self.slots[index].value;
                self.slots[index].value = value;
                return old;
            }

            const slot = &self.slots[insert_index];
            if (slot.state == .tombstone) self.tombstones -= 1;
            slot.* = .{
                .state = .full,
                .key = key,
                .value = value,
            };
            self.count_value += 1;
            return null;
        }

        pub fn remove(self: *Self, key: noise.Key) ?V {
            const index = self.lookupIndex(key) orelse return null;
            const old = self.slots[index].value;
            self.slots[index].state = .tombstone;
            self.count_value -= 1;
            self.tombstones += 1;
            return old;
        }

        pub fn forEach(self: *Self, func: anytype) void {
            for (self.slots) |*slot| {
                if (slot.state != .full) continue;
                func(slot.key, &slot.value);
            }
        }

        fn lookupIndex(self: *const Self, key: noise.Key) ?usize {
            if (self.slots.len == 0) return null;

            var index = bucketForKey(self.slots.len, key);
            var probes: usize = 0;
            while (probes < self.slots.len) : (probes += 1) {
                const slot = self.slots[index];
                switch (slot.state) {
                    .empty => return null,
                    .full => if (slot.key.eql(key)) return index,
                    .tombstone => {},
                }
                index = (index + 1) & (self.slots.len - 1);
            }
            return null;
        }

        fn findInsertSlot(self: *const Self, key: noise.Key) struct { usize, ?usize } {
            var index = bucketForKey(self.slots.len, key);
            var first_tombstone: ?usize = null;
            var probes: usize = 0;
            while (probes < self.slots.len) : (probes += 1) {
                const slot = self.slots[index];
                switch (slot.state) {
                    .empty => return .{ first_tombstone orelse index, null },
                    .full => if (slot.key.eql(key)) return .{ index, index },
                    .tombstone => {
                        if (first_tombstone == null) first_tombstone = index;
                    },
                }
                index = (index + 1) & (self.slots.len - 1);
            }
            return .{ first_tombstone orelse 0, null };
        }

        fn ensureCapacity(self: *Self) !void {
            if ((self.count_value + self.tombstones + 1) * 4 < self.slots.len * 3) return;
            try self.rehash(if (self.slots.len == 0) 8 else self.slots.len * 2);
        }

        fn rehash(self: *Self, requested_capacity: usize) !void {
            const new_slots = try self.allocator.alloc(Slot, nextCapacity(requested_capacity));
            for (new_slots) |*slot| slot.* = .{};

            const old_slots = self.slots;
            self.slots = new_slots;
            self.count_value = 0;
            self.tombstones = 0;

            for (old_slots) |slot| {
                if (slot.state != .full) continue;
                self.insertWithoutResize(slot.key, slot.value);
            }

            self.allocator.free(old_slots);
        }

        fn insertWithoutResize(self: *Self, key: noise.Key, value: V) void {
            const insert_index, _ = self.findInsertSlot(key);
            const slot = &self.slots[insert_index];
            if (slot.state == .tombstone) self.tombstones -= 1;
            slot.* = .{
                .state = .full,
                .key = key,
                .value = value,
            };
            self.count_value += 1;
        }
    };
}

fn bucketForInt(capacity: usize, value: anytype) usize {
    return @intCast(mix64(@as(u64, @intCast(value))) & @as(u64, @intCast(capacity - 1)));
}

fn bucketForKey(capacity: usize, key: noise.Key) usize {
    var hash: u64 = 0xcbf29ce484222325;
    for (key.asBytes()) |byte| {
        hash ^= byte;
        hash *%= 0x100000001b3;
    }
    return @intCast(mix64(hash) & @as(u64, @intCast(capacity - 1)));
}

pub fn testAll(testing: anytype, allocator: mem.Allocator) !void {
    var ints = try UIntMap(u32, u32).init(allocator, 2);
    defer ints.deinit();

    try testing.expectEqual(@as(?u32, null), try ints.put(1, 10));
    try testing.expectEqual(@as(?u32, null), try ints.put(9, 90));
    try testing.expectEqual(@as(?u32, null), try ints.put(17, 170));
    try testing.expectEqual(@as(u32, 90), ints.get(9).?);
    try testing.expectEqual(@as(u32, 10), ints.remove(1).?);
    try testing.expectEqual(@as(?u32, null), try ints.put(25, 250));
    try testing.expectEqual(@as(u32, 250), ints.get(25).?);

    var keys = try KeyMap(u32).init(allocator, 2);
    defer keys.deinit();

    const key_a = noise.Key.fromBytes([_]u8{1} ** noise.Key.key_size);
    const key_b = noise.Key.fromBytes([_]u8{2} ** noise.Key.key_size);
    const key_c = noise.Key.fromBytes([_]u8{3} ** noise.Key.key_size);

    try testing.expectEqual(@as(?u32, null), try keys.put(key_a, 11));
    try testing.expectEqual(@as(?u32, null), try keys.put(key_b, 22));
    try testing.expectEqual(@as(?u32, null), try keys.put(key_c, 33));
    try testing.expectEqual(@as(u32, 22), keys.remove(key_b).?);
    try testing.expectEqual(@as(?u32, null), try keys.put(key_b, 44));
    try testing.expectEqual(@as(u32, 11), keys.get(key_a).?);
    try testing.expectEqual(@as(u32, 33), keys.get(key_c).?);
    try testing.expectEqual(@as(u32, 44), keys.get(key_b).?);
}
