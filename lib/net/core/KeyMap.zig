const dep = @import("dep");
const mem = dep.embed.mem;
const noise = @import("../noise.zig");

const common = @import("map_common.zig");

pub fn make(comptime V: type) type {
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
            const slots = try allocator.alloc(Slot, common.nextCapacity(requested_capacity));
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

            var index = common.bucketForKey(self.slots.len, key);
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
            var index = common.bucketForKey(self.slots.len, key);
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
            const new_slots = try self.allocator.alloc(Slot, common.nextCapacity(requested_capacity));
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
