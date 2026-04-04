const dep = @import("dep");
const core = @import("../core.zig");

const mem = dep.embed.mem;

const Conn = @import("Conn.zig");
const errors = @import("errors.zig");
const SharedRefFile = @import("SharedRef.zig");

pub fn make(comptime Core: type) type {
    const Context = dep.context.Context;
    const PacketConn = dep.net.PacketConn;
    const ConnType = Conn.make(Core);
    const PeerEvent = Core.UDP.PeerEvent;
    const Key = @TypeOf(@as(PeerEvent, undefined).peer);
    const KeyPair = @TypeOf(@as(Core.UDP, undefined).local_static);
    const SharedRef = SharedRefFile.make(Core);

    return struct {
        allocator: mem.Allocator = undefined,
        state: ?*State = null,

        const Self = @This();

        pub const PeerEvents = struct {
            allocator: mem.Allocator,
            slots: []PeerEvent,
            head: usize = 0,
            tail: usize = 0,
            len: usize = 0,

            fn init(allocator: mem.Allocator, capacity_hint: usize) !PeerEvents {
                return .{
                    .allocator = allocator,
                    .slots = try allocator.alloc(PeerEvent, @max(capacity_hint, 1)),
                };
            }

            fn deinit(self: *PeerEvents) void {
                self.allocator.free(self.slots);
                self.slots = &.{};
                self.head = 0;
                self.tail = 0;
                self.len = 0;
            }

            pub fn pushDropNewest(self: *PeerEvents, event: PeerEvent) bool {
                if (self.len == self.slots.len) return false;
                self.slots[self.tail] = event;
                self.tail = (self.tail + 1) % self.slots.len;
                self.len += 1;
                return true;
            }

            pub fn pop(self: *PeerEvents) ?PeerEvent {
                if (self.len == 0) return null;
                const event = self.slots[self.head];
                self.head = (self.head + 1) % self.slots.len;
                self.len -= 1;
                return event;
            }

            pub fn count(self: *const PeerEvents) usize {
                return self.len;
            }

            pub fn capacity(self: *const PeerEvents) usize {
                return self.slots.len;
            }
        };

        const KnownSet = struct {
            allocator: mem.Allocator,
            items: []Entry,
            len: usize = 0,

            const Entry = struct {
                key: Key,
                refs: usize = 1,
            };

            fn init(allocator: mem.Allocator, capacity: usize) !KnownSet {
                return .{
                    .allocator = allocator,
                    .items = try allocator.alloc(Entry, @max(capacity, 1)),
                };
            }

            fn deinit(self: *KnownSet) void {
                self.allocator.free(self.items);
                self.items = &.{};
                self.len = 0;
            }

            fn contains(self: *const KnownSet, remote_pk: Key) bool {
                for (self.items[0..self.len]) |existing| {
                    if (existing.key.eql(remote_pk)) return true;
                }
                return false;
            }

            fn insert(self: *KnownSet, remote_pk: Key) !void {
                for (self.items[0..self.len]) |*existing| {
                    if (!existing.key.eql(remote_pk)) continue;
                    existing.refs += 1;
                    return;
                }
                try self.ensureCapacity(self.len + 1);
                self.items[self.len] = .{ .key = remote_pk };
                self.len += 1;
            }

            fn remove(self: *KnownSet, remote_pk: Key) void {
                var index: usize = 0;
                while (index < self.len) : (index += 1) {
                    if (!self.items[index].key.eql(remote_pk)) continue;
                    if (self.items[index].refs > 1) {
                        self.items[index].refs -= 1;
                        return;
                    }
                    if (index + 1 < self.len) {
                        var cursor = index;
                        while (cursor + 1 < self.len) : (cursor += 1) {
                            self.items[cursor] = self.items[cursor + 1];
                        }
                    }
                    self.len -= 1;
                    return;
                }
            }

            fn count(self: *const KnownSet) usize {
                return self.len;
            }

            fn ensureCapacity(self: *KnownSet, need: usize) !void {
                if (need <= self.items.len) return;
                const next_cap = @max(self.items.len * 2, need);
                const grown = try self.allocator.alloc(Entry, next_cap);
                @memcpy(grown[0..self.len], self.items[0..self.len]);
                self.allocator.free(self.items);
                self.items = grown;
            }
        };

        const State = struct {
            allocator: mem.Allocator,
            udp: *Core.UDP,
            owns_udp: bool,
            udp_initialized: bool,
            closed: bool = false,
            ref_count: usize = 1,
            previous_hook: ?Core.UDP.PeerEventHook = null,
            known: KnownSet,
            events: PeerEvents,

            fn init(
                allocator: mem.Allocator,
                udp: *Core.UDP,
                owns_udp: bool,
                udp_initialized: bool,
                previous_hook: ?Core.UDP.PeerEventHook,
            ) !*State {
                const state = try allocator.create(State);
                errdefer allocator.destroy(state);
                var known = try KnownSet.init(allocator, 4);
                errdefer known.deinit();
                var events = try PeerEvents.init(allocator, 64);
                errdefer events.deinit();
                state.* = .{
                    .allocator = allocator,
                    .udp = udp,
                    .owns_udp = owns_udp,
                    .udp_initialized = udp_initialized,
                    .previous_hook = previous_hook,
                    .known = known,
                    .events = events,
                };
                return state;
            }

            fn deinit(self: *State) void {
                if (self.udp_initialized) {
                    self.udp.on_peer_event = self.previous_hook;
                }
                if (self.owns_udp) {
                    if (self.udp_initialized) self.udp.deinit();
                    self.allocator.destroy(self.udp);
                }
                self.events.deinit();
                self.known.deinit();
                self.allocator.destroy(self);
            }

            fn retain(self: *State) void {
                self.ref_count += 1;
            }

            fn release(self: *State) void {
                if (self.ref_count == 0) return;
                self.ref_count -= 1;
                if (self.ref_count == 0) self.deinit();
            }
        };

        pub fn init(allocator: mem.Allocator, udp: *Core.UDP, owns_udp: bool) !*Self {
            const state = try State.init(allocator, udp, owns_udp, true, udp.on_peer_event);
            errdefer state.deinit();
            udp.on_peer_event = peerEventHook(state);
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            self.* = .{
                .allocator = allocator,
                .state = state,
            };
            return self;
        }

        pub fn listen(
            allocator: mem.Allocator,
            packet_conn: PacketConn,
            local_static: KeyPair,
            config: Core.UDP.Config,
        ) !*Self {
            const udp = try allocator.create(Core.UDP);
            var state_owns_udp = false;
            errdefer if (!state_owns_udp) allocator.destroy(udp);

            var resolved = config;
            const state = try State.init(allocator, udp, true, false, config.on_peer_event);
            state_owns_udp = true;
            errdefer state.deinit();

            resolved.on_peer_event = peerEventHook(state);
            udp.* = try Core.UDP.init(allocator, packet_conn, local_static, resolved);
            state.udp_initialized = true;
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            self.* = .{
                .allocator = allocator,
                .state = state,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            const state = self.state orelse return;
            const allocator = self.allocator;
            self.close() catch {};
            self.state = null;
            state.release();
            allocator.destroy(self);
        }

        pub fn close(self: *Self) !void {
            const state = try self.getState();
            if (state.closed) return;
            state.closed = true;
            state.udp.close();
        }

        pub fn accept(self: *Self) !*ConnType {
            const state = try self.getState();
            while (state.events.pop()) |event| {
                if (event.state != .established) continue;
                if (state.known.contains(event.peer)) continue;
                try state.known.insert(event.peer);
                errdefer state.known.remove(event.peer);
                return ConnType.init(state.allocator, sharedRef(state), event.peer, releaseHook(state));
            }
            return core.Error.QueueEmpty;
        }

        pub fn acceptContext(self: *Self, ctx: Context) !*ConnType {
            const state = try self.getState();
            while (true) {
                return self.accept() catch |err| switch (err) {
                    core.Error.QueueEmpty => {
                        _ = try state.udp.acceptContext(ctx);
                        continue;
                    },
                    else => return err,
                };
            }
        }

        pub fn peerEvents(self: *Self) !*PeerEvents {
            return &((try self.getState()).events);
        }

        pub fn peer(self: *Self, remote_pk: Key) !*ConnType {
            const state = try self.getState();
            const info = state.udp.peerInfo(remote_pk) orelse return core.Error.PeerNotFound;
            if (info.state != .established) return core.Error.NoSession;
            try state.known.insert(remote_pk);
            errdefer state.known.remove(remote_pk);
            return ConnType.init(state.allocator, sharedRef(state), remote_pk, releaseHook(state));
        }

        pub fn setPeerEndpoint(self: *Self, remote_pk: Key, addr: [*]const u8, addr_len: u32) !void {
            const state = try self.getState();
            try state.udp.setPeerEndpoint(remote_pk, addr, addr_len);
        }

        pub fn connectContext(self: *Self, ctx: Context, remote_pk: Key) !*ConnType {
            const state = try self.getState();
            try state.known.insert(remote_pk);
            errdefer state.known.remove(remote_pk);
            _ = try state.udp.connect(ctx, remote_pk);
            return ConnType.init(state.allocator, sharedRef(state), remote_pk, releaseHook(state));
        }

        pub fn dialContext(
            self: *Self,
            ctx: Context,
            remote_pk: Key,
            addr: [*]const u8,
            addr_len: u32,
        ) !*ConnType {
            const state = try self.getState();
            try state.known.insert(remote_pk);
            errdefer state.known.remove(remote_pk);
            try state.udp.setPeerEndpoint(remote_pk, addr, addr_len);
            _ = try state.udp.connect(ctx, remote_pk);
            return ConnType.init(state.allocator, sharedRef(state), remote_pk, releaseHook(state));
        }

        pub fn udpHandle(self: *Self) !*Core.UDP {
            return (try self.getState()).udp;
        }

        pub fn hostInfo(self: *Self) !Core.UDP.HostInfo {
            return (try self.getState()).udp.hostInfo();
        }

        pub fn testEnqueuePeerEvent(self: *Self, event: PeerEvent) !bool {
            return (try self.getState()).events.pushDropNewest(event);
        }

        pub fn testKnownCount(self: *Self) !usize {
            return (try self.getState()).known.count();
        }

        fn getState(self: *Self) !*State {
            if (self.state == null) return errors.Error.NilListener;
            if (self.state.?.closed) return errors.Error.Closed;
            return self.state.?;
        }

        fn peerEventHook(state: *State) Core.UDP.PeerEventHook {
            return .{
                .ctx = state,
                .emit = struct {
                    fn emit(ctx: *anyopaque, event: PeerEvent) void {
                        const state_ptr: *State = @ptrCast(@alignCast(ctx));
                        if (!state_ptr.closed) _ = state_ptr.events.pushDropNewest(event);
                        if (state_ptr.previous_hook) |previous| previous.emit(previous.ctx, event);
                    }
                }.emit,
            };
        }

        fn releaseHook(state: *State) ConnType.ReleaseHook {
            return .{
                .ctx = state,
                .release = struct {
                    fn release(ctx: *anyopaque, remote_pk: Key) void {
                        const state_ptr: *State = @ptrCast(@alignCast(ctx));
                        state_ptr.known.remove(remote_pk);
                    }
                }.release,
            };
        }

        fn sharedRef(state: *State) SharedRef {
            return .{
                .ctx = state,
                .retain = struct {
                    fn retain(ctx: *anyopaque) void {
                        const state_ptr: *State = @ptrCast(@alignCast(ctx));
                        state_ptr.retain();
                    }
                }.retain,
                .release = struct {
                    fn release(ctx: *anyopaque) void {
                        const state_ptr: *State = @ptrCast(@alignCast(ctx));
                        state_ptr.release();
                    }
                }.release,
                .udp = struct {
                    fn udp(ctx: *anyopaque) *Core.UDP {
                        const state_ptr: *State = @ptrCast(@alignCast(ctx));
                        return state_ptr.udp;
                    }
                }.udp,
            };
        }
    };
}
