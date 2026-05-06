const glib = @import("glib");
const kcp_ns = @import("kcp");

const Key = @import("../noise/Key.zig");
const KcpStreamType = @import("KcpStream.zig");
const packet = @import("../packet.zig");

pub const Config = struct {
    stream: KcpStreamType.Config = .{},
};

pub fn make(comptime grt: type) type {
    const KcpStream = KcpStreamType.make(grt);

    return struct {
        allocator: grt.std.mem.Allocator,
        stream_config: KcpStreamType.Config,
        pools: *packet.Pools,
        items: []*KcpStream = &.{},
        len: usize = 0,
        next_stream: u32 = 1,

        const Self = @This();
        pub const Stream = KcpStream;
        pub const GetOrCreateResult = struct {
            stream: *KcpStream,
            created: bool,
        };

        pub fn init(
            allocator: grt.std.mem.Allocator,
            pools: *packet.Pools,
            config: Config,
        ) Self {
            return .{
                .allocator = allocator,
                .stream_config = config.stream,
                .pools = pools,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.items[0..self.len]) |stream| {
                stream.deinit();
                self.allocator.destroy(stream);
            }
            if (self.items.len != 0) self.allocator.free(self.items);
            self.items = &.{};
            self.len = 0;
        }

        pub fn open(self: *Self, remote_static: Key, service: u64) !GetOrCreateResult {
            const stream = self.next_stream;
            self.next_stream +%= 1;
            if (self.next_stream == 0) self.next_stream = 1;
            return self.getOrCreate(remote_static, service, stream);
        }

        pub fn get(self: *Self, remote_static: Key, service: u64, stream: u32) ?*KcpStream {
            for (self.items[0..self.len]) |item| {
                if (item.remote_static.eql(remote_static) and item.service == service and item.stream == stream) return item;
            }
            return null;
        }

        pub fn getOrCreate(self: *Self, remote_static: Key, service: u64, stream: u32) !GetOrCreateResult {
            if (self.get(remote_static, service, stream)) |item| return .{
                .stream = item,
                .created = false,
            };

            try self.ensureCapacity(self.len + 1);
            const stream_ptr = try self.allocator.create(KcpStream);
            errdefer self.allocator.destroy(stream_ptr);
            stream_ptr.* = try KcpStream.init(
                self.allocator,
                remote_static,
                service,
                stream,
                self.pools,
                self.stream_config,
            );
            errdefer stream_ptr.deinit();
            self.items[self.len] = stream_ptr;
            self.len += 1;
            return .{
                .stream = stream_ptr,
                .created = true,
            };
        }

        pub fn getOrCreateFromFrame(self: *Self, remote_static: Key, service: u64, frame: []const u8) !GetOrCreateResult {
            return self.getOrCreate(remote_static, service, try kcp_ns.getconv(frame));
        }

        pub fn removeRemote(self: *Self, remote_static: Key) void {
            var index: usize = 0;
            while (index < self.len) {
                if (!self.items[index].remote_static.eql(remote_static)) {
                    index += 1;
                    continue;
                }
                self.removeAt(index);
            }
        }

        pub fn driveTick(self: *Self, now: glib.time.instant.Time, callback: KcpStream.Callback) !void {
            for (self.items[0..self.len]) |stream| {
                try stream.drive(.{ .tick = now }, callback);
            }
        }

        fn removeAt(self: *Self, index: usize) void {
            self.items[index].deinit();
            self.allocator.destroy(self.items[index]);
            const last = self.len - 1;
            if (index != last) self.items[index] = self.items[last];
            self.len -= 1;
        }

        fn ensureCapacity(self: *Self, needed: usize) !void {
            if (needed <= self.items.len) return;

            var next = if (self.items.len == 0) @as(usize, 4) else self.items.len * 2;
            while (next < needed) next *= 2;
            self.items = if (self.items.len == 0)
                try self.allocator.alloc(*KcpStream, next)
            else
                try self.allocator.realloc(self.items, next);
        }
    };
}

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    const testing_api = glib.testing;
    const packet_size_capacity = 4096;
    const stream_config = KcpStreamType.Config{
        .channel_capacity = 4,
        .kcp_nodelay = 1,
        .kcp_interval = 10,
        .kcp_resend = 2,
        .kcp_no_congestion_control = 1,
    };
    const key_a = Key{ .bytes = [_]u8{0x41} ** 32 };
    const key_b = Key{ .bytes = [_]u8{0x42} ** 32 };

    const Helpers = struct {
        fn initPools(allocator: glib.std.mem.Allocator) !packet.Pools {
            var pools = packet.Pools{
                .inbound = try packet.Inbound.initPool(grt, allocator, packet_size_capacity),
                .outbound = undefined,
            };
            errdefer pools.inbound.deinit();

            pools.outbound = try packet.Outbound.initPool(grt, allocator, packet_size_capacity);
            return pools;
        }

        fn deinitPools(pools: *packet.Pools) void {
            pools.outbound.deinit();
            pools.inbound.deinit();
        }

        fn convFrame(stream: u32) [4]u8 {
            var frame: [4]u8 = undefined;
            glib.std.mem.writeInt(u32, frame[0..4], stream, .little);
            return frame;
        }
    };

    const TickSink = struct {
        next_tick_deadline_count: usize = 0,

        fn callback(self: *@This()) make(grt).Stream.Callback {
            return .{ .ctx = self, .call = call };
        }

        fn call(ctx: *anyopaque, output: KcpStreamType.DriveOutput) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            switch (output) {
                .outbound => |pkt| pkt.deinit(),
                .next_tick_deadline => |_| self.next_tick_deadline_count += 1,
            }
        }
    };

    const Cases = struct {
        fn openAllocatesSequentialStreams(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            const Table = make(grt);
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var table = Table.init(allocator, &pools, .{ .stream = stream_config });
            defer table.deinit();

            const first = try table.open(key_a, 7);
            try grt.std.testing.expect(first.created);
            try grt.std.testing.expectEqual(@as(u32, 1), first.stream.stream);
            try grt.std.testing.expect(first.stream.remote_static.eql(key_a));
            try grt.std.testing.expectEqual(@as(u64, 7), first.stream.service);

            const second = try table.open(key_a, 7);
            try grt.std.testing.expect(second.created);
            try grt.std.testing.expectEqual(@as(u32, 2), second.stream.stream);
            try grt.std.testing.expectEqual(@as(usize, 2), table.len);
        }

        fn getOrCreateIsStable(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            const Table = make(grt);
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var table = Table.init(allocator, &pools, .{ .stream = stream_config });
            defer table.deinit();

            const created = try table.getOrCreate(key_a, 9, 123);
            try grt.std.testing.expect(created.created);

            const existing = try table.getOrCreate(key_a, 9, 123);
            try grt.std.testing.expect(!existing.created);
            try grt.std.testing.expect(existing.stream == created.stream);
            try grt.std.testing.expect(table.get(key_a, 9, 123) == created.stream);
            try grt.std.testing.expect(table.get(key_a, 10, 123) == null);
            try grt.std.testing.expect(table.get(key_b, 9, 123) == null);
        }

        fn getOrCreateFromFrameUsesConversationId(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            const Table = make(grt);
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var table = Table.init(allocator, &pools, .{ .stream = stream_config });
            defer table.deinit();

            const frame = Helpers.convFrame(0x01020304);
            const result = try table.getOrCreateFromFrame(key_a, 11, frame[0..]);
            try grt.std.testing.expect(result.created);
            try grt.std.testing.expectEqual(@as(u32, 0x01020304), result.stream.stream);

            const existing = try table.getOrCreateFromFrame(key_a, 11, frame[0..]);
            try grt.std.testing.expect(!existing.created);
            try grt.std.testing.expect(existing.stream == result.stream);
        }

        fn streamPointersSurviveTableGrowth(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            const Table = make(grt);
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var table = Table.init(allocator, &pools, .{ .stream = stream_config });
            defer table.deinit();

            const first = try table.getOrCreate(key_a, 7, 1);
            try grt.std.testing.expect(first.created);

            var stream: u32 = 2;
            while (stream <= 8) : (stream += 1) {
                _ = try table.getOrCreate(key_a, 7, stream);
            }

            const existing = table.get(key_a, 7, 1) orelse return error.MissingStream;
            try grt.std.testing.expect(existing == first.stream);
        }

        fn removeRemoteDropsOnlyMatchingStreams(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            const Table = make(grt);
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var table = Table.init(allocator, &pools, .{ .stream = stream_config });
            defer table.deinit();

            _ = try table.getOrCreate(key_a, 7, 1);
            _ = try table.getOrCreate(key_a, 8, 2);
            const keep = try table.getOrCreate(key_b, 7, 1);
            try grt.std.testing.expectEqual(@as(usize, 3), table.len);

            table.removeRemote(key_a);
            try grt.std.testing.expectEqual(@as(usize, 1), table.len);
            try grt.std.testing.expect(table.get(key_a, 7, 1) == null);
            try grt.std.testing.expect(table.get(key_a, 8, 2) == null);
            try grt.std.testing.expect(table.get(key_b, 7, 1) != null);
            try grt.std.testing.expect(table.get(key_b, 7, 1).?.remote_static.eql(keep.stream.remote_static));

            table.removeRemote(key_a);
            try grt.std.testing.expectEqual(@as(usize, 1), table.len);
        }

        fn openWrapsStreamIdZero(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            const Table = make(grt);
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var table = Table.init(allocator, &pools, .{ .stream = stream_config });
            defer table.deinit();
            table.next_stream = grt.std.math.maxInt(u32);

            const max_stream = try table.open(key_a, 7);
            try grt.std.testing.expectEqual(grt.std.math.maxInt(u32), max_stream.stream.stream);
            try grt.std.testing.expectEqual(@as(u32, 1), table.next_stream);

            const wrapped = try table.open(key_a, 7);
            try grt.std.testing.expectEqual(@as(u32, 1), wrapped.stream.stream);
            try grt.std.testing.expectEqual(@as(u32, 2), table.next_stream);
        }

        fn driveTickVisitsStreams(_: *testing_api.T, allocator: glib.std.mem.Allocator) !void {
            const Table = make(grt);
            var pools = try Helpers.initPools(allocator);
            defer Helpers.deinitPools(&pools);

            var table = Table.init(allocator, &pools, .{ .stream = stream_config });
            defer table.deinit();

            _ = try table.open(key_a, 7);
            _ = try table.open(key_b, 8);

            var sink = TickSink{};
            try table.driveTick(grt.time.instant.now(), sink.callback());
            try grt.std.testing.expect(sink.next_tick_deadline_count > 0);
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: glib.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: glib.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("open_allocates_sequential_streams", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.openAllocatesSequentialStreams));
            t.run("get_or_create_is_stable", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.getOrCreateIsStable));
            t.run("get_or_create_from_frame_uses_conversation_id", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.getOrCreateFromFrameUsesConversationId));
            t.run("stream_pointers_survive_table_growth", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.streamPointersSurviveTableGrowth));
            t.run("remove_remote_drops_only_matching_streams", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.removeRemoteDropsOnlyMatchingStreams));
            t.run("open_wraps_stream_id_zero", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.openWrapsStreamIdZero));
            t.run("drive_tick_visits_streams", testing_api.TestRunner.fromFn(grt.std, 64 * 1024, Cases.driveTickVisitsStreams));
            return true;
        }

        pub fn deinit(self: *@This(), allocator: glib.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
