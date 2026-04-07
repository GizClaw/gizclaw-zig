pub const Tier = enum {
    smoke,
    regular,
    stress,
};

pub const ImpairmentProfile = struct {
    name: []const u8,
    loss_pct: u8 = 0,
    reorder_pct: u8 = 0,
    duplicate_pct: u8 = 0,
    burst_len: usize = 0,
};

pub const no_impairment = ImpairmentProfile{
    .name = "none",
};

pub const low_loss = ImpairmentProfile{
    .name = "low_loss",
    .loss_pct = 1,
};

pub const reorder_only = ImpairmentProfile{
    .name = "reorder_only",
    .reorder_pct = 10,
};

pub const duplicate_only = ImpairmentProfile{
    .name = "duplicate_only",
    .duplicate_pct = 1,
};

pub const burst_loss = ImpairmentProfile{
    .name = "burst_loss",
    .loss_pct = 5,
    .burst_len = 4,
};

pub const Config = struct {
    warmup: usize,
    iterations: usize,
};

pub const Report = struct {
    tier: Tier = .smoke,
    impairment: ImpairmentProfile = no_impairment,
    payload_bytes_per_op: usize = 0,
    copy_bytes_per_op: usize = 0,
    alloc_calls_total: usize = 0,
    alloc_bytes_total: usize = 0,
    peak_live_bytes: usize = 0,
    extra_name: ?[]const u8 = null,
    extra_value: usize = 0,
};

pub fn runLoop(comptime lib: type, config: Config, state: anytype, body: anytype) !u64 {
    var iteration: usize = 0;
    while (iteration < config.warmup) : (iteration += 1) try body(state);

    const start_ns = lib.time.nanoTimestamp();
    iteration = 0;
    while (iteration < config.iterations) : (iteration += 1) try body(state);
    const end_ns = lib.time.nanoTimestamp();

    return @intCast(end_ns - start_ns);
}

pub fn print(comptime lib: type, label: []const u8, config: Config, elapsed_ns: u64, report: Report) void {
    const iterations_u64: u64 = @intCast(config.iterations);
    const ns_per_op = if (iterations_u64 == 0) 0 else @divTrunc(elapsed_ns, iterations_u64);
    const ops_per_s = if (elapsed_ns == 0)
        0
    else
        @as(u64, @intCast((@as(u128, iterations_u64) * @as(u128, lib.time.ns_per_s)) / @as(u128, elapsed_ns)));
    const payload_bytes_per_s = if (elapsed_ns == 0 or report.payload_bytes_per_op == 0)
        0
    else
        @as(u64, @intCast((@as(u128, iterations_u64) * @as(u128, report.payload_bytes_per_op) * @as(u128, lib.time.ns_per_s)) / @as(u128, elapsed_ns)));
    const alloc_calls_per_op = if (iterations_u64 == 0)
        0
    else
        @divTrunc(@as(u64, @intCast(report.alloc_calls_total)), iterations_u64);
    const alloc_bytes_per_op = if (iterations_u64 == 0)
        0
    else
        @divTrunc(@as(u64, @intCast(report.alloc_bytes_total)), iterations_u64);

    lib.debug.print(
        "bench label={s} tier={s} impairment={s} warmup={d} iters={d} elapsed_ns={d} ns/op={d} ops/s={d} payload_B/op={d} payload_B/s={d} copy_B/op={d} alloc_calls/op={d} alloc_B/op={d} peak_live_B={d}",
        .{
            label,
            tierName(report.tier),
            report.impairment.name,
            config.warmup,
            config.iterations,
            elapsed_ns,
            ns_per_op,
            ops_per_s,
            report.payload_bytes_per_op,
            payload_bytes_per_s,
            report.copy_bytes_per_op,
            alloc_calls_per_op,
            alloc_bytes_per_op,
            report.peak_live_bytes,
        },
    );
    if (report.extra_name) |name| {
        lib.debug.print(" {s}={d}", .{ name, report.extra_value });
    }
    lib.debug.print("\n", .{});
}

fn tierName(tier: Tier) []const u8 {
    return switch (tier) {
        .smoke => "smoke",
        .regular => "regular",
        .stress => "stress",
    };
}

pub fn CountingAllocator(comptime lib: type) type {
    const mem = lib.mem;

    return struct {
        child: mem.Allocator,
        stats: Stats = .{},

        const Self = @This();
        const vtable = mem.Allocator.VTable{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        };

        pub const Stats = struct {
            alloc_calls: usize = 0,
            resize_calls: usize = 0,
            remap_calls: usize = 0,
            free_calls: usize = 0,
            bytes_allocated: usize = 0,
            bytes_freed: usize = 0,
            live_bytes: usize = 0,
            peak_live_bytes: usize = 0,

            fn liveBytesGrow(self: *Stats, amount: usize) void {
                self.live_bytes += amount;
                if (self.live_bytes > self.peak_live_bytes) self.peak_live_bytes = self.live_bytes;
            }

            fn liveBytesShrink(self: *Stats, amount: usize) void {
                if (amount >= self.live_bytes) {
                    self.live_bytes = 0;
                    return;
                }
                self.live_bytes -= amount;
            }

            fn applyLenDelta(self: *Stats, old_len: usize, new_len: usize) void {
                if (new_len > old_len) {
                    const delta = new_len - old_len;
                    self.bytes_allocated += delta;
                    self.liveBytesGrow(delta);
                    return;
                }
                const delta = old_len - new_len;
                self.bytes_freed += delta;
                self.liveBytesShrink(delta);
            }
        };

        pub fn init(child: mem.Allocator) Self {
            return .{
                .child = child,
            };
        }

        pub fn allocator(self: *Self) mem.Allocator {
            return .{
                .ptr = self,
                .vtable = &vtable,
            };
        }

        pub fn reset(self: *Self) void {
            self.stats = .{};
        }

        fn alloc(ctx: *anyopaque, len: usize, alignment: mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const memory = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
            self.stats.alloc_calls += 1;
            self.stats.bytes_allocated += len;
            self.stats.liveBytesGrow(len);
            return memory;
        }

        fn resize(ctx: *anyopaque, memory: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const resized = self.child.rawResize(memory, alignment, new_len, ret_addr);
            if (!resized) return false;
            self.stats.resize_calls += 1;
            self.stats.applyLenDelta(memory.len, new_len);
            return true;
        }

        fn remap(ctx: *anyopaque, memory: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const remapped = self.child.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
            self.stats.remap_calls += 1;
            self.stats.applyLenDelta(memory.len, new_len);
            return remapped;
        }

        fn free(ctx: *anyopaque, memory: []u8, alignment: mem.Alignment, ret_addr: usize) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.stats.free_calls += 1;
            self.stats.bytes_freed += memory.len;
            self.stats.liveBytesShrink(memory.len);
            self.child.rawFree(memory, alignment, ret_addr);
        }
    };
}
