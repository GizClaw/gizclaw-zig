pub const Tier = enum {
    smoke,
    regular,
    stress,
};

pub const Config = struct {
    warmup: usize,
    iterations: usize,
};

pub const Report = struct {
    tier: Tier = .smoke,
    payload_bytes_per_op: usize = 0,
    copy_bytes_per_op: usize = 0,
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

pub fn payloadBytesPerSecond(comptime lib: type, config: Config, elapsed_ns: u64, payload_bytes_per_op: usize) u64 {
    if (elapsed_ns == 0 or payload_bytes_per_op == 0) return 0;
    const iterations_u64: u64 = @intCast(config.iterations);
    return @as(u64, @intCast((@as(u128, iterations_u64) * @as(u128, payload_bytes_per_op) * @as(u128, lib.time.ns_per_s)) / @as(u128, elapsed_ns)));
}

pub fn payloadMbps(comptime lib: type, config: Config, elapsed_ns: u64, payload_bytes_per_op: usize) u64 {
    const payload_bps = payloadBytesPerSecond(lib, config, elapsed_ns, payload_bytes_per_op);
    return @divTrunc(payload_bps * 8, 1_000_000);
}

pub fn print(comptime lib: type, label: []const u8, config: Config, elapsed_ns: u64, report: Report) void {
    const iterations_u64: u64 = @intCast(config.iterations);
    const ns_per_op = if (iterations_u64 == 0) 0 else @divTrunc(elapsed_ns, iterations_u64);
    const ops_per_s = if (elapsed_ns == 0)
        0
    else
        @as(u64, @intCast((@as(u128, iterations_u64) * @as(u128, lib.time.ns_per_s)) / @as(u128, elapsed_ns)));
    const payload_bytes_per_s = payloadBytesPerSecond(lib, config, elapsed_ns, report.payload_bytes_per_op);
    const payload_mbps = payloadMbps(lib, config, elapsed_ns, report.payload_bytes_per_op);

    lib.debug.print(
        "bench label={s} tier={s} warmup={d} iters={d} elapsed_ns={d} ns/op={d} ops/s={d} payload_B/op={d} payload_B/s={d} payload_Mbps={d} copy_B/op={d}",
        .{
            label,
            tierName(report.tier),
            config.warmup,
            config.iterations,
            elapsed_ns,
            ns_per_op,
            ops_per_s,
            report.payload_bytes_per_op,
            payload_bytes_per_s,
            payload_mbps,
            report.copy_bytes_per_op,
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
