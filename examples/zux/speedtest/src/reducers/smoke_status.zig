const glib = @import("glib");

pub const source_id: u32 = 6;

pub const Event = struct {
    pub const event_name = "smoke.status_update";

    allocator: glib.std.mem.Allocator,
    round: u64,
    ping_rtt_ms: u32,
    up_bytes: u64,
    down_bytes: u64,
    up_total: u64,
    down_total: u64,
    up_mbps_milli: u32,
    down_mbps_milli: u32,
    duplex_up_mbps_milli: u32,
    duplex_down_mbps_milli: u32,
    cpu0_percent: u32,
    cpu1_percent: u32,
    mem_internal_free_kib: u32,
    mem_psram_free_kib: u32,

    pub fn init(
        allocator: glib.std.mem.Allocator,
        value: Update,
    ) !*@This() {
        const payload = try allocator.create(@This());
        payload.* = .{
            .allocator = allocator,
            .round = value.round,
            .ping_rtt_ms = value.ping_rtt_ms,
            .up_bytes = value.up_bytes,
            .down_bytes = value.down_bytes,
            .up_total = value.up_total,
            .down_total = value.down_total,
            .up_mbps_milli = value.up_mbps_milli,
            .down_mbps_milli = value.down_mbps_milli,
            .duplex_up_mbps_milli = value.duplex_up_mbps_milli,
            .duplex_down_mbps_milli = value.duplex_down_mbps_milli,
            .cpu0_percent = value.cpu0_percent,
            .cpu1_percent = value.cpu1_percent,
            .mem_internal_free_kib = value.mem_internal_free_kib,
            .mem_psram_free_kib = value.mem_psram_free_kib,
        };
        return payload;
    }

    pub fn decodeJson(_: glib.std.mem.Allocator, _: glib.std.json.Value) !*@This() {
        return error.UnsupportedSmokeStatusJson;
    }

    pub fn deinit(payload: *@This()) void {
        payload.allocator.destroy(payload);
    }
};

pub const Update = struct {
    round: u64 = 0,
    ping_rtt_ms: u32 = 0,
    up_bytes: u64 = 0,
    down_bytes: u64 = 0,
    up_total: u64 = 0,
    down_total: u64 = 0,
    up_mbps_milli: u32 = 0,
    down_mbps_milli: u32 = 0,
    duplex_up_mbps_milli: u32 = 0,
    duplex_down_mbps_milli: u32 = 0,
    cpu0_percent: u32 = 0,
    cpu1_percent: u32 = 0,
    mem_internal_free_kib: u32 = 0,
    mem_psram_free_kib: u32 = 0,
};

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const Stores = ZuxAppType.Store.Stores;
    const Message = ZuxAppType.Message;
    const Emitter = ZuxAppType.Emitter;
    const SmokeStatus = @FieldType(Stores, "smoke_status").StateType;

    return struct {
        const log = grt.std.log.scoped(.smoke_status);

        pub fn init() @This() {
            return .{};
        }

        pub fn reduce(
            self: *@This(),
            stores: *Stores,
            message: Message,
            out: Emitter,
        ) !void {
            _ = self;

            switch (message.body) {
                .custom => |custom| {
                    if (custom.as(Event)) |payload| {
                        setState(stores, payload);
                        log.debug("smoke status update round={d} ping_rtt_ms={d} up={d}/{d} down={d}/{d} cpu={d}/{d} mem_i_p={d}/{d}KiB", .{
                            payload.round,
                            payload.ping_rtt_ms,
                            payload.up_bytes,
                            payload.up_total,
                            payload.down_bytes,
                            payload.down_total,
                            payload.cpu0_percent,
                            payload.cpu1_percent,
                            payload.mem_internal_free_kib,
                            payload.mem_psram_free_kib,
                        });
                        return;
                    } else |_| {}

                    try out.emit(message);
                },
                else => {
                    try out.emit(message);
                },
            }
        }

        fn setState(stores: *Stores, payload: *const Event) void {
            stores.smoke_status.invoke(payload, struct {
                fn apply(status: *SmokeStatus, input: *const Event) void {
                    status.round = input.round;
                    status.ping_rtt_ms = input.ping_rtt_ms;
                    status.up_bytes = input.up_bytes;
                    status.down_bytes = input.down_bytes;
                    status.up_total = input.up_total;
                    status.down_total = input.down_total;
                    status.up_mbps_milli = input.up_mbps_milli;
                    status.down_mbps_milli = input.down_mbps_milli;
                    status.duplex_up_mbps_milli = input.duplex_up_mbps_milli;
                    status.duplex_down_mbps_milli = input.duplex_down_mbps_milli;
                    status.cpu0_percent = input.cpu0_percent;
                    status.cpu1_percent = input.cpu1_percent;
                    status.mem_internal_free_kib = input.mem_internal_free_kib;
                    status.mem_psram_free_kib = input.mem_psram_free_kib;
                }
            }.apply);
        }
    };
}
