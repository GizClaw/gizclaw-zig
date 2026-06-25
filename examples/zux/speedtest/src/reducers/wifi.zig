const glib = @import("glib");
const consts = @import("../consts.zig");

pub const source_id: u32 = 4;

pub const Event = struct {
    pub const event_name = "wifi.set_state";

    pub const State = enum {
        off,
        on,
    };

    allocator: glib.std.mem.Allocator,
    state: State,

    pub fn init(allocator: glib.std.mem.Allocator, state: State) !*@This() {
        const payload = try allocator.create(@This());
        payload.* = .{
            .allocator = allocator,
            .state = state,
        };
        return payload;
    }

    pub fn decodeJson(allocator: glib.std.mem.Allocator, value: glib.std.json.Value) !*@This() {
        const object = switch (value) {
            .object => |object| object,
            else => return error.ExpectedObject,
        };
        const state_field = object.get("state") orelse return error.MissingObjectField;
        const state = switch (state_field) {
            .string => |v| try parseState(v),
            else => return error.ExpectedString,
        };
        return init(allocator, state);
    }

    pub fn deinit(payload: *@This()) void {
        payload.allocator.destroy(payload);
    }

    fn parseState(v: []const u8) !State {
        if (glib.std.mem.eql(u8, v, "off")) return .off;
        if (glib.std.mem.eql(u8, v, "on")) return .on;
        return error.InvalidWifiState;
    }
};

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const Stores = ZuxAppType.Store.Stores;
    const Message = ZuxAppType.Message;
    const Emitter = ZuxAppType.Emitter;
    const WifiState = @FieldType(Stores, "wifi_state").StateType;
    const WifiStateValue = @FieldType(WifiState, "state");
    const WifiStaState = @FieldType(Stores, "wifi").StateType;

    return struct {
        const log = grt.std.log.scoped(.wifi);

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
                        const v = stateValue(payload.state);
                        setState(stores, v);
                        log.info("wifi state set state={s}", .{@tagName(v)});
                        return;
                    } else |_| {}

                    try out.emit(message);
                },
                .wifi_sta_disconnected => |value| {
                    markReconnectBackoff(stores, message.timestamp, value.reason);
                    try out.emit(message);
                },
                .tick => {
                    markConnectTimeout(stores, message.timestamp);
                    clearReconnectBackoff(stores, message.timestamp);
                    try out.emit(message);
                },
                else => {
                    try out.emit(message);
                },
            }
        }

        fn stateValue(v: Event.State) WifiStateValue {
            return switch (v) {
                .off => .off,
                .on => .on,
            };
        }

        fn setState(stores: *Stores, v: WifiStateValue) void {
            const Input = struct {
                v: WifiStateValue,
            };
            stores.wifi_state.invoke(Input{ .v = v }, struct {
                fn apply(wifi: *WifiState, input: Input) void {
                    wifi.state = input.v;
                }
            }.apply);
        }

        fn markConnectTimeout(stores: *Stores, timestamp: glib.time.instant.Time) void {
            const Input = struct {
                timestamp: glib.time.instant.Time,
            };
            stores.wifi.invoke(Input{ .timestamp = timestamp }, struct {
                fn apply(wifi: *WifiStaState, input: Input) void {
                    if (!wifi.connected or wifi.has_ip) {
                        if (wifi.connect_timeout) {
                            log.info("wifi ip timeout clear connected={} has_ip={}", .{ wifi.connected, wifi.has_ip });
                        }
                        wifi.connect_timeout = false;
                        return;
                    }

                    if (wifi.connected_at == 0) {
                        wifi.connected_at = input.timestamp;
                        wifi.connect_timeout = false;
                        log.info("wifi ip wait start connected_at={d} timeout_ns={d}", .{ wifi.connected_at, consts.wifi_ip_timeout });
                        return;
                    }

                    const elapsed = glib.time.instant.sub(input.timestamp, wifi.connected_at);
                    const timed_out = elapsed >= consts.wifi_ip_timeout;
                    if (!wifi.connect_timeout and timed_out) {
                        log.warn("wifi ip timeout elapsed_ns={d} timeout_ns={d} connected_at={d} now={d}", .{
                            elapsed,
                            consts.wifi_ip_timeout,
                            wifi.connected_at,
                            input.timestamp,
                        });
                    } else if (!wifi.connect_timeout and elapsed == 0) {
                        log.info("wifi wait ip connected_at={d} timeout_ns={d}", .{ wifi.connected_at, consts.wifi_ip_timeout });
                    }
                    wifi.connect_timeout = timed_out;
                }
            }.apply);
        }

        fn markReconnectBackoff(stores: *Stores, timestamp: glib.time.instant.Time, reason: u16) void {
            if (stores.app_state.get().state != .on or stores.wifi_state.get().state != .on) return;
            const Input = struct {
                timestamp: glib.time.instant.Time,
                reason: u16,
            };
            stores.wifi.invoke(Input{ .timestamp = timestamp, .reason = reason }, struct {
                fn apply(wifi: *WifiStaState, input: Input) void {
                    if (wifi.status != .disconnected or wifi.connected) return;
                    wifi.reconnect_at = glib.time.instant.add(input.timestamp, consts.wifi_reconnect_backoff);
                    log.warn("wifi reconnect backoff start reason={d} reconnect_at={d} backoff_ns={d}", .{
                        input.reason,
                        wifi.reconnect_at,
                        consts.wifi_reconnect_backoff,
                    });
                }
            }.apply);
        }

        fn clearReconnectBackoff(stores: *Stores, timestamp: glib.time.instant.Time) void {
            const Input = struct {
                timestamp: glib.time.instant.Time,
            };
            stores.wifi.invoke(Input{ .timestamp = timestamp }, struct {
                fn apply(wifi: *WifiStaState, input: Input) void {
                    if (wifi.reconnect_at == 0) return;
                    if (wifi.status != .disconnected or wifi.connected) {
                        log.info("wifi reconnect backoff clear status={s} connected={}", .{ @tagName(wifi.status), wifi.connected });
                        wifi.reconnect_at = 0;
                        return;
                    }
                    if (input.timestamp < wifi.reconnect_at) return;
                    log.info("wifi reconnect backoff elapsed now={d} reconnect_at={d}", .{ input.timestamp, wifi.reconnect_at });
                    wifi.reconnect_at = 0;
                }
            }.apply);
        }
    };
}
