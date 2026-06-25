const app_mod = @import("reducers/app.zig");
const gizclaw_mod = @import("reducers/gizclaw.zig");
const smoke_status_mod = @import("reducers/smoke_status.zig");
const wifi_mod = @import("reducers/wifi.zig");

pub const app = app_mod;
pub const gizclaw = gizclaw_mod;
pub const smoke_status = smoke_status_mod;
pub const wifi = wifi_mod;

pub fn registerCustomEvents(assembler: anytype) void {
    assembler.registerCustomEvent(app.Event);
    assembler.registerCustomEvent(app.AutoStartEvent);
    assembler.registerCustomEvent(wifi.Event);
    assembler.registerCustomEvent(gizclaw.Event);
    assembler.registerCustomEvent(smoke_status.Event);
}

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const AppReducer = app.make(grt, ZuxAppType);
    const WifiReducer = wifi.make(grt, ZuxAppType);
    const GizclawReducer = gizclaw.make(grt, ZuxAppType);
    const SmokeStatusReducer = smoke_status.make(grt, ZuxAppType);
    const AppEvent = app.Event;
    const WifiEvent = wifi.Event;
    const GizclawEvent = gizclaw.Event;
    const SmokeStatusEvent = smoke_status.Event;
    const SmokeStatusUpdate = smoke_status.Update;
    const Allocator = grt.std.mem.Allocator;

    return struct {
        app: AppReducer,
        wifi: WifiReducer,
        gizclaw: GizclawReducer,
        smoke_status: SmokeStatusReducer,
        allocator: Allocator,
        zux_app: *ZuxAppType,

        const Self = @This();

        pub fn init(allocator: Allocator, zux_app: *ZuxAppType) Self {
            return .{
                .app = AppReducer.init(),
                .wifi = WifiReducer.init(),
                .gizclaw = GizclawReducer.init(allocator, zux_app),
                .smoke_status = SmokeStatusReducer.init(),
                .allocator = allocator,
                .zux_app = zux_app,
            };
        }

        pub fn reduce(
            self: *Self,
            stores: *ZuxAppType.Store.Stores,
            message: ZuxAppType.Message,
            emit: ZuxAppType.Emitter,
        ) !void {
            switch (message.body) {
                .custom => |custom| {
                    if (custom.as(AppEvent)) |_| {
                        try self.app.reduce(stores, message, emit);
                        return;
                    } else |_| {}
                    if (custom.as(WifiEvent)) |_| {
                        try self.wifi.reduce(stores, message, emit);
                        return;
                    } else |_| {}
                    if (custom.as(GizclawEvent)) |_| {
                        try self.gizclaw.reduce(stores, message, emit);
                        return;
                    } else |_| {}
                    if (custom.as(SmokeStatusEvent)) |_| {
                        try self.smoke_status.reduce(stores, message, emit);
                        return;
                    } else |_| {}
                    try emit.emit(message);
                },
                else => {
                    try emit.emit(message);
                },
            }
        }

        pub fn emitGizclawConnecting(self: *Self, timestamp: anytype) !void {
            try self.gizclaw.emitConnecting(timestamp);
        }

        pub fn emitGizclawConnected(self: *Self, timestamp: anytype) !void {
            try self.gizclaw.emitConnected(timestamp);
        }

        pub fn emitGizclawDisconnected(self: *Self, timestamp: anytype) !void {
            try self.gizclaw.emitDisconnected(timestamp);
        }

        pub fn emitAppOn(self: *Self, timestamp: anytype) !void {
            try self.emitAppState(.on, timestamp);
        }

        pub fn emitWifiOn(self: *Self, timestamp: anytype) !void {
            try self.emitWifiState(.on, timestamp);
        }

        pub fn emitAutoStart(self: *Self, timestamp: anytype) !void {
            const payload = try app.AutoStartEvent.init(self.allocator);
            errdefer payload.deinit();
            const custom = self.zux_app.initCustomEvent(app.AutoStartEvent, app.source_id, payload);
            _ = try self.zux_app.dispatch(.{
                .origin = .source,
                .timestamp = timestamp,
                .body = .{ .custom = custom },
            });
        }

        pub fn wifiHasIp(self: *Self) bool {
            return self.zux_app.store.stores.wifi.get().has_ip;
        }

        pub fn emitSmokeStatus(self: *Self, value: SmokeStatusUpdate, timestamp: anytype) !void {
            const payload = try SmokeStatusEvent.init(self.allocator, value);
            errdefer payload.deinit();
            const custom = self.zux_app.initCustomEvent(SmokeStatusEvent, smoke_status.source_id, payload);
            _ = try self.zux_app.dispatch(.{
                .origin = .source,
                .timestamp = timestamp,
                .body = .{ .custom = custom },
            });
        }

        fn emitAppState(self: *Self, v: AppEvent.State, timestamp: anytype) !void {
            const payload = try AppEvent.init(self.allocator, v);
            errdefer payload.deinit();
            const custom = self.zux_app.initCustomEvent(AppEvent, app.source_id, payload);
            _ = try self.zux_app.dispatch(.{
                .origin = .source,
                .timestamp = timestamp,
                .body = .{ .custom = custom },
            });
        }

        fn emitWifiState(self: *Self, v: WifiEvent.State, timestamp: anytype) !void {
            const payload = try WifiEvent.init(self.allocator, v);
            errdefer payload.deinit();
            const custom = self.zux_app.initCustomEvent(WifiEvent, wifi.source_id, payload);
            _ = try self.zux_app.dispatch(.{
                .origin = .source,
                .timestamp = timestamp,
                .body = .{ .custom = custom },
            });
        }
    };
}
