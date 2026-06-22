const app_mod = @import("reducers/app.zig");
const gizclaw_mod = @import("reducers/gizclaw.zig");
const wifi_mod = @import("reducers/wifi.zig");

pub const app = app_mod;
pub const gizclaw = gizclaw_mod;
pub const wifi = wifi_mod;

pub fn registerCustomEvents(assembler: anytype) void {
    assembler.registerCustomEvent(app.Event);
    assembler.registerCustomEvent(wifi.Event);
    assembler.registerCustomEvent(gizclaw.Event);
}

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const AppReducer = app.make(grt, ZuxAppType);
    const WifiReducer = wifi.make(grt, ZuxAppType);
    const GizclawReducer = gizclaw.make(grt, ZuxAppType);
    const AppEvent = app.Event;
    const WifiEvent = wifi.Event;
    const GizclawEvent = gizclaw.Event;

    return struct {
        app: AppReducer,
        wifi: WifiReducer,
        gizclaw: GizclawReducer,

        const Self = @This();

        pub fn init(allocator: anytype, zux_app: *ZuxAppType) Self {
            return .{
                .app = AppReducer.init(),
                .wifi = WifiReducer.init(),
                .gizclaw = GizclawReducer.init(allocator, zux_app),
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
    };
}
