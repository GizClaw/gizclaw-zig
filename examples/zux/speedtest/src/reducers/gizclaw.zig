const glib = @import("glib");

pub const source_id: u32 = 3;

pub const Event = struct {
    pub const event_name = "gizclaw.set_state";

    pub const State = enum {
        disconnected,
        connecting,
        connected,
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
        if (glib.std.mem.eql(u8, v, "disconnected")) return .disconnected;
        if (glib.std.mem.eql(u8, v, "connecting")) return .connecting;
        if (glib.std.mem.eql(u8, v, "connected")) return .connected;
        return error.InvalidGizclawState;
    }
};

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const Stores = ZuxAppType.Store.Stores;
    const Message = ZuxAppType.Message;
    const Emitter = ZuxAppType.Emitter;
    const GizclawState = @FieldType(Stores, "gizclaw_state").StateType;
    const GizclawStateValue = @FieldType(GizclawState, "state");

    return struct {
        const log = grt.std.log.scoped(.gizclaw);

        allocator: glib.std.mem.Allocator,
        zux_app: *ZuxAppType,

        const Self = @This();

        pub fn init(allocator: glib.std.mem.Allocator, zux_app: *ZuxAppType) Self {
            return .{
                .allocator = allocator,
                .zux_app = zux_app,
            };
        }

        pub fn reduce(
            self: *Self,
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
                        log.info("gizclaw state set state={s}", .{@tagName(v)});
                        return;
                    } else |_| {}

                    try out.emit(message);
                },
                else => {
                    try out.emit(message);
                },
            }
        }

        pub fn emitConnecting(self: *Self, timestamp: anytype) !void {
            try self.emitState(.connecting, timestamp);
        }

        pub fn emitConnected(self: *Self, timestamp: anytype) !void {
            try self.emitState(.connected, timestamp);
        }

        pub fn emitDisconnected(self: *Self, timestamp: anytype) !void {
            try self.emitState(.disconnected, timestamp);
        }

        fn emitState(self: *Self, v: Event.State, timestamp: anytype) !void {
            const payload = try Event.init(self.allocator, v);
            errdefer payload.deinit();
            const custom = self.zux_app.initCustomEvent(Event, source_id, payload);
            _ = try self.zux_app.dispatch(.{
                .origin = .source,
                .timestamp = timestamp,
                .body = .{ .custom = custom },
            });
        }

        fn stateValue(v: Event.State) GizclawStateValue {
            return switch (v) {
                .disconnected => .disconnected,
                .connecting => .connecting,
                .connected => .connected,
            };
        }

        fn setState(stores: *Stores, state: GizclawStateValue) void {
            const Input = struct {
                state: GizclawStateValue,
            };
            stores.gizclaw_state.invoke(Input{ .state = state }, struct {
                fn apply(gizclaw: *GizclawState, input: Input) void {
                    gizclaw.state = input.state;
                }
            }.apply);
        }
    };
}
