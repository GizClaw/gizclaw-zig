const glib = @import("glib");

pub const source_id: u32 = 5;

pub const Event = struct {
    pub const event_name = "app.set_state";

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
        return error.InvalidAppState;
    }
};

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const Stores = ZuxAppType.Store.Stores;
    const Message = ZuxAppType.Message;
    const Emitter = ZuxAppType.Emitter;
    const AppState = @FieldType(Stores, "app_state").StateType;
    const AppStateValue = @FieldType(AppState, "state");

    return struct {
        const log = grt.std.log.scoped(.app_state);

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
                        log.info("app state set state={s}", .{@tagName(v)});
                        return;
                    } else |_| {}

                    try out.emit(message);
                },
                else => {
                    try out.emit(message);
                },
            }
        }

        fn stateValue(v: Event.State) AppStateValue {
            return switch (v) {
                .off => .off,
                .on => .on,
            };
        }

        fn setState(stores: *Stores, v: AppStateValue) void {
            const Input = struct {
                v: AppStateValue,
            };
            stores.app_state.invoke(Input{ .v = v }, struct {
                fn apply(app: *AppState, input: Input) void {
                    app.state = input.v;
                }
            }.apply);
        }
    };
}
