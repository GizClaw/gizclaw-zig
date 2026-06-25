pub fn make(comptime ZuxAppType: type, comptime RuntimeType: type) type {
    return struct {
        const Self = @This();

        runtime: ?*RuntimeType = null,

        pub fn init() Self {
            return .{};
        }

        pub fn bindRuntime(self: *Self, runtime: *RuntimeType) void {
            self.runtime = runtime;
        }

        pub fn render(self: *Self, app: *ZuxAppType.ImplType) !void {
            _ = app;
            if (self.runtime) |runtime| {
                try runtime.ui.requestRender();
            }
        }
    };
}
