const gizclaw_mod = @import("runtime/gizclaw.zig");
const reducers_mod = @import("reducers.zig");

pub fn make(
    comptime platform_ctx: type,
    comptime grt: type,
    comptime ZuxAppType: type,
) type {
    const Reducers = reducers_mod.make(grt, ZuxAppType);
    const Gizclaw = gizclaw_mod.make(.{
        .platform_ctx = platform_ctx,
        .grt = grt,
        .Reducers = Reducers,
    });

    return struct {
        gizclaw: Gizclaw,

        const Self = @This();

        pub const InitConfig = struct {
            allocator: grt.std.mem.Allocator,
            zux_app: *ZuxAppType,
            reducers: *Reducers,
        };

        pub fn init(config: InitConfig) Self {
            return .{
                .gizclaw = Gizclaw.init(config.allocator, config.reducers, gizclawConfig()),
            };
        }

        pub fn start(self: *Self) !void {
            try self.gizclaw.start();
        }

        pub fn deinit(self: *Self) void {
            self.gizclaw.deinit();
            self.* = undefined;
        }

        fn gizclawConfig() Gizclaw.Config {
            return .{
                .loop_task_options = taskOptions(Gizclaw.Config, "loop_task_options", "gizclaw_loop_stack_size"),
                .drive_task_options = taskOptions(Gizclaw.Config, "drive_task_options", "giznet_drive_stack_size"),
                .read_task_options = taskOptions(Gizclaw.Config, "read_task_options", "giznet_read_stack_size"),
                .timer_task_options = taskOptions(Gizclaw.Config, "timer_task_options", "giznet_timer_stack_size"),
                .rpc_task_options = taskOptions(Gizclaw.Config, "rpc_task_options", "gizclaw_rpc_stack_size"),
            };
        }

        fn taskOptions(
            comptime Config: type,
            comptime field_name: []const u8,
            comptime stack_size_decl: []const u8,
        ) @FieldType(Config, field_name) {
            var config = @field(Config{}, field_name);
            if (comptime @hasDecl(platform_ctx, stack_size_decl)) {
                config.min_stack_size = @field(platform_ctx, stack_size_decl);
            }
            return config;
        }
    };
}
