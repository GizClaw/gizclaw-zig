const esp = @import("esp");
const launcher_options = @import("launcher_options");
const selected_app = @import("selected_app");

const sleep_interval: esp.grt.time.duration.Duration = 1 * esp.grt.time.duration.Second;

const PlatformCtx = struct {
    pub const enable_gizclaw_loop = true;
    pub const wifi_core_id = 0;
    pub const gizclaw_core_id = 1;
    pub const gizclaw_loop_stack_size = 24 * 1024;
    pub const giznet_drive_stack_size = 64 * 1024;
    pub const giznet_read_stack_size = 24 * 1024;
    pub const giznet_timer_stack_size = 16 * 1024;
    pub const gizclaw_rpc_stack_size = 24 * 1024;
    pub const gizclaw_loop_core_id = gizclaw_core_id;
    pub const giznet_drive_core_id = gizclaw_core_id;
    pub const giznet_read_core_id = gizclaw_core_id;
    pub const giznet_timer_core_id = gizclaw_core_id;
    pub const gizclaw_rpc_core_id = gizclaw_core_id;
    pub const gizclaw_loop_priority = 5;
    pub const giznet_drive_priority = 9;
    pub const giznet_read_priority = 8;
    pub const giznet_timer_priority = 8;
    pub const gizclaw_rpc_priority = 5;

    pub fn gizclawAllocator(_: anytype) esp.grt.std.mem.Allocator {
        return esp.heap.Allocator(.{ .caps = .spiram_8bit, .alignment = .align_u32 });
    }

    pub fn gizclawInternalAllocator(_: anytype) esp.grt.std.mem.Allocator {
        return esp.heap.Allocator(.{ .caps = .internal_8bit, .alignment = .align_u32 });
    }

    pub fn gizclawSpiramAllocator(_: anytype) esp.grt.std.mem.Allocator {
        return esp.heap.Allocator(.{ .caps = .spiram_8bit, .alignment = .align_u32 });
    }
};

const Board = @field(esp.embed.boards, launcher_options.board_name).Board;
const ZuxAppType = selected_app.make(PlatformCtx, esp.grt);
const App = esp.Launcher.make(ZuxAppType, Board);
const app_allocator = esp.heap.Allocator(.{ .caps = .spiram_8bit, .alignment = .align_u32 });

pub export fn zig_esp_main() void {
    run() catch @panic("esp launcher failed");
}

fn run() !void {
    var launcher = try App.init(app_allocator, .{
        .pipeline_task_options = .{
            .min_stack_size = 64 * 1024,
        },
        .poller_task_options = .{
            .min_stack_size = 16 * 1024,
        },
    });
    defer launcher.deinit();

    try launcher.start();
    defer launcher.stop() catch {};

    while (true) {
        esp.grt.time.sleep(sleep_interval);
    }
}
