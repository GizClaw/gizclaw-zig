const glib = @import("glib");
const lvgl = @import("lvgl");

const ScreenMod = @import("ui/Screen.zig");

pub fn make(comptime grt: type, comptime ZuxAppType: type) type {
    const Impl = ZuxAppType.ImplType;
    const LvglRuntimeType = lvgl.embed.LvglZuxRuntime.make(grt, Impl);
    const Screen = ScreenMod.make(grt, ZuxAppType);
    const WifiStaState = @FieldType(ZuxAppType.Store.Stores, "wifi").StateType;
    const SmokeStatus = @FieldType(ZuxAppType.Store.Stores, "smoke_status").StateType;
    const Command = union(enum) {
        render: u8,
    };
    const CommandChannel = grt.sync.Channel(Command);
    const AtomicBool = grt.std.atomic.Value(bool);
    const log = grt.std.log.scoped(.smoke_ui);

    return struct {
        const Runtime = @This();

        pub const Config = struct {
            task_options: glib.task.Options = .{
                .min_stack_size = 16 * 1024,
            },
            command_capacity: usize = 8,
        };

        allocator: glib.std.mem.Allocator,
        zux_app: *ZuxAppType,
        config: Config,
        commands: CommandChannel,
        command_open: bool = true,
        render_pending: AtomicBool = AtomicBool.init(false),
        stop: AtomicBool = AtomicBool.init(false),
        task: ?grt.task.Handle = null,

        pub fn init(allocator: glib.std.mem.Allocator, zux_app: *ZuxAppType, config: Config) !Runtime {
            return .{
                .allocator = allocator,
                .zux_app = zux_app,
                .config = config,
                .commands = try CommandChannel.make(allocator, config.command_capacity),
            };
        }

        pub fn start(self: *Runtime) !void {
            if (self.task != null) return;
            self.stop.store(false, .release);
            self.task = try grt.task.go(
                "zux/speedtest/ui",
                self.config.task_options,
                glib.task.Routine.init(self, loop),
            );
            try self.requestRender();
        }

        pub fn requestRender(self: *Runtime) !void {
            if (!self.command_open) return;
            if (self.render_pending.swap(true, .acq_rel)) return;

            const result = try self.commands.sendTimeout(.{ .render = 0 }, 0);
            if (!result.ok) {
                self.render_pending.store(false, .release);
                log.warn("render request dropped: ui command queue full", .{});
                return;
            }
        }

        pub fn deinit(self: *Runtime) void {
            self.stop.store(true, .release);
            if (self.command_open) {
                self.command_open = false;
                self.commands.close();
            }
            if (self.task) |task| {
                task.join();
                self.task = null;
            }
            self.commands.deinit();
            self.* = undefined;
        }

        fn loop(self: *Runtime) void {
            self.run() catch |err| {
                log.err("smoke ui loop stopped: {s}", .{@errorName(err)});
            };
        }

        fn run(self: *Runtime) !void {
            log.info("smoke ui thread started", .{});
            var lvgl_runtime = try LvglRuntimeType.init(.{
                .allocator = self.allocator,
                .threaded = false,
                .command_capacity = self.config.command_capacity,
            });
            defer lvgl_runtime.deinit();

            lvgl_runtime.bindZuxApp(&self.zux_app.impl);
            var render_state: RenderState = .{};
            lvgl_runtime.setRenderFunc(&render_state, render);

            while (!self.stop.load(.acquire)) {
                const first = self.commands.recv() catch break;
                if (!first.ok) break;
                try self.handleCommand(&lvgl_runtime, &render_state, first.value);

                var coalesced: u32 = 0;
                while (true) {
                    const next = self.commands.recvTimeout(0) catch break;
                    if (!next.ok) return;
                    try self.handleCommand(&lvgl_runtime, &render_state, next.value);
                    coalesced += 1;
                }
                if (coalesced != 0) {
                    log.debug("smoke ui render coalesced requests={}", .{coalesced});
                }
            }
            log.info("smoke ui thread stopped", .{});
        }

        fn handleCommand(
            self: *Runtime,
            lvgl_runtime: *LvglRuntimeType,
            render_state: *RenderState,
            command: Command,
        ) !void {
            switch (command) {
                .render => {
                    defer self.render_pending.store(false, .release);
                    try self.renderOnce(lvgl_runtime, render_state);
                },
            }
        }

        fn renderOnce(self: *Runtime, lvgl_runtime: *LvglRuntimeType, render_state: *RenderState) !void {
            render_state.wifi = self.zux_app.store.stores.wifi.get();
            render_state.status = self.zux_app.store.stores.smoke_status.get();
            try lvgl_runtime.render(&self.zux_app.impl);
            render_state.wifi = null;
            render_state.status = null;
        }

        fn render(render_state: *RenderState, runtime: *LvglRuntimeType, app: *Impl) !void {
            try ensureScreen(render_state, runtime, app);
            const wifi = render_state.wifi orelse app.store().stores.wifi.get();
            const status = render_state.status orelse app.store().stores.smoke_status.get();
            render_state.screen.?.setState(wifi, status);
        }

        const RenderState = struct {
            screen: ?Screen = null,
            wifi: ?WifiStaState = null,
            status: ?SmokeStatus = null,
        };

        fn ensureScreen(render_state: *RenderState, runtime: *LvglRuntimeType, app: *Impl) !void {
            if (render_state.screen != null) return;

            const display_state = app.store().stores.display.get();
            var display = app.display(.display);
            try display.setEnabled(display_state.enabled);
            try display.setBrightness(display_state.brightness);
            try runtime.ensureDisplay(display);
            render_state.screen = try Screen.init(runtime.displayHandle());
        }
    };
}
