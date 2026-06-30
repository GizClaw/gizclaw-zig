const std = @import("std");
const builtin = @import("builtin");
const desktop = @import("desktop");
const gstd = @import("gstd");
const lvgl_osal = @import("lvgl_osal");
const app = @import("app");
const config = @import("desktop_launcher_config");

pub const std_options: std.Options = .{
    .logFn = desktop.log.logFn,
};

comptime {
    _ = lvgl_osal.make(gstd.runtime, std.heap.page_allocator);
}

const DesktopPlatformCtx = desktop.PlatformCtxWith(.{
    .bundle_id = config.bundle_id,
    .home_dir = config.home_dir,
    .storage_root = config.storage_root,
});

const PlatformCtx = struct {
    pub const AudioSystem = DesktopPlatformCtx.AudioSystem;
    pub const Net = DesktopPlatformCtx.Net;
    pub const fs = DesktopPlatformCtx.fs;

    pub fn preferencesProvider(allocator: gstd.runtime.std.mem.Allocator) !desktop.system.Preferences.Provider {
        return DesktopPlatformCtx.preferencesProvider(allocator);
    }

    pub fn gizclawAllocator(default_allocator: anytype) @TypeOf(default_allocator) {
        return default_allocator;
    }
};

pub fn main() void {
    redirectLogs();
    if (comptime builtin.target.os.tag == .macos and config.run_tray) {
        runMacosApp();
        return;
    }

    run() catch |err| {
        std.log.err("desktop app '{s}' failed: {s}", .{ config.app_name, @errorName(err) });
        std.process.exit(1);
    };
}

extern fn desktop_launcher_run_tray(port: c_uint) void;

fn runMacosApp() void {
    const server_thread = std.Thread.spawn(.{}, serverThreadMain, .{}) catch |err| {
        std.log.err("desktop app '{s}' failed to start server thread: {s}", .{ config.app_name, @errorName(err) });
        std.process.exit(1);
    };
    server_thread.detach();

    desktop_launcher_run_tray(config.port);
    std.process.exit(0);
}

fn serverThreadMain() void {
    run() catch |err| {
        std.log.err("desktop app '{s}' server failed: {s}", .{ config.app_name, @errorName(err) });
        std.process.exit(1);
    };
}

pub export fn desktop_launcher_quit() callconv(.c) void {
    std.process.exit(0);
}

fn run() !void {
    try mountStorage();

    const Launcher = app.make(PlatformCtx, gstd.runtime);
    const DesktopApp = desktop.App.make(Launcher);

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();

    const address = desktop.http.AddrPort.from4(.{ 127, 0, 0, 1 }, config.port);
    var listener = try gstd.runtime.net.listen(gpa.allocator(), .{ .address = address });
    defer listener.deinit();

    var desktop_app = try DesktopApp.init(gpa.allocator(), .{
        .address = address,
    });
    defer desktop_app.deinit();

    std.log.info("desktop app '{s}' listening on http://127.0.0.1:{d}", .{
        config.app_name,
        config.port,
    });
    try desktop_app.serve(listener);
}

fn mountStorage() !void {
    try DesktopPlatformCtx.fs.mountStorage();
}

fn redirectLogs() void {
    if (comptime builtin.target.os.tag != .macos) return;

    const out = std.fs.createFileAbsolute("/private/tmp/gizclaw-desktop-launcher.out", .{
        .truncate = true,
    }) catch return;
    defer out.close();
    const err = std.fs.createFileAbsolute("/private/tmp/gizclaw-desktop-launcher.err", .{
        .truncate = true,
    }) catch return;
    defer err.close();

    out.seekFromEnd(0) catch {};
    err.seekFromEnd(0) catch {};
    _ = std.c.dup2(out.handle, std.c.STDOUT_FILENO);
    _ = std.c.dup2(err.handle, std.c.STDERR_FILENO);
}
