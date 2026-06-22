const std = @import("std");
const desktop = @import("desktop");
const gstd = @import("gstd");
const app = @import("app");
const config = @import("desktop_launcher_config");

pub fn main() void {
    run() catch |err| {
        std.log.err("desktop app '{s}' failed: {s}", .{ config.app_name, @errorName(err) });
        std.process.exit(1);
    };
}

fn run() !void {
    const Launcher = app.make(app.DesktopPlatformCtx, gstd.runtime);
    const DesktopApp = desktop.App.make(Launcher);

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();

    const address = desktop.http.AddrPort.from4(.{ 127, 0, 0, 1 }, config.port);
    var desktop_app = try DesktopApp.init(gpa.allocator(), .{
        .address = address,
    });
    defer desktop_app.deinit();

    std.log.info("desktop app '{s}' listening on http://127.0.0.1:{d}", .{
        config.app_name,
        config.port,
    });
    try desktop_app.listenAndServe();
}
