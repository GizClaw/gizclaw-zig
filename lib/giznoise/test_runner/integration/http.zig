const glib = @import("glib");
const testing_api = glib.testing;

const DuplexRunner = @import("http/duplex.zig");
const DownloadRunner = @import("http/download.zig");
const GetRunner = @import("http/get.zig");
const KeepAliveRunner = @import("http/keep_alive.zig");
const UnsupportedSchemeRunner = @import("http/unsupported_scheme.zig");
const UploadRunner = @import("http/upload.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;

            t.run("get", GetRunner.make(grt));
            t.run("upload", UploadRunner.make(grt));
            t.run("download", DownloadRunner.make(grt));
            t.run("duplex", DuplexRunner.make(grt));
            t.run("keep_alive", KeepAliveRunner.make(grt));
            t.run("unsupported_scheme", UnsupportedSchemeRunner.make(grt));

            _ = allocator;
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
