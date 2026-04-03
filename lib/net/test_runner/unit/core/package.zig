const dep = @import("dep");
const noise_pkg = @import("../../../noise.zig");
const testing_api = @import("dep").testing;
const core = @import("../../../core.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runImpl(lib, allocator) catch |err| {
                t.logErrorf("core/package failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runImpl(comptime lib: type, allocator: dep.embed.mem.Allocator) !void {
    const Core = core.make(lib);
    const kp = try noise_pkg.make(lib).KeyPair.fromPrivate(
        noise_pkg.Key.fromBytes([_]u8{11} ** noise_pkg.Key.key_size),
    );
    var manager = try Core.SessionManager.init(allocator);
    defer manager.deinit();
    var conn = Core.Conn.initResponder(kp, 1);
    _ = &conn;

    try lib.testing.expect(core.isFoundationProtocol(core.protocol.event));
    try lib.testing.expect(core.isStreamProtocol(core.protocol.http));
    try lib.testing.expect(core.isDirectProtocol(core.protocol.opus));
}
