const dep = @import("dep");
const testing_api = @import("dep").testing;
const noise = @import("../../../noise.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;
            runCases(lib, lib.testing) catch |err| {
                t.logErrorf("noise/KeyPair failed: {}", .{err});
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

fn runCases(comptime lib: type, testing: anytype) !void {
    const T = noise.KeyPair.make(lib);
    const Key = noise.Key;

    const private_a = Key.fromBytes([_]u8{42} ** Key.key_size);
    const private_b = Key.fromBytes([_]u8{99} ** Key.key_size);

    const alice = try T.fromPrivate(private_a);
    const alice_again = try T.fromPrivate(private_a);
    const bob = try T.fromPrivate(private_b);

    try testing.expect(!alice.private.isZero());
    try testing.expect(!alice.public.isZero());
    try testing.expect(alice.public.eql(alice_again.public));

    const shared_ab = try alice.dh(bob.public);
    const shared_ba = try bob.dh(alice.public);
    try testing.expect(shared_ab.eql(shared_ba));
    try testing.expect(!shared_ab.isZero());
}
