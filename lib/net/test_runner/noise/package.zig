const embed = @import("embed");
const testing_api = @import("testing");
const noise = @import("../../noise.zig");
const support = @import("support.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;
            runImpl(lib) catch |err| {
                t.logErrorf("noise/package failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runImpl(comptime lib: type) !void {
    const testing = lib.testing;
    const Package = noise.Package(support.TestCrypto(lib));
    const KP = Package.KeyPair;
    const Handshake = Package.Handshake;

    const alice_static = try KP.fromPrivate(noise.Key.fromBytes([_]u8{3} ** noise.Key.key_size));
    const bob_static = try KP.fromPrivate(noise.Key.fromBytes([_]u8{4} ** noise.Key.key_size));

    var initiator = try Handshake.init(.{
        .initiator = true,
        .local_static = alice_static,
        .remote_static = bob_static.public,
    });
    var responder = try Handshake.init(.{
        .initiator = false,
        .local_static = bob_static,
    });

    var msg1: [96]u8 = undefined;
    var msg2: [96]u8 = undefined;
    var payload: [16]u8 = undefined;

    const msg1_len = try initiator.writeMessage("", &msg1);
    _ = try responder.readMessage(msg1[0..msg1_len], &payload);
    const msg2_len = try responder.writeMessage("", &msg2);
    _ = try initiator.readMessage(msg2[0..msg2_len], &payload);

    var split_i = try initiator.split();
    var split_r = try responder.split();

    var ciphertext: [4 + noise.TagSize]u8 = undefined;
    _ = split_i.send.encrypt("pong", "", &ciphertext);

    var plaintext: [4]u8 = undefined;
    const read = try split_r.recv.decrypt(&ciphertext, "", &plaintext);
    try testing.expectEqualSlices(u8, "pong", plaintext[0..read]);
}
