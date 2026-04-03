const dep = @import("dep");
const testing_api = @import("dep").testing;

const KeyRunner = @import("noise/Key.zig");
const KeyPairRunner = @import("noise/KeyPair.zig");
const ReplayFilterRunner = @import("noise/ReplayFilter.zig");
const Blake2sRunner = @import("noise/Blake2s.zig");
const cipher_runner = @import("noise/cipher.zig");
const CipherStateRunner = @import("noise/CipherState.zig");
const SymmetricStateRunner = @import("noise/SymmetricState.zig");
const SessionRunner = @import("noise/Session.zig");
const HandshakeRunner = @import("noise/Handshake.zig");
const varint_runner = @import("noise/varint.zig");
const message_runner = @import("noise/message.zig");
const package_runner = @import("noise/package.zig");

pub fn runner(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.parallel();
            t.run("key", KeyRunner.make(lib));
            t.run("key_pair", KeyPairRunner.make(lib));
            t.run("replay_filter", ReplayFilterRunner.make(lib));
            t.run("blake2s", Blake2sRunner.make(lib));
            t.run("cipher", cipher_runner.make(lib));
            t.run("cipher_state", CipherStateRunner.make(lib));
            t.run("symmetric_state", SymmetricStateRunner.make(lib));
            t.run("session", SessionRunner.make(lib));
            t.run("handshake", HandshakeRunner.make(lib));
            t.run("varint", varint_runner.make(lib));
            t.run("message", message_runner.make(lib));
            t.run("package", package_runner.make(lib));
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
