const embed = @import("embed");
const testing_api = @import("testing");

const key_runner = @import("noise/key.zig");
const key_pair_runner = @import("noise/key_pair.zig");
const replay_filter_runner = @import("noise/replay_filter.zig");
const transport_runner = @import("noise/transport.zig");
const blake2s_runner = @import("noise/blake2s.zig");
const cipher_runner = @import("noise/cipher.zig");
const cipher_state_runner = @import("noise/cipher_state.zig");
const symmetric_state_runner = @import("noise/symmetric_state.zig");
const session_runner = @import("noise/session.zig");
const handshake_runner = @import("noise/handshake.zig");
const varint_runner = @import("noise/varint.zig");
const address_runner = @import("noise/address.zig");
const message_runner = @import("noise/message.zig");
const package_runner = @import("noise/package.zig");

pub fn runner(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: embed.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.parallel();
            t.run("key", key_runner.make(lib));
            t.run("key_pair", key_pair_runner.make(lib));
            t.run("replay_filter", replay_filter_runner.make(lib));
            t.run("transport", transport_runner.make(lib));
            t.run("blake2s", blake2s_runner.make(lib));
            t.run("cipher", cipher_runner.make(lib));
            t.run("cipher_state", cipher_state_runner.make(lib));
            t.run("symmetric_state", symmetric_state_runner.make(lib));
            t.run("session", session_runner.make(lib));
            t.run("handshake", handshake_runner.make(lib));
            t.run("varint", varint_runner.make(lib));
            t.run("address", address_runner.make(lib));
            t.run("message", message_runner.make(lib));
            t.run("package", package_runner.make(lib));
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
