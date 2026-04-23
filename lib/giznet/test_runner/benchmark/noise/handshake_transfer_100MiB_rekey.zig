const embed = @import("embed");
const std = embed.std;
const testing_api = embed.testing;

const bench = @import("../testutils.zig");
const Cipher = @import("../../../noise/Cipher.zig");
const noise_testutils = @import("../../testutils/noise.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Cases = struct {
        fn chacha(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            try runCase(.chacha_poly);
        }

        fn aes(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            try runCase(.aes_256_gcm);
        }

        fn plaintext(_: *testing_api.T, allocator: std.mem.Allocator) !void {
            _ = allocator;
            try runCase(.plaintext);
        }

        fn runCase(comptime cipher_kind: Cipher.Kind) !void {
            const report = try noise_testutils.runSinglePeerTransfer(
                lib,
                cipher_kind,
                100 * 1024 * 1024,
                4096,
            );

            const label = switch (cipher_kind) {
                .chacha_poly => "giznet.noise.engine.handshake_transfer_rekey.chacha_poly",
                .aes_256_gcm => "giznet.noise.engine.handshake_transfer_rekey.aes_256_gcm",
                .plaintext => "giznet.noise.engine.handshake_transfer_rekey.plaintext",
            };

            bench.print(lib, label, .{
                .warmup = 0,
                .iterations = 1,
            }, report.elapsed_ns, .{
                .tier = .regular,
                .payload_bytes_per_op = report.bytes,
                .copy_bytes_per_op = report.bytes,
                .extra_name = "rekeys",
                .extra_value = report.rekey_count,
            });
            std.debug.print(
                "bench label=giznet.noise.engine.handshake_transfer_rekey cipher={s} established_events={d} received_packets={d} received_bytes={d} payload_B/s={d} payload_Mbps={d}\n",
                .{
                    @tagName(cipher_kind),
                    report.established_events,
                    report.received_packets,
                    report.received_bytes,
                    report.bytes_per_second,
                    report.mbps,
                },
            );
        }
    };

    const Runner = struct {
        pub fn init(self: *@This(), allocator: std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("chacha_poly", testing_api.TestRunner.fromFn(lib, 512 * 1024, Cases.chacha));
            t.run("aes_256_gcm", testing_api.TestRunner.fromFn(lib, 512 * 1024, Cases.aes));
            t.run("plaintext", testing_api.TestRunner.fromFn(lib, 512 * 1024, Cases.plaintext));
            return true;
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
