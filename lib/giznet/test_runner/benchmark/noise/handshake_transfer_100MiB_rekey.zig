const glib = @import("glib");
const testing_api = glib.testing;

const bench = @import("../test_utils/common.zig");
const Cipher = @import("../../../noise/Cipher.zig");
const noise_test_utils = @import("../../test_utils/noise.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Cases = struct {
        fn chacha(_: *testing_api.T, allocator: grt.std.mem.Allocator) !void {
            _ = allocator;
            try runCase(.chacha_poly);
        }

        fn aes(_: *testing_api.T, allocator: grt.std.mem.Allocator) !void {
            _ = allocator;
            try runCase(.aes_256_gcm);
        }

        fn plaintext(_: *testing_api.T, allocator: grt.std.mem.Allocator) !void {
            _ = allocator;
            try runCase(.plaintext);
        }

        fn runCase(comptime cipher_kind: Cipher.Kind) !void {
            const report = try noise_test_utils.runSinglePeerTransfer(
                grt,
                cipher_kind,
                100 * 1024 * 1024,
                4096,
            );

            const label = switch (cipher_kind) {
                .chacha_poly => "giznet.noise.engine.handshake_transfer_rekey.chacha_poly",
                .aes_256_gcm => "giznet.noise.engine.handshake_transfer_rekey.aes_256_gcm",
                .plaintext => "giznet.noise.engine.handshake_transfer_rekey.plaintext",
            };

            bench.print(grt, label, .{
                .warmup = 0,
                .iterations = 1,
            }, report.elapsed_ns, .{
                .tier = .regular,
                .payload_bytes_per_op = report.bytes,
                .copy_bytes_per_op = report.bytes,
                .extra_name = "rekeys",
                .extra_value = report.rekey_count,
            });
            grt.std.debug.print(
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
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("chacha_poly", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.chacha));
            t.run("aes_256_gcm", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.aes));
            t.run("plaintext", testing_api.TestRunner.fromFn(grt.std, 512 * 1024, Cases.plaintext));
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
