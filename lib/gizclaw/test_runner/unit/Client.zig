const glib = @import("glib");
const gizclaw = @import("../../../gizclaw.zig");

pub fn make(comptime grt: type) glib.testing.TestRunner {
    return glib.testing.TestRunner.fromFn(grt.std, 1024 * 1024, struct {
        fn run(_: *glib.testing.T, allocator: grt.std.mem.Allocator) !void {
            const testing = grt.std.testing;
            const lib = gizclaw.make(grt, .{});

            var name_buf = [_]u8{ 'z', 'i', 'g' };
            var client = try lib.Client.init(allocator, .{
                .key_pair = .{},
                .device_info = .{ .name = name_buf[0..] },
            });
            defer client.deinit();
            name_buf[0] = 'b';
            try testing.expectEqualStrings("zig", client.local_device_info.name.?);

            const simple = try lib.models.toJson(allocator, lib.models.DeviceInfo{ .name = "zig-dev" });
            defer allocator.free(simple);
            try testing.expectEqualStrings("{\"name\":\"zig-dev\"}", simple);

            const name = "main";
            const imeis = [_]lib.models.GearIMEI{.{
                .name = name,
                .serial = "0000001",
                .tac = "12345678",
            }};
            const labels = [_]lib.models.GearLabel{.{
                .key = "zone",
                .value = "dev",
            }};
            const nested = try lib.models.toJson(allocator, lib.models.DeviceInfo{
                .name = "gear",
                .hardware = .{
                    .manufacturer = "giz",
                    .imeis = &imeis,
                    .labels = &labels,
                },
            });
            defer allocator.free(nested);
            try testing.expectEqualStrings(
                "{\"name\":\"gear\",\"hardware\":{\"manufacturer\":\"giz\",\"imeis\":[{\"name\":\"main\",\"tac\":\"12345678\",\"serial\":\"0000001\"}],\"labels\":[{\"key\":\"zone\",\"value\":\"dev\"}]}}",
                nested,
            );

            var parsed = try lib.models.fromJson(
                lib.models.DeviceInfo,
                allocator,
                "{\"name\":\"parsed\",\"sn\":\"sn-1\",\"ignored\":true}",
            );
            defer parsed.deinit();
            try testing.expectEqualStrings("parsed", parsed.value.name.?);
            try testing.expectEqualStrings("sn-1", parsed.value.sn.?);
        }
    }.run);
}
