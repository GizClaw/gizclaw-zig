const glib = @import("glib");
const giznet = @import("giznet");
const gizclaw = @import("../../../gizclaw.zig");

pub fn make(comptime grt: type) glib.testing.TestRunner {
    return glib.testing.TestRunner.fromFn(grt.std, 1024 * 1024, struct {
        fn run(_: *glib.testing.T, _: grt.std.mem.Allocator) !void {
            const testing = grt.std.testing;
            const lib = gizclaw.make(grt, .{});
            const Context = lib.Context;

            const private_text = "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw";
            const server_text = "041061050R3GG28A1C60T3GF208H44RM2MB1E60S38DHR78Y3WG0";
            const expected_pair = try lib.key.fromPrivate(try lib.key.parse(private_text));

            const explicit = try Context.fromExplicit(.{
                .server_addr = "127.0.0.1:9820",
                .server_key = server_text,
                .client_key = private_text,
            });
            try testing.expectEqualStrings("127.0.0.1:9820", explicit.server_addr);
            try testing.expect(explicit.server_key.eql(try lib.key.parse(server_text)));
            try testing.expect(explicit.key_pair.private.eql(expected_pair.private));

            var stored = TestStore.init();
            try stored.put("client_key", private_text);
            const stored_identity = try Context.resolveIdentity(.{
                .server_addr = "127.0.0.1:9820",
                .server_key = server_text,
            }, &stored);
            try testing.expectEqual(gizclaw.Context.IdentitySource.preferences, stored_identity.source);
            try testing.expectEqual(@as(usize, 0), stored.sync_count);
            try testing.expect(stored_identity.key_pair.private.eql(expected_pair.private));

            var generated = TestStore.init();
            const generated_identity = try Context.resolveIdentity(.{
                .server_addr = "127.0.0.1:9820",
                .server_key = server_text,
            }, &generated);
            try testing.expectEqual(gizclaw.Context.IdentitySource.generated, generated_identity.source);
            try testing.expectEqual(@as(usize, 1), generated.sync_count);
            try testing.expect(generated.len != 0);

            var identity_bytes: [32]u8 = undefined;
            for (&identity_bytes, 0..) |*byte, index| byte.* = @intCast(index + 1);
            var host = try Context.fromHostData(
                grt.std.testing.allocator,
                "server:\n  address: \"192.0.2.1:9820\"\n  public-key: '041061050R3GG28A1C60T3GF208H44RM2MB1E60S38DHR78Y3WG0'\n  cipher-mode: plaintext\n",
                &identity_bytes,
                .{ .context_dir = "unused" },
            );
            defer host.deinit();
            try testing.expectEqualStrings("192.0.2.1:9820", host.config.server_addr);
            try testing.expect(host.config.server_key.eql(try lib.key.parse(server_text)));
            try testing.expectEqual(giznet.noise.Cipher.Kind.plaintext, host.config.cipher_kind);
            try testing.expect(host.config.key_pair.private.eql((try lib.key.fromPrivate(.{ .bytes = identity_bytes })).private));
        }
    }.run);
}

const TestStore = struct {
    value: [64]u8 = undefined,
    len: usize = 0,
    sync_count: usize = 0,

    fn init() TestStore {
        return .{};
    }

    pub fn get(self: *TestStore, name: []const u8, out: []u8) !usize {
        if (!glib.std.mem.eql(u8, name, "client_key")) return error.NotFound;
        if (self.len == 0) return error.NotFound;
        if (out.len < self.len) return error.BufferTooSmall;
        @memcpy(out[0..self.len], self.value[0..self.len]);
        return self.len;
    }

    pub fn put(self: *TestStore, name: []const u8, value: []const u8) !void {
        if (!glib.std.mem.eql(u8, name, "client_key")) return error.InvalidKey;
        if (value.len > self.value.len) return error.BufferTooSmall;
        @memcpy(self.value[0..value.len], value);
        self.len = value.len;
    }

    pub fn sync(self: *TestStore) !void {
        self.sync_count += 1;
    }

    pub fn deinit(self: *TestStore) void {
        _ = self;
    }
};
