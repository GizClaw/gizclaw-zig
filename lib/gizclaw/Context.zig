const glib = @import("glib");
const giznet = @import("giznet");

const Client = @import("Client.zig");
const key_mod = @import("key.zig");
const models = @import("models.zig");

pub const IdentitySource = enum {
    build_config,
    preferences,
    generated,
};

pub fn make(comptime grt: type) type {
    const key = key_mod.make(grt);

    return struct {
        pub const Config = struct {
            server_addr: []const u8,
            server_key: giznet.Key,
            key_pair: giznet.KeyPair,
            device_info: models.DeviceInfo = .{},
            runtime_options: Client.RuntimeOptions = .{},
            connect_timeout: ?glib.time.duration.Duration = null,
        };

        pub const ExplicitOptions = struct {
            server_addr: []const u8,
            server_key: []const u8,
            client_key: []const u8,
            device_info: models.DeviceInfo = .{},
            runtime_options: Client.RuntimeOptions = .{},
            connect_timeout: ?glib.time.duration.Duration = null,
        };

        pub const PreferencesOptions = struct {
            server_addr: []const u8,
            server_key: []const u8,
            client_key: []const u8 = "",
            namespace: []const u8 = "gizclaw",
            client_key_name: []const u8 = "client_key",
            device_info: models.DeviceInfo = .{},
            runtime_options: Client.RuntimeOptions = .{},
            connect_timeout: ?glib.time.duration.Duration = null,
        };

        pub const IdentityResult = struct {
            key_pair: giznet.KeyPair,
            source: IdentitySource,
        };

        pub fn fromExplicit(options: ExplicitOptions) !Config {
            return .{
                .server_addr = options.server_addr,
                .server_key = try key.parse(options.server_key),
                .key_pair = try key.fromPrivate(try key.parse(options.client_key)),
                .device_info = options.device_info,
                .runtime_options = options.runtime_options,
                .connect_timeout = options.connect_timeout,
            };
        }

        pub fn fromPreferences(options: PreferencesOptions, provider: anytype) !Config {
            var store = try provider.open(options.namespace, .{ .create = true });
            defer store.deinit();

            const identity = try resolveIdentity(options, store);
            return .{
                .server_addr = options.server_addr,
                .server_key = try key.parse(options.server_key),
                .key_pair = identity.key_pair,
                .device_info = options.device_info,
                .runtime_options = options.runtime_options,
                .connect_timeout = options.connect_timeout,
            };
        }

        pub fn resolveIdentity(options: PreferencesOptions, store: anytype) !IdentityResult {
            if (options.client_key.len != 0) {
                return .{
                    .key_pair = try key.fromPrivate(try key.parse(options.client_key)),
                    .source = .build_config,
                };
            }

            var key_buf: [64]u8 = undefined;
            const stored_len = store.get(options.client_key_name, &key_buf) catch |err| switch (err) {
                error.NotFound => return try generateAndStoreIdentity(options, store),
                else => return err,
            };
            const stored = key_buf[0..stored_len];
            if (stored.len != 0) {
                const private = key.parse(stored) catch {
                    return try generateAndStoreIdentity(options, store);
                };
                return .{
                    .key_pair = try key.fromPrivate(private),
                    .source = .preferences,
                };
            }

            return try generateAndStoreIdentity(options, store);
        }

        fn generateAndStoreIdentity(options: PreferencesOptions, store: anytype) !IdentityResult {
            const key_pair = key.randomKeyPair();
            var private_buf: [52]u8 = undefined;
            const private_text = key.format(key_pair.private, &private_buf);
            try store.put(options.client_key_name, private_text);
            try store.sync();
            return .{
                .key_pair = key_pair,
                .source = .generated,
            };
        }
    };
}
