const glib = @import("glib");
const giznet = @import("giznet");
const giznoise = @import("giznoise");
const std = @import("std");

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
            cipher_kind: giznoise.noise.Cipher.Kind = giznoise.default_cipher_kind,
            device_info: models.DeviceInfo = .{},
            runtime_options: Client.RuntimeOptions = .{},
            connect_timeout: ?glib.time.duration.Duration = null,
        };

        pub const OwnedConfig = struct {
            allocator: grt.std.mem.Allocator,
            server_addr: []u8,
            config: Config,

            pub fn deinit(self: *OwnedConfig) void {
                self.allocator.free(self.server_addr);
                self.* = undefined;
            }
        };

        pub const ExplicitOptions = struct {
            server_addr: []const u8,
            server_key: []const u8,
            client_key: []const u8,
            cipher_kind: giznoise.noise.Cipher.Kind = giznoise.default_cipher_kind,
            device_info: models.DeviceInfo = .{},
            runtime_options: Client.RuntimeOptions = .{},
            connect_timeout: ?glib.time.duration.Duration = null,
        };

        pub const PreferencesOptions = struct {
            server_addr: []const u8,
            server_key: []const u8,
            client_key: []const u8 = "",
            cipher_kind: giznoise.noise.Cipher.Kind = giznoise.default_cipher_kind,
            namespace: []const u8 = "gizclaw",
            client_key_name: []const u8 = "client_key",
            device_info: models.DeviceInfo = .{},
            runtime_options: Client.RuntimeOptions = .{},
            connect_timeout: ?glib.time.duration.Duration = null,
        };

        pub const HostOptions = struct {
            context_dir: []const u8,
            server_addr: ?[]const u8 = null,
            server_key: ?[]const u8 = null,
            client_key: ?[]const u8 = null,
            cipher_kind: ?giznoise.noise.Cipher.Kind = null,
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
                .cipher_kind = options.cipher_kind,
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
                .cipher_kind = options.cipher_kind,
                .device_info = options.device_info,
                .runtime_options = options.runtime_options,
                .connect_timeout = options.connect_timeout,
            };
        }

        pub fn fromHostDir(allocator: grt.std.mem.Allocator, options: HostOptions) !OwnedConfig {
            const config_path = try std.fs.path.join(allocator, &.{ options.context_dir, "config.yaml" });
            defer allocator.free(config_path);
            const config_data = try std.fs.cwd().readFileAlloc(allocator, config_path, 64 * 1024);
            defer allocator.free(config_data);

            var identity_data_alloc: ?[]u8 = null;
            defer if (identity_data_alloc) |identity_data| allocator.free(identity_data);
            const identity_data = if (options.client_key != null)
                ""
            else blk: {
                const identity_path = try std.fs.path.join(allocator, &.{ options.context_dir, "identity.key" });
                defer allocator.free(identity_path);
                identity_data_alloc = try std.fs.cwd().readFileAlloc(allocator, identity_path, 64);
                break :blk identity_data_alloc.?;
            };

            return try fromHostData(allocator, config_data, identity_data, options);
        }

        pub fn fromHostData(
            allocator: grt.std.mem.Allocator,
            config_data: []const u8,
            identity_data: []const u8,
            options: HostOptions,
        ) !OwnedConfig {
            var parsed = try parseHostConfig(allocator, config_data);
            errdefer parsed.deinit(allocator);

            if (options.server_addr) |override| {
                if (parsed.server_addr) |server_addr| allocator.free(server_addr);
                parsed.server_addr = try allocator.dupe(u8, override);
            }
            if (options.server_key) |override| {
                parsed.server_key = try key.parse(override);
            }
            if (options.cipher_kind) |override| {
                parsed.cipher_kind = override;
            }

            const server_addr = parsed.server_addr orelse return error.MissingServerAddress;
            parsed.server_addr = null;
            errdefer allocator.free(server_addr);

            const private = if (options.client_key) |override|
                try key.parse(override)
            else
                try parseIdentityData(identity_data);

            return .{
                .allocator = allocator,
                .server_addr = server_addr,
                .config = .{
                    .server_addr = server_addr,
                    .server_key = parsed.server_key orelse return error.MissingServerPublicKey,
                    .key_pair = try key.fromPrivate(private),
                    .cipher_kind = parsed.cipher_kind,
                    .device_info = options.device_info,
                    .runtime_options = options.runtime_options,
                    .connect_timeout = options.connect_timeout,
                },
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

        const ParsedHostConfig = struct {
            server_addr: ?[]u8 = null,
            server_key: ?giznet.Key = null,
            cipher_kind: giznoise.noise.Cipher.Kind = giznoise.default_cipher_kind,

            fn deinit(self: *ParsedHostConfig, allocator: grt.std.mem.Allocator) void {
                if (self.server_addr) |server_addr| allocator.free(server_addr);
                self.* = undefined;
            }
        };

        fn parseHostConfig(allocator: grt.std.mem.Allocator, data: []const u8) !ParsedHostConfig {
            var parsed = ParsedHostConfig{};
            errdefer parsed.deinit(allocator);

            var lines = grt.std.mem.splitScalar(u8, data, '\n');
            while (lines.next()) |line| {
                const trimmed = grt.std.mem.trim(u8, line, " \t\r");
                if (grt.std.mem.startsWith(u8, trimmed, "address:")) {
                    if (parsed.server_addr) |server_addr| allocator.free(server_addr);
                    parsed.server_addr = try allocator.dupe(u8, yamlScalar(trimmed["address:".len..]));
                } else if (grt.std.mem.startsWith(u8, trimmed, "public-key:")) {
                    parsed.server_key = try key.parse(yamlScalar(trimmed["public-key:".len..]));
                } else if (grt.std.mem.startsWith(u8, trimmed, "cipher-mode:")) {
                    parsed.cipher_kind = try parseCipherKind(yamlScalar(trimmed["cipher-mode:".len..]));
                }
            }

            return parsed;
        }

        fn yamlScalar(raw: []const u8) []const u8 {
            return grt.std.mem.trim(u8, raw, " \t\"'");
        }

        fn parseCipherKind(raw: []const u8) !giznoise.noise.Cipher.Kind {
            if (grt.std.mem.eql(u8, raw, "chacha_poly")) return .chacha_poly;
            if (grt.std.mem.eql(u8, raw, "aes_256_gcm")) return .aes_256_gcm;
            if (grt.std.mem.eql(u8, raw, "plaintext")) return .plaintext;
            return error.InvalidCipherMode;
        }

        fn parseIdentityData(data: []const u8) !giznet.Key {
            if (data.len != 32) return error.InvalidIdentityKey;
            var private: giznet.Key = .{};
            @memcpy(&private.bytes, data);
            return private;
        }
    };
}
