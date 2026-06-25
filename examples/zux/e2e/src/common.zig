const giznet = @import("giznet");
const gizclaw = @import("gizclaw");
const runtime_mod = @import("e2e_runtime");
const build_config = @import("e2e_build_config");

pub const grt = runtime_mod.runtime;
pub const key = gizclaw.make(grt, .{}).key;
pub const chacha_sdk = gizclaw.make(grt, .{ .cipher_kind = .chacha_poly });
pub const aes_256_gcm_sdk = gizclaw.make(grt, .{ .cipher_kind = .aes_256_gcm });
pub const plaintext_sdk = gizclaw.make(grt, .{ .cipher_kind = .plaintext });

pub const default_server_addr = build_config.server_addr;
pub const default_server_pub_key = build_config.server_pub_key;
pub const default_client_pri_key = build_config.client_pri_key;
pub const default_cipher_mode = build_config.cipher_mode;

pub const CipherMode = enum {
    chacha_poly,
    aes_256_gcm,
    plaintext,
};

pub const runtime_options = gizclaw.RuntimeOptions{
    .channel_capacity = 64,
    .serve_rpc = false,
    .drive_task_options = .{ .min_stack_size = 64 * 1024 },
    .read_task_options = .{ .min_stack_size = 24 * 1024 },
    .timer_task_options = .{ .min_stack_size = 16 * 1024 },
    .rpc_task_options = .{ .min_stack_size = 24 * 1024 },
    .kcp_stream = .{
        .channel_capacity = 256,
        .kcp_nodelay = 1,
        .kcp_interval = 10,
        .kcp_resend = 2,
        .kcp_no_congestion_control = 0,
    },
};

pub const Context = struct {
    allocator: grt.std.mem.Allocator,
    server_addr: []u8,
    server_pub_key: giznet.Key,
    cipher_mode: CipherMode,
    key_pair: giznet.KeyPair,
    connect_timeout: ?grt.time.duration.Duration = null,

    pub fn deinit(self: *Context) void {
        self.allocator.free(self.server_addr);
        self.* = undefined;
    }
};

pub const BaseOptions = struct {
    server_addr: ?[]const u8 = null,
    server_pub_key: ?[]const u8 = null,
    client_pri_key: ?[]const u8 = null,
    cipher_mode: ?CipherMode = null,
    connect_timeout_ms: ?i64 = null,
};

pub fn loadContext(allocator: grt.std.mem.Allocator, options: BaseOptions) !Context {
    var resolved = options;
    applyBuildDefaults(&resolved);
    const server_pub_key_text = resolved.server_pub_key orelse default_server_pub_key;
    const client_pri_key_text = resolved.client_pri_key orelse default_client_pri_key;
    if (server_pub_key_text.len == 0) return error.MissingServerPublicKey;
    if (client_pri_key_text.len == 0) return error.MissingClientPrivateKey;
    _ = key.parse(server_pub_key_text) catch return error.InvalidServerPublicKey;
    _ = key.parse(client_pri_key_text) catch return error.InvalidClientPrivateKey;

    const config = try chacha_sdk.Context.fromExplicit(.{
        .server_addr = resolved.server_addr orelse default_server_addr,
        .server_key = server_pub_key_text,
        .client_key = client_pri_key_text,
        .cipher_kind = if (resolved.cipher_mode) |mode| toCipherKind(mode) else .chacha_poly,
        .runtime_options = runtime_options,
        .connect_timeout = connectTimeout(resolved),
    });
    return try contextFromSdkConfig(allocator, config);
}

pub fn connectClient(comptime sdk: type, allocator: grt.std.mem.Allocator, ctx: *const Context) !*sdk.Client {
    const client = try allocator.create(sdk.Client);
    errdefer allocator.destroy(client);

    client.* = try sdk.Client.init(allocator, .{
        .key_pair = ctx.key_pair,
        .runtime_options = runtime_options,
    });
    errdefer client.deinit();

    try client.connect(.{
        .server_key = ctx.server_pub_key,
        .server_addr = ctx.server_addr,
        .connect_timeout = ctx.connect_timeout,
    });
    return client;
}

pub fn disconnectClient(comptime sdk: type, allocator: grt.std.mem.Allocator, client: *sdk.Client) void {
    client.deinit();
    allocator.destroy(client);
}

fn applyBuildDefaults(options: *BaseOptions) void {
    if (options.server_addr == null and default_server_addr.len != 0) {
        options.server_addr = default_server_addr;
    }
    if (options.server_pub_key == null and default_server_pub_key.len != 0) {
        options.server_pub_key = default_server_pub_key;
    }
    if (options.client_pri_key == null and default_client_pri_key.len != 0) {
        options.client_pri_key = default_client_pri_key;
    }
    if (options.cipher_mode == null and default_cipher_mode.len != 0) {
        options.cipher_mode = parseCipherMode(default_cipher_mode) catch null;
    }
}

fn connectTimeout(options: BaseOptions) ?grt.time.duration.Duration {
    const timeout_ms = options.connect_timeout_ms orelse return null;
    return @as(grt.time.duration.Duration, @intCast(@max(timeout_ms, 1))) * grt.time.duration.MilliSecond;
}

fn contextFromSdkConfig(allocator: grt.std.mem.Allocator, config: chacha_sdk.Context.Config) !Context {
    return .{
        .allocator = allocator,
        .server_addr = try allocator.dupe(u8, config.server_addr),
        .server_pub_key = config.server_key,
        .cipher_mode = try cipherModeFromKind(config.cipher_kind),
        .key_pair = config.key_pair,
        .connect_timeout = config.connect_timeout,
    };
}

fn toCipherKind(mode: CipherMode) giznet.noise.Cipher.Kind {
    return switch (mode) {
        .chacha_poly => .chacha_poly,
        .aes_256_gcm => .aes_256_gcm,
        .plaintext => .plaintext,
    };
}

fn cipherModeFromKind(kind: giznet.noise.Cipher.Kind) !CipherMode {
    return switch (kind) {
        .chacha_poly => .chacha_poly,
        .aes_256_gcm => .aes_256_gcm,
        .plaintext => .plaintext,
    };
}

pub fn parseCipherMode(raw: []const u8) !CipherMode {
    if (grt.std.mem.eql(u8, raw, "chacha_poly")) return .chacha_poly;
    if (grt.std.mem.eql(u8, raw, "aes_256_gcm")) return .aes_256_gcm;
    if (grt.std.mem.eql(u8, raw, "plaintext")) return .plaintext;
    return error.InvalidCipherMode;
}
