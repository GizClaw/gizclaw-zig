const std = @import("std");
const giznet = @import("giznet");
const giznoise = @import("giznoise");
const gizclaw = @import("gizclaw");
const gstd = @import("gstd");
const build_config = @import("e2e_build_config");

pub const grt = gstd.runtime;
pub const key = gizclaw.make(grt, .{}).key;
pub const chacha_sdk = gizclaw.make(grt, .{ .cipher_kind = .chacha_poly });
pub const aes_256_gcm_sdk = gizclaw.make(grt, .{ .cipher_kind = .aes_256_gcm });
pub const plaintext_sdk = gizclaw.make(grt, .{ .cipher_kind = .plaintext });

pub const host_default_context_dir = "../gizclaw-go/test/gizclaw-e2e/testdata/gizclaw-config-home/gizclaw/e2e-client";
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
    allocator: std.mem.Allocator,
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

    pub fn applyArg(self: *BaseOptions, args: []const []const u8, index: *usize) !bool {
        const arg = args[index.*];
        if (std.mem.eql(u8, arg, "--server-addr")) {
            index.* += 1;
            self.server_addr = try needValue(args, index.*, arg);
            return true;
        }
        if (std.mem.eql(u8, arg, "--server-pub-key")) {
            index.* += 1;
            self.server_pub_key = try needValue(args, index.*, arg);
            return true;
        }
        if (std.mem.eql(u8, arg, "--client-pri-key")) {
            index.* += 1;
            self.client_pri_key = try needValue(args, index.*, arg);
            return true;
        }
        if (std.mem.eql(u8, arg, "--cipher-mode")) {
            index.* += 1;
            self.cipher_mode = try parseCipherMode(try needValue(args, index.*, arg));
            return true;
        }
        if (std.mem.eql(u8, arg, "--connect-timeout-ms")) {
            index.* += 1;
            self.connect_timeout_ms = try std.fmt.parseInt(i64, try needValue(args, index.*, arg), 10);
            return true;
        }
        return false;
    }
};

pub const HostOptions = struct {
    context_dir: ?[]const u8 = host_default_context_dir,

    pub fn applyArg(self: *HostOptions, args: []const []const u8, index: *usize) !bool {
        const arg = args[index.*];
        if (std.mem.eql(u8, arg, "--context")) {
            index.* += 1;
            self.context_dir = try needValue(args, index.*, arg);
            return true;
        }
        if (std.mem.eql(u8, arg, "--no-context")) {
            self.context_dir = null;
            return true;
        }
        return false;
    }
};

pub fn loadContext(allocator: std.mem.Allocator, options: BaseOptions) !Context {
    var resolved = options;
    applyBuildDefaults(&resolved);
    return try loadExplicitContext(allocator, resolved);
}

pub fn loadHostContext(allocator: std.mem.Allocator, options: BaseOptions, host_options: HostOptions) !Context {
    var resolved = options;
    applyBuildDefaults(&resolved);
    if (hasExplicitConnection(resolved)) return try loadExplicitContext(allocator, resolved);
    if (host_options.context_dir) |dir| {
        return loadContextDir(allocator, dir, resolved) catch |err| switch (err) {
            error.FileNotFound => try loadExplicitContext(allocator, resolved),
            else => return err,
        };
    }
    return try loadExplicitContext(allocator, resolved);
}

pub fn connectClient(comptime sdk: type, allocator: std.mem.Allocator, ctx: *const Context) !*sdk.Client {
    const client = try allocator.create(sdk.Client);
    errdefer allocator.destroy(client);

    const net = try sdk.Config.initNoiseGizNet(.{
        .allocator = allocator,
        .key_pair = ctx.key_pair,
        .server_key = ctx.server_pub_key,
        .runtime_options = runtime_options,
    });
    var net_owned = true;
    errdefer if (net_owned) net.deinit();

    client.* = try sdk.Client.init(allocator, .{
        .key_pair = ctx.key_pair,
        .giznet = net,
        .runtime_options = runtime_options,
    });
    net_owned = false;
    errdefer client.deinit();

    try client.connect(.{
        .server_key = ctx.server_pub_key,
        .server_addr = ctx.server_addr,
        .connect_timeout = ctx.connect_timeout,
    });
    return client;
}

pub fn disconnectClient(comptime sdk: type, allocator: std.mem.Allocator, client: *sdk.Client) void {
    client.deinit();
    allocator.destroy(client);
}

pub const Summary = struct {
    out: @TypeOf(std.fs.File.stdout().deprecatedWriter()),
    passed: usize = 0,
    failed: usize = 0,
    skipped: usize = 0,

    pub fn init() Summary {
        return .{ .out = std.fs.File.stdout().deprecatedWriter() };
    }

    pub fn pass(self: *Summary, name: []const u8) !void {
        self.passed += 1;
        try self.out.print("PASS {s}\n", .{name});
    }

    pub fn fail(self: *Summary, name: []const u8, err: anyerror) !void {
        self.failed += 1;
        try self.out.print("FAIL {s}: {s}\n", .{ name, @errorName(err) });
    }

    pub fn finish(self: *Summary) !void {
        try self.out.print("SUMMARY pass={d} skip={d} fail={d}\n", .{ self.passed, self.skipped, self.failed });
        if (self.failed != 0) return error.E2EFailed;
    }
};

fn loadExplicitContext(allocator: std.mem.Allocator, options: BaseOptions) !Context {
    const server_pub_key_text = options.server_pub_key orelse default_server_pub_key;
    const client_pri_key_text = options.client_pri_key orelse default_client_pri_key;
    if (server_pub_key_text.len == 0) return error.MissingServerPublicKey;
    if (client_pri_key_text.len == 0) return error.MissingClientPrivateKey;
    _ = key.parse(server_pub_key_text) catch return error.InvalidServerPublicKey;
    _ = key.parse(client_pri_key_text) catch return error.InvalidClientPrivateKey;

    const config = try chacha_sdk.Context.fromExplicit(.{
        .server_addr = options.server_addr orelse default_server_addr,
        .server_key = server_pub_key_text,
        .client_key = client_pri_key_text,
        .cipher_kind = if (options.cipher_mode) |mode| toCipherKind(mode) else .chacha_poly,
        .runtime_options = runtime_options,
        .connect_timeout = connectTimeout(options),
    });
    return try contextFromSdkConfig(allocator, config);
}

fn loadContextDir(allocator: std.mem.Allocator, dir: []const u8, options: BaseOptions) !Context {
    var config = try chacha_sdk.Context.fromHostDir(allocator, .{
        .context_dir = dir,
        .server_addr = options.server_addr,
        .server_key = options.server_pub_key,
        .client_key = options.client_pri_key,
        .cipher_kind = if (options.cipher_mode) |mode| toCipherKind(mode) else null,
        .runtime_options = runtime_options,
        .connect_timeout = connectTimeout(options),
    });
    defer config.deinit();
    return try contextFromSdkConfig(allocator, config.config);
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

fn contextFromSdkConfig(allocator: std.mem.Allocator, config: chacha_sdk.Context.Config) !Context {
    return .{
        .allocator = allocator,
        .server_addr = try allocator.dupe(u8, config.server_addr),
        .server_pub_key = config.server_key,
        .cipher_mode = try cipherModeFromKind(config.cipher_kind),
        .key_pair = config.key_pair,
        .connect_timeout = config.connect_timeout,
    };
}

fn hasExplicitConnection(options: BaseOptions) bool {
    return nonEmpty(options.server_addr) and
        nonEmpty(options.server_pub_key) and
        nonEmpty(options.client_pri_key);
}

fn nonEmpty(value: ?[]const u8) bool {
    return if (value) |bytes| bytes.len != 0 else false;
}

fn toCipherKind(mode: CipherMode) giznoise.noise.Cipher.Kind {
    return switch (mode) {
        .chacha_poly => .chacha_poly,
        .aes_256_gcm => .aes_256_gcm,
        .plaintext => .plaintext,
    };
}

fn cipherModeFromKind(kind: giznoise.noise.Cipher.Kind) !CipherMode {
    return switch (kind) {
        .chacha_poly => .chacha_poly,
        .aes_256_gcm => .aes_256_gcm,
        .plaintext => .plaintext,
    };
}

pub fn parseCipherMode(raw: []const u8) !CipherMode {
    if (std.mem.eql(u8, raw, "chacha_poly")) return .chacha_poly;
    if (std.mem.eql(u8, raw, "aes_256_gcm")) return .aes_256_gcm;
    if (std.mem.eql(u8, raw, "plaintext")) return .plaintext;
    return error.InvalidCipherMode;
}

pub fn needValue(args: []const []const u8, index: usize, flag: []const u8) ![]const u8 {
    if (index >= args.len) {
        var stderr = std.fs.File.stderr().deprecatedWriter();
        try stderr.print("missing value for {s}\n", .{flag});
        return error.MissingArgument;
    }
    return args[index];
}
