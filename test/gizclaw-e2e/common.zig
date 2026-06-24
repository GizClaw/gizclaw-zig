const std = @import("std");
const giznet = @import("giznet");
const gizclaw = @import("gizclaw");
const gstd = @import("gstd");

pub const grt = gstd.runtime;
pub const key = gizclaw.make(grt, .{}).key;
pub const chacha_sdk = gizclaw.make(grt, .{ .cipher_kind = .chacha_poly });
pub const aes_256_gcm_sdk = gizclaw.make(grt, .{ .cipher_kind = .aes_256_gcm });
pub const plaintext_sdk = gizclaw.make(grt, .{ .cipher_kind = .plaintext });

pub const default_context_dir = "test/gizclaw-e2e/testdata/client-context";
pub const default_server_addr = "";
pub const default_server_key = "";

pub const CipherMode = enum {
    chacha_poly,
    aes_256_gcm,
    plaintext,
};

pub const runtime_options = gizclaw.RuntimeOptions{
    .channel_capacity = 64,
    .serve_rpc = false,
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
    server_key: giznet.Key,
    cipher_mode: CipherMode,
    key_pair: giznet.KeyPair,
    connect_timeout: ?grt.time.duration.Duration = null,

    pub fn deinit(self: *Context) void {
        self.allocator.free(self.server_addr);
        self.* = undefined;
    }
};

pub const BaseOptions = struct {
    context_dir: ?[]const u8 = default_context_dir,
    server_addr: ?[]const u8 = null,
    server_key: ?[]const u8 = null,
    client_key: ?[]const u8 = null,
    cipher_mode: ?CipherMode = null,
    connect_timeout_ms: ?i64 = null,

    pub fn applyArg(self: *BaseOptions, args: []const []const u8, index: *usize) !bool {
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
        if (std.mem.eql(u8, arg, "--server-addr")) {
            index.* += 1;
            self.server_addr = try needValue(args, index.*, arg);
            return true;
        }
        if (std.mem.eql(u8, arg, "--server-key")) {
            index.* += 1;
            self.server_key = try needValue(args, index.*, arg);
            return true;
        }
        if (std.mem.eql(u8, arg, "--client-key")) {
            index.* += 1;
            self.client_key = try needValue(args, index.*, arg);
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

pub fn loadContext(allocator: std.mem.Allocator, options: BaseOptions) !Context {
    if (options.context_dir) |dir| {
        return loadContextDir(allocator, dir, options) catch |err| switch (err) {
            error.FileNotFound => try loadExplicitContext(allocator, options),
            else => return err,
        };
    }
    return try loadExplicitContext(allocator, options);
}

pub fn connectClient(comptime sdk: type, allocator: std.mem.Allocator, ctx: *const Context) !sdk.Client {
    var client = try sdk.Client.init(allocator, .{
        .key_pair = ctx.key_pair,
        .runtime_options = runtime_options,
    });
    errdefer client.deinit();
    try client.connect(.{
        .server_key = ctx.server_key,
        .server_addr = ctx.server_addr,
        .connect_timeout = ctx.connect_timeout,
    });
    return client;
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

    pub fn skip(self: *Summary, name: []const u8, reason: []const u8) !void {
        self.skipped += 1;
        try self.out.print("SKIP {s}: {s}\n", .{ name, reason });
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
    const server_addr = options.server_addr orelse default_server_addr;
    const server_key_text = options.server_key orelse default_server_key;
    const client_key_text = options.client_key orelse return error.MissingClientPrivateKey;
    const private = key.parse(client_key_text) catch return error.InvalidClientPrivateKey;
    const server_key = key.parse(server_key_text) catch return error.InvalidServerPublicKey;
    return .{
        .allocator = allocator,
        .server_addr = try allocator.dupe(u8, server_addr),
        .server_key = server_key,
        .cipher_mode = options.cipher_mode orelse .chacha_poly,
        .key_pair = try key.fromPrivate(private),
        .connect_timeout = connectTimeout(options),
    };
}

fn loadContextDir(allocator: std.mem.Allocator, dir: []const u8, options: BaseOptions) !Context {
    const config_path = try std.fs.path.join(allocator, &.{ dir, "config.yaml" });
    defer allocator.free(config_path);
    const data = try std.fs.cwd().readFileAlloc(allocator, config_path, 64 * 1024);
    defer allocator.free(data);

    var server_addr: ?[]u8 = null;
    errdefer if (server_addr) |value| allocator.free(value);
    var server_key: ?giznet.Key = null;
    var cipher_mode: CipherMode = .chacha_poly;

    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "address:")) {
            const raw = yamlScalar(trimmed["address:".len..]);
            server_addr = try allocator.dupe(u8, raw);
        } else if (std.mem.startsWith(u8, trimmed, "public-key:")) {
            const raw = yamlScalar(trimmed["public-key:".len..]);
            server_key = key.parse(raw) catch return error.InvalidServerPublicKey;
        } else if (std.mem.startsWith(u8, trimmed, "cipher-mode:")) {
            const raw = yamlScalar(trimmed["cipher-mode:".len..]);
            cipher_mode = try parseCipherMode(raw);
        }
    }

    const identity_path = try std.fs.path.join(allocator, &.{ dir, "identity.key" });
    defer allocator.free(identity_path);
    const private = try readPrivateKeyBytes(identity_path, error.InvalidIdentityKey);

    if (options.server_addr) |override| {
        if (server_addr) |value| allocator.free(value);
        server_addr = try allocator.dupe(u8, override);
    }
    if (options.server_key) |override| {
        server_key = key.parse(override) catch return error.InvalidServerPublicKey;
    }
    if (options.cipher_mode) |override| {
        cipher_mode = override;
    }

    return .{
        .allocator = allocator,
        .server_addr = server_addr orelse return error.MissingServerAddress,
        .server_key = server_key orelse return error.MissingServerPublicKey,
        .cipher_mode = cipher_mode,
        .key_pair = try key.fromPrivate(private),
        .connect_timeout = connectTimeout(options),
    };
}

fn yamlScalar(raw: []const u8) []const u8 {
    return std.mem.trim(u8, raw, " \t\"'");
}

fn readPrivateKeyBytes(path: []const u8, invalid_error: anyerror) !giznet.Key {
    const data = std.fs.cwd().readFileAlloc(std.heap.page_allocator, path, 32) catch |err| switch (err) {
        error.FileNotFound => return invalid_error,
        else => return err,
    };
    defer std.heap.page_allocator.free(data);
    if (data.len != 32) return invalid_error;
    var private: giznet.Key = .{};
    @memcpy(&private.bytes, data);
    return private;
}

fn connectTimeout(options: BaseOptions) ?grt.time.duration.Duration {
    const timeout_ms = options.connect_timeout_ms orelse return null;
    return @as(grt.time.duration.Duration, @intCast(@max(timeout_ms, 1))) * grt.time.duration.MilliSecond;
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
