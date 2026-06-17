const std = @import("std");
const glib = @import("glib");
const gstd = @import("gstd");
const gizclaw = @import("gizclaw");

const cli_context = @import("context.zig");

const grt = gstd.runtime;
const chacha_sdk = gizclaw.make(grt, .{ .cipher_kind = .chacha_poly });
const aes_256_gcm_sdk = gizclaw.make(grt, .{ .cipher_kind = .aes_256_gcm });
const plaintext_sdk = gizclaw.make(grt, .{ .cipher_kind = .plaintext });
const cmd_runtime_options = gizclaw.RuntimeOptions{
    .channel_capacity = 64,
    .kcp_stream = .{
        .channel_capacity = 256,
        .kcp_nodelay = 1,
        .kcp_interval = 10,
        .kcp_resend = 2,
        .kcp_no_congestion_control = 0,
        .kcp_send_window = 64,
        .kcp_recv_window = 64,
    },
};
pub const models = chacha_sdk.models;

pub const Client = union(cli_context.CipherMode) {
    chacha_poly: chacha_sdk.Client,
    aes_256_gcm: aes_256_gcm_sdk.Client,
    plaintext: plaintext_sdk.Client,

    pub const SpeedTestResult = chacha_sdk.Client.SpeedTestResult;

    pub fn init(allocator: std.mem.Allocator, ctx: *const cli_context.Context) !Client {
        return switch (ctx.config.server.cipher_mode) {
            .chacha_poly => .{ .chacha_poly = try chacha_sdk.Client.init(allocator, .{
                .key_pair = ctx.key_pair,
                .runtime_options = cmd_runtime_options,
            }) },
            .aes_256_gcm => .{ .aes_256_gcm = try aes_256_gcm_sdk.Client.init(allocator, .{
                .key_pair = ctx.key_pair,
                .runtime_options = cmd_runtime_options,
            }) },
            .plaintext => .{ .plaintext = try plaintext_sdk.Client.init(allocator, .{
                .key_pair = ctx.key_pair,
                .runtime_options = cmd_runtime_options,
            }) },
        };
    }

    pub fn deinit(self: *Client) void {
        switch (self.*) {
            inline else => |*client| client.deinit(),
        }
    }

    pub fn connect(self: *Client, ctx: *const cli_context.Context) !void {
        switch (self.*) {
            .chacha_poly => |*client| try client.connect(.{
                .server_key = ctx.config.server.public_key,
                .server_addr = ctx.config.server.address,
            }),
            .aes_256_gcm => |*client| try client.connect(.{
                .server_key = ctx.config.server.public_key,
                .server_addr = ctx.config.server.address,
            }),
            .plaintext => |*client| try client.connect(.{
                .server_key = ctx.config.server.public_key,
                .server_addr = ctx.config.server.address,
            }),
        }
    }

    pub fn ping(self: *Client) !models.PingResponse {
        return switch (self.*) {
            inline else => |*client| try client.ping(),
        };
    }

    pub fn speedTest(
        self: *Client,
        request: models.SpeedTestRequest,
        timeout: ?glib.time.duration.Duration,
    ) !SpeedTestResult {
        return switch (self.*) {
            inline else => |*client| try client.speedTest(request, timeout),
        };
    }

    pub fn serverInfo(self: *Client) !models.ServerInfo {
        return switch (self.*) {
            inline else => |*client| try client.serverInfo(),
        };
    }

    pub fn peerInfo(self: *Client) !models.DeviceInfo {
        return switch (self.*) {
            inline else => |*client| try client.peerInfo(),
        };
    }

    pub fn setPeerName(self: *Client, name: []const u8) !models.DeviceInfo {
        return switch (self.*) {
            inline else => |*client| try client.setPeerName(name),
        };
    }

    pub fn deinitServerInfo(allocator: std.mem.Allocator, info: *models.ServerInfo) void {
        chacha_sdk.Client.deinitServerInfo(allocator, info);
    }

    pub fn deinitDeviceInfo(allocator: std.mem.Allocator, info: *models.DeviceInfo) void {
        chacha_sdk.Client.deinitDeviceInfo(allocator, info);
    }
};

pub fn initFromContext(allocator: std.mem.Allocator, ctx: *const cli_context.Context) !Client {
    return try Client.init(allocator, ctx);
}

pub fn connect(client: *Client, ctx: *const cli_context.Context) !void {
    try client.connect(ctx);
}

pub fn loadSelectedContext(allocator: std.mem.Allocator, name: ?[]const u8) !cli_context.Context {
    var store = try cli_context.Store.default(allocator);
    defer store.deinit();
    if (name) |ctx_name| return try store.loadByName(ctx_name);
    return (try store.current()) orelse error.NoActiveContext;
}

pub fn armNetworkWatchdog() void {
    armNetworkWatchdogAfter(10 * std.time.ns_per_s);
}

pub fn armNetworkWatchdogAfter(timeout_ns: u64) void {
    const thread = std.Thread.spawn(.{}, networkWatchdog, .{timeout_ns}) catch return;
    thread.detach();
}

fn networkWatchdog(timeout_ns: u64) void {
    std.Thread.sleep(timeout_ns);
    var stderr = std.fs.File.stderr().deprecatedWriter();
    stderr.writeAll("Error: network operation timed out\n") catch {};
    std.process.exit(124);
}
