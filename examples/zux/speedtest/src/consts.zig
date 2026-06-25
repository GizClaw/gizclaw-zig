const build_config = @import("build_config");
const glib = @import("glib");
const giznet = @import("giznet");

pub const gizclaw_accept_timeout: glib.time.duration.Duration = 5 * glib.time.duration.Second;
pub const gizclaw_ping_interval: glib.time.duration.Duration = 10 * glib.time.duration.Second;
pub const gizclaw_speed_test_content_length: i64 = 5 * 1024 * 1024;
pub const gizclaw_speed_test_progress_interval: glib.time.duration.Duration = glib.time.duration.Second;
pub const gizclaw_speed_test_timeout: glib.time.duration.Duration = 180 * glib.time.duration.Second;

pub const gizclaw_connect_timeout_ms: u32 = 5000;
pub const gizclaw_keepalive_ms: u32 = 15_000;

pub const wifi_connect_timeout: glib.time.duration.Duration = 10 * glib.time.duration.Second;
pub const wifi_ip_timeout: glib.time.duration.Duration = 3 * glib.time.duration.Second;
pub const wifi_reconnect_backoff: glib.time.duration.Duration = 5 * glib.time.duration.Second;

pub const power_hold_interval: glib.time.duration.Duration = 3 * glib.time.duration.Second;

pub const gizclaw_server_addr = build_config.gizclaw_server_addr;
pub const gizclaw_server_key = build_config.gizclaw_server_key;
pub const gizclaw_client_key = build_config.gizclaw_client_key;
pub const wifi_ssid = build_config.wifi_ssid;
pub const wifi_password = build_config.wifi_password;

pub const GizclawConfig = struct {
    server_key: giznet.Key,
    key_pair: giznet.KeyPair,
    server_endpoint: giznet.AddrPort,
};

pub fn parseGizclaw(comptime sdk: type, comptime Client: type, key_pair: giznet.KeyPair) !GizclawConfig {
    const server_key = try sdk.key.parse(gizclaw_server_key);
    return .{
        .server_key = server_key,
        .key_pair = key_pair,
        .server_endpoint = try Client.parseAddrPort(gizclaw_server_addr),
    };
}
