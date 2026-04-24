const embed = @import("embed");
const Key = @import("noise/Key.zig");

const AddrPort = embed.net.netip.AddrPort;
const DialOptions = @This();

remote_key: Key = .{},
endpoint: ?AddrPort = null,
connect_timeout_ms: ?u32 = null,
keepalive_ms: ?u32 = null,
