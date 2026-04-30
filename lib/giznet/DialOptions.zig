const glib = @import("glib");
const Key = @import("noise/Key.zig");

const AddrPort = glib.net.netip.AddrPort;
const DialOptions = @This();

remote_key: Key = .{},
endpoint: ?AddrPort = null,
connect_timeout_ms: ?u32 = null,
keepalive_ms: ?u32 = null,
