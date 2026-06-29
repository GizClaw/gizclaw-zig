//! Transport-independent giznet VTable/API root.

const glib = @import("glib");

pub const GizNet = @import("giznet/GizNet.zig");
pub const Conn = @import("giznet/Conn.zig");
pub const HttpTransport = @import("giznet/HttpTransport.zig");
pub const Listener = @import("giznet/Listener.zig");
pub const Stream = @import("giznet/Stream.zig");
pub const StreamConn = @import("giznet/StreamConn.zig");
pub const DialOptions = @import("giznet/DialOptions.zig");
pub const Key = @import("giznet/Key.zig");
pub const KeyPair = @import("giznet/KeyPair.zig");
pub const NetPerfClient = @import("giznet/perf/Client.zig");
pub const NetPerfServer = @import("giznet/perf/Server.zig");
pub const Stats = @import("giznet/Stats.zig");
pub const AddrPort = glib.net.netip.AddrPort;

pub fn eqlAddrPort(lhs: AddrPort, rhs: AddrPort) bool {
    return glib.std.meta.eql(lhs, rhs);
}

pub const test_runner = struct {
    pub const unit = @import("giznet/test_runner/unit.zig");
    pub const integration = @import("giznet/test_runner/integration.zig");
    pub const benchmark = @import("giznet/test_runner/benchmark.zig");
    pub const cork = @import("giznet/test_runner/cork.zig");
};

pub fn make(comptime grt: type) type {
    return struct {
        pub const GizNet = @import("giznet/GizNet.zig");
        pub const Conn = @import("giznet/Conn.zig");
        pub const HttpTransport = @import("giznet/HttpTransport.zig").make(grt);
        pub const Listener = @import("giznet/Listener.zig").make(grt);
        pub const Stream = @import("giznet/Stream.zig");
        pub const StreamConn = @import("giznet/StreamConn.zig").make(grt);
        pub const DialOptions = @import("giznet/DialOptions.zig");
        pub const Key = @import("giznet/Key.zig");
        pub const KeyPair = @import("giznet/KeyPair.zig");
        pub const NetPerfClient = @import("giznet/perf/Client.zig").make(grt);
        pub const NetPerfServer = @import("giznet/perf/Server.zig").make(grt);
        pub const Stats = @import("giznet/Stats.zig");
        pub const AddrPort = glib.net.netip.AddrPort;
    };
}
