//! Client-side GizClaw helpers.

pub const Client = @import("gizclaw/Client.zig");
pub const key = @import("gizclaw/key.zig");
pub const rpc = @import("gizclaw/rpc.zig");
pub const service = @import("gizclaw/service.zig");

pub const test_runner = struct {
    pub const unit = @import("gizclaw/test_runner/unit.zig");
    pub const integration = @import("gizclaw/test_runner/integration.zig");
    pub const benchmark = @import("gizclaw/test_runner/benchmark.zig");
    pub const cork = @import("gizclaw/test_runner/cork.zig");
};

pub fn make(comptime grt: type) type {
    return struct {
        pub const Client = @import("gizclaw/Client.zig").make(grt);
        pub const key = @import("gizclaw/key.zig").make(grt);
        pub const rpc = @import("gizclaw/rpc.zig").make(grt);
        pub const service = @import("gizclaw/service.zig");
    };
}
