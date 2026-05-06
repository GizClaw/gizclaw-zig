//! Shared packet views above the noise transport.

pub const Inbound = @import("packet/Inbound.zig");
pub const Outbound = @import("packet/Outbound.zig");

pub const Pools = struct {
    inbound: Inbound.Pool,
    outbound: Outbound.Pool,
};
