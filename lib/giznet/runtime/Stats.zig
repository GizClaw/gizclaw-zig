const Stats = @This();

pub const Snapshot = struct {
    active_peers: usize = 0,
    udp_rx_packets: u64 = 0,
    udp_tx_packets: u64 = 0,
    dropped_packets: u64 = 0,
};

pub fn make(comptime grt: type) type {
    return struct {
        active_peers: grt.std.atomic.Value(usize) = grt.std.atomic.Value(usize).init(0),
        udp_rx_packets: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
        udp_tx_packets: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),
        dropped_packets: grt.std.atomic.Value(u64) = grt.std.atomic.Value(u64).init(0),

        pub fn snapshot(self: *@This()) Stats.Snapshot {
            return .{
                .active_peers = self.active_peers.load(.monotonic),
                .udp_rx_packets = self.udp_rx_packets.load(.monotonic),
                .udp_tx_packets = self.udp_tx_packets.load(.monotonic),
                .dropped_packets = self.dropped_packets.load(.monotonic),
            };
        }
    };
}
