const glib = @import("glib");
const testing_api = glib.testing;

const NoiseHandshake = @import("../noise/Handshake.zig");
const NoiseSession = @import("../noise/Session.zig");
const NoiseTimerState = @import("../noise/TimerState.zig");
const NoisePeer = @import("../noise/Peer.zig");
const NoisePeerTable = @import("../noise/PeerTable.zig");
const NoiseEngine = @import("../noise/Engine.zig");
const packet = @import("../packet.zig");
const ServiceEngine = @import("../service/Engine.zig");
const ServiceKcpStream = @import("../service/KcpStream.zig");
const ServiceKcpStreamTable = @import("../service/KcpStreamTable.zig");
const ServicePeer = @import("../service/Peer.zig");
const ServicePeerTable = @import("../service/PeerTable.zig");
const ServiceUvarint = @import("../service/Uvarint.zig");

pub fn make(comptime grt: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: grt.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: grt.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            t.run("noise/handshake", NoiseHandshake.TestRunner(grt));
            t.run("noise/session", NoiseSession.TestRunner(grt));
            t.run("noise/timer_state", NoiseTimerState.TestRunner(grt));
            t.run("noise/peer", NoisePeer.TestRunner(grt));
            t.run("noise/peer_table", NoisePeerTable.TestRunner(grt));
            t.run("noise/engine", NoiseEngine.TestRunner(grt));
            t.run("packet/inbound", packet.Inbound.TestRunner(grt));
            t.run("packet/outbound", packet.Outbound.TestRunner(grt));
            t.run("service/engine", ServiceEngine.TestRunner(grt));
            t.run("service/kcp_stream", ServiceKcpStream.TestRunner(grt));
            t.run("service/kcp_stream_table", ServiceKcpStreamTable.TestRunner(grt));
            t.run("service/uvarint", ServiceUvarint.TestRunner(grt));
            t.run("service/peer", ServicePeer.TestRunner(grt));
            t.run("service/peer_table", ServicePeerTable.TestRunner(grt));
            return true;
        }

        pub fn deinit(self: *@This(), allocator: grt.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
        }
    };

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
