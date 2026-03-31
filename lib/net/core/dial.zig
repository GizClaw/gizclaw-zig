const noise = @import("noise");

const conn = @import("conn.zig");
const consts = @import("consts.zig");
const errors = @import("errors.zig");

// Single-threaded: callers must serialize all Dial access.
pub fn Dial(comptime Noise: type) type {
    const ConnType = conn.Conn(Noise);
    const KeyPair = Noise.KeyPair;

    return struct {
        conn: ConnType,

        const Self = @This();

        pub fn init(local_static: KeyPair, remote_static: noise.Key, local_index: u32) Self {
            return .{
                .conn = ConnType.initInitiator(local_static, remote_static, local_index),
            };
        }

        pub fn connection(self: *Self) *ConnType {
            return &self.conn;
        }

        pub fn start(self: *Self, wire_out: []u8, now_ms: u64) !usize {
            return self.conn.beginHandshake(wire_out, now_ms);
        }

        pub fn pollRetry(self: *Self, wire_out: []u8, now_ms: u64) !?usize {
            if (self.conn.state() == .closed) return errors.Error.ConnClosed;
            if (self.conn.handshake == null) return null;
            if (self.conn.handshake_attempt_start_ms != 0 and
                now_ms >= self.conn.handshake_attempt_start_ms and
                now_ms - self.conn.handshake_attempt_start_ms >= consts.rekey_attempt_time_ms)
            {
                self.conn.abortHandshakeAttempt();
                return errors.Error.HandshakeTimeout;
            }
            if (self.conn.last_handshake_sent_ms == 0) return null;
            if (now_ms - self.conn.last_handshake_sent_ms < consts.rekey_timeout_ms) return null;
            return try self.conn.beginHandshake(wire_out, now_ms);
        }

        pub fn handleResponse(self: *Self, data: []const u8, now_ms: u64) !void {
            try self.conn.handleHandshakeResponse(data, now_ms);
        }
    };
}

pub fn testAll(comptime lib: type, testing: anytype) !void {
    const noise_mod = @import("noise");
    const Noise = noise_mod.make(noise_mod.LibAdapter.make(lib));
    const DialType = Dial(Noise);
    const ConnType = conn.Conn(Noise);

    const alice_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{5} ** noise.Key.key_size));
    const bob_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{6} ** noise.Key.key_size));

    var dialer = DialType.init(alice_static, bob_static.public, 11);
    var init_wire: [128]u8 = undefined;
    _ = try dialer.start(&init_wire, 100);
    try testing.expect((try dialer.pollRetry(&init_wire, 101)) == null);

    var retry_wire: [128]u8 = undefined;
    const retry_n = (try dialer.pollRetry(&retry_wire, 100 + consts.rekey_timeout_ms + 1)).?;
    try testing.expect(retry_n > 0);

    var successful_dialer = DialType.init(alice_static, bob_static.public, 12);
    var responder = ConnType.initResponder(bob_static, 21);
    const init_n = try successful_dialer.start(&init_wire, 200);

    var resp_wire: [128]u8 = undefined;
    const resp_n = try responder.acceptHandshakeInit(init_wire[0..init_n], &resp_wire, 200);
    try successful_dialer.handleResponse(resp_wire[0..resp_n], 201);
    try testing.expectEqual(conn.State.established, successful_dialer.connection().state());
    try testing.expect((try successful_dialer.pollRetry(&retry_wire, 201 + consts.rekey_attempt_time_ms + 1)) == null);

    _ = try successful_dialer.connection().beginHandshake(&init_wire, 300);
    try testing.expect((try successful_dialer.pollRetry(&retry_wire, 300 + consts.rekey_timeout_ms + 1)) != null);
    try testing.expectError(errors.Error.HandshakeTimeout, successful_dialer.pollRetry(&retry_wire, 300 + consts.rekey_attempt_time_ms + 1));
    try testing.expect((try successful_dialer.pollRetry(&retry_wire, 300 + consts.rekey_attempt_time_ms + 2)) == null);
}
