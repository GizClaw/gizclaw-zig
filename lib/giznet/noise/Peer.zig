const embed = @import("embed");
const std = embed.std;

const Key = @import("Key.zig");
const AddrPort = embed.net.netip.AddrPort;
const Cipher = @import("Cipher.zig");
const HandshakeType = @import("Handshake.zig");
const SessionType = @import("Session.zig");
const TimerState = @import("TimerState.zig");
const root = @This();

pub const PeerTimerConfig = struct {
    keepalive_timeout_ms: u64,
    keepalive_interval_ms: ?u64 = null,
    rekey_after_time_ms: u64,
    rekey_timeout_ms: u64,
    handshake_attempt_ms: u64,
    offline_timeout_ms: u64,
    session_cleanup_ms: u64,
    rekey_after_messages: u64,
};

pub fn make(comptime lib: type, comptime cipher_kind: Cipher.Kind) type {
    const packet_size_capacity = SessionType.legacy_packet_size_capacity;
    const Handshake = HandshakeType.make(lib, cipher_kind);
    const Session = SessionType.make(lib, packet_size_capacity, cipher_kind);

    return struct {
        pub const TimerConfig = root.PeerTimerConfig;

        pub const PendingHandshake = struct {
            local_static: Key,
            endpoint: AddrPort,
            local_session_index: u32,
            handshake: Handshake,
            attempt_started_ms: u64,
            last_sent_ms: u64,
        };

        key: Key,
        timer_config: TimerConfig,
        local_static: Key = .{},
        endpoint: AddrPort = .{},
        current: ?Session = null,
        previous: ?Session = null,
        pending_handshake: ?PendingHandshake = null,
        is_offline: bool = false,
        persistent_keepalive: bool = false,
        keepalive_interval_ms: ?u64 = null,
        is_initiator: bool = false,
        rekey_triggered: bool = false,
        rekey_requested: bool = false,
        session_created_ms: u64 = 0,
        last_sent_ms: u64 = 0,
        last_received_ms: u64 = 0,
        offline_deadline_ms: ?u64 = null,
        timers: TimerState = .{},

        const Self = @This();

        pub fn init(key: Key, timer_config: TimerConfig) Self {
            return .{
                .key = key,
                .timer_config = timer_config,
                .persistent_keepalive = timer_config.keepalive_interval_ms != null,
                .keepalive_interval_ms = timer_config.keepalive_interval_ms,
            };
        }

        pub fn startPendingHandshake(
            self: *Self,
            local_static: Key,
            endpoint: AddrPort,
            local_session_index: u32,
            handshake: Handshake,
            now_ms: u64,
        ) void {
            self.local_static = local_static;
            self.endpoint = endpoint;
            self.pending_handshake = .{
                .local_static = local_static,
                .endpoint = endpoint,
                .local_session_index = local_session_index,
                .handshake = handshake,
                .attempt_started_ms = now_ms,
                .last_sent_ms = now_ms,
            };
        }

        pub fn clearPendingHandshake(self: *Self) void {
            self.pending_handshake = null;
            self.timers.set(.handshake_retry_deadline, null);
            self.timers.set(.handshake_deadline, null);
        }

        pub fn markOnline(self: *Self, now_ms: u64) void {
            self.is_offline = false;
            self.offline_deadline_ms = if (self.current != null)
                now_ms + self.timer_config.offline_timeout_ms
            else
                null;
        }

        pub fn markOffline(self: *Self) void {
            self.is_offline = true;
            self.offline_deadline_ms = null;
            self.timers.set(.keepalive_deadline, null);
            self.timers.set(.rekey_deadline, null);
            self.timers.set(.offline_deadline, null);
        }

        pub fn establish(
            self: *Self,
            local_static: Key,
            endpoint: AddrPort,
            session: Session,
            is_initiator: bool,
            now_ms: u64,
        ) void {
            self.local_static = local_static;
            self.endpoint = endpoint;
            self.is_initiator = is_initiator;
            self.rekey_triggered = false;
            self.rekey_requested = false;
            self.session_created_ms = now_ms;
            self.last_sent_ms = now_ms;
            self.last_received_ms = now_ms;
            self.clearPendingHandshake();
            self.previous = self.current;
            self.current = session;
            self.markOnline(now_ms);
            if (self.current) |*current| current.setEndpoint(endpoint);
        }

        pub fn updateTimers(self: *Self, now_ms: u64, transport_messages: usize) void {
            if (transport_messages != 0) {
                if (self.current) |current| {
                    if (self.is_initiator and !self.rekey_triggered and self.pending_handshake == null) {
                        if (current.sendNonce() >= self.timer_config.rekey_after_messages or
                            current.recvMaxNonce() >= self.timer_config.rekey_after_messages or
                            (now_ms -| self.session_created_ms) >= self.timer_config.rekey_after_time_ms)
                        {
                            self.rekey_requested = true;
                        }
                    }
                }
            }

            self.recomputeTimers(
                self.timer_config.keepalive_timeout_ms,
                self.timer_config.rekey_after_time_ms,
                self.timer_config.rekey_timeout_ms,
                self.timer_config.handshake_attempt_ms,
                self.timer_config.offline_timeout_ms,
                self.timer_config.session_cleanup_ms,
            );
        }

        pub fn sessionByLocalIndex(self: *Self, local_session_index: u32) ?*Session {
            if (self.current) |*session| {
                if (session.localIndex() == local_session_index) return session;
            }
            if (self.previous) |*session| {
                if (session.localIndex() == local_session_index) return session;
            }
            return null;
        }

        pub fn isCompletelyIdle(self: Self) bool {
            return self.current == null and self.previous == null and self.pending_handshake == null;
        }

        pub fn recomputeTimers(
            self: *Self,
            keepalive_timeout_ms: u64,
            rekey_after_time_ms: u64,
            rekey_timeout_ms: u64,
            handshake_attempt_ms: u64,
            offline_timeout_ms: u64,
            session_cleanup_ms: u64,
        ) void {
            if (self.current != null and !self.is_offline and self.last_received_ms > self.last_sent_ms) {
                self.timers.set(.keepalive_deadline, self.last_received_ms + keepalive_timeout_ms);
            } else {
                self.timers.set(.keepalive_deadline, null);
            }

            if (self.current != null and !self.is_offline and self.is_initiator and !self.rekey_triggered) {
                if (self.rekey_requested) {
                    self.timers.set(.rekey_deadline, @max(self.last_received_ms, self.last_sent_ms));
                } else {
                    self.timers.set(.rekey_deadline, self.session_created_ms + rekey_after_time_ms);
                }
            } else {
                self.timers.set(.rekey_deadline, null);
            }

            if (self.current != null and !self.is_offline) {
                const deadline_ms = self.last_received_ms + offline_timeout_ms;
                self.offline_deadline_ms = deadline_ms;
                self.timers.set(.offline_deadline, deadline_ms);
            } else {
                self.offline_deadline_ms = null;
                self.timers.set(.offline_deadline, null);
            }

            if (self.pending_handshake) |pending_handshake| {
                self.timers.set(.handshake_retry_deadline, pending_handshake.last_sent_ms + rekey_timeout_ms);
                self.timers.set(.handshake_deadline, pending_handshake.attempt_started_ms + handshake_attempt_ms);
            } else {
                self.timers.set(.handshake_retry_deadline, null);
                self.timers.set(.handshake_deadline, null);
            }

            if (self.previous) |previous| {
                self.timers.set(
                    .cleanup_deadline,
                    @max(previous.lastReceivedMs(), previous.lastSentMs()) + session_cleanup_ms,
                );
            } else {
                self.timers.set(.cleanup_deadline, null);
            }
        }
    };
}

pub fn testRunner(comptime lib: type) embed.testing.TestRunner {
    const testing_api = embed.testing;
    const giznet = @import("../../giznet.zig");

    const Runner = struct {
        pub fn init(self: *@This(), allocator: std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase(lib) catch |err| {
                t.logErrorf("giznet/noise Peer unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }

        fn tryCase(comptime any_lib: type) !void {
            const Peer = make(any_lib, Cipher.default_kind);
            const Handshake = HandshakeType.make(any_lib, Cipher.default_kind);
            const Session = SessionType.make(any_lib, SessionType.legacy_packet_size_capacity, Cipher.default_kind);
            const initiator_pair = giznet.noise.KeyPair.seed(any_lib, 31);
            const responder_pair = giznet.noise.KeyPair.seed(any_lib, 41);
            const endpoint_one = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 3010);
            const endpoint_two = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 3020);
            const endpoint_three = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 3030);

            const timer_config: Peer.TimerConfig = .{
                .keepalive_timeout_ms = 10,
                .rekey_after_time_ms = 50,
                .rekey_timeout_ms = 5,
                .handshake_attempt_ms = 20,
                .offline_timeout_ms = 60,
                .session_cleanup_ms = 40,
                .rekey_after_messages = 8,
            };

            var peer = Peer.init(responder_pair.public, timer_config);
            try any_lib.testing.expect(peer.key.eql(responder_pair.public));
            try any_lib.testing.expect(peer.isCompletelyIdle());

            const handshake = try Handshake.initInitiator(initiator_pair, responder_pair.public, 77);
            peer.startPendingHandshake(initiator_pair.public, endpoint_one, 77, handshake, 100);
            try any_lib.testing.expect(peer.pending_handshake != null);
            try any_lib.testing.expect(peer.local_static.eql(initiator_pair.public));
            try any_lib.testing.expect(giznet.eqlAddrPort(peer.pending_handshake.?.endpoint, endpoint_one));
            try any_lib.testing.expectEqual(@as(?u32, 77), if (peer.pending_handshake) |pending_handshake| pending_handshake.local_session_index else null);
            try any_lib.testing.expect(peer.pending_handshake != null);

            peer.pending_handshake.?.last_sent_ms = 111;
            peer.updateTimers(111, 0);
            try any_lib.testing.expectEqual(@as(?u64, 116), peer.timers.get(.handshake_retry_deadline));
            try any_lib.testing.expectEqual(@as(?u64, 120), peer.timers.get(.handshake_deadline));

            peer.clearPendingHandshake();
            try any_lib.testing.expect(peer.pending_handshake == null);
            try any_lib.testing.expectEqual(@as(?u64, null), peer.timers.get(.handshake_retry_deadline));
            try any_lib.testing.expectEqual(@as(?u64, null), peer.timers.get(.handshake_deadline));

            const session_one = makeSession(Session, responder_pair.public, endpoint_one, 1, 2, 0x11, 0x22);
            peer.establish(initiator_pair.public, endpoint_one, session_one, true, 200);
            try any_lib.testing.expect(peer.current != null);
            try any_lib.testing.expect(peer.previous == null);
            try any_lib.testing.expectEqual(@as(u32, 1), peer.current.?.localIndex());
            try any_lib.testing.expect(peer.current != null and peer.current.?.canSend());
            try any_lib.testing.expect(!peer.is_offline);

            const session_two = makeSession(Session, responder_pair.public, endpoint_two, 3, 4, 0x33, 0x44);
            peer.establish(initiator_pair.public, endpoint_two, session_two, true, 300);
            try any_lib.testing.expectEqual(@as(u32, 3), peer.current.?.localIndex());
            try any_lib.testing.expectEqual(@as(u32, 1), peer.previous.?.localIndex());
            try any_lib.testing.expect(giznet.eqlAddrPort(peer.endpoint, endpoint_two));

            peer.endpoint = endpoint_three;
            peer.last_received_ms = 310;
            if (peer.current) |*current| current.setEndpoint(endpoint_three);
            if (peer.previous) |*previous| previous.setEndpoint(endpoint_three);
            peer.updateTimers(310, 1);
            try any_lib.testing.expect(giznet.eqlAddrPort(peer.endpoint, endpoint_three));
            try any_lib.testing.expect(giznet.eqlAddrPort(peer.current.?.endpointValue(), endpoint_three));
            try any_lib.testing.expect(giznet.eqlAddrPort(peer.previous.?.endpointValue(), endpoint_three));
            try any_lib.testing.expectEqual(@as(?u64, 320), peer.timers.get(.keepalive_deadline));
            try any_lib.testing.expectEqual(@as(?u64, 350), peer.timers.get(.rekey_deadline));
            try any_lib.testing.expectEqual(@as(?u64, 370), peer.timers.get(.offline_deadline));
            try any_lib.testing.expectEqual(@as(?u64, 370), peer.offline_deadline_ms);

            peer.rekey_triggered = true;
            peer.rekey_requested = false;
            peer.updateTimers(310, 0);
            try any_lib.testing.expectEqual(@as(?u64, null), peer.timers.get(.rekey_deadline));
            peer.rekey_triggered = false;
            peer.rekey_requested = false;

            peer.markOffline();
            peer.updateTimers(310, 0);
            try any_lib.testing.expect(peer.is_offline);
            try any_lib.testing.expectEqual(@as(?u64, null), peer.timers.get(.offline_deadline));
            try any_lib.testing.expectEqual(@as(?u64, null), peer.timers.get(.keepalive_deadline));
            try any_lib.testing.expectEqual(@as(?u64, null), peer.offline_deadline_ms);

            peer.current = peer.previous;
            peer.previous = null;
            try any_lib.testing.expectEqual(@as(u32, 1), peer.current.?.localIndex());
            try any_lib.testing.expect(peer.previous == null);
            peer.current = null;
            try any_lib.testing.expect(peer.isCompletelyIdle());
        }

        fn makeSession(
            Session: type,
            peer_key: giznet.noise.Key,
            endpoint: giznet.AddrPort,
            local_index: u32,
            remote_index: u32,
            send_fill: u8,
            recv_fill: u8,
        ) Session {
            return Session.init(.{
                .local_index = local_index,
                .remote_index = remote_index,
                .peer_key = peer_key,
                .endpoint = endpoint,
                .send_key = giznet.noise.Key{ .bytes = [_]u8{send_fill} ** 32 },
                .recv_key = giznet.noise.Key{ .bytes = [_]u8{recv_fill} ** 32 },
            });
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
