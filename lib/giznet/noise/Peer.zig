const glib = @import("glib");

const Key = @import("Key.zig");
const AddrPort = glib.net.netip.AddrPort;
const Cipher = @import("Cipher.zig");
const HandshakeType = @import("Handshake.zig");
const SessionType = @import("Session.zig");
const TimerState = @import("TimerState.zig");
const root = @This();

pub const PeerTimerConfig = struct {
    keepalive_timeout: glib.time.duration.Duration,
    rekey_after_time: glib.time.duration.Duration,
    rekey_timeout: glib.time.duration.Duration,
    handshake_attempt: glib.time.duration.Duration,
    offline_timeout: glib.time.duration.Duration,
    session_cleanup: glib.time.duration.Duration,
    rekey_after_messages: u64,
};

pub fn make(comptime grt: type, comptime cipher_kind: Cipher.Kind) type {
    const packet_size_capacity = SessionType.legacy_packet_size_capacity;
    const Handshake = HandshakeType.make(grt, cipher_kind);
    const Session = SessionType.make(grt, packet_size_capacity, cipher_kind);

    return struct {
        pub const TimerConfig = root.PeerTimerConfig;

        pub const PendingHandshake = struct {
            local_static: Key,
            endpoint: AddrPort,
            local_session_index: u32,
            handshake: Handshake,
            attempt_started: glib.time.instant.Time,
            last_sent: glib.time.instant.Time,
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
        keepalive_interval: ?glib.time.duration.Duration = null,
        is_initiator: bool = false,
        rekey_triggered: bool = false,
        rekey_requested: bool = false,
        session_created: glib.time.instant.Time = 0,
        last_sent: glib.time.instant.Time = 0,
        last_received: glib.time.instant.Time = 0,
        offline_deadline: ?glib.time.instant.Time = null,
        timers: TimerState = .{},

        const Self = @This();

        pub fn init(key: Key, timer_config: TimerConfig) Self {
            return .{
                .key = key,
                .timer_config = root.normalizeTimerConfig(timer_config),
            };
        }

        pub fn startPendingHandshake(
            self: *Self,
            local_static: Key,
            endpoint: AddrPort,
            local_session_index: u32,
            handshake: Handshake,
            keepalive_interval: ?glib.time.duration.Duration,
            now: glib.time.instant.Time,
        ) void {
            self.local_static = local_static;
            self.endpoint = endpoint;
            self.persistent_keepalive = keepalive_interval != null;
            self.keepalive_interval = keepalive_interval;
            self.pending_handshake = .{
                .local_static = local_static,
                .endpoint = endpoint,
                .local_session_index = local_session_index,
                .handshake = handshake,
                .attempt_started = now,
                .last_sent = now,
            };
        }

        pub fn clearPendingHandshake(self: *Self) void {
            self.pending_handshake = null;
            self.timers.set(.handshake_retry_deadline, null);
            self.timers.set(.handshake_deadline, null);
        }

        pub fn markOnline(self: *Self, now: glib.time.instant.Time) void {
            self.is_offline = false;
            self.offline_deadline = if (self.current != null)
                glib.time.instant.add(now, self.timer_config.offline_timeout)
            else
                null;
        }

        pub fn markOffline(self: *Self) void {
            self.is_offline = true;
            self.offline_deadline = null;
            self.timers.set(.keepalive_deadline, null);
            self.timers.set(.persistent_keepalive_deadline, null);
            self.timers.set(.rekey_deadline, null);
            self.timers.set(.offline_deadline, null);
        }

        pub fn establish(
            self: *Self,
            local_static: Key,
            endpoint: AddrPort,
            session: Session,
            is_initiator: bool,
            now: glib.time.instant.Time,
        ) void {
            self.local_static = local_static;
            self.endpoint = endpoint;
            self.is_initiator = is_initiator;
            self.rekey_triggered = false;
            self.rekey_requested = false;
            self.session_created = now;
            self.last_sent = now;
            self.last_received = now;
            self.clearPendingHandshake();
            self.previous = self.current;
            self.current = session;
            self.markOnline(now);
            if (self.current) |*current| current.setEndpoint(endpoint);
        }

        pub fn updateTimers(self: *Self, now: glib.time.instant.Time, transport_messages: usize) void {
            if (transport_messages != 0) {
                if (self.current) |current| {
                    if (self.is_initiator and !self.rekey_triggered and self.pending_handshake == null) {
                        if (current.sendNonce() >= self.timer_config.rekey_after_messages or
                            current.recvMaxNonce() >= self.timer_config.rekey_after_messages or
                            glib.time.instant.sub(now, self.session_created) >= self.timer_config.rekey_after_time)
                        {
                            self.rekey_requested = true;
                        }
                    }
                }
            }

            self.recomputeTimers(
                self.timer_config.keepalive_timeout,
                self.timer_config.rekey_after_time,
                self.timer_config.rekey_timeout,
                self.timer_config.handshake_attempt,
                self.timer_config.offline_timeout,
                self.timer_config.session_cleanup,
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
            keepalive_timeout: glib.time.duration.Duration,
            rekey_after_time: glib.time.duration.Duration,
            rekey_timeout: glib.time.duration.Duration,
            handshake_attempt: glib.time.duration.Duration,
            offline_timeout: glib.time.duration.Duration,
            session_cleanup: glib.time.duration.Duration,
        ) void {
            const safe_keepalive_timeout = root.nonNegativeDuration(keepalive_timeout);
            const safe_rekey_after_time = root.nonNegativeDuration(rekey_after_time);
            const safe_rekey_timeout = root.nonNegativeDuration(rekey_timeout);
            const safe_handshake_attempt = root.nonNegativeDuration(handshake_attempt);
            const safe_offline_timeout = root.nonNegativeDuration(offline_timeout);
            const safe_session_cleanup = root.nonNegativeDuration(session_cleanup);

            if (self.current != null and !self.is_offline and self.last_received > self.last_sent) {
                self.timers.set(.keepalive_deadline, glib.time.instant.add(self.last_received, safe_keepalive_timeout));
            } else {
                self.timers.set(.keepalive_deadline, null);
            }

            if (self.current != null and !self.is_offline and self.persistent_keepalive and self.keepalive_interval != null) {
                const interval = self.keepalive_interval.?;
                const safe_interval: glib.time.duration.Duration = if (interval <= 0) glib.time.duration.MilliSecond else interval;
                self.timers.set(.persistent_keepalive_deadline, glib.time.instant.add(self.last_sent, safe_interval));
            } else {
                self.timers.set(.persistent_keepalive_deadline, null);
            }

            if (self.current != null and !self.is_offline and self.is_initiator and !self.rekey_triggered) {
                if (self.rekey_requested) {
                    self.timers.set(.rekey_deadline, @max(self.last_received, self.last_sent));
                } else {
                    self.timers.set(.rekey_deadline, glib.time.instant.add(self.session_created, safe_rekey_after_time));
                }
            } else {
                self.timers.set(.rekey_deadline, null);
            }

            if (self.current != null and !self.is_offline) {
                const deadline = glib.time.instant.add(self.last_received, safe_offline_timeout);
                self.offline_deadline = deadline;
                self.timers.set(.offline_deadline, deadline);
            } else {
                self.offline_deadline = null;
                self.timers.set(.offline_deadline, null);
            }

            if (self.pending_handshake) |pending_handshake| {
                self.timers.set(.handshake_retry_deadline, glib.time.instant.add(pending_handshake.last_sent, safe_rekey_timeout));
                self.timers.set(.handshake_deadline, glib.time.instant.add(pending_handshake.attempt_started, safe_handshake_attempt));
            } else {
                self.timers.set(.handshake_retry_deadline, null);
                self.timers.set(.handshake_deadline, null);
            }

            if (self.previous) |previous| {
                self.timers.set(
                    .cleanup_deadline,
                    glib.time.instant.add(@max(previous.lastReceivedTime(), previous.lastSentTime()), safe_session_cleanup),
                );
            } else {
                self.timers.set(.cleanup_deadline, null);
            }
        }
    };
}

fn normalizeTimerConfig(config: PeerTimerConfig) PeerTimerConfig {
    var normalized = config;
    normalized.keepalive_timeout = nonNegativeDuration(normalized.keepalive_timeout);
    normalized.rekey_after_time = nonNegativeDuration(normalized.rekey_after_time);
    normalized.rekey_timeout = nonNegativeDuration(normalized.rekey_timeout);
    normalized.handshake_attempt = nonNegativeDuration(normalized.handshake_attempt);
    normalized.offline_timeout = nonNegativeDuration(normalized.offline_timeout);
    normalized.session_cleanup = nonNegativeDuration(normalized.session_cleanup);
    return normalized;
}

fn nonNegativeDuration(duration: glib.time.duration.Duration) glib.time.duration.Duration {
    return @max(duration, 0);
}

pub fn TestRunner(comptime grt: type) glib.testing.TestRunner {
    const testing_api = glib.testing;
    const giznet = @import("../../giznet.zig");

    const Runner = struct {
        pub fn init(self: *@This(), allocator: glib.std.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: glib.std.mem.Allocator) bool {
            _ = self;
            _ = allocator;

            tryCase(grt) catch |err| {
                t.logErrorf("giznet/noise Peer unit failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: glib.std.mem.Allocator) void {
            _ = allocator;
            grt.std.testing.allocator.destroy(self);
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
                .keepalive_timeout = 10,
                .rekey_after_time = 50,
                .rekey_timeout = 5,
                .handshake_attempt = 20,
                .offline_timeout = 60,
                .session_cleanup = 40,
                .rekey_after_messages = 8,
            };

            const negative_timer_config: Peer.TimerConfig = .{
                .keepalive_timeout = -1,
                .rekey_after_time = -1,
                .rekey_timeout = -1,
                .handshake_attempt = -1,
                .offline_timeout = -1,
                .session_cleanup = -1,
                .rekey_after_messages = 8,
            };

            const negative_peer = Peer.init(responder_pair.public, negative_timer_config);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), negative_peer.timer_config.keepalive_timeout);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), negative_peer.timer_config.rekey_after_time);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), negative_peer.timer_config.rekey_timeout);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), negative_peer.timer_config.handshake_attempt);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), negative_peer.timer_config.offline_timeout);
            try grt.std.testing.expectEqual(@as(glib.time.duration.Duration, 0), negative_peer.timer_config.session_cleanup);

            var peer = Peer.init(responder_pair.public, timer_config);
            try grt.std.testing.expect(peer.key.eql(responder_pair.public));
            try grt.std.testing.expect(peer.isCompletelyIdle());
            try grt.std.testing.expect(!peer.persistent_keepalive);
            try grt.std.testing.expectEqual(@as(?glib.time.duration.Duration, null), peer.keepalive_interval);

            const handshake = try Handshake.initInitiator(initiator_pair, responder_pair.public, 77);
            peer.startPendingHandshake(initiator_pair.public, endpoint_one, 77, handshake, 15, 100);
            try grt.std.testing.expect(peer.pending_handshake != null);
            try grt.std.testing.expect(peer.local_static.eql(initiator_pair.public));
            try grt.std.testing.expect(peer.persistent_keepalive);
            try grt.std.testing.expectEqual(@as(?glib.time.duration.Duration, 15), peer.keepalive_interval);
            try grt.std.testing.expect(giznet.eqlAddrPort(peer.pending_handshake.?.endpoint, endpoint_one));
            try grt.std.testing.expectEqual(@as(?u32, 77), if (peer.pending_handshake) |pending_handshake| pending_handshake.local_session_index else null);
            try grt.std.testing.expect(peer.pending_handshake != null);

            peer.pending_handshake.?.last_sent = 111;
            peer.updateTimers(111, 0);
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 116), peer.timers.get(.handshake_retry_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 120), peer.timers.get(.handshake_deadline));

            peer.clearPendingHandshake();
            try grt.std.testing.expect(peer.pending_handshake == null);
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), peer.timers.get(.handshake_retry_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), peer.timers.get(.handshake_deadline));

            const session_one = makeSession(Session, responder_pair.public, endpoint_one, 1, 2, 0x11, 0x22);
            peer.establish(initiator_pair.public, endpoint_one, session_one, true, 200);
            try grt.std.testing.expect(peer.current != null);
            try grt.std.testing.expect(peer.previous == null);
            try grt.std.testing.expectEqual(@as(u32, 1), peer.current.?.localIndex());
            try grt.std.testing.expect(peer.current != null and peer.current.?.canSend());
            try grt.std.testing.expect(!peer.is_offline);

            const session_two = makeSession(Session, responder_pair.public, endpoint_two, 3, 4, 0x33, 0x44);
            peer.establish(initiator_pair.public, endpoint_two, session_two, true, 300);
            try grt.std.testing.expectEqual(@as(u32, 3), peer.current.?.localIndex());
            try grt.std.testing.expectEqual(@as(u32, 1), peer.previous.?.localIndex());
            try grt.std.testing.expect(giznet.eqlAddrPort(peer.endpoint, endpoint_two));

            peer.endpoint = endpoint_three;
            peer.last_received = 310;
            if (peer.current) |*current| current.setEndpoint(endpoint_three);
            if (peer.previous) |*previous| previous.setEndpoint(endpoint_three);
            peer.updateTimers(310, 1);
            try grt.std.testing.expect(giznet.eqlAddrPort(peer.endpoint, endpoint_three));
            try grt.std.testing.expect(giznet.eqlAddrPort(peer.current.?.endpointValue(), endpoint_three));
            try grt.std.testing.expect(giznet.eqlAddrPort(peer.previous.?.endpointValue(), endpoint_three));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 320), peer.timers.get(.keepalive_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 315), peer.timers.get(.persistent_keepalive_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 350), peer.timers.get(.rekey_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 370), peer.timers.get(.offline_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, 370), peer.offline_deadline);

            peer.rekey_triggered = true;
            peer.rekey_requested = false;
            peer.updateTimers(310, 0);
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), peer.timers.get(.rekey_deadline));
            peer.rekey_triggered = false;
            peer.rekey_requested = false;

            peer.markOffline();
            peer.updateTimers(310, 0);
            try grt.std.testing.expect(peer.is_offline);
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), peer.timers.get(.offline_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), peer.timers.get(.keepalive_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), peer.timers.get(.persistent_keepalive_deadline));
            try grt.std.testing.expectEqual(@as(?glib.time.instant.Time, null), peer.offline_deadline);

            peer.current = peer.previous;
            peer.previous = null;
            try grt.std.testing.expectEqual(@as(u32, 1), peer.current.?.localIndex());
            try grt.std.testing.expect(peer.previous == null);
            peer.current = null;
            try grt.std.testing.expect(peer.isCompletelyIdle());
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

    const value = grt.std.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}
