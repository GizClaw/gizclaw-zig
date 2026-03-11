const std = @import("std");
const runtime = @import("embed").runtime;
const consts = @import("consts.zig");
const errors = @import("errors.zig");
const conn_mod = @import("conn.zig");
const endpoint_mod = @import("endpoint.zig");

const Allocator = std.mem.Allocator;
const Endpoint = endpoint_mod.Endpoint;
const DialError = errors.DialError;
const max_handshake_msg_len = 65536;

fn ValidateHandshakeRespError() type {
    return DialError || error{IgnorePacket};
}

fn validateHandshakeResp(
    comptime Session: type,
    comptime Handshake: type,
    comptime ConnType: type,
    conn: *ConnType,
    hs: *Handshake,
    packet: []const u8,
    from_addr: Endpoint,
    local_idx: u32,
) ValidateHandshakeRespError()!Session.HandshakeResp {
    const resp = Session.parseHandshakeResp(packet) catch return error.IgnorePacket;
    if (resp.receiver_index != local_idx) return error.IgnorePacket;

    var noise_msg: [Session.key_size + 16]u8 = undefined;
    @memcpy(noise_msg[0..Session.key_size], resp.ephemeral.asBytes());
    @memcpy(noise_msg[Session.key_size..][0..16], &resp.empty_encrypted);

    var payload_buf: [1]u8 = undefined;
    _ = hs.readMessage(&noise_msg, &payload_buf) catch return DialError.HandshakeError;
    if (!hs.isFinished()) return DialError.HandshakeError;

    conn.setRemoteAddr(from_addr);
    return resp;
}

/// Dial options, generic over Noise types.
pub fn DialOptions(
    comptime Session: type,
    comptime TransportImpl: type,
    comptime TimeImpl: type,
) type {
    return struct {
        allocator: Allocator,
        local_key: Session.KeyPair,
        remote_pk: Session.Key,
        transport: TransportImpl,
        remote_addr: Endpoint,
        time: TimeImpl,
        deadline_ms: ?u64 = null,
    };
}

/// Dials a remote peer and returns an established connection.
///
/// Implements WireGuard's retry mechanism:
///   1. Send handshake initiation
///   2. Wait up to rekey_timeout (5 s) for response
///   3. Retransmit with new ephemeral keys on timeout
///   4. Give up after deadline
pub fn dial(
    comptime Session: type,
    comptime Handshake: type,
    comptime TransportImpl: type,
    comptime MutexImpl: type,
    comptime CondImpl: type,
    comptime TimeImpl: type,
    opts: DialOptions(Session, TransportImpl, TimeImpl),
) DialError!*conn_mod.Conn(Session, Handshake, TransportImpl, MutexImpl, CondImpl, TimeImpl) {
    const ConnType = conn_mod.Conn(Session, Handshake, TransportImpl, MutexImpl, CondImpl, TimeImpl);

    if (Session.Key.isZero(opts.remote_pk))
        return DialError.MissingRemotePK;

    const now = opts.time.nowMs();
    const deadline = opts.deadline_ms orelse (now + consts.rekey_attempt_time_ms);

    const conn = opts.allocator.create(ConnType) catch return DialError.OutOfMemory;
    conn.* = ConnType.init(opts.allocator, .{
        .local_key = opts.local_key,
        .remote_pk = opts.remote_pk,
        .transport = opts.transport,
        .remote_addr = opts.remote_addr,
    }, opts.time);
    errdefer {
        conn.deinit();
        opts.allocator.destroy(conn);
    }

    const local_idx = conn.getLocalIndex();
    conn.setState(.handshaking);

    while (true) {
        const current_time = opts.time.nowMs();
        if (current_time >= deadline) {
            conn.setState(.new);
            return DialError.HandshakeTimeout;
        }

        var hs = Handshake.init(.{
            .pattern = .IK,
            .initiator = true,
            .local_static = opts.local_key,
            .remote_static = opts.remote_pk,
        }) catch {
            conn.setState(.new);
            return DialError.HandshakeError;
        };

        var msg1_buf: [max_handshake_msg_len]u8 = undefined;
        var wire_buf: [max_handshake_msg_len + 5]u8 = undefined;
        const msg1_len = hs.writeMessage(&[_]u8{}, &msg1_buf) catch {
            conn.setState(.new);
            return DialError.HandshakeError;
        };

        const ephemeral = hs.localEphemeral() orelse {
            conn.setState(.new);
            return DialError.HandshakeError;
        };

        const wire_msg = Session.buildHandshakeInit(&wire_buf, local_idx, &ephemeral, msg1_buf[Session.key_size..msg1_len]) catch {
            conn.setState(.new);
            return DialError.HandshakeError;
        };

        opts.transport.sendTo(wire_msg, opts.remote_addr) catch {
            conn.setState(.new);
            return DialError.TransportError;
        };

        const recv_time = opts.time.nowMs();
        const rekey_deadline = recv_time + consts.rekey_timeout_ms;
        const read_deadline = @min(rekey_deadline, deadline);

        opts.transport.setReadDeadline(read_deadline) catch {
            conn.setState(.new);
            return DialError.TransportError;
        };

        var buf: [65536]u8 = undefined;
        var resp: Session.HandshakeResp = undefined;
        var matched = false;

        const ChildTransport = if (@typeInfo(TransportImpl) == .pointer) std.meta.Child(TransportImpl) else TransportImpl;

        while (!matched) {
            const recv_result = opts.transport.recvFrom(&buf);

            opts.transport.setReadDeadline(null) catch {};

            const result = recv_result catch |err| {
                if (err == ChildTransport.Error.WouldBlock) break;
                conn.setState(.new);
                return DialError.TransportError;
            };

            resp = validateHandshakeResp(
                Session,
                Handshake,
                ConnType,
                conn,
                &hs,
                buf[0..result.bytes_read],
                result.from_addr,
                local_idx,
            ) catch |err| switch (err) {
                error.IgnorePacket => {
                    opts.transport.setReadDeadline(read_deadline) catch {};
                    continue;
                },
                else => |dial_err| {
                    conn.setState(.new);
                    return dial_err;
                },
            };
            matched = true;
        }

        opts.transport.setReadDeadline(null) catch {};

        if (!matched) continue;

        const ciphers = hs.split() catch {
            conn.setState(.new);
            return DialError.HandshakeError;
        };

        const session = Session.init(.{
            .local_index = local_idx,
            .remote_index = resp.sender_index,
            .send_key = ciphers[0].getKey(),
            .recv_key = ciphers[1].getKey(),
            .remote_pk = opts.remote_pk,
            .now_ms = opts.time.nowMs(),
        });

        conn.setSession(session);
        conn.setInitiator(true);
        conn.setState(.established);

        return conn;
    }
}

pub fn StdDialOptions(comptime Session: type, comptime TransportImpl: type) type {
    return DialOptions(Session, TransportImpl, runtime.std.Time);
}

pub fn stdDial(
    comptime Session: type,
    comptime Handshake: type,
    comptime TransportImpl: type,
    opts: StdDialOptions(Session, TransportImpl),
) DialError!*conn_mod.StdConn(Session, Handshake, TransportImpl) {
    return dial(
        Session,
        Handshake,
        TransportImpl,
        runtime.std.Mutex,
        runtime.std.Condition,
        runtime.std.Time,
        opts,
    );
}

const testing = std.testing;

const TestSession = struct {
    pub const Key = struct {
        data: [32]u8 = [_]u8{0} ** 32,

        pub const zero = Key{};

        pub fn isZero(self: Key) bool {
            for (self.data) |b| {
                if (b != 0) return false;
            }
            return true;
        }

        pub fn asBytes(self: *const Key) *const [32]u8 {
            return &self.data;
        }
    };

    pub const KeyPair = struct {
        public: Key = .{},
        secret: Key = .{},
    };

    pub const tag_size: usize = 4;
    pub const key_size: usize = 32;

    local_index: u32,
    remote_index: u32,
    created_ms: u64 = 0,
    last_received_ms: u64 = 0,
    last_sent_ms: u64 = 0,

    pub fn generateIndex() u32 {
        return 7;
    }

    pub fn init(cfg: struct {
        local_index: u32,
        remote_index: u32,
        send_key: Key,
        recv_key: Key,
        remote_pk: Key,
        now_ms: u64,
    }) TestSession {
        _ = cfg.send_key;
        _ = cfg.recv_key;
        _ = cfg.remote_pk;
        return .{
            .local_index = cfg.local_index,
            .remote_index = cfg.remote_index,
            .created_ms = cfg.now_ms,
            .last_received_ms = cfg.now_ms,
            .last_sent_ms = cfg.now_ms,
        };
    }

    pub fn remoteIndex(self: *TestSession) u32 {
        return self.remote_index;
    }

    pub fn localIndex(self: *const TestSession) u32 {
        return self.local_index;
    }

    pub fn sendNonce(_: *TestSession) u64 {
        return 0;
    }

    pub fn recvMaxNonce(_: *TestSession) u64 {
        return 0;
    }

    pub fn expire(_: *TestSession) void {}

    pub fn encrypt(_: *TestSession, plaintext: []const u8, ciphertext: []u8, _: u64) !u64 {
        @memcpy(ciphertext[0..plaintext.len], plaintext);
        @memset(ciphertext[plaintext.len..][0..tag_size], 0xAA);
        return 0;
    }

    pub fn decrypt(_: *TestSession, ciphertext: []const u8, _: u64, plaintext: []u8, _: u64) !usize {
        const payload_len = ciphertext.len - tag_size;
        @memcpy(plaintext[0..payload_len], ciphertext[0..payload_len]);
        return payload_len;
    }

    pub fn buildTransportMessage(_: Allocator, _: u32, _: u64, _: []const u8) ![]u8 {
        return error.Unused;
    }

    pub fn parseTransportMessage(_: []const u8) !void {
        return error.Unused;
    }

    pub fn buildHandshakeInit(out: []u8, _: u32, _: *const Key, static_encrypted: []const u8) ![]u8 {
        const msg_len = 1 + 4 + 32 + static_encrypted.len;
        if (out.len < msg_len) return error.BufferTooSmall;
        @memset(out[0..msg_len], 0);
        return out[0..msg_len];
    }

    pub const HandshakeResp = struct {
        sender_index: u32,
        receiver_index: u32,
        ephemeral: Key,
        empty_encrypted: [16]u8,
    };

    pub fn parseHandshakeResp(data: []const u8) !HandshakeResp {
        if (data.len < 8) return error.MessageTooShort;
        var ephemeral = Key{};
        if (data.len > 8) ephemeral.data[0] = data[8];
        return .{
            .sender_index = std.mem.readInt(u32, data[0..4], .little),
            .receiver_index = std.mem.readInt(u32, data[4..8], .little),
            .ephemeral = ephemeral,
            .empty_encrypted = [_]u8{0} ** 16,
        };
    }
};

const TestHandshake = struct {
    finished: bool = false,

    pub const InitConfig = struct {
        pattern: enum { IK },
        initiator: bool,
        local_static: TestSession.KeyPair,
        remote_static: TestSession.Key,
    };

    pub fn init(_: InitConfig) !TestHandshake {
        return .{};
    }

    pub fn writeMessage(_: *TestHandshake, _: []const u8, out: []u8) !usize {
        const msg_len = TestSession.key_size + 48;
        @memset(out[0..msg_len], 0);
        return msg_len;
    }

    pub fn localEphemeral(_: *TestHandshake) ?TestSession.Key {
        return .{};
    }

    pub fn readMessage(self: *TestHandshake, _: []const u8, _: []u8) !usize {
        self.finished = true;
        return 0;
    }

    pub fn isFinished(self: *const TestHandshake) bool {
        return self.finished;
    }

    pub fn split(_: *const TestHandshake) !struct { Cipher, Cipher } {
        return .{ .{}, .{} };
    }

    const Cipher = struct {
        bytes: TestSession.Key = .{},

        pub fn getKey(self: @This()) TestSession.Key {
            return self.bytes;
        }
    };
};

const TestTransport = struct {
    response: [64]u8 = [_]u8{0} ** 64,
    response_len: usize = 0,
    read_deadline: ?u64 = null,
    send_count: usize = 0,
    last_sent_len: usize = 0,

    pub const Error = error{WouldBlock};

    pub const RecvResult = struct {
        bytes_read: usize,
        from_addr: Endpoint,
    };

    pub fn sendTo(self: *TestTransport, data: []const u8, _: Endpoint) !void {
        self.send_count += 1;
        self.last_sent_len = data.len;
    }

    pub fn recvFrom(self: *TestTransport, buf: []u8) !RecvResult {
        @memcpy(buf[0..self.response_len], self.response[0..self.response_len]);
        return .{
            .bytes_read = self.response_len,
            .from_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 9000),
        };
    }

    pub fn setReadDeadline(self: *TestTransport, deadline_ms: ?u64) !void {
        self.read_deadline = deadline_ms;
    }
};

const TestTime = struct {
    now_ms: u64 = 1000,

    pub fn nowMs(self: TestTime) u64 {
        return self.now_ms;
    }

    pub fn sleepMs(_: TestTime, _: u32) void {}
};

test "dial marks established connection as initiator" {
    var transport = TestTransport{};
    std.mem.writeInt(u32, transport.response[0..4], 99, .little);
    std.mem.writeInt(u32, transport.response[4..8], TestSession.generateIndex(), .little);
    transport.response_len = 8;

    const conn = try dial(
        TestSession,
        TestHandshake,
        *TestTransport,
        runtime.std.Mutex,
        runtime.std.Condition,
        TestTime,
        .{
            .allocator = testing.allocator,
            .local_key = .{},
            .remote_pk = TestSession.Key{ .data = [_]u8{1} ** 32 },
            .transport = &transport,
            .remote_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 51820),
            .time = .{},
        },
    );
    defer {
        conn.deinit();
        testing.allocator.destroy(conn);
    }

    conn.mu.lock();
    defer conn.mu.unlock();
    try testing.expect(conn.is_initiator);
    try testing.expectEqual(conn_mod.ConnState.established, conn.state);
}

test "dial skips dirty packets and succeeds on valid response" {
    const MultiTransport = struct {
        responses: [8]struct { data: [64]u8, len: usize } = undefined,
        response_count: usize = 0,
        recv_index: usize = 0,
        read_deadline: ?u64 = null,
        send_count: usize = 0,

        pub const Error = error{WouldBlock};

        pub const RecvResult = struct {
            bytes_read: usize,
            from_addr: Endpoint,
        };

        pub fn sendTo(self: *@This(), _: []const u8, _: Endpoint) !void {
            self.send_count += 1;
        }

        pub fn recvFrom(self: *@This(), buf: []u8) Error!RecvResult {
            if (self.recv_index >= self.response_count) return Error.WouldBlock;
            const resp = &self.responses[self.recv_index];
            @memcpy(buf[0..resp.len], resp.data[0..resp.len]);
            self.recv_index += 1;
            return .{
                .bytes_read = resp.len,
                .from_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 9000),
            };
        }

        pub fn setReadDeadline(self: *@This(), deadline_ms: ?u64) !void {
            self.read_deadline = deadline_ms;
        }
    };

    var transport = MultiTransport{};

    // First: garbage packet (too short to parse)
    @memcpy(transport.responses[0].data[0..2], &[_]u8{ 0xFF, 0xFE });
    transport.responses[0].len = 2;
    transport.response_count = 1;

    // Second: valid-length but wrong receiver_index
    std.mem.writeInt(u32, transport.responses[1].data[0..4], 99, .little);
    std.mem.writeInt(u32, transport.responses[1].data[4..8], 999, .little);
    transport.responses[1].len = 8;
    transport.response_count = 2;

    // Third: valid response with correct receiver_index
    std.mem.writeInt(u32, transport.responses[2].data[0..4], 99, .little);
    std.mem.writeInt(u32, transport.responses[2].data[4..8], TestSession.generateIndex(), .little);
    transport.responses[2].len = 8;
    transport.response_count = 3;

    const conn = try dial(
        TestSession,
        TestHandshake,
        *MultiTransport,
        runtime.std.Mutex,
        runtime.std.Condition,
        TestTime,
        .{
            .allocator = testing.allocator,
            .local_key = .{},
            .remote_pk = TestSession.Key{ .data = [_]u8{1} ** 32 },
            .transport = &transport,
            .remote_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 51820),
            .time = .{},
        },
    );
    defer {
        conn.deinit();
        testing.allocator.destroy(conn);
    }

    conn.mu.lock();
    defer conn.mu.unlock();
    try testing.expect(conn.is_initiator);
    try testing.expectEqual(conn_mod.ConnState.established, conn.state);
}

test "validateHandshakeResp keeps remote address unchanged on failed Noise validation" {
    const FailingReadHandshake = struct {
        finished: bool = false,

        pub const InitConfig = TestHandshake.InitConfig;

        pub fn init(cfg: InitConfig) !@This() {
            _ = cfg;
            return .{};
        }

        pub fn writeMessage(_: *@This(), _: []const u8, _: []u8) !usize {
            return error.Unused;
        }

        pub fn localEphemeral(_: *@This()) ?TestSession.Key {
            return .{};
        }

        pub fn readMessage(_: *@This(), msg: []const u8, _: []u8) !usize {
            if (msg.len > 0 and msg[0] == 0xFF) return error.InvalidHandshake;
            return 0;
        }

        pub fn isFinished(self: *const @This()) bool {
            return self.finished;
        }

        pub fn split(_: *const @This()) !struct { TestHandshake.Cipher, TestHandshake.Cipher } {
            return .{ .{}, .{} };
        }
    };

    const ConnType = conn_mod.Conn(
        TestSession,
        FailingReadHandshake,
        *TestTransport,
        runtime.std.Mutex,
        runtime.std.Condition,
        TestTime,
    );

    var transport = TestTransport{};
    var conn = try testing.allocator.create(ConnType);
    defer {
        conn.deinit();
        testing.allocator.destroy(conn);
    }
    const original_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 51820);
    conn.* = ConnType.init(testing.allocator, .{
        .local_key = .{},
        .remote_pk = TestSession.Key{ .data = [_]u8{1} ** 32 },
        .transport = &transport,
        .remote_addr = original_addr,
    }, .{});

    var hs = try FailingReadHandshake.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = .{},
        .remote_static = TestSession.Key{ .data = [_]u8{1} ** 32 },
    });

    var packet: [9]u8 = [_]u8{0} ** 9;
    std.mem.writeInt(u32, packet[0..4], 99, .little);
    std.mem.writeInt(u32, packet[4..8], conn.getLocalIndex(), .little);
    packet[8] = 0xFF;

    try testing.expectError(
        DialError.HandshakeError,
        validateHandshakeResp(
            TestSession,
            FailingReadHandshake,
            ConnType,
            conn,
            &hs,
            &packet,
            Endpoint.init(.{ 10, 0, 0, 9 }, 9999),
            conn.getLocalIndex(),
        ),
    );
    try testing.expect(conn.remote_addr != null);
    try testing.expect(conn.remote_addr.?.eql(original_addr));
}

test "dial destroys conn shell on send failure" {
    const FailingSendTransport = struct {
        pub const Error = error{WouldBlock};

        pub const RecvResult = struct {
            bytes_read: usize,
            from_addr: Endpoint,
        };

        pub fn sendTo(_: *@This(), _: []const u8, _: Endpoint) !void {
            return error.BrokenPipe;
        }

        pub fn recvFrom(_: *@This(), _: []u8) !RecvResult {
            return Error.WouldBlock;
        }

        pub fn setReadDeadline(_: *@This(), _: ?u64) !void {}
    };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        testing.expect(gpa.deinit() == .ok) catch @panic("dial leaked allocation on failure");
    }

    var transport = FailingSendTransport{};
    try testing.expectError(
        DialError.TransportError,
        dial(
            TestSession,
            TestHandshake,
            *FailingSendTransport,
            runtime.std.Mutex,
            runtime.std.Condition,
            TestTime,
            .{
                .allocator = gpa.allocator(),
                .local_key = .{},
                .remote_pk = TestSession.Key{ .data = [_]u8{1} ** 32 },
                .transport = &transport,
                .remote_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 51820),
                .time = .{},
            },
        ),
    );
}

test "dial accepts longer variable-length IK initiation messages" {
    const LongInitHandshake = struct {
        finished: bool = false,

        pub const InitConfig = TestHandshake.InitConfig;

        pub fn init(cfg: InitConfig) !@This() {
            _ = cfg;
            return .{};
        }

        pub fn writeMessage(_: *@This(), _: []const u8, out: []u8) !usize {
            const msg_len = TestSession.key_size + 64;
            if (out.len < msg_len) return error.BufferTooSmall;
            @memset(out[0..msg_len], 0xAB);
            return msg_len;
        }

        pub fn localEphemeral(_: *@This()) ?TestSession.Key {
            return .{};
        }

        pub fn readMessage(self: *@This(), _: []const u8, _: []u8) !usize {
            self.finished = true;
            return 0;
        }

        pub fn isFinished(self: *const @This()) bool {
            return self.finished;
        }

        pub fn split(_: *const @This()) !struct { TestHandshake.Cipher, TestHandshake.Cipher } {
            return .{ .{}, .{} };
        }
    };

    var transport = TestTransport{};
    std.mem.writeInt(u32, transport.response[0..4], 99, .little);
    std.mem.writeInt(u32, transport.response[4..8], TestSession.generateIndex(), .little);
    transport.response_len = 8;

    const conn = try dial(
        TestSession,
        LongInitHandshake,
        *TestTransport,
        runtime.std.Mutex,
        runtime.std.Condition,
        TestTime,
        .{
            .allocator = testing.allocator,
            .local_key = .{},
            .remote_pk = TestSession.Key{ .data = [_]u8{1} ** 32 },
            .transport = &transport,
            .remote_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 51820),
            .time = .{},
        },
    );
    defer {
        conn.deinit();
        testing.allocator.destroy(conn);
    }

    try testing.expectEqual(conn_mod.ConnState.established, conn.getState());
    try testing.expectEqual(@as(usize, 1 + 4 + TestSession.key_size + 64), transport.last_sent_len);
}

test "dial seeds session timestamps from current time" {
    var transport = TestTransport{};
    std.mem.writeInt(u32, transport.response[0..4], 99, .little);
    std.mem.writeInt(u32, transport.response[4..8], TestSession.generateIndex(), .little);
    transport.response_len = 8;

    const conn = try dial(
        TestSession,
        TestHandshake,
        *TestTransport,
        runtime.std.Mutex,
        runtime.std.Condition,
        TestTime,
        .{
            .allocator = testing.allocator,
            .local_key = .{},
            .remote_pk = TestSession.Key{ .data = [_]u8{1} ** 32 },
            .transport = &transport,
            .remote_addr = Endpoint.init(.{ 127, 0, 0, 1 }, 51820),
            .time = .{ .now_ms = 4242 },
        },
    );
    defer {
        conn.deinit();
        testing.allocator.destroy(conn);
    }

    conn.mu.lock();
    defer conn.mu.unlock();
    try testing.expect(conn.current != null);
    try testing.expectEqual(@as(u64, 4242), conn.current.?.created_ms);
    try testing.expectEqual(@as(u64, 4242), conn.current.?.last_sent_ms);
    try testing.expectEqual(@as(u64, 4242), conn.current.?.last_received_ms);
}
