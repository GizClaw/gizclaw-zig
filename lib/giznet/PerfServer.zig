//! Giznet-owned packet and stream perf server.

const glib = @import("glib");

const Conn = @import("Conn.zig");
const Stream = @import("Stream.zig");

pub const default_control_protocol: u8 = 0x7e;
pub const default_packet_protocol: u8 = 0x7d;
pub const default_stream_service: u64 = 0x67697a6e65747066;
pub const default_timeout: glib.time.duration.Duration = 5 * glib.time.duration.Second;

const magic: u32 = 0x47504631;
const version: u8 = 1;
const min_packet_payload_size: usize = @sizeOf(u32);
pub const max_packet_payload_size: usize = 2048;
pub const max_stream_chunk_size: usize = 16 * 1024;
pub const request_wire_size: usize = 64;
pub const result_wire_size: usize = 224;

pub const Mode = enum(u8) {
    peer_packet = 1,
    kcp_stream = 2,
};

pub const Direction = enum(u8) {
    up = 1,
    down = 2,
    duplex = 3,
    ping = 4,
    all = 5,
};

pub const Status = enum(u8) {
    ok = 0,
    error_status = 1,
};

pub const ErrorStage = enum(u8) {
    none = 0,
    peer_packet = 1,
    kcp_stream = 2,
    timeout = 3,
    runtime = 4,
};

const FrameKind = enum(u8) {
    request = 1,
    result = 2,
};

pub const KcpParams = struct {
    send_window: u32 = 0,
    recv_window: u32 = 0,
    nodelay: u8 = 0,
    interval_ms: u32 = 0,
    resend: u32 = 0,
    nc: u8 = 0,
};

pub const Config = struct {
    mode: Mode = .peer_packet,
    direction: Direction = .up,
    packet_protocol: u8 = default_packet_protocol,
    packet_count: u32 = 256,
    packet_payload_size: u16 = 256,
    packet_pps: u32 = 0,
    stream_service: u64 = default_stream_service,
    stream_bytes: u64 = 1024 * 1024,
    stream_chunk_size: u32 = 8192,
    timeout: glib.time.duration.Duration = default_timeout,
    kcp: KcpParams = .{},
};

pub const Counters = struct {
    sent_bytes: u64 = 0,
    received_bytes: u64 = 0,
    sent_packets: u64 = 0,
    received_packets: u64 = 0,
    expected_packets: u64 = 0,
    missing_packets: u64 = 0,
    duplicate_packets: u64 = 0,
    out_of_order_packets: u64 = 0,
    mismatched_packets: u64 = 0,
    elapsed_ns: u64 = 0,
    first_response_ns: u64 = 0,
    rtt_ns: u64 = 0,
    mbps: u64 = 0,
};

pub const Result = struct {
    mode: Mode = .peer_packet,
    direction: Direction = .up,
    status: Status = .ok,
    error_stage: ErrorStage = .none,
    client: Counters = .{},
    server: Counters = .{},
};

pub fn make(comptime grt: type) type {
    return struct {
        pub const Options = struct {
            control_protocol: u8 = default_control_protocol,
            task_options: grt.task.Options = .{},
        };

        pub fn serveOnce(conn: Conn, options: Options) !Result {
            var frame: [result_wire_size]u8 = undefined;
            const request = try readRequest(conn, options.control_protocol, &frame, default_timeout);
            const result = runRequest(conn, request, options) catch |err| errorResult(request, err);
            const len = try encodeResult(&frame, result);
            _ = try conn.write(options.control_protocol, frame[0..len]);
            return result;
        }

        fn runRequest(conn: Conn, config: Config, options: Options) !Result {
            if (config.direction == .all) return error.InvalidPerfDirection;
            switch (config.mode) {
                .peer_packet => return runPeerPacket(conn, config, options),
                .kcp_stream => return runKcpStream(conn, config, options),
            }
        }

        fn runPeerPacket(conn: Conn, config: Config, options: Options) !Result {
            try validatePacketConfig(config);
            if (config.packet_protocol == options.control_protocol) return error.InvalidPerfProtocol;
            var result = Result{
                .mode = .peer_packet,
                .direction = config.direction,
            };
            switch (config.direction) {
                .up => {
                    result.server = try receivePeerPackets(conn, config, .{ .control_protocol = options.control_protocol });
                },
                .down => {
                    result.server = try sendPeerPackets(conn, config);
                },
                .duplex => {
                    const SendTask = struct {
                        conn: Conn,
                        config: Config,
                        counters: Counters = .{},
                        err: ?anyerror = null,

                        fn run(task: *@This()) void {
                            task.counters = sendPeerPackets(task.conn, task.config) catch |err| {
                                task.err = err;
                                return;
                            };
                        }
                    };
                    var task = SendTask{ .conn = conn, .config = config };
                    const handle = try grt.task.go("giznet/perf/packet/send", options.task_options, grt.task.Routine.init(&task, SendTask.run));
                    result.server = try receivePeerPackets(conn, config, .{ .control_protocol = options.control_protocol });
                    handle.join();
                    if (task.err) |err| return err;
                    result.server.sent_bytes += task.counters.sent_bytes;
                    result.server.sent_packets += task.counters.sent_packets;
                    if (task.counters.elapsed_ns > result.server.elapsed_ns) result.server.elapsed_ns = task.counters.elapsed_ns;
                    result.server.mbps = mbpsFor(result.server.sent_bytes + result.server.received_bytes, result.server.elapsed_ns);
                },
                .ping => {
                    const start_ns = grt.time.instant.now();
                    var pong: [min_packet_payload_size]u8 = undefined;
                    writeU32(pong[0..4], 0);
                    _ = try conn.write(config.packet_protocol, &pong);
                    const end_ns = grt.time.instant.now();
                    result.server.sent_packets = 1;
                    result.server.sent_bytes = pong.len;
                    result.server.elapsed_ns = elapsedSince(start_ns, end_ns);
                    result.server.rtt_ns = result.server.elapsed_ns;
                },
                .all => return error.InvalidPerfDirection,
            }
            return result;
        }

        fn runKcpStream(conn: Conn, config: Config, options: Options) !Result {
            try validateStreamConfig(config);
            var result = Result{
                .mode = .kcp_stream,
                .direction = config.direction,
            };
            switch (config.direction) {
                .up => {
                    var stream = try conn.accept(config.timeout);
                    defer stream.deinit();
                    result.server = try readStream(stream, config);
                },
                .down => {
                    var stream = try conn.openStream(config.stream_service);
                    defer stream.deinit();
                    result.server = try writeStream(stream, config);
                },
                .duplex => {
                    var stream = try conn.accept(config.timeout);
                    defer stream.deinit();
                    const WriteTask = struct {
                        stream: Stream,
                        config: Config,
                        counters: Counters = .{},
                        err: ?anyerror = null,

                        fn run(task: *@This()) void {
                            task.counters = writeStream(task.stream, task.config) catch |err| {
                                task.err = err;
                                return;
                            };
                        }
                    };
                    var task = WriteTask{ .stream = stream, .config = config };
                    const handle = try grt.task.go("giznet/perf/stream/write", options.task_options, grt.task.Routine.init(&task, WriteTask.run));
                    result.server = try readStream(stream, config);
                    handle.join();
                    if (task.err) |err| return err;
                    result.server.sent_bytes += task.counters.sent_bytes;
                    if (task.counters.elapsed_ns > result.server.elapsed_ns) result.server.elapsed_ns = task.counters.elapsed_ns;
                    result.server.mbps = mbpsFor(result.server.sent_bytes + result.server.received_bytes, result.server.elapsed_ns);
                },
                .ping => {
                    var stream = try conn.accept(config.timeout);
                    defer stream.deinit();
                    try setStreamDeadlines(stream, config.timeout);
                    var buf: [1]u8 = undefined;
                    const start_ns = grt.time.instant.now();
                    const read_n = try stream.read(&buf);
                    if (read_n != 1) return error.ShortRead;
                    const written = try stream.write(buf[0..1]);
                    if (written != 1) return error.ShortWrite;
                    const end_ns = grt.time.instant.now();
                    result.server.received_bytes = 1;
                    result.server.sent_bytes = 1;
                    result.server.elapsed_ns = elapsedSince(start_ns, end_ns);
                    result.server.rtt_ns = result.server.elapsed_ns;
                },
                .all => return error.InvalidPerfDirection,
            }
            return result;
        }

        const ReceiveOptions = struct {
            control_protocol: u8,
            pending_result: ?*?Result = null,
        };

        fn sendPeerPackets(conn: Conn, config: Config) !Counters {
            var counters = Counters{ .expected_packets = config.packet_count };
            var buf: [max_packet_payload_size]u8 = undefined;
            const payload_size: usize = config.packet_payload_size;
            const start_ns = grt.time.instant.now();
            var seq: u32 = 0;
            while (seq < config.packet_count) : (seq += 1) {
                pace(start_ns, seq, config.packet_pps);
                writeU32(buf[0..4], seq);
                @memset(buf[4..payload_size], 0x5a);
                const written = try conn.write(config.packet_protocol, buf[0..payload_size]);
                if (written != payload_size) return error.ShortWrite;
                counters.sent_packets += 1;
                counters.sent_bytes += written;
            }
            counters.elapsed_ns = elapsedSince(start_ns, grt.time.instant.now());
            counters.mbps = mbpsFor(counters.sent_bytes, counters.elapsed_ns);
            return counters;
        }

        fn receivePeerPackets(conn: Conn, config: Config, receive_options: ReceiveOptions) !Counters {
            var counters = Counters{ .expected_packets = config.packet_count };
            var buf: [@max(max_packet_payload_size, result_wire_size)]u8 = undefined;
            const start_ns = grt.time.instant.now();
            const deadline = glib.time.instant.add(start_ns, config.timeout);
            var expected_seq: u32 = 0;
            var highest_seq: u32 = 0;
            var has_highest = false;

            while (counters.received_packets < config.packet_count) {
                const now = grt.time.instant.now();
                if (now >= deadline) break;
                const result = try conn.readTimeout(&buf, glib.time.instant.sub(deadline, now));
                if (result.protocol == receive_options.control_protocol) {
                    if (receive_options.pending_result) |pending| {
                        pending.* = try decodeResult(buf[0..result.n]);
                    }
                    continue;
                }
                if (result.protocol != config.packet_protocol) continue;
                if (result.n != config.packet_payload_size or result.n < min_packet_payload_size) {
                    counters.mismatched_packets += 1;
                    continue;
                }
                const seq = readU32(buf[0..4]);
                if (has_highest and seq <= highest_seq) {
                    counters.duplicate_packets += 1;
                    continue;
                } else {
                    if (seq != expected_seq) counters.out_of_order_packets += 1;
                    expected_seq = seq +% 1;
                    highest_seq = seq;
                    has_highest = true;
                }
                var payload_ok = true;
                for (buf[4..result.n]) |byte| {
                    if (byte != 0x5a) {
                        payload_ok = false;
                        break;
                    }
                }
                if (!payload_ok) {
                    counters.mismatched_packets += 1;
                    continue;
                }
                counters.received_packets += 1;
                counters.received_bytes += result.n;
                if (counters.first_response_ns == 0) {
                    counters.first_response_ns = elapsedSince(start_ns, grt.time.instant.now());
                }
            }

            if (config.packet_count > counters.received_packets) {
                counters.missing_packets = config.packet_count - counters.received_packets;
            }
            counters.elapsed_ns = elapsedSince(start_ns, grt.time.instant.now());
            counters.mbps = mbpsFor(counters.received_bytes, counters.elapsed_ns);
            return counters;
        }

        fn writeStream(stream: Stream, config: Config) !Counters {
            var counters = Counters{};
            try setStreamDeadlines(stream, config.timeout);
            var buf: [max_stream_chunk_size]u8 = undefined;
            const chunk_limit: usize = config.stream_chunk_size;
            @memset(buf[0..chunk_limit], 0x5a);
            const start_ns = grt.time.instant.now();
            while (counters.sent_bytes < config.stream_bytes) {
                const remaining = config.stream_bytes - counters.sent_bytes;
                const chunk_len: usize = @intCast(@min(@as(u64, @intCast(chunk_limit)), remaining));
                const written = try stream.write(buf[0..chunk_len]);
                if (written == 0) return error.ShortWrite;
                counters.sent_bytes += written;
            }
            counters.elapsed_ns = elapsedSince(start_ns, grt.time.instant.now());
            counters.mbps = mbpsFor(counters.sent_bytes, counters.elapsed_ns);
            return counters;
        }

        fn readStream(stream: Stream, config: Config) !Counters {
            var counters = Counters{};
            try setStreamDeadlines(stream, config.timeout);
            var buf: [max_stream_chunk_size]u8 = undefined;
            const chunk_limit: usize = config.stream_chunk_size;
            const start_ns = grt.time.instant.now();
            while (counters.received_bytes < config.stream_bytes) {
                const remaining = config.stream_bytes - counters.received_bytes;
                const chunk_len: usize = @intCast(@min(@as(u64, @intCast(chunk_limit)), remaining));
                const read_n = try stream.read(buf[0..chunk_len]);
                if (read_n == 0) return error.ShortRead;
                counters.received_bytes += read_n;
                if (counters.first_response_ns == 0) {
                    counters.first_response_ns = elapsedSince(start_ns, grt.time.instant.now());
                }
            }
            counters.elapsed_ns = elapsedSince(start_ns, grt.time.instant.now());
            counters.mbps = mbpsFor(counters.received_bytes, counters.elapsed_ns);
            return counters;
        }

        fn setStreamDeadlines(stream: Stream, timeout: glib.time.duration.Duration) !void {
            const deadline = glib.time.instant.add(grt.time.instant.now(), timeout);
            try stream.setReadDeadline(deadline);
            try stream.setWriteDeadline(deadline);
        }

        fn pace(start_ns: glib.time.instant.Time, sent_packets: u32, pps: u32) void {
            if (pps == 0 or sent_packets == 0) return;
            const offset: glib.time.duration.Duration = @intCast(@divTrunc(@as(u64, sent_packets) * @as(u64, @intCast(glib.time.duration.Second)), pps));
            const target = glib.time.instant.add(start_ns, offset);
            const now = grt.time.instant.now();
            if (target > now) grt.time.sleep(@intCast(glib.time.instant.sub(target, now)));
        }
    };
}

fn errorResult(config: Config, err: anyerror) Result {
    return .{
        .mode = config.mode,
        .direction = config.direction,
        .status = .error_status,
        .error_stage = switch (err) {
            error.Timeout => .timeout,
            else => switch (config.mode) {
                .peer_packet => .peer_packet,
                .kcp_stream => .kcp_stream,
            },
        },
    };
}

pub fn validatePacketConfig(config: Config) !void {
    if (config.packet_protocol == default_control_protocol) return error.InvalidPerfProtocol;
    if (config.packet_protocol == 0x00 or config.packet_protocol == 0xff) return error.InvalidPerfProtocol;
    if (config.packet_payload_size < min_packet_payload_size) return error.InvalidPacketPayloadSize;
    if (config.packet_payload_size > max_packet_payload_size) return error.InvalidPacketPayloadSize;
}

pub fn validateStreamConfig(config: Config) !void {
    if (config.stream_chunk_size == 0 or config.stream_chunk_size > max_stream_chunk_size) return error.InvalidStreamChunkSize;
}

pub fn encodeRequest(buf: []u8, config: Config) !usize {
    if (buf.len < request_wire_size) return error.NoSpaceLeft;
    var c = Cursor{ .buf = buf };
    c.putU32(magic);
    c.putU8(version);
    c.putU8(@intFromEnum(FrameKind.request));
    c.putU8(@intFromEnum(config.mode));
    c.putU8(@intFromEnum(config.direction));
    c.putU8(config.packet_protocol);
    c.putU8(0);
    c.putU16(config.packet_payload_size);
    c.putU32(config.packet_count);
    c.putU32(config.packet_pps);
    c.putU64(config.stream_service);
    c.putU64(config.stream_bytes);
    c.putU32(config.stream_chunk_size);
    c.putU32(@intCast(@divTrunc(config.timeout, glib.time.duration.MilliSecond)));
    c.putU32(config.kcp.send_window);
    c.putU32(config.kcp.recv_window);
    c.putU8(config.kcp.nodelay);
    c.putU8(config.kcp.nc);
    c.putU16(0);
    c.putU32(config.kcp.interval_ms);
    c.putU32(config.kcp.resend);
    c.zeroTo(request_wire_size);
    return request_wire_size;
}

pub fn decodeRequest(buf: []const u8) !Config {
    if (buf.len < request_wire_size) return error.ShortPerfFrame;
    var c = ReadCursor{ .buf = buf };
    if (c.getU32() != magic) return error.InvalidPerfMagic;
    if (c.getU8() != version) return error.InvalidPerfVersion;
    if (c.getU8() != @intFromEnum(FrameKind.request)) return error.InvalidPerfFrameKind;
    const mode: Mode = @enumFromInt(c.getU8());
    const direction: Direction = @enumFromInt(c.getU8());
    const packet_protocol = c.getU8();
    _ = c.getU8();
    const packet_payload_size = c.getU16();
    return .{
        .mode = mode,
        .direction = direction,
        .packet_protocol = packet_protocol,
        .packet_payload_size = packet_payload_size,
        .packet_count = c.getU32(),
        .packet_pps = c.getU32(),
        .stream_service = c.getU64(),
        .stream_bytes = c.getU64(),
        .stream_chunk_size = c.getU32(),
        .timeout = @as(glib.time.duration.Duration, c.getU32()) * glib.time.duration.MilliSecond,
        .kcp = .{
            .send_window = c.getU32(),
            .recv_window = c.getU32(),
            .nodelay = c.getU8(),
            .nc = c.getU8(),
            .interval_ms = blk: {
                _ = c.getU16();
                break :blk c.getU32();
            },
            .resend = c.getU32(),
        },
    };
}

pub fn encodeResult(buf: []u8, result: Result) !usize {
    if (buf.len < result_wire_size) return error.NoSpaceLeft;
    var c = Cursor{ .buf = buf };
    c.putU32(magic);
    c.putU8(version);
    c.putU8(@intFromEnum(FrameKind.result));
    c.putU8(@intFromEnum(result.mode));
    c.putU8(@intFromEnum(result.direction));
    c.putU8(@intFromEnum(result.status));
    c.putU8(@intFromEnum(result.error_stage));
    c.putU16(0);
    putCounters(&c, result.client);
    putCounters(&c, result.server);
    c.zeroTo(result_wire_size);
    return result_wire_size;
}

pub fn decodeResult(buf: []const u8) !Result {
    if (buf.len < result_wire_size) return error.ShortPerfFrame;
    var c = ReadCursor{ .buf = buf };
    if (c.getU32() != magic) return error.InvalidPerfMagic;
    if (c.getU8() != version) return error.InvalidPerfVersion;
    if (c.getU8() != @intFromEnum(FrameKind.result)) return error.InvalidPerfFrameKind;
    const mode: Mode = @enumFromInt(c.getU8());
    const direction: Direction = @enumFromInt(c.getU8());
    const status: Status = @enumFromInt(c.getU8());
    const error_stage: ErrorStage = @enumFromInt(c.getU8());
    _ = c.getU16();
    return .{
        .mode = mode,
        .direction = direction,
        .status = status,
        .error_stage = error_stage,
        .client = getCounters(&c),
        .server = getCounters(&c),
    };
}

fn readRequest(conn: Conn, protocol: u8, buf: []u8, timeout: glib.time.duration.Duration) !Config {
    while (true) {
        const result = try conn.readTimeout(buf, timeout);
        if (result.protocol != protocol) continue;
        return decodeRequest(buf[0..result.n]);
    }
}

fn putCounters(c: *Cursor, counters: Counters) void {
    c.putU64(counters.sent_bytes);
    c.putU64(counters.received_bytes);
    c.putU64(counters.sent_packets);
    c.putU64(counters.received_packets);
    c.putU64(counters.expected_packets);
    c.putU64(counters.missing_packets);
    c.putU64(counters.duplicate_packets);
    c.putU64(counters.out_of_order_packets);
    c.putU64(counters.mismatched_packets);
    c.putU64(counters.elapsed_ns);
    c.putU64(counters.first_response_ns);
    c.putU64(counters.rtt_ns);
    c.putU64(counters.mbps);
}

fn getCounters(c: *ReadCursor) Counters {
    return .{
        .sent_bytes = c.getU64(),
        .received_bytes = c.getU64(),
        .sent_packets = c.getU64(),
        .received_packets = c.getU64(),
        .expected_packets = c.getU64(),
        .missing_packets = c.getU64(),
        .duplicate_packets = c.getU64(),
        .out_of_order_packets = c.getU64(),
        .mismatched_packets = c.getU64(),
        .elapsed_ns = c.getU64(),
        .first_response_ns = c.getU64(),
        .rtt_ns = c.getU64(),
        .mbps = c.getU64(),
    };
}

fn mbpsFor(bytes: u64, elapsed_ns: u64) u64 {
    if (bytes == 0 or elapsed_ns == 0) return 0;
    return mulDivU64(mulDivU64(bytes, 8, 1_000_000), @intCast(glib.time.duration.Second), elapsed_ns);
}

fn elapsedSince(start_ns: glib.time.instant.Time, end_ns: glib.time.instant.Time) u64 {
    if (end_ns <= start_ns) return 0;
    return @intCast(glib.time.instant.sub(end_ns, start_ns));
}

fn mulDivU64(a: u64, b: u64, divisor: u64) u64 {
    if (a == 0 or b == 0) return 0;
    if (divisor == 0) return 0xffffffffffffffff;
    const product, const overflowed = @mulWithOverflow(a, b);
    if (overflowed != 0) return 0xffffffffffffffff;
    return @divTrunc(product, divisor);
}

fn writeU32(buf: []u8, value: u32) void {
    glib.std.mem.writeInt(u32, buf[0..4], value, .little);
}

fn readU32(buf: []const u8) u32 {
    return glib.std.mem.readInt(u32, buf[0..4], .little);
}

const Cursor = struct {
    buf: []u8,
    pos: usize = 0,

    fn putU8(self: *Cursor, value: u8) void {
        self.buf[self.pos] = value;
        self.pos += 1;
    }

    fn putU16(self: *Cursor, value: u16) void {
        glib.std.mem.writeInt(u16, self.buf[self.pos..][0..2], value, .little);
        self.pos += 2;
    }

    fn putU32(self: *Cursor, value: u32) void {
        glib.std.mem.writeInt(u32, self.buf[self.pos..][0..4], value, .little);
        self.pos += 4;
    }

    fn putU64(self: *Cursor, value: u64) void {
        glib.std.mem.writeInt(u64, self.buf[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    fn zeroTo(self: *Cursor, end: usize) void {
        @memset(self.buf[self.pos..end], 0);
        self.pos = end;
    }
};

const ReadCursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn getU8(self: *ReadCursor) u8 {
        const value = self.buf[self.pos];
        self.pos += 1;
        return value;
    }

    fn getU16(self: *ReadCursor) u16 {
        const value = glib.std.mem.readInt(u16, self.buf[self.pos..][0..2], .little);
        self.pos += 2;
        return value;
    }

    fn getU32(self: *ReadCursor) u32 {
        const value = glib.std.mem.readInt(u32, self.buf[self.pos..][0..4], .little);
        self.pos += 4;
        return value;
    }

    fn getU64(self: *ReadCursor) u64 {
        const value = glib.std.mem.readInt(u64, self.buf[self.pos..][0..8], .little);
        self.pos += 8;
        return value;
    }
};
