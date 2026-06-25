//! Giznet-owned packet and stream perf client.

const glib = @import("glib");

const Conn = @import("Conn.zig");
const Stream = @import("Stream.zig");
const PerfServer = @import("PerfServer.zig");

pub const Mode = PerfServer.Mode;
pub const Direction = PerfServer.Direction;
pub const Config = PerfServer.Config;
pub const Counters = PerfServer.Counters;
pub const Result = PerfServer.Result;
pub const default_control_protocol = PerfServer.default_control_protocol;
pub const default_packet_protocol = PerfServer.default_packet_protocol;
pub const default_stream_service = PerfServer.default_stream_service;

pub fn make(comptime grt: type) type {
    return struct {
        pub const Options = struct {
            control_protocol: u8 = default_control_protocol,
            task_options: grt.task.Options = .{},
        };

        pub fn run(conn: Conn, config: Config, options: Options) !Result {
            if (config.direction == .all) return error.InvalidPerfDirection;
            switch (config.mode) {
                .peer_packet => {
                    try PerfServer.validatePacketConfig(config);
                    if (config.packet_protocol == options.control_protocol) return error.InvalidPerfProtocol;
                },
                .kcp_stream => try PerfServer.validateStreamConfig(config),
            }

            var frame: [PerfServer.result_wire_size]u8 = undefined;
            const request_len = try PerfServer.encodeRequest(&frame, config);
            _ = try conn.write(options.control_protocol, frame[0..request_len]);

            var result = switch (config.mode) {
                .peer_packet => try runPeerPacket(conn, config, options),
                .kcp_stream => try runKcpStream(conn, config, options),
            };
            result.mode = config.mode;
            result.direction = config.direction;
            return result;
        }

        pub fn runAll(conn: Conn, config: Config, out: []Result, options: Options) !usize {
            if (out.len < 4) return error.NoSpaceLeft;
            var base = config;
            var count: usize = 0;
            const directions = [_]Direction{ .ping, .up, .down, .duplex };
            for (directions) |direction| {
                base.direction = direction;
                out[count] = try run(conn, base, options);
                count += 1;
            }
            return count;
        }

        fn runPeerPacket(conn: Conn, config: Config, options: Options) !Result {
            var result = Result{
                .mode = .peer_packet,
                .direction = config.direction,
            };
            switch (config.direction) {
                .up => {
                    result.client = try sendPeerPackets(conn, config);
                    const server_result = try readResponse(conn, options.control_protocol, config.timeout);
                    result.server = server_result.server;
                    result.status = server_result.status;
                    result.error_stage = server_result.error_stage;
                },
                .down => {
                    var pending: ?Result = null;
                    result.client = try receivePeerPackets(conn, config, .{
                        .control_protocol = options.control_protocol,
                        .pending_result = &pending,
                    });
                    const server_result = if (pending) |value| value else try readResponse(conn, options.control_protocol, config.timeout);
                    result.server = server_result.server;
                    result.status = server_result.status;
                    result.error_stage = server_result.error_stage;
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
                    var pending: ?Result = null;
                    var task = SendTask{ .conn = conn, .config = config };
                    const handle = try grt.task.go("giznet/perf/packet/client-send", options.task_options, grt.task.Routine.init(&task, SendTask.run));
                    result.client = try receivePeerPackets(conn, config, .{
                        .control_protocol = options.control_protocol,
                        .pending_result = &pending,
                    });
                    handle.join();
                    if (task.err) |err| return err;
                    result.client.sent_bytes += task.counters.sent_bytes;
                    result.client.sent_packets += task.counters.sent_packets;
                    if (task.counters.elapsed_ns > result.client.elapsed_ns) result.client.elapsed_ns = task.counters.elapsed_ns;
                    result.client.mbps = mbpsFor(result.client.sent_bytes + result.client.received_bytes, result.client.elapsed_ns);
                    const server_result = if (pending) |value| value else try readResponse(conn, options.control_protocol, config.timeout);
                    result.server = server_result.server;
                    result.status = server_result.status;
                    result.error_stage = server_result.error_stage;
                },
                .ping => {
                    const start_ns = grt.time.instant.now();
                    var buf: [PerfServer.max_packet_payload_size]u8 = undefined;
                    while (true) {
                        const read_result = try conn.readTimeout(&buf, config.timeout);
                        if (read_result.protocol != config.packet_protocol) continue;
                        if (read_result.n < @sizeOf(u32)) return error.ShortRead;
                        break;
                    }
                    const end_ns = grt.time.instant.now();
                    result.client.received_packets = 1;
                    result.client.received_bytes = @sizeOf(u32);
                    result.client.first_response_ns = elapsedSince(start_ns, end_ns);
                    result.client.rtt_ns = result.client.first_response_ns;
                    result.client.elapsed_ns = result.client.first_response_ns;
                    const server_result = try readResponse(conn, options.control_protocol, config.timeout);
                    result.server = server_result.server;
                },
                .all => return error.InvalidPerfDirection,
            }
            return result;
        }

        fn runKcpStream(conn: Conn, config: Config, options: Options) !Result {
            var result = Result{
                .mode = .kcp_stream,
                .direction = config.direction,
            };
            switch (config.direction) {
                .up => {
                    var stream = try conn.openStream(config.stream_service);
                    defer stream.deinit();
                    result.client = try writeStream(stream, config);
                    const server_result = try readResponse(conn, options.control_protocol, config.timeout);
                    result.server = server_result.server;
                },
                .down => {
                    var stream = try conn.accept(config.timeout);
                    defer stream.deinit();
                    result.client = try readStream(stream, config);
                    const server_result = try readResponse(conn, options.control_protocol, config.timeout);
                    result.server = server_result.server;
                },
                .duplex => {
                    var stream = try conn.openStream(config.stream_service);
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
                    const handle = try grt.task.go("giznet/perf/stream/client-write", options.task_options, grt.task.Routine.init(&task, WriteTask.run));
                    result.client = try readStream(stream, config);
                    handle.join();
                    if (task.err) |err| return err;
                    result.client.sent_bytes += task.counters.sent_bytes;
                    if (task.counters.elapsed_ns > result.client.elapsed_ns) result.client.elapsed_ns = task.counters.elapsed_ns;
                    result.client.mbps = mbpsFor(result.client.sent_bytes + result.client.received_bytes, result.client.elapsed_ns);
                    const server_result = try readResponse(conn, options.control_protocol, config.timeout);
                    result.server = server_result.server;
                },
                .ping => {
                    var stream = try conn.openStream(config.stream_service);
                    defer stream.deinit();
                    try setStreamDeadlines(stream, config.timeout);
                    const start_ns = grt.time.instant.now();
                    const written = try stream.write("\x01");
                    if (written != 1) return error.ShortWrite;
                    var buf: [1]u8 = undefined;
                    const read_n = try stream.read(&buf);
                    if (read_n != 1) return error.ShortRead;
                    const end_ns = grt.time.instant.now();
                    result.client.sent_bytes = 1;
                    result.client.received_bytes = 1;
                    result.client.first_response_ns = elapsedSince(start_ns, end_ns);
                    result.client.rtt_ns = result.client.first_response_ns;
                    result.client.elapsed_ns = result.client.first_response_ns;
                    const server_result = try readResponse(conn, options.control_protocol, config.timeout);
                    result.server = server_result.server;
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
            var buf: [PerfServer.max_packet_payload_size]u8 = undefined;
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
            var buf: [@max(PerfServer.max_packet_payload_size, PerfServer.result_wire_size)]u8 = undefined;
            const start_ns = grt.time.instant.now();
            const deadline = glib.time.instant.add(start_ns, config.timeout);
            var expected_seq: u32 = 0;
            var highest_seq: u32 = 0;
            var has_highest = false;

            while (counters.received_packets < config.packet_count) {
                const now = grt.time.instant.now();
                if (now >= deadline) break;
                const read_result = try conn.readTimeout(&buf, glib.time.instant.sub(deadline, now));
                if (read_result.protocol == receive_options.control_protocol) {
                    if (receive_options.pending_result) |pending| {
                        pending.* = try PerfServer.decodeResult(buf[0..read_result.n]);
                    }
                    continue;
                }
                if (read_result.protocol != config.packet_protocol) continue;
                if (read_result.n != config.packet_payload_size or read_result.n < @sizeOf(u32)) {
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
                for (buf[4..read_result.n]) |byte| {
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
                counters.received_bytes += read_result.n;
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
            var buf: [PerfServer.max_stream_chunk_size]u8 = undefined;
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
            var buf: [PerfServer.max_stream_chunk_size]u8 = undefined;
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

        fn readResponse(conn: Conn, protocol: u8, timeout: glib.time.duration.Duration) !Result {
            var buf: [PerfServer.result_wire_size]u8 = undefined;
            while (true) {
                const read_result = try conn.readTimeout(&buf, timeout);
                if (read_result.protocol != protocol) continue;
                return PerfServer.decodeResult(buf[0..read_result.n]);
            }
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

fn writeU32(buf: []u8, value: u32) void {
    glib.std.mem.writeInt(u32, buf[0..4], value, .little);
}

fn readU32(buf: []const u8) u32 {
    return glib.std.mem.readInt(u32, buf[0..4], .little);
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
