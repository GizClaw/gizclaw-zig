const glib = @import("glib");

const giznet = @import("../../../giznet.zig");
const NoiseCipher = @import("../../noise/Cipher.zig");
const NoiseEngine = @import("../../noise/Engine.zig");
const RuntimeEngine = @import("../../runtime/Engine.zig");
const ServiceEngine = @import("../../service/Engine.zig");
const Session = @import("../../noise/Session.zig");

pub const default_accept_timeout: glib.time.duration.Duration = 2 * glib.time.duration.Second;
pub const copy_buffer_bytes: usize = 1024;
pub const transfer_chunk_bytes: usize = 1023;
const transfer_seq_bytes: usize = @sizeOf(u32);

fn nextTransferChunkLen(remaining: usize) usize {
    var chunk_len: usize = @min(transfer_chunk_bytes, remaining);
    const next_remaining = remaining - chunk_len;
    if (next_remaining > 0 and next_remaining < transfer_seq_bytes) {
        chunk_len -= transfer_seq_bytes - next_remaining;
    }
    return chunk_len;
}

fn transferPacketCount(size: usize) !usize {
    var remaining = size;
    var count: usize = 0;
    while (remaining > 0) {
        const chunk_len = nextTransferChunkLen(remaining);
        if (chunk_len < transfer_seq_bytes) return error.TestUnexpectedResult;
        remaining -= chunk_len;
        count += 1;
    }
    return count;
}

fn fillTransferChunkLens(lengths: []u16, size: usize) !void {
    var remaining = size;
    for (lengths) |*len| {
        const chunk_len = nextTransferChunkLen(remaining);
        if (chunk_len < transfer_seq_bytes or chunk_len > transfer_chunk_bytes) return error.TestUnexpectedResult;
        len.* = @intCast(chunk_len);
        remaining -= chunk_len;
    }
    if (remaining != 0) return error.TestUnexpectedResult;
}

pub const Rate = struct {
    bytes: usize,
    elapsed_ns: u64,
    bytes_per_second: u64,
    mbps: u64,
    sent_bytes: usize = 0,
    received_bytes: usize = 0,
    expected_packets: u64 = 0,
    received_packets: u64 = 0,
    missing_packets: u64 = 0,
    duplicate_packets: u64 = 0,
    total_mismatches: u64 = 0,
};

pub const ReadWriter = struct {
    protocol: u8,
    reader: giznet.Conn,
    writer: giznet.Conn,

    pub fn read(self: *ReadWriter, buf: []u8) anyerror!usize {
        const result = try self.reader.read(buf);
        if (result.protocol != self.protocol) return error.UnexpectedProtocol;
        return result.n;
    }

    pub fn readTimeout(self: *ReadWriter, buf: []u8, timeout: glib.time.duration.Duration) anyerror!usize {
        const result = try self.reader.readTimeout(buf, timeout);
        if (result.protocol != self.protocol) return error.UnexpectedProtocol;
        return result.n;
    }

    pub fn write(self: *ReadWriter, buf: []const u8) anyerror!usize {
        return self.writer.write(self.protocol, buf);
    }
};

pub fn copy(
    allocator: glib.std.mem.Allocator,
    dst: anytype,
    src: anytype,
) !usize {
    const buf = try allocator.alloc(u8, copy_buffer_bytes);
    defer allocator.free(buf);

    var total: usize = 0;
    while (true) {
        const read_n = src.read(buf) catch |err| switch (err) {
            error.ConnClosed, error.Closed, error.EndOfStream => return total,
            else => return err,
        };
        if (read_n == 0) return total;

        var written_total: usize = 0;
        while (written_total < read_n) {
            const written = try dst.write(buf[written_total..read_n]);
            if (written == 0) return error.ShortWrite;
            written_total += written;
        }
        total += read_n;
    }
}

pub fn Fixture(
    comptime grt: type,
    comptime packet_size_capacity: usize,
    comptime cipher_kind: NoiseCipher.Kind,
    comptime seeds: []const u32,
) type {
    const peer_count = seeds.len;
    const RuntimePackage = giznet.runtime.make(grt, packet_size_capacity, cipher_kind);
    const GizNetType = RuntimePackage.GizNet;
    const ErrorReport = struct {
        peer_idx: usize,
        err: anyerror,
    };
    const ErrorChannel = grt.sync.Channel(ErrorReport);

    return struct {
        allocator: grt.std.mem.Allocator,
        config: Config = .{},
        error_output: ?*ErrorChannel = null,
        error_sinks: ?*[peer_count]ErrorSink = null,
        peers: [peer_count]Peer = undefined,

        const Self = @This();

        pub const Config = struct {
            noise: NoiseEngine.Config = .{},
            service: ServiceEngine.Config = .{},
            channel_capacity: usize = 32,
            accept_channel_capacity: usize = 32,
            error_channel_capacity: usize = peer_count,
            accept_timeout: glib.time.duration.Duration = default_accept_timeout,
            up: GizNetType.UpConfig = .{},
            transfer_spawn_config: grt.std.Thread.SpawnConfig = .{},
            transfer_yield_every: usize = 0,
        };

        pub const Error = ErrorReport;

        pub const ErrorSink = struct {
            peer_idx: usize,
            output: ?*ErrorChannel = null,

            fn handler(self: *const ErrorSink) RuntimeEngine.OnError {
                return .{
                    .ctx = @constCast(self),
                    .call = call,
                };
            }

            fn call(ctx: ?*anyopaque, err: anyerror) void {
                const raw_ctx = ctx orelse return;
                const self: *ErrorSink = @ptrCast(@alignCast(raw_ctx));
                const output = self.output orelse return;
                _ = output.sendTimeout(.{
                    .peer_idx = self.peer_idx,
                    .err = err,
                }, 0) catch {};
            }
        };

        pub const Peer = struct {
            keypair_seed: u32,
            keypair: giznet.KeyPair = .{},
            endpoint: giznet.AddrPort = .{},
            impl: ?*GizNetType = null,
            gnet: ?giznet.GizNet = null,
            packet_conn: ?grt.net.PacketConn = null,
        };

        pub const ConnPair = struct {
            allocator: grt.std.mem.Allocator,
            a: giznet.Conn,
            b: giznet.Conn,

            pub fn deinit(self: ConnPair) void {
                self.a.close() catch {};
                self.b.close() catch {};
                self.b.deinit();
                self.a.deinit();
            }

            pub fn forward(self: ConnPair, protocol: u8) ReadWriter {
                return .{
                    .protocol = protocol,
                    .reader = self.b,
                    .writer = self.a,
                };
            }

            pub fn backward(self: ConnPair, protocol: u8) ReadWriter {
                return .{
                    .protocol = protocol,
                    .reader = self.a,
                    .writer = self.b,
                };
            }

            pub fn copyForwardToBackward(self: ConnPair, protocol: u8) !usize {
                var src = self.forward(protocol);
                var dst = self.backward(protocol);
                return copy(self.allocator, &dst, &src);
            }

            pub fn copyBackwardToForward(self: ConnPair, protocol: u8) !usize {
                var src = self.backward(protocol);
                var dst = self.forward(protocol);
                return copy(self.allocator, &dst, &src);
            }
        };

        pub fn init(
            allocator: grt.std.mem.Allocator,
            config: Config,
        ) !Self {
            var self: Self = .{
                .allocator = allocator,
                .config = config,
            };

            for (0..peer_count) |idx| {
                self.peers[idx] = .{
                    .keypair_seed = seeds[idx],
                };
            }
            errdefer self.deinit();

            const error_output = try allocator.create(ErrorChannel);
            errdefer allocator.destroy(error_output);
            error_output.* = try ErrorChannel.make(allocator, config.error_channel_capacity);
            errdefer {
                error_output.close();
                error_output.deinit();
            }
            self.error_output = error_output;

            const error_sinks = try allocator.create([peer_count]ErrorSink);
            errdefer allocator.destroy(error_sinks);
            for (0..peer_count) |idx| {
                error_sinks[idx] = .{
                    .peer_idx = idx,
                    .output = error_output,
                };
            }
            self.error_sinks = error_sinks;

            for (0..peer_count) |idx| {
                try self.upPeer(idx);
            }
            return self;
        }

        pub fn deinit(self: *Self) void {
            if (self.error_sinks) |error_sinks| {
                for (0..peer_count) |idx| {
                    error_sinks[idx].output = null;
                }
            }

            var idx = peer_count;
            while (idx > 0) {
                idx -= 1;
                if (self.peers[idx].packet_conn) |packet_conn| {
                    packet_conn.close();
                }
                if (self.peers[idx].gnet) |gnet| {
                    gnet.deinit();
                    self.peers[idx].gnet = null;
                    self.peers[idx].impl = null;
                }
                if (self.peers[idx].packet_conn) |packet_conn| {
                    packet_conn.deinit();
                    self.peers[idx].packet_conn = null;
                }
            }

            if (self.error_sinks) |error_sinks| {
                self.allocator.destroy(error_sinks);
                self.error_sinks = null;
            }
            if (self.error_output) |error_output| {
                error_output.close();
                error_output.deinit();
                self.allocator.destroy(error_output);
                self.error_output = null;
            }
        }

        pub fn connect(
            self: *Self,
            idx_a: usize,
            idx_b: usize,
        ) !ConnPair {
            const gnet_a = self.peers[idx_a].gnet orelse return error.MissingGizNet;
            const impl_a = self.peers[idx_a].impl orelse return error.MissingGizNet;
            const impl_b = self.peers[idx_b].impl orelse return error.MissingGizNet;

            try gnet_a.dial(.{
                .remote_key = self.peers[idx_b].keypair.public,
                .endpoint = self.peers[idx_b].endpoint,
            });

            const conn_b = try impl_b.acceptTimeout(self.config.accept_timeout);
            errdefer conn_b.deinit();
            const conn_a = try impl_a.acceptTimeout(self.config.accept_timeout);
            errdefer conn_a.deinit();

            return .{
                .allocator = self.allocator,
                .a = conn_a,
                .b = conn_b,
            };
        }

        pub fn recvError(self: *Self, timeout: glib.time.duration.Duration) !?Error {
            const output = self.error_output orelse return null;
            const result = output.recvTimeout(timeout) catch |err| switch (err) {
                error.Timeout => return null,
                else => return err,
            };
            if (!result.ok) return null;
            return result.value;
        }

        pub fn testCorrectness(self: *Self, rw: ReadWriter, size: usize) !void {
            if (size == 0) return;

            const expected = try self.allocator.alloc(u8, size);
            defer self.allocator.free(expected);
            const actual = try self.allocator.alloc(u8, size);
            defer self.allocator.free(actual);

            for (expected, 0..) |*byte, idx| {
                byte.* = @truncate((idx * 131 + 17) & 0xff);
            }

            var value = rw;
            const written = try value.write(expected);
            try grt.std.testing.expectEqual(size, written);

            const read_n = try value.read(actual);
            try grt.std.testing.expectEqual(size, read_n);
            try grt.std.testing.expectEqualSlices(u8, expected, actual[0..read_n]);
        }

        pub fn measureTransfer(self: *Self, rw: ReadWriter, size: usize) !Rate {
            if (size == 0) return .{
                .bytes = 0,
                .elapsed_ns = 0,
                .bytes_per_second = 0,
                .mbps = 0,
            };

            const WriterTask = struct {
                rw: ReadWriter,
                total: usize,
                transferred: usize = 0,
                err: ?anyerror = null,
                checksum: u64 = 0,

                fn run(task: *@This()) void {
                    var buf: [transfer_chunk_bytes]u8 = undefined;
                    while (task.transferred < task.total) {
                        const remaining = task.total - task.transferred;
                        const chunk_len = nextTransferChunkLen(remaining);
                        @memset(buf[0..chunk_len], 0x5a);
                        const written = task.rw.write(buf[0..chunk_len]) catch |err| {
                            task.err = err;
                            return;
                        };
                        if (written != chunk_len) {
                            task.err = error.ShortWrite;
                            return;
                        }
                        task.transferred += written;
                        task.checksum +%= buf[written - 1];
                    }
                }
            };

            const ReaderTask = struct {
                rw: ReadWriter,
                total: usize,
                transferred: usize = 0,
                err: ?anyerror = null,
                checksum: u64 = 0,

                fn run(task: *@This()) void {
                    var buf: [transfer_chunk_bytes]u8 = undefined;
                    while (task.transferred < task.total) {
                        const remaining = task.total - task.transferred;
                        const expected_len = nextTransferChunkLen(remaining);
                        const read_n = task.rw.read(buf[0..expected_len]) catch |err| {
                            task.err = err;
                            return;
                        };
                        if (read_n != expected_len) {
                            task.err = error.ShortRead;
                            return;
                        }
                        task.transferred += read_n;
                        task.checksum +%= buf[read_n - 1];
                    }
                }
            };

            var writer_task: WriterTask = .{
                .rw = rw,
                .total = size,
            };
            var reader_task: ReaderTask = .{
                .rw = rw,
                .total = size,
            };

            const start_ns = grt.time.instant.now();
            var reader_thread = try grt.std.Thread.spawn(self.config.transfer_spawn_config, ReaderTask.run, .{&reader_task});
            var writer_thread = try grt.std.Thread.spawn(self.config.transfer_spawn_config, WriterTask.run, .{&writer_task});
            writer_thread.join();
            reader_thread.join();
            const end_ns = grt.time.instant.now();

            if (writer_task.err) |err| return err;
            if (reader_task.err) |err| return err;
            if (writer_task.transferred != size or reader_task.transferred != size) return error.TestUnexpectedResult;

            grt.std.mem.doNotOptimizeAway(writer_task.checksum);
            grt.std.mem.doNotOptimizeAway(reader_task.checksum);

            const elapsed_ns: u64 = @intCast(glib.time.instant.sub(end_ns, start_ns));
            const bytes_per_second = if (elapsed_ns == 0)
                0
            else
                @as(u64, @intCast((@as(u128, size) * @as(u128, glib.time.duration.Second)) / @as(u128, elapsed_ns)));

            return .{
                .bytes = size,
                .elapsed_ns = elapsed_ns,
                .bytes_per_second = bytes_per_second,
                .mbps = @divTrunc(bytes_per_second * 8, 1_000_000),
                .sent_bytes = writer_task.transferred,
                .received_bytes = reader_task.transferred,
            };
        }

        pub fn measureTransferSeqChecked(self: *Self, rw: ReadWriter, size: usize) !Rate {
            if (size == 0) return .{
                .bytes = 0,
                .elapsed_ns = 0,
                .bytes_per_second = 0,
                .mbps = 0,
            };
            if (transfer_chunk_bytes < transfer_seq_bytes) return error.TestUnexpectedResult;
            if (size < transfer_seq_bytes) return error.TestUnexpectedResult;

            const packet_count = try transferPacketCount(size);
            const expected_lens = try self.allocator.alloc(u16, packet_count);
            defer self.allocator.free(expected_lens);
            try fillTransferChunkLens(expected_lens, size);

            const seen_packets = try self.allocator.alloc(bool, packet_count);
            defer self.allocator.free(seen_packets);
            @memset(seen_packets, false);

            const TransferPacket = struct {
                fn encodeSeq(buf: []u8, seq: u32) void {
                    buf[0] = @truncate(seq);
                    buf[1] = @truncate(seq >> 8);
                    buf[2] = @truncate(seq >> 16);
                    buf[3] = @truncate(seq >> 24);
                }

                fn decodeSeq(buf: []const u8) u32 {
                    return @as(u32, buf[0]) |
                        (@as(u32, buf[1]) << 8) |
                        (@as(u32, buf[2]) << 16) |
                        (@as(u32, buf[3]) << 24);
                }
            };

            const SharedState = struct {
                writer_done: grt.std.atomic.Value(u8) = grt.std.atomic.Value(u8).init(0),
            };

            const WriterTask = struct {
                rw: ReadWriter,
                expected_lens: []const u16,
                yield_every: usize,
                transferred: usize = 0,
                err: ?anyerror = null,
                checksum: u64 = 0,
                next_seq: u32 = 0,
                shared: *SharedState,

                fn run(task: *@This()) void {
                    defer task.shared.writer_done.store(1, .seq_cst);

                    var buf: [transfer_chunk_bytes]u8 = undefined;
                    while (@as(usize, @intCast(task.next_seq)) < task.expected_lens.len) {
                        const seq_idx: usize = @intCast(task.next_seq);
                        const chunk_len: usize = task.expected_lens[seq_idx];
                        if (chunk_len < transfer_seq_bytes) {
                            task.err = error.TestUnexpectedResult;
                            return;
                        }

                        TransferPacket.encodeSeq(buf[0..transfer_seq_bytes], task.next_seq);
                        @memset(buf[transfer_seq_bytes..chunk_len], 0x5a);

                        const written = task.rw.write(buf[0..chunk_len]) catch |err| {
                            task.err = err;
                            return;
                        };
                        if (written != chunk_len) {
                            task.err = error.ShortWrite;
                            return;
                        }
                        task.transferred += written;
                        task.checksum +%= buf[written - 1];
                        task.next_seq +%= 1;
                        if (task.yield_every != 0 and task.next_seq % task.yield_every == 0) {
                            grt.std.Thread.yield() catch {};
                        }
                    }
                }
            };

            const ReaderTask = struct {
                rw: ReadWriter,
                expected_lens: []const u16,
                seen_packets: []bool,
                drain_timeout: glib.time.duration.Duration,
                transferred: usize = 0,
                err: ?anyerror = null,
                checksum: u64 = 0,
                missing_packets: u64 = 0,
                duplicate_packets: u64 = 0,
                total_mismatches: u64 = 0,
                received_packets: usize = 0,
                shared: *SharedState,

                fn run(task: *@This()) void {
                    var buf: [transfer_chunk_bytes]u8 = undefined;
                    while (task.received_packets < task.expected_lens.len) {
                        const read_n = task.rw.readTimeout(&buf, task.drain_timeout) catch |err| switch (err) {
                            error.Timeout => {
                                if (task.shared.writer_done.load(.seq_cst) != 0) break;
                                continue;
                            },
                            error.ConnClosed, error.Closed, error.EndOfStream => break,
                            else => {
                                task.err = err;
                                return;
                            },
                        };
                        if (read_n < transfer_seq_bytes) {
                            task.total_mismatches += 1;
                            continue;
                        }

                        const got_seq = TransferPacket.decodeSeq(buf[0..transfer_seq_bytes]);
                        const seq_idx: usize = @intCast(got_seq);
                        if (seq_idx >= task.expected_lens.len) {
                            task.total_mismatches += 1;
                            continue;
                        }
                        if (task.seen_packets[seq_idx]) {
                            task.duplicate_packets += 1;
                            continue;
                        }
                        if (read_n != task.expected_lens[seq_idx]) {
                            task.total_mismatches += 1;
                            continue;
                        }
                        var payload_ok = true;
                        for (buf[transfer_seq_bytes..read_n]) |byte| {
                            if (byte != 0x5a) {
                                payload_ok = false;
                                break;
                            }
                        }
                        if (!payload_ok) {
                            task.total_mismatches += 1;
                            continue;
                        }

                        task.seen_packets[seq_idx] = true;
                        task.transferred += read_n;
                        task.checksum +%= buf[read_n - 1];
                        task.received_packets += 1;
                    }

                    for (task.seen_packets) |seen| {
                        if (!seen) task.missing_packets += 1;
                    }
                }
            };

            var shared: SharedState = .{};
            var writer_task: WriterTask = .{
                .rw = rw,
                .expected_lens = expected_lens,
                .yield_every = self.config.transfer_yield_every,
                .shared = &shared,
            };
            var reader_task: ReaderTask = .{
                .rw = rw,
                .expected_lens = expected_lens,
                .seen_packets = seen_packets,
                .drain_timeout = glib.time.duration.Second,
                .shared = &shared,
            };

            const start_ns = grt.time.instant.now();
            var reader_thread = try grt.std.Thread.spawn(self.config.transfer_spawn_config, ReaderTask.run, .{&reader_task});
            var writer_thread = try grt.std.Thread.spawn(self.config.transfer_spawn_config, WriterTask.run, .{&writer_task});
            writer_thread.join();
            reader_thread.join();
            const end_ns = grt.time.instant.now();

            if (writer_task.err) |err| return err;
            if (reader_task.err) |err| return err;

            grt.std.mem.doNotOptimizeAway(writer_task.checksum);
            grt.std.mem.doNotOptimizeAway(reader_task.checksum);

            const elapsed_ns: u64 = @intCast(glib.time.instant.sub(end_ns, start_ns));
            const bytes_per_second = if (elapsed_ns == 0)
                0
            else
                @as(u64, @intCast((@as(u128, size) * @as(u128, glib.time.duration.Second)) / @as(u128, elapsed_ns)));

            return .{
                .bytes = size,
                .elapsed_ns = elapsed_ns,
                .bytes_per_second = bytes_per_second,
                .mbps = @divTrunc(bytes_per_second * 8, 1_000_000),
                .sent_bytes = writer_task.transferred,
                .received_bytes = reader_task.transferred,
                .expected_packets = @intCast(packet_count),
                .received_packets = @intCast(reader_task.received_packets),
                .missing_packets = reader_task.missing_packets,
                .duplicate_packets = reader_task.duplicate_packets,
                .total_mismatches = reader_task.total_mismatches,
            };
        }

        pub fn measureTransferSeqObserved(
            self: *Self,
            rw: ReadWriter,
            size: usize,
            drain_timeout: glib.time.duration.Duration,
        ) !Rate {
            if (size == 0) return .{
                .bytes = 0,
                .elapsed_ns = 0,
                .bytes_per_second = 0,
                .mbps = 0,
            };
            if (transfer_chunk_bytes < transfer_seq_bytes) return error.TestUnexpectedResult;
            if (size < transfer_seq_bytes) return error.TestUnexpectedResult;

            const packet_count = try transferPacketCount(size);
            const expected_lens = try self.allocator.alloc(u16, packet_count);
            defer self.allocator.free(expected_lens);
            try fillTransferChunkLens(expected_lens, size);

            const seen_packets = try self.allocator.alloc(bool, packet_count);
            defer self.allocator.free(seen_packets);
            @memset(seen_packets, false);

            const TransferPacket = struct {
                fn encodeSeq(buf: []u8, seq: u32) void {
                    buf[0] = @truncate(seq);
                    buf[1] = @truncate(seq >> 8);
                    buf[2] = @truncate(seq >> 16);
                    buf[3] = @truncate(seq >> 24);
                }

                fn decodeSeq(buf: []const u8) u32 {
                    return @as(u32, buf[0]) |
                        (@as(u32, buf[1]) << 8) |
                        (@as(u32, buf[2]) << 16) |
                        (@as(u32, buf[3]) << 24);
                }
            };

            const SharedState = struct {
                writer_done: grt.std.atomic.Value(u8) = grt.std.atomic.Value(u8).init(0),
            };

            const WriterTask = struct {
                rw: ReadWriter,
                expected_lens: []const u16,
                yield_every: usize,
                transferred: usize = 0,
                err: ?anyerror = null,
                checksum: u64 = 0,
                next_seq: u32 = 0,
                shared: *SharedState,

                fn run(task: *@This()) void {
                    defer task.shared.writer_done.store(1, .seq_cst);

                    var buf: [transfer_chunk_bytes]u8 = undefined;
                    while (@as(usize, @intCast(task.next_seq)) < task.expected_lens.len) {
                        const seq_idx: usize = @intCast(task.next_seq);
                        const chunk_len: usize = task.expected_lens[seq_idx];
                        if (chunk_len < transfer_seq_bytes) {
                            task.err = error.TestUnexpectedResult;
                            return;
                        }

                        TransferPacket.encodeSeq(buf[0..transfer_seq_bytes], task.next_seq);
                        @memset(buf[transfer_seq_bytes..chunk_len], 0x5a);

                        const written = task.rw.write(buf[0..chunk_len]) catch |err| {
                            task.err = err;
                            return;
                        };
                        if (written != chunk_len) {
                            task.err = error.ShortWrite;
                            return;
                        }
                        task.transferred += written;
                        task.checksum +%= buf[written - 1];
                        task.next_seq +%= 1;
                        if (task.yield_every != 0 and task.next_seq % task.yield_every == 0) {
                            grt.std.Thread.yield() catch {};
                        }
                    }
                }
            };

            const ReaderTask = struct {
                rw: ReadWriter,
                expected_lens: []const u16,
                seen_packets: []bool,
                drain_timeout: glib.time.duration.Duration,
                transferred: usize = 0,
                err: ?anyerror = null,
                checksum: u64 = 0,
                missing_packets: u64 = 0,
                duplicate_packets: u64 = 0,
                total_mismatches: u64 = 0,
                received_packets: usize = 0,
                shared: *SharedState,

                fn run(task: *@This()) void {
                    var buf: [transfer_chunk_bytes]u8 = undefined;
                    while (task.received_packets < task.expected_lens.len) {
                        const read_n = task.rw.readTimeout(&buf, task.drain_timeout) catch |err| switch (err) {
                            error.Timeout => {
                                if (task.shared.writer_done.load(.seq_cst) != 0) break;
                                continue;
                            },
                            error.ConnClosed, error.Closed, error.EndOfStream => break,
                            else => {
                                task.err = err;
                                return;
                            },
                        };
                        if (read_n < transfer_seq_bytes) {
                            task.total_mismatches += 1;
                            continue;
                        }

                        const got_seq = TransferPacket.decodeSeq(buf[0..transfer_seq_bytes]);
                        const seq_idx: usize = @intCast(got_seq);
                        if (seq_idx >= task.expected_lens.len) {
                            task.total_mismatches += 1;
                            continue;
                        }
                        if (task.seen_packets[seq_idx]) {
                            task.duplicate_packets += 1;
                            continue;
                        }
                        if (read_n != task.expected_lens[seq_idx]) {
                            task.total_mismatches += 1;
                            continue;
                        }
                        var payload_ok = true;
                        for (buf[transfer_seq_bytes..read_n]) |byte| {
                            if (byte != 0x5a) {
                                payload_ok = false;
                                break;
                            }
                        }
                        if (!payload_ok) {
                            task.total_mismatches += 1;
                            continue;
                        }

                        task.seen_packets[seq_idx] = true;
                        task.transferred += read_n;
                        task.checksum +%= buf[read_n - 1];
                        task.received_packets += 1;
                    }

                    for (task.seen_packets) |seen| {
                        if (!seen) task.missing_packets += 1;
                    }
                }
            };

            var shared: SharedState = .{};
            var writer_task: WriterTask = .{
                .rw = rw,
                .expected_lens = expected_lens,
                .yield_every = self.config.transfer_yield_every,
                .shared = &shared,
            };
            var reader_task: ReaderTask = .{
                .rw = rw,
                .expected_lens = expected_lens,
                .seen_packets = seen_packets,
                .drain_timeout = drain_timeout,
                .shared = &shared,
            };

            const start_ns = grt.time.instant.now();
            var reader_thread = try grt.std.Thread.spawn(self.config.transfer_spawn_config, ReaderTask.run, .{&reader_task});
            var writer_thread = try grt.std.Thread.spawn(self.config.transfer_spawn_config, WriterTask.run, .{&writer_task});
            writer_thread.join();
            reader_thread.join();
            const end_ns = grt.time.instant.now();

            if (writer_task.err) |err| return err;
            if (reader_task.err) |err| return err;

            grt.std.mem.doNotOptimizeAway(writer_task.checksum);
            grt.std.mem.doNotOptimizeAway(reader_task.checksum);

            const elapsed_ns: u64 = @intCast(glib.time.instant.sub(end_ns, start_ns));
            const bytes_per_second = if (elapsed_ns == 0 or reader_task.transferred == 0)
                0
            else
                @as(u64, @intCast((@as(u128, reader_task.transferred) * @as(u128, glib.time.duration.Second)) / @as(u128, elapsed_ns)));

            return .{
                .bytes = reader_task.transferred,
                .elapsed_ns = elapsed_ns,
                .bytes_per_second = bytes_per_second,
                .mbps = @divTrunc(bytes_per_second * 8, 1_000_000),
                .sent_bytes = writer_task.transferred,
                .received_bytes = reader_task.transferred,
                .expected_packets = @intCast(packet_count),
                .received_packets = @intCast(reader_task.received_packets),
                .missing_packets = reader_task.missing_packets,
                .duplicate_packets = reader_task.duplicate_packets,
                .total_mismatches = reader_task.total_mismatches,
            };
        }

        fn upPeer(self: *Self, idx: usize) !void {
            self.peers[idx].keypair = giznet.KeyPair.seed(grt, self.peers[idx].keypair_seed);

            var packet_conn = try grt.net.listenPacket(.{
                .allocator = self.allocator,
                .address = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
            });
            errdefer packet_conn.deinit();

            const udp_impl = try packet_conn.as(grt.net.UdpConn);
            self.peers[idx].endpoint = try udp_impl.localAddr();

            const error_sinks = self.error_sinks orelse return error.MissingErrorSinks;
            const impl = try GizNetType.init(self.allocator, packet_conn, .{
                .local_static = self.peers[idx].keypair,
                .noise = self.config.noise,
                .service = self.config.service,
                .channel_capacity = self.config.channel_capacity,
                .accept_channel_capacity = self.config.accept_channel_capacity,
                .on_error = error_sinks[idx].handler(),
            });
            errdefer impl.deinit();

            self.peers[idx].gnet = try impl.up(self.config.up);
            self.peers[idx].impl = impl;
            self.peers[idx].packet_conn = packet_conn;
        }
    };
}

pub fn DefaultFixture(comptime grt: type, comptime seeds: []const u32) type {
    return Fixture(
        grt,
        Session.legacy_packet_size_capacity,
        NoiseCipher.default_kind,
        seeds,
    );
}
