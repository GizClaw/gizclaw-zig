const dep = @import("dep");
const noise = @import("../noise.zig");

const Conn = @import("Conn.zig");
const consts = @import("consts.zig");
const errors = @import("errors.zig");

// Single-threaded: callers must serialize all Dialer access.
pub fn make(comptime lib: type, comptime Noise: type) type {
    const Context = dep.context.Context;
    const PacketConn = dep.net.PacketConn;
    const ConnType = Conn.make(Noise);
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

        pub fn dialContext(
            self: *Self,
            ctx: Context,
            packet_conn: PacketConn,
            remote_addr: [*]const u8,
            remote_addr_len: u32,
        ) !void {
            if (self.conn.state() != .new) return errors.Error.InvalidConnState;
            if (remote_addr_len == 0) return errors.Error.MissingRemoteAddress;
            if (contextCause(ctx)) |cause| return cause;

            var wire_out: [noise.Message.max_packet_size]u8 = undefined;
            var read_buf: [noise.Message.max_packet_size]u8 = undefined;
            var wire_n = try self.start(&wire_out, nowMs());
            _ = try packet_conn.writeTo(wire_out[0..wire_n], remote_addr, remote_addr_len);

            while (self.conn.state() != .established) {
                self.waitForHandshakeResponse(ctx, packet_conn, &read_buf) catch |err| switch (err) {
                    error.TimedOut => {
                        wire_n = (try self.pollRetry(&wire_out, nowMs())) orelse continue;
                        _ = try packet_conn.writeTo(wire_out[0..wire_n], remote_addr, remote_addr_len);
                    },
                    else => return err,
                };
            }
        }

        fn waitForHandshakeResponse(self: *Self, ctx: Context, packet_conn: PacketConn, read_buf: []u8) !void {
            while (true) {
                if (contextCause(ctx)) |cause| return cause;

                const timeout_ms = try self.nextReadTimeoutMs(ctx);
                const recv = blk: {
                    packet_conn.setReadTimeout(timeout_ms);
                    defer packet_conn.setReadTimeout(null);
                    break :blk packet_conn.readFrom(read_buf);
                } catch |err| switch (err) {
                    error.TimedOut => {
                        if (contextCause(ctx)) |cause| return cause;
                        return error.TimedOut;
                    },
                    else => return err,
                };

                const packet = read_buf[0..recv.bytes_read];
                const message_type = noise.Message.getMessageType(packet) catch continue;
                if (message_type != .handshake_resp) continue;

                self.handleResponse(packet, nowMs()) catch |err| switch (err) {
                    errors.Error.InvalidReceiverIndex => continue,
                    else => return err,
                };
                return;
            }
        }

        fn nextReadTimeoutMs(self: *const Self, ctx: Context) !u32 {
            if (contextCause(ctx)) |cause| return cause;

            const now_ms = nowMs();
            const sent_ms = self.conn.last_handshake_sent_ms;
            if (sent_ms == 0) return errors.Error.HandshakeIncomplete;

            const elapsed_ms = now_ms -| sent_ms;
            if (elapsed_ms >= consts.rekey_timeout_ms) return error.TimedOut;

            var remaining_ms: u64 = consts.rekey_timeout_ms - elapsed_ms;
            if (ctx.deadline()) |deadline_ns| {
                const now_ns = lib.time.nanoTimestamp();
                if (deadline_ns <= now_ns) return Context.DeadlineExceeded;

                const remaining_ns = deadline_ns - now_ns;
                var ctx_remaining_ms: u64 = @intCast(@divFloor(remaining_ns, lib.time.ns_per_ms));
                if (ctx_remaining_ms == 0) ctx_remaining_ms = 1;
                remaining_ms = @min(remaining_ms, ctx_remaining_ms);
            }

            if (remaining_ms == 0) return error.TimedOut;
            return @intCast(@min(remaining_ms, @as(u64, @intCast(@import("dep").embed.math.maxInt(u32)))));
        }

        fn nowMs() u64 {
            return @intCast(lib.time.milliTimestamp());
        }

        fn contextCause(ctx: Context) ?anyerror {
            if (ctx.err()) |cause| return cause;
            if (ctx.deadline()) |deadline_ns| {
                if (deadline_ns <= lib.time.nanoTimestamp()) return Context.DeadlineExceeded;
            }
            return null;
        }
    };
}

