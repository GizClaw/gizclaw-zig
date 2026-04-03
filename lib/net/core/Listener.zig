const dep = @import("dep");
const mem = dep.embed.mem;
const noise = @import("../noise.zig");

const ConnFile = @import("Conn.zig");
const consts = @import("consts.zig");
const errors = @import("errors.zig");
const protocol = @import("protocol.zig");
const SessionManagerFile = @import("SessionManager.zig");
const UIntMapFile = @import("UIntMap.zig");

// Single-threaded: callers must serialize all Listener access.
pub fn make(comptime lib: type, comptime Noise: type) type {
    const ConnType = ConnFile.make(Noise);
    const Manager = SessionManagerFile.make(lib, Noise);
    const KeyPair = Noise.KeyPair;

    return struct {
        allocator: mem.Allocator,
        local_static: KeyPair,
        conns: UIntMapFile.make(u32, *ConnType),
        ready: AcceptQueue,
        manager: Manager,
        closed: bool = false,

        const Self = @This();

        pub const ReceiveResult = union(enum) {
            none,
            response: usize,
            payload: struct {
                conn: *ConnType,
                protocol_byte: u8,
                // This slice aliases the caller-provided plaintext buffer.
                payload: []const u8,
            },
        };

        const AcceptQueue = struct {
            slots: []*ConnType,
            head: usize = 0,
            tail: usize = 0,
            len: usize = 0,

            fn init(allocator: mem.Allocator, capacity: usize) !AcceptQueue {
                return .{
                    .slots = try allocator.alloc(*ConnType, @max(capacity, 1)),
                };
            }

            fn deinit(self: *AcceptQueue, allocator: mem.Allocator) void {
                allocator.free(self.slots);
                self.slots = &.{};
            }

            fn push(self: *AcceptQueue, conn_ptr: *ConnType) !void {
                if (self.len == self.slots.len) return errors.Error.QueueFull;
                self.slots[self.tail] = conn_ptr;
                self.tail = (self.tail + 1) % self.slots.len;
                self.len += 1;
            }

            fn pop(self: *AcceptQueue) ?*ConnType {
                if (self.len == 0) return null;
                const conn_ptr = self.slots[self.head];
                self.head = (self.head + 1) % self.slots.len;
                self.len -= 1;
                return conn_ptr;
            }

            fn remove(self: *AcceptQueue, conn_ptr: *ConnType) void {
                const retained = self.len;
                var index: usize = 0;
                while (index < retained) : (index += 1) {
                    const current = self.pop() orelse break;
                    if (current == conn_ptr) continue;
                    self.slots[self.tail] = current;
                    self.tail = (self.tail + 1) % self.slots.len;
                    self.len += 1;
                }
            }
        };

        pub fn init(allocator: mem.Allocator, local_static: KeyPair, accept_capacity: usize) !Self {
            return .{
                .allocator = allocator,
                .local_static = local_static,
                .conns = try UIntMapFile.make(u32, *ConnType).init(allocator, 8),
                .ready = try AcceptQueue.init(allocator, if (accept_capacity == 0) consts.default_accept_queue_size else accept_capacity),
                .manager = try Manager.init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.manager.deinit();
            self.ready.deinit(self.allocator);
            self.conns.deinit();
        }

        pub fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;
            self.manager.clear();
            for (self.conns.slots) |slot| {
                if (slot.state != .full) continue;
                self.allocator.destroy(slot.value);
            }
            self.conns.clear();
            self.ready.head = 0;
            self.ready.tail = 0;
            self.ready.len = 0;
        }

        pub fn accept(self: *Self) !*ConnType {
            if (self.closed) return errors.Error.ListenerClosed;
            return self.ready.pop() orelse errors.Error.AcceptQueueEmpty;
        }

        pub fn removeConn(self: *Self, local_index: u32) void {
            const conn_ptr = self.conns.remove(local_index) orelse return;
            _ = self.manager.removeByIndex(local_index);
            self.ready.remove(conn_ptr);
            self.allocator.destroy(conn_ptr);
        }

        pub fn receive(
            self: *Self,
            data: []const u8,
            plaintext_out: []u8,
            response_out: []u8,
            now_ms: u64,
        ) !ReceiveResult {
            if (self.closed) return errors.Error.ListenerClosed;
            // Listener only surfaces direct payloads. Stream protocols are routed
            // through Host/ServiceMux, not returned through ReceiveResult.

            const message_type = try noise.Message.getMessageType(data);
            return switch (message_type) {
                .handshake_init => .{ .response = try self.handleHandshakeInit(data, response_out, now_ms) },
                .transport => try self.handleTransport(data, plaintext_out, now_ms),
                else => .none,
            };
        }

        pub fn sessionManager(self: *Self) *const Manager {
            // Expose the synchronized manager as a read-mostly view.
            // `get*()` still returns borrowed Session pointers that alias live
            // connection state, so do not retain them after removeConn/close.
            return &self.manager;
        }

        fn handleHandshakeInit(self: *Self, data: []const u8, response_out: []u8, now_ms: u64) !usize {
            const init_msg = try noise.Message.parseHandshakeInit(data);
            var conn_ptr = try self.allocator.create(ConnType);
            errdefer self.allocator.destroy(conn_ptr);
            conn_ptr.* = ConnType.initResponder(self.local_static, try self.allocateLocalIndex(init_msg.sender_index));

            var response_buf: [noise.Message.handshake_resp_header_size + 64]u8 = undefined;
            const response_n = try conn_ptr.acceptHandshakeInit(data, &response_buf, now_ms);

            if (conn_ptr.currentSession()) |session| {
                _ = try self.manager.registerSession(session);
            }
            errdefer _ = self.manager.removeByIndex(conn_ptr.localIndex());

            _ = try self.conns.put(conn_ptr.localIndex(), conn_ptr);
            errdefer _ = self.conns.remove(conn_ptr.localIndex());

            try self.ready.push(conn_ptr);
            if (response_out.len < response_n) return errors.Error.BufferTooSmall;
            @memcpy(response_out[0..response_n], response_buf[0..response_n]);
            return response_n;
        }

        fn handleTransport(self: *Self, data: []const u8, plaintext_out: []u8, now_ms: u64) !ReceiveResult {
            const message = try noise.Message.parseTransportMessage(data);
            const conn_ptr = self.conns.get(message.receiver_index) orelse return .none;
            const result = try conn_ptr.recv(data, plaintext_out, now_ms);
            return .{
                .payload = .{
                    .conn = conn_ptr,
                    .protocol_byte = result.protocol_byte,
                    .payload = result.payload,
                },
            };
        }

        fn allocateLocalIndex(self: *Self, remote_index: u32) !u32 {
            var candidate = remote_index + 1;
            if (candidate == 0) candidate = 1;
            const start = candidate;
            while (self.conns.get(candidate) != null) : (candidate +%= 1) {
                if (candidate == 0) candidate = 1;
                if (candidate == start) return errors.Error.NoFreeIndex;
            }
            return candidate;
        }
    };
}

