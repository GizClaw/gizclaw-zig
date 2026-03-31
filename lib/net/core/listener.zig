const embed = @import("embed");
const mem = embed.mem;
const noise = @import("noise");

const conn = @import("conn.zig");
const consts = @import("consts.zig");
const errors = @import("errors.zig");
const map = @import("map.zig");
const protocol = @import("protocol.zig");
const session_manager = @import("session_manager.zig");

// Single-threaded: callers must serialize all Listener access.
pub fn Listener(comptime Noise: type) type {
    const ConnType = conn.Conn(Noise);
    const Manager = session_manager.SessionManager(Noise);
    const KeyPair = Noise.KeyPair;

    return struct {
        allocator: mem.Allocator,
        local_static: KeyPair,
        conns: map.UIntMap(u32, *ConnType),
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
                .conns = try map.UIntMap(u32, *ConnType).init(allocator, 8),
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

        pub fn sessionManager(self: *Self) *Manager {
            // The manager aliases Session storage owned by live connections.
            // Do not retain returned Session pointers after removeConn/close.
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

pub fn testAll(comptime lib: type, testing: anytype, allocator: mem.Allocator) !void {
    const noise_mod = @import("noise");
    const Noise = noise_mod.make(noise_mod.LibAdapter.make(lib));
    const ListenerType = Listener(Noise);
    const DialType = @import("dial.zig").Dial(Noise);

    const alice_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{7} ** noise.Key.key_size));
    const bob_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{8} ** noise.Key.key_size));

    var listener = try ListenerType.init(allocator, bob_static, 4);
    defer listener.deinit();

    var dialer = DialType.init(alice_static, bob_static.public, 30);
    var init_wire: [128]u8 = undefined;
    const init_n = try dialer.start(&init_wire, 1);

    var response_wire: [128]u8 = undefined;
    var plaintext: [64]u8 = undefined;
    const response = try listener.receive(init_wire[0..init_n], &plaintext, &response_wire, 2);
    const response_n = response.response;
    try dialer.handleResponse(response_wire[0..response_n], 3);

    const accepted = try listener.accept();
    try testing.expectEqual(conn.State.established, accepted.state());

    var send_plaintext: [64]u8 = undefined;
    var send_ciphertext: [80]u8 = undefined;
    var send_wire: [96]u8 = undefined;
    const send_n = try dialer.connection().send(protocol.event, "listener", &send_plaintext, &send_ciphertext, &send_wire, 10);
    const payload_result = try listener.receive(send_wire[0..send_n], &plaintext, &response_wire, 11);
    try testing.expectEqualStrings("listener", payload_result.payload.payload);

    const send_session = dialer.connection().currentSession().?;
    const prefix_len = noise.Varint.encode(&send_plaintext, 9);
    @memcpy(send_plaintext[prefix_len .. prefix_len + 2], "hi");
    var encoded_payload: [noise.Message.max_payload_size]u8 = undefined;
    const wrapped_len = try noise.Message.encodePayload(&encoded_payload, protocol.http, send_plaintext[0 .. prefix_len + 2]);
    const encrypted = try send_session.encrypt(encoded_payload[0..wrapped_len], &send_ciphertext, 12);
    const stream_wire_n = try noise.Message.buildTransportMessage(
        &send_wire,
        send_session.remoteIndex(),
        encrypted.nonce,
        send_ciphertext[0..encrypted.n],
    );
    try testing.expectError(errors.Error.HTTPMustUseStream, listener.receive(send_wire[0..stream_wire_n], &plaintext, &response_wire, 13));

    var tight_listener = try ListenerType.init(allocator, bob_static, 1);
    defer tight_listener.deinit();
    var dialer_b = DialType.init(alice_static, bob_static.public, 31);
    const dialer_c_static = try Noise.KeyPair.fromPrivate(noise.Key.fromBytes([_]u8{9} ** noise.Key.key_size));
    var dialer_c = DialType.init(dialer_c_static, bob_static.public, 32);

    const init_b_n = try dialer_b.start(&init_wire, 20);
    _ = try tight_listener.receive(init_wire[0..init_b_n], &plaintext, &response_wire, 21);

    const init_c_n = try dialer_c.start(&init_wire, 22);
    try testing.expectError(errors.Error.QueueFull, tight_listener.receive(init_wire[0..init_c_n], &plaintext, &response_wire, 23));
}
