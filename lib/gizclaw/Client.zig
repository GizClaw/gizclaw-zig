const glib = @import("glib");
const giznet = @import("giznet");

const RpcClient = @import("RpcClient.zig");
const models = @import("models.zig");
const service = @import("service.zig");

pub const ConnectOptions = struct {
    server_key: giznet.Key,
    server_addr: []const u8,
};

pub const InitConfig = struct {
    key_pair: giznet.KeyPair,
    device_info: models.DeviceInfo = .{},
};

pub const Config = struct {
    packet_size_capacity: usize = giznet.noise.min_packet_size_capacity + 1024,
    cipher_kind: giznet.noise.Cipher.Kind = giznet.noise.default_cipher_kind,
};

pub fn make(comptime grt: type, comptime config: Config) type {
    const Allocator = grt.std.mem.Allocator;
    const RuntimePackage = giznet.runtime.make(grt, config.packet_size_capacity, config.cipher_kind);
    const RuntimeGizNet = RuntimePackage.GizNet;
    const Rpc = RpcClient.make(grt);
    const ServerInfo = models.ServerInfo;
    const DeviceInfo = models.DeviceInfo;
    const HardwareInfo = models.HardwareInfo;
    const GearIMEI = models.GearIMEI;
    const GearLabel = models.GearLabel;
    const RuntimeStatus = models.Runtime;
    const request_timeout = 5 * glib.time.duration.Second;
    const stream_accept_timeout = 200 * glib.time.duration.MilliSecond;

    return struct {
        pub const Runtime = RuntimePackage;
        pub const GizNetImpl = RuntimeGizNet;

        allocator: Allocator,
        key_pair: giznet.KeyPair,
        local_device_info: DeviceInfo = .{},
        server_key: giznet.Key = .{},
        packet_conn: ?grt.net.PacketConn = null,
        impl: ?*GizNetImpl = null,
        root: ?giznet.GizNet = null,
        conn: ?giznet.Conn = null,
        stream_thread: ?grt.std.Thread = null,
        closing: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),

        const Self = @This();

        pub fn init(allocator: Allocator, init_config: InitConfig) !Self {
            var self = Self{
                .allocator = allocator,
                .key_pair = init_config.key_pair,
            };
            errdefer deinitDeviceInfo(allocator, &self.local_device_info);
            self.local_device_info = try self.dupeDeviceInfo(init_config.device_info);
            return self;
        }

        pub fn runtimeConfig(key_pair: giznet.KeyPair, peer_policy: giznet.noise.Engine.PeerPolicy) giznet.runtime.Engine.Config {
            return .{
                .local_static = key_pair,
                .noise = .{
                    .peer_policy = peer_policy,
                },
            };
        }

        pub fn connect(self: *Self, options: ConnectOptions) !void {
            if (self.conn != null or self.impl != null) return error.ClientAlreadyConnected;
            self.server_key = options.server_key;
            errdefer self.server_key = .{};

            var packet_conn = try grt.net.listenPacket(.{
                .allocator = self.allocator,
                .address = giznet.AddrPort.from4(.{ 0, 0, 0, 0 }, 0),
            });
            errdefer packet_conn.deinit();

            const impl = try RuntimeGizNet.init(self.allocator, packet_conn, runtimeConfig(self.key_pair, .{
                .ctx = self,
                .allow = allowServerPeer,
            }));
            errdefer impl.deinit();

            const root = try impl.up(.{});
            errdefer root.deinit();

            const endpoint = try parseAddrPort(options.server_addr);
            try root.dial(.{
                .remote_key = options.server_key,
                .endpoint = endpoint,
                .connect_timeout_ms = 5000,
                .keepalive_ms = 15_000,
            });

            const conn = try impl.acceptTimeout(5 * glib.time.duration.Second);
            self.packet_conn = packet_conn;
            self.impl = impl;
            self.root = root;
            self.conn = conn;
            errdefer self.disconnect();

            try self.startServe(.{});
        }

        fn allowServerPeer(ctx: ?*anyopaque, peer_key: giznet.Key) bool {
            const self: *Self = @ptrCast(@alignCast(ctx orelse return false));
            return peer_key.eql(self.server_key);
        }

        pub fn attach(
            self: *Self,
            server_key: giznet.Key,
            conn: giznet.Conn,
            stream_spawn_config: grt.std.Thread.SpawnConfig,
        ) !void {
            if (self.conn != null) return error.ClientAlreadyConnected;
            self.server_key = server_key;
            self.conn = conn;
            errdefer {
                self.conn = null;
                self.server_key = .{};
            }

            try self.startServe(stream_spawn_config);
        }

        pub fn deinit(self: *Self) void {
            self.disconnect();
            deinitDeviceInfo(self.allocator, &self.local_device_info);
            self.* = undefined;
        }

        fn disconnect(self: *Self) void {
            self.closing.store(true, .release);
            if (self.stream_thread) |thread| {
                thread.join();
                self.stream_thread = null;
            }
            if (self.conn) |conn| {
                conn.close() catch {};
                conn.deinit();
                self.conn = null;
            }
            if (self.root) |root| {
                root.deinit();
                self.root = null;
                self.impl = null;
            }
            if (self.packet_conn) |packet_conn| {
                packet_conn.close();
                packet_conn.deinit();
                self.packet_conn = null;
            }
        }

        fn startServe(self: *Self, stream_spawn_config: grt.std.Thread.SpawnConfig) !void {
            self.closing.store(false, .release);
            self.stream_thread = try grt.std.Thread.spawn(stream_spawn_config, streamLoop, .{self});
        }

        pub fn ping(self: *Self) !models.PingResponse {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.rpc);
            try setStreamDeadline(stream);
            var rpc_client = Rpc.Client.init(self.allocator, stream);
            defer rpc_client.deinit();
            return try rpc_client.ping("ping");
        }

        pub fn serverInfo(self: *Self) !ServerInfo {
            const response_data = try self.rpcCall("server-info-get", RpcClient.method_server_info_get, "{}");
            defer self.allocator.free(response_data);
            return try self.parseRpcServerInfo(response_data);
        }

        pub fn peerInfo(self: *Self) !DeviceInfo {
            const response_data = try self.rpcCall("peer-info-get", RpcClient.method_peer_info_get, "{}");
            defer self.allocator.free(response_data);
            return try self.parseRpcDeviceInfo(response_data);
        }

        pub fn putPeerInfo(self: *Self, info: DeviceInfo) !DeviceInfo {
            const body = try models.toJson(self.allocator, info);
            defer self.allocator.free(body);
            const response_data = try self.rpcCall("peer-info-put", RpcClient.method_peer_info_put, body);
            defer self.allocator.free(response_data);
            return try self.parseRpcDeviceInfo(response_data);
        }

        pub fn putLocalPeerInfo(self: *Self) !DeviceInfo {
            return try self.putPeerInfo(self.local_device_info);
        }

        pub fn peerRuntime(self: *Self) !RuntimeStatus {
            const response_data = try self.rpcCall("peer-runtime-get", RpcClient.method_peer_runtime_get, "{}");
            defer self.allocator.free(response_data);
            return try self.parseRpcPeerRuntime(response_data);
        }

        pub fn setPeerName(self: *Self, name: []const u8) !DeviceInfo {
            if (self.peerInfo()) |existing| {
                var info = existing;
                defer deinitDeviceInfo(self.allocator, &info);
                if (info.name) |old| {
                    self.allocator.free(old);
                    info.name = null;
                }
                info.name = try self.allocator.dupe(u8, name);
                return try self.putPeerInfo(info);
            } else |err| {
                if (err == error.GearNotFound) return try self.putPeerInfo(.{ .name = name });
                return err;
            }
        }

        pub fn deinitServerInfo(allocator: Allocator, info: *ServerInfo) void {
            allocator.free(info.public_key);
            allocator.free(info.build_commit);
            info.* = undefined;
        }

        pub fn deinitRuntime(allocator: Allocator, runtime: *RuntimeStatus) void {
            allocator.free(runtime.last_seen_at);
            if (runtime.last_addr) |value| allocator.free(value);
            runtime.* = undefined;
        }

        pub fn deinitDeviceInfo(allocator: Allocator, info: *DeviceInfo) void {
            if (info.name) |value| allocator.free(value);
            if (info.sn) |value| allocator.free(value);
            if (info.hardware) |*hardware| deinitHardwareInfo(allocator, hardware);
            info.* = undefined;
        }

        fn setStreamDeadline(stream: giznet.Stream) !void {
            const deadline = grt.time.instant.add(grt.time.instant.now(), request_timeout);
            try stream.setReadDeadline(deadline);
            try stream.setWriteDeadline(deadline);
        }

        fn streamLoop(self: *Self) void {
            while (!self.closing.load(.acquire)) {
                const conn = self.conn orelse return;
                self.acceptOneStream(conn) catch |err| {
                    if (err == error.Timeout) continue;
                    if (isClosedError(err) or self.closing.load(.acquire)) return;
                };
            }
        }

        fn acceptOneStream(self: *Self, conn: giznet.Conn) !void {
            var stream = try conn.accept(stream_accept_timeout);
            defer stream.deinit();
            defer stream.close() catch {};

            try setStreamDeadline(stream);
            switch (stream.service) {
                service.rpc => self.serveRpc(stream) catch {},
                else => {},
            }
        }

        fn serveRpc(self: *Self, stream: giznet.Stream) !void {
            const data = try Rpc.readFrame(self.allocator, stream);
            defer self.allocator.free(data);

            const Request = struct {
                v: i64,
                id: []const u8,
                method: []const u8,
            };
            const parsed = try grt.std.json.parseFromSlice(Request, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;

            const response = self.servePeerService(parsed.value.id, parsed.value.method) catch |peer_err| switch (peer_err) {
                error.RpcMethodNotFound => self.serveDeviceService(parsed.value.id, parsed.value.method) catch |device_err| switch (device_err) {
                    error.RpcMethodNotFound => try buildRpcErrorResponse(self.allocator, parsed.value.id, -32601, "method not found"),
                    else => return device_err,
                },
                else => return peer_err,
            };
            defer self.allocator.free(response);
            try Rpc.writeFrame(stream, response);
        }

        fn servePeerService(self: *Self, id: []const u8, method: []const u8) ![]u8 {
            if (grt.std.mem.eql(u8, method, RpcClient.method_ping)) {
                return try buildRpcPingResponse(self.allocator, id);
            }
            return error.RpcMethodNotFound;
        }

        fn serveDeviceService(self: *Self, id: []const u8, method: []const u8) ![]u8 {
            if (grt.std.mem.eql(u8, method, RpcClient.method_device_info_get)) {
                return try self.buildRpcDeviceInfoResponse(id);
            }
            if (grt.std.mem.eql(u8, method, RpcClient.method_device_identifiers_get)) {
                return try self.buildRpcDeviceIdentifiersResponse(id);
            }
            return error.RpcMethodNotFound;
        }

        fn deinitHardwareInfo(allocator: Allocator, hardware: *HardwareInfo) void {
            if (hardware.manufacturer) |value| allocator.free(value);
            if (hardware.model) |value| allocator.free(value);
            if (hardware.hardware_revision) |value| allocator.free(value);
            if (hardware.imeis) |items| {
                for (items) |item| deinitGearIMEI(allocator, item);
                allocator.free(items);
            }
            if (hardware.labels) |items| {
                for (items) |item| deinitGearLabel(allocator, item);
                allocator.free(items);
            }
            hardware.* = undefined;
        }

        fn deinitGearIMEI(allocator: Allocator, item: GearIMEI) void {
            allocator.free(item.tac);
            allocator.free(item.serial);
            if (item.name) |value| allocator.free(value);
        }

        fn deinitGearLabel(allocator: Allocator, item: GearLabel) void {
            allocator.free(item.key);
            allocator.free(item.value);
        }

        fn rpcCall(self: *Self, id: []const u8, method: []const u8, params_json: []const u8) ![]u8 {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.rpc);
            try setStreamDeadline(stream);
            var rpc_client = Rpc.Client.init(self.allocator, stream);
            defer rpc_client.deinit();
            return try rpc_client.call(id, method, params_json);
        }

        fn buildRpcPingResponse(allocator: Allocator, id: []const u8) ![]u8 {
            const result = models.PingResponse{ .server_time = grt.time.now().unixMilli() };
            const result_json = try models.toJson(allocator, result);
            defer allocator.free(result_json);
            return try buildRpcResultResponse(allocator, id, result_json);
        }

        fn buildRpcDeviceInfoResponse(self: *Self, id: []const u8) ![]u8 {
            const local = self.local_device_info;
            var result = models.RefreshInfo{
                .name = local.name,
            };
            if (local.hardware) |hardware| {
                result.manufacturer = hardware.manufacturer;
                result.model = hardware.model;
                result.hardware_revision = hardware.hardware_revision;
            }

            const result_json = try models.toJson(self.allocator, result);
            defer self.allocator.free(result_json);
            return try buildRpcResultResponse(self.allocator, id, result_json);
        }

        fn buildRpcDeviceIdentifiersResponse(self: *Self, id: []const u8) ![]u8 {
            const local = self.local_device_info;
            var result = models.RefreshIdentifiers{
                .sn = local.sn,
            };
            if (local.hardware) |hardware| {
                result.imeis = hardware.imeis;
                result.labels = hardware.labels;
            }

            const result_json = try models.toJson(self.allocator, result);
            defer self.allocator.free(result_json);
            return try buildRpcResultResponse(self.allocator, id, result_json);
        }

        fn buildRpcResultResponse(allocator: Allocator, id: []const u8, result_json: []const u8) ![]u8 {
            var out = grt.std.Io.Writer.Allocating.init(allocator);
            errdefer out.deinit();
            try out.writer.writeAll("{\"v\":1,\"id\":");
            try grt.std.json.Stringify.value(id, .{}, &out.writer);
            try out.writer.writeAll(",\"result\":");
            try out.writer.writeAll(result_json);
            try out.writer.writeAll("}");
            return try out.toOwnedSlice();
        }

        fn buildRpcErrorResponse(allocator: Allocator, id: []const u8, code: i64, message: []const u8) ![]u8 {
            var out = grt.std.Io.Writer.Allocating.init(allocator);
            errdefer out.deinit();
            try out.writer.writeAll("{\"v\":1,\"id\":");
            try grt.std.json.Stringify.value(id, .{}, &out.writer);
            try out.writer.print(",\"error\":{{\"code\":{d},\"message\":", .{code});
            try grt.std.json.Stringify.value(message, .{}, &out.writer);
            try out.writer.writeAll("}}");
            return try out.toOwnedSlice();
        }

        fn isClosedError(err: anyerror) bool {
            return switch (err) {
                error.ConnClosed,
                error.EndOfStream,
                error.RuntimeAcceptChannelClosed,
                error.RuntimeChannelClosed,
                error.RuntimeEngineClosed,
                error.ServiceMuxClosed,
                error.UDPClosed,
                => true,
                else => false,
            };
        }

        pub fn parseAddrPort(input: []const u8) !giznet.AddrPort {
            const text = grt.std.mem.trim(u8, input, " \t\r\n");
            if (text.len == 0) return error.InvalidServerAddress;

            if (text[0] == '[') {
                const close = grt.std.mem.indexOfScalar(u8, text, ']') orelse return error.InvalidServerAddress;
                if (close + 2 > text.len or text[close + 1] != ':') return error.InvalidServerAddress;
                const host = text[1..close];
                const port = try grt.std.fmt.parseInt(u16, text[close + 2 ..], 10);
                return giznet.AddrPort.init(try glib.net.netip.Addr.parse(host), port);
            }

            const colon = grt.std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidServerAddress;
            const host = text[0..colon];
            const port = try grt.std.fmt.parseInt(u16, text[colon + 1 ..], 10);
            return giznet.AddrPort.init(try glib.net.netip.Addr.parse(host), port);
        }

        fn parseRpcDeviceInfo(self: *Self, data: []const u8) !DeviceInfo {
            const Response = struct {
                v: i64,
                id: []const u8,
                result: ?DeviceInfo = null,
                @"error": ?models.RPCError = null,
            };
            const parsed = try grt.std.json.parseFromSlice(Response, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;
            _ = parsed.value.id;
            if (parsed.value.@"error") |rpc_error| return rpcResponseError(rpc_error);
            return try self.dupeDeviceInfo(parsed.value.result orelse return error.MissingRpcResult);
        }

        fn parseRpcPeerRuntime(self: *Self, data: []const u8) !RuntimeStatus {
            const Response = struct {
                v: i64,
                id: []const u8,
                result: ?RuntimeStatus = null,
                @"error": ?models.RPCError = null,
            };
            const parsed = try grt.std.json.parseFromSlice(Response, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;
            _ = parsed.value.id;
            if (parsed.value.@"error") |rpc_error| return rpcResponseError(rpc_error);
            return try self.dupeRuntime(parsed.value.result orelse return error.MissingRpcResult);
        }

        fn parseRpcServerInfo(self: *Self, data: []const u8) !ServerInfo {
            const Response = struct {
                v: i64,
                id: []const u8,
                result: ?ServerInfo = null,
                @"error": ?models.RPCError = null,
            };
            const parsed = try grt.std.json.parseFromSlice(Response, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;
            _ = parsed.value.id;
            if (parsed.value.@"error") |rpc_error| return rpcResponseError(rpc_error);
            return try self.dupeServerInfo(parsed.value.result orelse return error.MissingRpcResult);
        }

        fn rpcResponseError(rpc_error: models.RPCError) anyerror {
            if (rpc_error.code == -1) return error.RpcMethodNotFound;
            if (rpc_error.code == -32600) return error.RpcInvalidRequest;
            if (rpc_error.code == -32601) return error.RpcMethodNotFound;
            if (rpc_error.code == -32602) return error.RpcInvalidParams;
            if (rpc_error.code == -32603) return error.RpcInternalError;
            if (rpc_error.code == 404) return error.GearNotFound;
            if (rpc_error.code == 409) return error.GearAlreadyExists;
            if (rpc_error.code == 400) return error.BadRequest;
            return error.RpcError;
        }

        fn dupeDeviceInfo(self: *Self, info: DeviceInfo) !DeviceInfo {
            var out = DeviceInfo{};
            errdefer deinitDeviceInfo(self.allocator, &out);
            out.name = try dupeOptional(self.allocator, info.name);
            out.sn = try dupeOptional(self.allocator, info.sn);
            if (info.hardware) |hardware| {
                out.hardware = HardwareInfo{};
                out.hardware.?.manufacturer = try dupeOptional(self.allocator, hardware.manufacturer);
                out.hardware.?.model = try dupeOptional(self.allocator, hardware.model);
                out.hardware.?.hardware_revision = try dupeOptional(self.allocator, hardware.hardware_revision);
                out.hardware.?.imeis = try self.dupeGearIMEIs(hardware.imeis);
                out.hardware.?.labels = try self.dupeGearLabels(hardware.labels);
            }
            return out;
        }

        fn dupeServerInfo(self: *Self, info: ServerInfo) !ServerInfo {
            return .{
                .public_key = try self.allocator.dupe(u8, info.public_key),
                .server_time = info.server_time,
                .build_commit = try self.allocator.dupe(u8, info.build_commit),
            };
        }

        fn dupeRuntime(self: *Self, runtime: RuntimeStatus) !RuntimeStatus {
            return .{
                .online = runtime.online,
                .last_seen_at = try self.allocator.dupe(u8, runtime.last_seen_at),
                .last_addr = try dupeOptional(self.allocator, runtime.last_addr),
                .rx_bytes = runtime.rx_bytes,
                .tx_bytes = runtime.tx_bytes,
            };
        }

        fn dupeGearIMEIs(self: *Self, value: ?[]const GearIMEI) !?[]const GearIMEI {
            const items = value orelse return null;
            const out = try self.allocator.alloc(GearIMEI, items.len);
            errdefer self.allocator.free(out);
            var filled: usize = 0;
            errdefer {
                for (out[0..filled]) |item| deinitGearIMEI(self.allocator, item);
            }
            for (items, 0..) |item, index| {
                out[index] = .{
                    .tac = try self.allocator.dupe(u8, item.tac),
                    .serial = try self.allocator.dupe(u8, item.serial),
                    .name = try dupeOptional(self.allocator, item.name),
                };
                filled += 1;
            }
            return out;
        }

        fn dupeGearLabels(self: *Self, value: ?[]const GearLabel) !?[]const GearLabel {
            const items = value orelse return null;
            const out = try self.allocator.alloc(GearLabel, items.len);
            errdefer self.allocator.free(out);
            var filled: usize = 0;
            errdefer {
                for (out[0..filled]) |item| deinitGearLabel(self.allocator, item);
            }
            for (items, 0..) |item, index| {
                out[index] = .{
                    .key = try self.allocator.dupe(u8, item.key),
                    .value = try self.allocator.dupe(u8, item.value),
                };
                filled += 1;
            }
            return out;
        }

        fn dupeOptional(allocator: Allocator, value: ?[]const u8) !?[]u8 {
            if (value) |text| return try allocator.dupe(u8, text);
            return null;
        }
    };
}
