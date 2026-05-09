const glib = @import("glib");
const giznet = @import("giznet");

const rpc_mod = @import("rpc.zig");
const service = @import("service.zig");

pub const ServerInfo = struct {
    public_key: []const u8,
    server_time: i64,
    build_commit: []const u8,
};

pub const DeviceInfo = struct {
    name: ?[]const u8 = null,
    sn: ?[]const u8 = null,
    hardware: ?HardwareInfo = null,
};

pub const HardwareInfo = struct {
    manufacturer: ?[]const u8 = null,
    model: ?[]const u8 = null,
    hardware_revision: ?[]const u8 = null,
    depot: ?[]const u8 = null,
    firmware_semver: ?[]const u8 = null,
    imeis: ?[]GearIMEI = null,
    labels: ?[]GearLabel = null,
};

pub const GearIMEI = struct {
    tac: []const u8 = &.{},
    serial: []const u8 = &.{},
    name: ?[]const u8 = null,
};

pub const GearLabel = struct {
    key: []const u8 = &.{},
    value: []const u8 = &.{},
};

pub const ConnectOptions = struct {
    server_key: giznet.Key,
    server_addr: []const u8,
};

pub fn make(comptime grt: type) type {
    const rt = grt.std;
    const Allocator = grt.std.mem.Allocator;
    const packet_size_capacity = 1053;
    const RuntimePackage = giznet.runtime.make(grt, packet_size_capacity, giznet.noise.default_cipher_kind);
    const GizNetImpl = RuntimePackage.GizNet;
    const Rpc = rpc_mod.make(grt);
    const request_timeout = 5 * glib.time.duration.Second;

    return struct {
        allocator: Allocator,
        key_pair: giznet.KeyPair,
        server_key: giznet.Key = .{},
        packet_conn: ?grt.net.PacketConn = null,
        impl: ?*GizNetImpl = null,
        root: ?giznet.GizNet = null,
        conn: ?giznet.Conn = null,

        const Self = @This();

        pub fn init(allocator: Allocator, key_pair: giznet.KeyPair) Self {
            return .{
                .allocator = allocator,
                .key_pair = key_pair,
            };
        }

        pub fn connect(self: *Self, options: ConnectOptions) !void {
            if (self.conn != null or self.impl != null) return error.ClientAlreadyConnected;

            var packet_conn = try grt.net.listenPacket(.{
                .allocator = self.allocator,
                .address = giznet.AddrPort.from4(.{ 127, 0, 0, 1 }, 0),
            });
            errdefer packet_conn.deinit();

            const impl = try GizNetImpl.init(self.allocator, packet_conn, .{
                .local_static = self.key_pair,
            });
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
            self.server_key = options.server_key;
            self.packet_conn = packet_conn;
            self.impl = impl;
            self.root = root;
            self.conn = conn;
        }

        pub fn deinit(self: *Self) void {
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
            self.* = undefined;
        }

        pub fn ping(self: *Self) !rpc_mod.PingResponse {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.rpc);
            try setStreamDeadline(stream);
            var rpc_client = Rpc.Client.init(self.allocator, stream);
            defer rpc_client.deinit();
            return try rpc_client.ping("ping");
        }

        pub fn serverInfo(self: *Self) !ServerInfo {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.server_public);
            defer {
                stream.close() catch {};
                stream.deinit();
            }
            try setStreamDeadline(stream);
            try writeAll(stream,
                "GET /server-info HTTP/1.1\r\n" ++
                    "Host: gizclaw\r\n" ++
                    "User-Agent: Go-http-client/1.1\r\n" ++
                    "\r\n",
            );
            const data = try readHttpBody(self.allocator, stream, 1024 * 1024);
            defer self.allocator.free(data);
            const parsed = try rt.json.parseFromSlice(ServerInfo, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            return .{
                .public_key = try self.allocator.dupe(u8, parsed.value.public_key),
                .server_time = parsed.value.server_time,
                .build_commit = try self.allocator.dupe(u8, parsed.value.build_commit),
            };
        }

        pub fn deviceInfo(self: *Self) !DeviceInfo {
            const response_data = try self.rpcCall("gear-info-get", rpc_mod.method_gear_info_get, "{}");
            defer self.allocator.free(response_data);
            return try self.parseRpcDeviceInfo(response_data);
        }

        pub fn putDeviceInfo(self: *Self, info: DeviceInfo) !DeviceInfo {
            const body = try self.deviceInfoJson(info);
            defer self.allocator.free(body);
            const response_data = try self.rpcCall("gear-info-put", rpc_mod.method_gear_info_put, body);
            defer self.allocator.free(response_data);
            return try self.parseRpcDeviceInfo(response_data);
        }

        pub fn setDeviceName(self: *Self, name: []const u8) !DeviceInfo {
            if (self.deviceInfo()) |existing| {
                var info = existing;
                errdefer deinitDeviceInfo(self.allocator, &info);
                if (info.name) |old| self.allocator.free(old);
                info.name = try self.allocator.dupe(u8, name);
                defer deinitDeviceInfo(self.allocator, &info);
                return try self.putDeviceInfo(info);
            } else |err| {
                if (err == error.GearNotFound) return try self.registerDeviceName(name);
                return err;
            }
        }

        fn setStreamDeadline(stream: giznet.Stream) !void {
            const deadline = grt.time.instant.add(grt.time.instant.now(), request_timeout);
            try stream.setReadDeadline(deadline);
            try stream.setWriteDeadline(deadline);
        }

        pub fn deinitServerInfo(allocator: Allocator, info: *ServerInfo) void {
            allocator.free(info.public_key);
            allocator.free(info.build_commit);
            info.* = undefined;
        }

        pub fn deinitDeviceInfo(allocator: Allocator, info: *DeviceInfo) void {
            if (info.name) |value| allocator.free(value);
            if (info.sn) |value| allocator.free(value);
            if (info.hardware) |*hardware| deinitHardwareInfo(allocator, hardware);
            info.* = undefined;
        }

        fn deinitHardwareInfo(allocator: Allocator, hardware: *HardwareInfo) void {
            if (hardware.manufacturer) |value| allocator.free(value);
            if (hardware.model) |value| allocator.free(value);
            if (hardware.hardware_revision) |value| allocator.free(value);
            if (hardware.depot) |value| allocator.free(value);
            if (hardware.firmware_semver) |value| allocator.free(value);
            if (hardware.imeis) |items| {
                for (items) |*item| deinitGearIMEI(allocator, item);
                allocator.free(items);
            }
            if (hardware.labels) |items| {
                for (items) |*item| deinitGearLabel(allocator, item);
                allocator.free(items);
            }
            hardware.* = undefined;
        }

        fn deinitGearIMEI(allocator: Allocator, item: *GearIMEI) void {
            allocator.free(item.tac);
            allocator.free(item.serial);
            if (item.name) |value| allocator.free(value);
            item.* = undefined;
        }

        fn deinitGearLabel(allocator: Allocator, item: *GearLabel) void {
            allocator.free(item.key);
            allocator.free(item.value);
            item.* = undefined;
        }

        fn rpcCall(self: *Self, id: []const u8, method: []const u8, params_json: []const u8) ![]u8 {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.rpc);
            try setStreamDeadline(stream);
            var rpc_client = Rpc.Client.init(self.allocator, stream);
            defer rpc_client.deinit();
            return try rpc_client.call(id, method, params_json);
        }

        fn readHttpBody(allocator: Allocator, stream: giznet.Stream, max_size: usize) ![]u8 {
            var response = try readHttpResponse(allocator, stream, max_size);
            defer response.deinit(allocator);
            if (response.status_code != 200) return error.ServerInfoRequestFailed;
            return try allocator.dupe(u8, response.body);
        }

        const HttpResponse = struct {
            status_code: u16,
            body: []u8,

            fn deinit(self: *@This(), allocator: Allocator) void {
                allocator.free(self.body);
                self.* = undefined;
            }
        };

        fn readHttpResponse(allocator: Allocator, stream: giznet.Stream, max_size: usize) !HttpResponse {
            var out: rt.ArrayList(u8) = .{};
            defer out.deinit(allocator);
            var buf: [4096]u8 = undefined;
            var header_end: ?usize = null;
            var content_length: ?usize = null;
            var status_code: ?u16 = null;
            while (true) {
                const n = try stream.read(&buf);
                if (n == 0) {
                    const end = header_end orelse return error.EndOfStream;
                    return .{
                        .status_code = status_code orelse return error.InvalidHttpResponse,
                        .body = try allocator.dupe(u8, out.items[end..]),
                    };
                }
                if (out.items.len + n > max_size) return error.ResponseBodyTooLarge;
                try out.appendSlice(allocator, buf[0..n]);
                if (header_end == null) {
                    header_end = findHeaderEnd(out.items);
                    if (header_end) |end| {
                        status_code = try parseStatusCode(out.items[0..end]);
                        content_length = try parseContentLength(out.items[0..end]);
                    }
                }
                if (header_end) |end| {
                    if (content_length) |len| {
                        if (out.items.len >= end + len) {
                            return .{
                                .status_code = status_code orelse return error.InvalidHttpResponse,
                                .body = try allocator.dupe(u8, out.items[end .. end + len]),
                            };
                        }
                    }
                }
            }
        }

        fn writeAll(stream: giznet.Stream, data: []const u8) !void {
            var offset: usize = 0;
            while (offset < data.len) {
                const n = try stream.write(data[offset..]);
                if (n == 0) return error.WriteZero;
                offset += n;
            }
        }

        fn findHeaderEnd(data: []const u8) ?usize {
            if (rt.mem.indexOf(u8, data, "\r\n\r\n")) |pos| return pos + 4;
            return null;
        }

        fn parseStatusCode(head: []const u8) !u16 {
            const first_line_end = rt.mem.indexOf(u8, head, "\r\n") orelse return error.InvalidHttpResponse;
            const first_line = head[0..first_line_end];
            if (!rt.mem.startsWith(u8, first_line, "HTTP/1.1 ") and
                !rt.mem.startsWith(u8, first_line, "HTTP/1.0 ")) return error.InvalidHttpResponse;
            if (first_line.len < "HTTP/1.1 000".len) return error.InvalidHttpResponse;
            return try rt.fmt.parseInt(u16, first_line["HTTP/1.1 ".len..][0..3], 10);
        }

        fn parseContentLength(head: []const u8) !?usize {
            var lines = rt.mem.splitSequence(u8, head, "\r\n");
            _ = lines.next();
            while (lines.next()) |line| {
                const colon = rt.mem.indexOfScalar(u8, line, ':') orelse continue;
                const name = rt.mem.trim(u8, line[0..colon], " \t");
                if (!rt.ascii.eqlIgnoreCase(name, "Content-Length")) continue;
                const value = rt.mem.trim(u8, line[colon + 1 ..], " \t");
                return try rt.fmt.parseInt(usize, value, 10);
            }
            return null;
        }

        fn parseAddrPort(input: []const u8) !giznet.AddrPort {
            const text = rt.mem.trim(u8, input, " \t\r\n");
            if (text.len == 0) return error.InvalidServerAddress;

            if (text[0] == '[') {
                const close = rt.mem.indexOfScalar(u8, text, ']') orelse return error.InvalidServerAddress;
                if (close + 2 > text.len or text[close + 1] != ':') return error.InvalidServerAddress;
                const host = text[1..close];
                const port = try rt.fmt.parseInt(u16, text[close + 2 ..], 10);
                return giznet.AddrPort.init(try glib.net.netip.Addr.parse(host), port);
            }

            const colon = rt.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidServerAddress;
            const host = text[0..colon];
            const port = try rt.fmt.parseInt(u16, text[colon + 1 ..], 10);
            return giznet.AddrPort.init(try glib.net.netip.Addr.parse(host), port);
        }

        fn registerDeviceName(self: *Self, name: []const u8) !DeviceInfo {
            const device = DeviceInfo{ .name = name };
            const device_json = try self.deviceInfoJson(device);
            defer self.allocator.free(device_json);
            const body = try rt.fmt.allocPrint(self.allocator, "{{\"device\":{s}}}", .{device_json});
            defer self.allocator.free(body);

            const response_data = try self.rpcCall("gear-registration-register", rpc_mod.method_gear_registration_register, body);
            defer self.allocator.free(response_data);
            const Result = struct {
                v: i64,
                id: []const u8,
                result: ?struct {
                    gear: struct {
                        device: DeviceInfo = .{},
                    },
                } = null,
                @"error": ?rpc_mod.RpcError = null,
            };
            const parsed = try rt.json.parseFromSlice(Result, self.allocator, response_data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;
            _ = parsed.value.id;
            if (parsed.value.@"error") |rpc_error| return rpcResponseError(rpc_error);
            const result = parsed.value.result orelse return error.MissingRpcResult;
            return try self.dupeDeviceInfo(result.gear.device);
        }

        fn parseRpcDeviceInfo(self: *Self, data: []const u8) !DeviceInfo {
            const Response = struct {
                v: i64,
                id: []const u8,
                result: ?DeviceInfo = null,
                @"error": ?rpc_mod.RpcError = null,
            };
            const parsed = try rt.json.parseFromSlice(Response, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;
            _ = parsed.value.id;
            if (parsed.value.@"error") |rpc_error| return rpcResponseError(rpc_error);
            return try self.dupeDeviceInfo(parsed.value.result orelse return error.MissingRpcResult);
        }

        fn rpcResponseError(rpc_error: rpc_mod.RpcError) anyerror {
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
                out.hardware.?.depot = try dupeOptional(self.allocator, hardware.depot);
                out.hardware.?.firmware_semver = try dupeOptional(self.allocator, hardware.firmware_semver);
                out.hardware.?.imeis = try self.dupeGearIMEIs(hardware.imeis);
                out.hardware.?.labels = try self.dupeGearLabels(hardware.labels);
            }
            return out;
        }

        fn dupeGearIMEIs(self: *Self, value: ?[]GearIMEI) !?[]GearIMEI {
            const items = value orelse return null;
            const out = try self.allocator.alloc(GearIMEI, items.len);
            errdefer self.allocator.free(out);
            var filled: usize = 0;
            errdefer {
                for (out[0..filled]) |*item| deinitGearIMEI(self.allocator, item);
            }
            for (items, 0..) |item, index| {
                out[index] = .{};
                out[index].tac = try self.allocator.dupe(u8, item.tac);
                out[index].serial = try self.allocator.dupe(u8, item.serial);
                out[index].name = try dupeOptional(self.allocator, item.name);
                filled += 1;
            }
            return out;
        }

        fn dupeGearLabels(self: *Self, value: ?[]GearLabel) !?[]GearLabel {
            const items = value orelse return null;
            const out = try self.allocator.alloc(GearLabel, items.len);
            errdefer self.allocator.free(out);
            var filled: usize = 0;
            errdefer {
                for (out[0..filled]) |*item| deinitGearLabel(self.allocator, item);
            }
            for (items, 0..) |item, index| {
                out[index] = .{};
                out[index].key = try self.allocator.dupe(u8, item.key);
                out[index].value = try self.allocator.dupe(u8, item.value);
                filled += 1;
            }
            return out;
        }

        fn dupeOptional(allocator: Allocator, value: ?[]const u8) !?[]u8 {
            if (value) |text| return try allocator.dupe(u8, text);
            return null;
        }

        fn deviceInfoJson(self: *Self, info: DeviceInfo) ![]u8 {
            var out = rt.Io.Writer.Allocating.init(self.allocator);
            errdefer out.deinit();
            try rt.json.Stringify.value(info, .{}, &out.writer);
            return try out.toOwnedSlice();
        }
    };
}
