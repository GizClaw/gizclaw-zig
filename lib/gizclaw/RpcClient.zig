const giznet = @import("giznet");
const models = @import("models.zig");

pub const max_frame_size: u32 = 1 << 20;
pub const method_ping = models.RpcMethods.peer_ping;
pub const method_device_info_get = models.RpcMethods.device_info_get;
pub const method_device_identifiers_get = models.RpcMethods.device_identifiers_get;
pub const method_peer_info_get = models.RpcMethods.peer_info_get;
pub const method_peer_info_put = models.RpcMethods.peer_info_put;
pub const method_peer_runtime_get = models.RpcMethods.peer_runtime_get;
pub const method_server_info_get = models.RpcMethods.server_info_get;

pub fn make(comptime grt: type) type {
    const Allocator = grt.std.mem.Allocator;

    return struct {
        pub const Client = struct {
            allocator: Allocator,
            stream: giznet.Stream,

            pub fn init(allocator: Allocator, stream: giznet.Stream) Client {
                return .{
                    .allocator = allocator,
                    .stream = stream,
                };
            }

            pub fn deinit(self: *Client) void {
                self.stream.close() catch {};
                self.stream.deinit();
                self.* = undefined;
            }

            pub fn ping(self: *Client, id: []const u8) !models.PingResponse {
                const params = try grt.std.fmt.allocPrint(
                    self.allocator,
                    "{{\"client_send_time\":{d}}}",
                    .{grt.time.now().unixMilli()},
                );
                defer self.allocator.free(params);
                const response_data = try self.call(id, method_ping, params);
                defer self.allocator.free(response_data);

                const Response = struct {
                    v: i64,
                    id: []const u8,
                    result: ?models.PingResponse = null,
                    @"error": ?models.RPCError = null,
                };
                const parsed = try grt.std.json.parseFromSlice(Response, self.allocator, response_data, .{ .ignore_unknown_fields = true });
                defer parsed.deinit();
                _ = parsed.value.v;
                _ = parsed.value.id;
                if (parsed.value.@"error") |_| return error.RpcError;
                return parsed.value.result orelse error.MissingRpcResult;
            }

            pub fn call(self: *Client, id: []const u8, method: []const u8, params_json: []const u8) ![]u8 {
                const request = try buildRequest(self.allocator, id, method, params_json);
                defer self.allocator.free(request);

                try writeFrame(self.stream, request);
                return try readFrame(self.allocator, self.stream);
            }
        };

        pub fn buildRequest(allocator: Allocator, id: []const u8, method: []const u8, params_json: []const u8) ![]u8 {
            var out = grt.std.Io.Writer.Allocating.init(allocator);
            errdefer out.deinit();

            try out.writer.writeAll("{\"v\":1,\"id\":");
            try grt.std.json.Stringify.value(id, .{}, &out.writer);
            try out.writer.writeAll(",\"method\":");
            try grt.std.json.Stringify.value(method, .{}, &out.writer);
            try out.writer.writeAll(",\"params\":");
            try out.writer.writeAll(params_json);
            try out.writer.writeAll("}");
            return try out.toOwnedSlice();
        }

        pub fn writeFrame(stream: giznet.Stream, data: []const u8) !void {
            if (data.len > max_frame_size) return error.RpcFrameTooLarge;
            var header: [4]u8 = undefined;
            grt.std.mem.writeInt(u32, &header, @intCast(data.len), .little);
            try writeAll(stream, &header);
            try writeAll(stream, data);
        }

        pub fn readFrame(allocator: Allocator, stream: giznet.Stream) ![]u8 {
            var header: [4]u8 = undefined;
            try readExact(stream, &header);
            const length = grt.std.mem.readInt(u32, &header, .little);
            if (length > max_frame_size) return error.RpcFrameTooLarge;
            const out = try allocator.alloc(u8, length);
            errdefer allocator.free(out);
            try readExact(stream, out);
            return out;
        }

        fn readExact(stream: giznet.Stream, buf: []u8) !void {
            var offset: usize = 0;
            while (offset < buf.len) {
                const n = try stream.read(buf[offset..]);
                if (n == 0) return error.EndOfStream;
                offset += n;
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
    };
}
