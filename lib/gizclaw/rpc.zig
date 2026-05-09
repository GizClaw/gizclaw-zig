const rpc_types = @import("rpc_types.zig");

pub const max_frame_size: u32 = 1 << 20;
pub const method_ping = "peer.ping";
pub const method_gear_info_get = "gear.info.get";
pub const method_gear_info_put = "gear.info.put";
pub const method_gear_registration_register = "gear.registration.register";

pub const PingRequest = rpc_types.PingRequest;
pub const PingResponse = rpc_types.PingResponse;
pub const RpcError = rpc_types.RPCError;
pub const RPCRequest = rpc_types.RPCRequest;
pub const RPCResponse = rpc_types.RPCResponse;

pub fn make(comptime grt: type) type {
    const rt = grt.std;
    const Allocator = grt.std.mem.Allocator;
    const Stream = @import("giznet").Stream;

    return struct {
        pub const Client = struct {
            allocator: Allocator,
            stream: Stream,

            pub fn init(allocator: Allocator, stream: Stream) Client {
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

            pub fn ping(self: *Client, id: []const u8) !PingResponse {
                const params = try rt.fmt.allocPrint(
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
                    result: ?PingResponse = null,
                    @"error": ?RpcError = null,
                };
                const parsed = try rt.json.parseFromSlice(Response, self.allocator, response_data, .{ .ignore_unknown_fields = true });
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
            var out = rt.Io.Writer.Allocating.init(allocator);
            errdefer out.deinit();

            try out.writer.writeAll("{\"v\":1,\"id\":");
            try rt.json.Stringify.value(id, .{}, &out.writer);
            try out.writer.writeAll(",\"method\":");
            try rt.json.Stringify.value(method, .{}, &out.writer);
            try out.writer.writeAll(",\"params\":");
            try out.writer.writeAll(params_json);
            try out.writer.writeAll("}");
            return try out.toOwnedSlice();
        }

        pub fn writeFrame(stream: Stream, data: []const u8) !void {
            if (data.len > max_frame_size) return error.RpcFrameTooLarge;
            var header: [4]u8 = undefined;
            rt.mem.writeInt(u32, &header, @intCast(data.len), .little);
            try writeAll(stream, &header);
            try writeAll(stream, data);
        }

        pub fn readFrame(allocator: Allocator, stream: Stream) ![]u8 {
            var header: [4]u8 = undefined;
            try readExact(stream, &header);
            const length = rt.mem.readInt(u32, &header, .little);
            if (length > max_frame_size) return error.RpcFrameTooLarge;
            const out = try allocator.alloc(u8, length);
            errdefer allocator.free(out);
            try readExact(stream, out);
            return out;
        }

        fn readExact(stream: Stream, buf: []u8) !void {
            var offset: usize = 0;
            while (offset < buf.len) {
                const n = try stream.read(buf[offset..]);
                if (n == 0) return error.EndOfStream;
                offset += n;
            }
        }

        fn writeAll(stream: Stream, data: []const u8) !void {
            var offset: usize = 0;
            while (offset < data.len) {
                const n = try stream.write(data[offset..]);
                if (n == 0) return error.WriteZero;
                offset += n;
            }
        }
    };
}
