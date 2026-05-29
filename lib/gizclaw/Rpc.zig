const giznet = @import("giznet");
const models = @import("models.zig");

pub const max_frame_size: usize = 65535;
pub const method_ping = models.RpcMethods.peer_ping;
pub const method_device_info_get = models.RpcMethods.device_info_get;
pub const method_device_identifiers_get = models.RpcMethods.device_identifiers_get;
pub const method_peer_info_get = models.RpcMethods.peer_info_get;
pub const method_peer_info_put = models.RpcMethods.peer_info_put;
pub const method_peer_runtime_get = models.RpcMethods.peer_runtime_get;
pub const method_server_info_get = models.RpcMethods.server_info_get;

pub const FrameType = enum(u16) {
    eos = 0,
    json = 1,
    binary = 2,
    text = 3,
};

pub fn make(comptime grt: type) type {
    const Allocator = grt.std.mem.Allocator;

    return struct {
        const Package = @This();

        pub const Frame = struct {
            type: FrameType,
            payload: []u8,

            pub fn deinit(self: *Frame, allocator: Allocator) void {
                allocator.free(self.payload);
                self.* = undefined;
            }
        };

        pub const Rpc = struct {
            allocator: Allocator,
            stream: giznet.Stream,
            closed: bool = false,

            pub fn init(allocator: Allocator, stream: giznet.Stream) Rpc {
                return .{
                    .allocator = allocator,
                    .stream = stream,
                };
            }

            pub fn close(self: *Rpc) !void {
                if (self.closed) return;
                self.closed = true;
                try self.stream.close();
            }

            pub fn deinit(self: *Rpc) void {
                self.close() catch {};
                self.stream.deinit();
                self.* = undefined;
            }

            pub fn ping(self: *Rpc, id: []const u8) !models.PingResponse {
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

            pub fn call(self: *Rpc, id: []const u8, method: []const u8, params_json: []const u8) ![]u8 {
                const request = try buildRequest(self.allocator, id, method, params_json);
                defer self.allocator.free(request);

                try self.writeJsonFrame(request);
                try self.writeEOS();

                const response_data = try self.readJsonFrame();
                errdefer self.allocator.free(response_data);
                try self.readEOS();
                return response_data;
            }

            pub fn writeFrame(self: *Rpc, frame_type: FrameType, payload: []const u8) !void {
                try Package.writeFrame(self.stream, frame_type, payload);
            }

            pub fn readFrame(self: *Rpc) !Frame {
                return try Package.readFrame(self.allocator, self.stream);
            }

            pub fn writeEOS(self: *Rpc) !void {
                try Package.writeEOS(self.stream);
            }

            pub fn readEOS(self: *Rpc) !void {
                try Package.readEOS(self.allocator, self.stream);
            }

            pub fn writeJsonFrame(self: *Rpc, data: []const u8) !void {
                try Package.writeJsonFrame(self.stream, data);
            }

            pub fn readJsonFrame(self: *Rpc) ![]u8 {
                return try Package.readJsonFrame(self.allocator, self.stream);
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

        pub fn writeFrame(stream: giznet.Stream, frame_type: FrameType, payload: []const u8) !void {
            if (payload.len > max_frame_size) return error.RpcFrameTooLarge;
            if (frame_type == .eos and payload.len != 0) return error.RpcEOSFrameMustBeEmpty;

            var header: [4]u8 = undefined;
            grt.std.mem.writeInt(u16, header[0..2], @intCast(payload.len), .little);
            grt.std.mem.writeInt(u16, header[2..4], @intFromEnum(frame_type), .little);
            try writeAll(stream, &header);
            try writeAll(stream, payload);
        }

        pub fn readFrame(allocator: Allocator, stream: giznet.Stream) !Frame {
            var header: [4]u8 = undefined;
            try readExact(stream, &header);
            const length = grt.std.mem.readInt(u16, header[0..2], .little);
            const raw_type = grt.std.mem.readInt(u16, header[2..4], .little);
            const frame_type: FrameType = switch (raw_type) {
                0 => .eos,
                1 => .json,
                2 => .binary,
                3 => .text,
                else => return error.UnknownRpcFrameType,
            };
            if (frame_type == .eos and length != 0) return error.RpcEOSFrameMustBeEmpty;

            const payload = try allocator.alloc(u8, length);
            errdefer allocator.free(payload);
            try readExact(stream, payload);
            return .{
                .type = frame_type,
                .payload = payload,
            };
        }

        pub fn writeEOS(stream: giznet.Stream) !void {
            try writeFrame(stream, .eos, "");
        }

        pub fn readEOS(allocator: Allocator, stream: giznet.Stream) !void {
            var frame = try readFrame(allocator, stream);
            defer frame.deinit(allocator);
            if (frame.type != .eos) return error.ExpectedRpcEOSFrame;
        }

        pub fn writeJsonFrame(stream: giznet.Stream, data: []const u8) !void {
            try writeFrame(stream, .json, data);
        }

        pub fn readJsonFrame(allocator: Allocator, stream: giznet.Stream) ![]u8 {
            var frame = try readFrame(allocator, stream);
            if (frame.type != .json) {
                frame.deinit(allocator);
                return error.ExpectedRpcJsonFrame;
            }
            return frame.payload;
        }

        fn readExact(stream: giznet.Stream, buf: []u8) !void {
            var offset: usize = 0;
            while (offset < buf.len) {
                const n = stream.read(buf[offset..]) catch |err| switch (err) {
                    error.EndOfStream => return error.TruncatedRpcStream,
                    error.StreamClosed => return error.TruncatedRpcStream,
                    error.ConnClosed => return error.TruncatedRpcStream,
                    else => return err,
                };
                if (n == 0) return error.TruncatedRpcStream;
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
