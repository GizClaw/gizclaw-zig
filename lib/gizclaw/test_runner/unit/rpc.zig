const glib = @import("glib");
const giznet = @import("giznet");
const gizclaw = @import("../../../gizclaw.zig");
const models = @import("../../models.zig");

pub fn make(comptime grt: type) glib.testing.TestRunner {
    return glib.testing.TestRunner.fromFn(grt.std, 1024 * 1024, struct {
        fn run(_: *glib.testing.T, allocator: grt.std.mem.Allocator) !void {
            try rpcTypes(grt);
            try rpcRequestEscapesStrings(grt, allocator);
            try rpcFrameProtocol(grt, allocator);
        }

        fn rpcTypes(comptime any_grt: type) !void {
            const testing = any_grt.std.testing;
            const req: models.PingRequest = .{ .client_send_time = 123 };
            const resp: models.PingResponse = .{ .server_time = 456 };
            const rpc_error: models.RPCError = .{ .code = 1, .message = "boom" };

            try testing.expectEqual(@as(i64, 123), req.client_send_time);
            try testing.expectEqual(@as(i64, 456), resp.server_time);
            try testing.expectEqual(@as(i64, 1), rpc_error.code);
            try testing.expectEqualStrings("boom", rpc_error.message);
            try testing.expectEqualStrings("peer.ping", models.RpcMethods.peer_ping);
            try testing.expectEqualStrings("device.info.get", models.RpcMethods.device_info_get);
            try testing.expectEqualStrings("device.identifiers.get", models.RpcMethods.device_identifiers_get);
            try testing.expectEqualStrings("peer.info.get", models.RpcMethods.peer_info_get);
            try testing.expectEqualStrings("peer.info.put", models.RpcMethods.peer_info_put);
            try testing.expectEqualStrings("peer.runtime.get", models.RpcMethods.peer_runtime_get);
            try testing.expectEqualStrings("server.info.get", models.RpcMethods.server_info_get);
            _ = models.RPCRequest;
            _ = models.RPCResponse;
        }

        fn rpcRequestEscapesStrings(comptime any_grt: type, allocator: any_grt.std.mem.Allocator) !void {
            const testing = any_grt.std.testing;
            const rpc = gizclaw.Rpc.make(any_grt);

            const request = try rpc.buildRequest(allocator, "quote\"id", gizclaw.Rpc.method_ping, "{}");
            defer allocator.free(request);

            try testing.expectEqualStrings(
                "{\"v\":1,\"id\":\"quote\\\"id\",\"method\":\"peer.ping\",\"params\":{}}",
                request,
            );
        }

        fn rpcFrameProtocol(comptime any_grt: type, allocator: any_grt.std.mem.Allocator) !void {
            const testing = any_grt.std.testing;
            const rpc = gizclaw.Rpc.make(any_grt);

            const MemoryStream = struct {
                input: []const u8,
                read_offset: usize = 0,
                output: []u8,
                output_len: usize = 0,
                closed: bool = false,
                deinited: bool = false,

                fn written(self: *@This()) []const u8 {
                    return self.output[0..self.output_len];
                }

                pub fn read(self: *@This(), buf: []u8) !usize {
                    if (self.read_offset >= self.input.len) return 0;
                    const n = @min(buf.len, self.input.len - self.read_offset);
                    @memcpy(buf[0..n], self.input[self.read_offset..][0..n]);
                    self.read_offset += n;
                    return n;
                }

                pub fn setReadDeadline(_: *@This(), _: glib.time.instant.Time) !void {}

                pub fn write(self: *@This(), payload: []const u8) !usize {
                    if (self.output_len + payload.len > self.output.len) return error.NoSpaceLeft;
                    @memcpy(self.output[self.output_len..][0..payload.len], payload);
                    self.output_len += payload.len;
                    return payload.len;
                }

                pub fn setWriteDeadline(_: *@This(), _: glib.time.instant.Time) !void {}

                pub fn close(self: *@This()) !void {
                    self.closed = true;
                }

                pub fn deinit(self: *@This()) void {
                    self.deinited = true;
                }
            };

            const Helper = struct {
                fn stream(impl: *MemoryStream) giznet.Stream {
                    return giznet.Stream.init(impl, 0, 0);
                }

                fn appendFrame(
                    buf: []u8,
                    len: *usize,
                    frame_type: gizclaw.Rpc.FrameType,
                    payload: []const u8,
                ) void {
                    any_grt.std.mem.writeInt(u16, buf[len.*..][0..2], @intCast(payload.len), .little);
                    any_grt.std.mem.writeInt(u16, buf[len.* + 2 ..][0..2], @intFromEnum(frame_type), .little);
                    len.* += 4;
                    @memcpy(buf[len.*..][0..payload.len], payload);
                    len.* += payload.len;
                }
            };

            {
                var out_buf: [16]u8 = undefined;
                var impl = MemoryStream{ .input = "", .output = &out_buf };
                try rpc.writeJsonFrame(Helper.stream(&impl), "{}");
                try testing.expectEqualSlices(u8, &[_]u8{ 2, 0, 1, 0, '{', '}' }, impl.written());
            }

            {
                var out_buf: [16]u8 = undefined;
                var impl = MemoryStream{ .input = "", .output = &out_buf };
                try rpc.writeEOS(Helper.stream(&impl));
                try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, impl.written());
            }

            {
                const input = [_]u8{ 2, 0, 1, 0, '{', '}' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                var frame = try rpc.readFrame(allocator, Helper.stream(&impl));
                defer frame.deinit(allocator);
                try testing.expectEqual(gizclaw.Rpc.FrameType.json, frame.type);
                try testing.expectEqualStrings("{}", frame.payload);
            }

            {
                const input = [_]u8{ 0, 0, 0, 0 };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try rpc.readEOS(allocator, Helper.stream(&impl));
            }

            {
                const input = [_]u8{ 0, 0, 99, 0 };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.UnknownRpcFrameType, rpc.readFrame(allocator, Helper.stream(&impl)));
            }

            {
                const input = [_]u8{ 1, 0, 0, 0, 'x' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.RpcEOSFrameMustBeEmpty, rpc.readFrame(allocator, Helper.stream(&impl)));
            }

            {
                const payload = try allocator.alloc(u8, gizclaw.Rpc.max_frame_size + 1);
                defer allocator.free(payload);
                var out_buf: [16]u8 = undefined;
                var impl = MemoryStream{ .input = "", .output = &out_buf };
                try testing.expectError(error.RpcFrameTooLarge, rpc.writeFrame(Helper.stream(&impl), .binary, payload));
            }

            {
                const input = [_]u8{ 2, 0, 2, 0, '{', '}' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.ExpectedRpcJsonFrame, rpc.readJsonFrame(allocator, Helper.stream(&impl)));
            }

            {
                const input = [_]u8{ 2, 0, 1, 0, '{', '}' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.ExpectedRpcEOSFrame, rpc.readEOS(allocator, Helper.stream(&impl)));
            }

            {
                const input = [_]u8{ 2, 0, 1 };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.TruncatedRpcStream, rpc.readFrame(allocator, Helper.stream(&impl)));
            }

            {
                const input = [_]u8{ 2, 0, 1, 0, '{' };
                var out_buf: [1]u8 = undefined;
                var impl = MemoryStream{ .input = &input, .output = &out_buf };
                try testing.expectError(error.TruncatedRpcStream, rpc.readFrame(allocator, Helper.stream(&impl)));
            }

            {
                const response_json = "{\"v\":1,\"id\":\"req\",\"result\":{\"server_time\":456}}";
                var input_buf: [128]u8 = undefined;
                var input_len: usize = 0;
                Helper.appendFrame(&input_buf, &input_len, .json, response_json);
                Helper.appendFrame(&input_buf, &input_len, .eos, "");

                var out_buf: [256]u8 = undefined;
                var impl = MemoryStream{ .input = input_buf[0..input_len], .output = &out_buf };
                var client = rpc.Rpc.init(allocator, Helper.stream(&impl));
                const response = try client.call("req", gizclaw.Rpc.method_ping, "{\"client_send_time\":1}");
                defer allocator.free(response);
                try testing.expectEqualStrings(response_json, response);

                const request = try rpc.buildRequest(allocator, "req", gizclaw.Rpc.method_ping, "{\"client_send_time\":1}");
                defer allocator.free(request);
                var expected: [256]u8 = undefined;
                var expected_len: usize = 0;
                Helper.appendFrame(&expected, &expected_len, .json, request);
                Helper.appendFrame(&expected, &expected_len, .eos, "");
                try testing.expectEqualSlices(u8, expected[0..expected_len], impl.written());

                try client.close();
                client.deinit();
                try testing.expect(impl.closed);
                try testing.expect(impl.deinited);
            }
        }
    }.run);
}
