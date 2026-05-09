const glib = @import("glib");
const gizclaw = @import("../../../gizclaw.zig");

pub fn make(comptime grt: type) glib.testing.TestRunner {
    return glib.testing.TestRunner.fromFn(grt.std, 1024 * 1024, struct {
        fn run(_: *glib.testing.T, allocator: grt.std.mem.Allocator) !void {
            try rpcTypes(grt);
            try rpcRequestEscapesStrings(grt, allocator);
        }

        fn rpcTypes(comptime any_grt: type) !void {
            const testing = any_grt.std.testing;
            const rpc = gizclaw.rpc;

            const req: rpc.PingRequest = .{ .client_send_time = 123 };
            const resp: rpc.PingResponse = .{ .server_time = 456 };
            const rpc_error: rpc.RpcError = .{ .code = 1, .message = "boom" };

            try testing.expectEqual(@as(i64, 123), req.client_send_time);
            try testing.expectEqual(@as(i64, 456), resp.server_time);
            try testing.expectEqual(@as(i64, 1), rpc_error.code);
            try testing.expectEqualStrings("boom", rpc_error.message);
            _ = rpc.RPCRequest;
            _ = rpc.RPCResponse;
        }

        fn rpcRequestEscapesStrings(comptime any_grt: type, allocator: any_grt.std.mem.Allocator) !void {
            const testing = any_grt.std.testing;
            const rpc = gizclaw.rpc.make(any_grt);

            const request = try rpc.buildRequest(allocator, "quote\"id", "peer.ping", "{}");
            defer allocator.free(request);

            try testing.expectEqualStrings(
                "{\"v\":1,\"id\":\"quote\\\"id\",\"method\":\"peer.ping\",\"params\":{}}",
                request,
            );
        }
    }.run);
}
