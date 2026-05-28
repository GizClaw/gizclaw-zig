const glib = @import("glib");
const gizclaw = @import("../../../gizclaw.zig");
const models = @import("../../models.zig");

pub fn make(comptime grt: type) glib.testing.TestRunner {
    return glib.testing.TestRunner.fromFn(grt.std, 1024 * 1024, struct {
        fn run(_: *glib.testing.T, allocator: grt.std.mem.Allocator) !void {
            try rpcTypes(grt);
            try rpcRequestEscapesStrings(grt, allocator);
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
            const rpc = gizclaw.RpcClient.make(any_grt);

            const request = try rpc.buildRequest(allocator, "quote\"id", gizclaw.RpcClient.method_ping, "{}");
            defer allocator.free(request);

            try testing.expectEqualStrings(
                "{\"v\":1,\"id\":\"quote\\\"id\",\"method\":\"peer.ping\",\"params\":{}}",
                request,
            );
        }
    }.run);
}
