const dep = @import("dep");
const net_pkg = @import("../../../../net.zig");
const testing_api = dep.testing;

const peer = net_pkg.peer;
const PeerRealUdpFixtureFile = @import("../test_utils/peer_real_udp_fixture.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const testing = lib.testing;
    const Fixture = PeerRealUdpFixtureFile.make(lib);

    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;

            var fixture = Fixture.init(allocator, .{
                .enable_kcp = true,
            }) catch |err| {
                t.logErrorf("integration/net/peer_rpc_round_trip_real_udp setup failed: {}", .{err});
                return false;
            };
            defer fixture.deinit();

            runCase(&fixture, testing, allocator) catch |err| {
                t.logErrorf("integration/net/peer_rpc_round_trip_real_udp failed: {}", .{err});
                return false;
            };
            return true;
        }

        pub fn deinit(self: *@This(), allocator: dep.embed.mem.Allocator) void {
            _ = allocator;
            lib.testing.allocator.destroy(self);
        }
    };

    const value = lib.testing.allocator.create(Runner) catch @panic("OOM");
    value.* = .{};
    return testing_api.TestRunner.make(Runner).new(value);
}

fn runCase(fixture: anytype, testing: anytype, allocator: dep.embed.mem.Allocator) !void {
    try fixture.dialAndAccept();

    var client_stream = try (try fixture.clientConn()).openRPC();
    defer client_stream.deinit();
    var server_stream = try fixture.waitForAcceptedServerRPC(256);
    defer server_stream.deinit();

    const request = peer.RPCRequest{
        .id = "rpc-1",
        .method = "ping",
        .params = "{\"seq\":1}",
    };
    const request_bytes = try peer.encodeRPCRequest(allocator, request);
    defer allocator.free(request_bytes);

    _ = try client_stream.write(request_bytes);
    var buf: [256]u8 = undefined;
    const request_n = try fixture.waitForStreamRead(server_stream, &buf, 256);
    var decoded_request = try peer.decodeRPCRequest(allocator, buf[0..request_n]);
    defer decoded_request.deinit(allocator);
    try testing.expectEqualStrings("rpc-1", decoded_request.id);
    try testing.expectEqualStrings("ping", decoded_request.method);
    try testing.expectEqualStrings("{\"seq\":1}", decoded_request.params.?);

    const response = peer.RPCResponse{
        .id = "rpc-1",
        .result = "{\"ok\":true}",
    };
    const response_bytes = try peer.encodeRPCResponse(allocator, response);
    defer allocator.free(response_bytes);

    _ = try server_stream.write(response_bytes);
    const response_n = try fixture.waitForStreamRead(client_stream, &buf, 256);
    var decoded_response = try peer.decodeRPCResponse(allocator, buf[0..response_n]);
    defer decoded_response.deinit(allocator);
    try testing.expectEqualStrings("rpc-1", decoded_response.id);
    try testing.expectEqualStrings("{\"ok\":true}", decoded_response.result.?);

    const error_response = peer.RPCResponse{
        .id = "rpc-2",
        .@"error" = .{
            .code = 7,
            .message = "boom",
            .data = "{\"detail\":2}",
        },
    };
    const error_response_bytes = try peer.encodeRPCResponse(allocator, error_response);
    defer allocator.free(error_response_bytes);

    _ = try server_stream.write(error_response_bytes);
    const error_n = try fixture.waitForStreamRead(client_stream, &buf, 256);
    var decoded_error_response = try peer.decodeRPCResponse(allocator, buf[0..error_n]);
    defer decoded_error_response.deinit(allocator);
    try testing.expectEqualStrings("rpc-2", decoded_error_response.id);
    try testing.expect(decoded_error_response.result == null);
    try testing.expectEqual(@as(i32, 7), decoded_error_response.@"error".?.code);
    try testing.expectEqualStrings("boom", decoded_error_response.@"error".?.message);
    try testing.expectEqualStrings("{\"detail\":2}", decoded_error_response.@"error".?.data.?);
}
