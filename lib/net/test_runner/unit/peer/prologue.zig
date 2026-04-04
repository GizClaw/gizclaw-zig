const dep = @import("dep");
const testing_api = dep.testing;

const peer = @import("../../../peer.zig");

pub fn make(comptime lib: type) testing_api.TestRunner {
    const Runner = struct {
        pub fn init(self: *@This(), allocator: dep.embed.mem.Allocator) !void {
            _ = self;
            _ = allocator;
        }

        pub fn run(self: *@This(), t: *testing_api.T, allocator: dep.embed.mem.Allocator) bool {
            _ = self;
            runCases(lib, lib.testing, allocator) catch |err| {
                t.logErrorf("peer/prologue failed: {}", .{err});
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

fn runCases(comptime _: type, testing: anytype, allocator: dep.embed.mem.Allocator) !void {
    const request = peer.RPCRequest{
        .id = "rpc-1",
        .method = "ping",
        .params = "{\"x\":1}",
    };
    const encoded_request = try peer.encodeRPCRequest(allocator, request);
    defer allocator.free(encoded_request);
    try testing.expectEqualStrings(
        "{\"v\":1,\"id\":\"rpc-1\",\"method\":\"ping\",\"params\":{\"x\":1}}",
        encoded_request,
    );

    var decoded_request = try peer.decodeRPCRequest(allocator, encoded_request);
    defer decoded_request.deinit(allocator);
    try testing.expectEqual(peer.PrologueVersion, decoded_request.v);
    try testing.expectEqualStrings("rpc-1", decoded_request.id);
    try testing.expectEqualStrings("ping", decoded_request.method);
    try testing.expectEqualStrings("{\"x\":1}", decoded_request.params.?);

    const response = peer.RPCResponse{
        .id = "rpc-2",
        .result = "{\"ok\":true}",
        .@"error" = .{
            .code = 7,
            .message = "boom",
            .data = "{\"detail\":1}",
        },
    };
    const encoded_response = try peer.encodeRPCResponse(allocator, response);
    defer allocator.free(encoded_response);
    try testing.expectEqualStrings(
        "{\"v\":1,\"id\":\"rpc-2\",\"result\":{\"ok\":true},\"error\":{\"code\":7,\"message\":\"boom\",\"data\":{\"detail\":1}}}",
        encoded_response,
    );

    var decoded_response = try peer.decodeRPCResponse(allocator, encoded_response);
    defer decoded_response.deinit(allocator);
    try testing.expectEqualStrings("rpc-2", decoded_response.id);
    try testing.expectEqualStrings("{\"ok\":true}", decoded_response.result.?);
    try testing.expectEqual(@as(i32, 7), decoded_response.@"error".?.code);
    try testing.expectEqualStrings("boom", decoded_response.@"error".?.message);
    try testing.expectEqualStrings("{\"detail\":1}", decoded_response.@"error".?.data.?);

    const encoded_event = try peer.encodeEvent(allocator, .{
        .name = "ready",
        .data = "[1,2,3]",
    });
    defer allocator.free(encoded_event);
    try testing.expectEqualStrings(
        "{\"v\":1,\"name\":\"ready\",\"data\":[1,2,3]}",
        encoded_event,
    );

    var decoded_event = try peer.decodeEvent(allocator, encoded_event);
    defer decoded_event.deinit(allocator);
    try testing.expectEqualStrings("ready", decoded_event.name);
    try testing.expectEqualStrings("[1,2,3]", decoded_event.data.?);

    var unknowns = try peer.decodeRPCRequest(
        allocator,
        "{ \"id\":\"x\", \"v\":1, \"extra\":{\"keep\":true}, \"method\":\"pong\" }",
    );
    defer unknowns.deinit(allocator);
    try testing.expectEqualStrings("x", unknowns.id);
    try testing.expectEqualStrings("pong", unknowns.method);

    var unknown_float = try peer.decodeRPCRequest(
        allocator,
        "{\"v\":1,\"id\":\"x\",\"method\":\"pong\",\"extra\":1.5}",
    );
    defer unknown_float.deinit(allocator);
    try testing.expectEqualStrings("pong", unknown_float.method);

    try testing.expectError(peer.Error.InvalidV, peer.encodeRPCRequest(allocator, .{
        .v = 2,
        .id = "x",
        .method = "ping",
    }));
    try testing.expectError(peer.Error.MissingID, peer.encodeRPCRequest(allocator, .{
        .id = "   ",
        .method = "ping",
    }));
    try testing.expectError(peer.Error.MissingMethod, peer.encodeRPCRequest(allocator, .{
        .id = "x",
        .method = "\t",
    }));
    try testing.expectError(peer.Error.MissingID, peer.encodeRPCRequest(allocator, .{
        .id = "\xe3\x80\x80",
        .method = "ping",
    }));
    try testing.expectError(peer.Error.MissingName, peer.encodeEvent(allocator, .{
        .name = " \n ",
    }));
    try testing.expectError(peer.Error.RPCErrorMessageRequired, peer.encodeRPCResponse(allocator, .{
        .id = "x",
        .@"error" = .{ .code = 1, .message = "   " },
    }));

    try testing.expectError(peer.Error.InvalidV, peer.decodeRPCRequest(allocator, "{\"v\":2,\"id\":\"x\",\"method\":\"ping\"}"));
    try testing.expectError(peer.Error.MissingID, peer.decodeRPCResponse(allocator, "{\"v\":1,\"id\":\" \",\"result\":true}"));
    try testing.expectError(
        peer.Error.RPCErrorMessageRequired,
        peer.decodeRPCResponse(allocator, "{\"v\":1,\"id\":\"x\",\"error\":{\"code\":1,\"message\":\"   \"}}"),
    );
    try testing.expectError(
        peer.Error.RPCErrorMessageRequired,
        peer.decodeRPCResponse(allocator, "{\"v\":1,\"id\":\"x\",\"error\":{\"code\":1,\"message\":\"\\u3000\"}}"),
    );
    try testing.expectError(peer.Error.MissingName, peer.decodeEvent(allocator, "{\"v\":1,\"name\":\"\\t\"}"));
    try testing.expectError(peer.Error.MissingName, peer.decodeEvent(allocator, "{\"v\":1,\"name\":\"\\u3000\"}"));
    try testing.expectError(peer.Error.InvalidJSON, peer.decodeRPCRequest(allocator, "{\"v\":1,\"id\":\"x\",\"method\":}"));
    try testing.expectError(peer.Error.InvalidJSON, peer.decodeEvent(allocator, "[]"));

    const escaped = try peer.decodeEvent(allocator, "{\"v\":1,\"name\":\"line\\nquote\\\"\"}");
    defer {
        var mutable = escaped;
        mutable.deinit(allocator);
    }
    try testing.expectEqualStrings("line\nquote\"", escaped.name);
}
