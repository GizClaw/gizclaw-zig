const dep = @import("dep");
const fmt = dep.embed.fmt;
const json = dep.embed.json;
const mem = dep.embed.mem;

const errors = @import("errors.zig");

pub const PrologueVersion: i32 = 1;

pub const ServicePublic: u64 = 0;
pub const ServiceAdmin: u64 = 1;
pub const ServiceReverse: u64 = 2;

const parse_options = json.ParseOptions{
    .ignore_unknown_fields = true,
};

const stringify_options = json.Stringify.Options{
    .whitespace = .minified,
    .emit_null_optional_fields = false,
};

pub const RPCError = struct {
    code: i32 = 0,
    message: []const u8 = "",
    data: ?[]const u8 = null,
    _message_owned: bool = false,
    _data_owned: bool = false,

    const Self = @This();

    pub fn validate(self: Self) errors.Error!void {
        if (isBlank(self.message)) return errors.Error.RPCErrorMessageRequired;
    }

    pub fn deinit(self: *Self, allocator: mem.Allocator) void {
        if (self._message_owned) allocator.free(@constCast(self.message));
        if (self._data_owned and self.data != null) allocator.free(@constCast(self.data.?));
        self.* = .{};
    }
};

pub const RPCRequest = struct {
    v: i32 = PrologueVersion,
    id: []const u8 = "",
    method: []const u8 = "",
    params: ?[]const u8 = null,
    _id_owned: bool = false,
    _method_owned: bool = false,
    _params_owned: bool = false,

    const Self = @This();

    pub fn validate(self: Self) errors.Error!void {
        if (self.v != PrologueVersion) return errors.Error.InvalidV;
        if (isBlank(self.id)) return errors.Error.MissingID;
        if (isBlank(self.method)) return errors.Error.MissingMethod;
    }

    pub fn deinit(self: *Self, allocator: mem.Allocator) void {
        if (self._id_owned) allocator.free(@constCast(self.id));
        if (self._method_owned) allocator.free(@constCast(self.method));
        if (self._params_owned and self.params != null) allocator.free(@constCast(self.params.?));
        self.* = .{};
    }
};

pub const RPCResponse = struct {
    v: i32 = PrologueVersion,
    id: []const u8 = "",
    result: ?[]const u8 = null,
    @"error": ?RPCError = null,
    _id_owned: bool = false,
    _result_owned: bool = false,

    const Self = @This();

    pub fn validate(self: Self) errors.Error!void {
        if (self.v != PrologueVersion) return errors.Error.InvalidV;
        if (isBlank(self.id)) return errors.Error.MissingID;
        if (self.@"error") |rpc_error| try rpc_error.validate();
    }

    pub fn deinit(self: *Self, allocator: mem.Allocator) void {
        if (self._id_owned) allocator.free(@constCast(self.id));
        if (self._result_owned and self.result != null) allocator.free(@constCast(self.result.?));
        if (self.@"error") |*rpc_error| rpc_error.deinit(allocator);
        self.* = .{};
    }
};

pub const Event = struct {
    v: i32 = PrologueVersion,
    name: []const u8 = "",
    data: ?[]const u8 = null,
    _name_owned: bool = false,
    _data_owned: bool = false,

    const Self = @This();

    pub fn validate(self: Self) errors.Error!void {
        if (self.v != PrologueVersion) return errors.Error.InvalidV;
        if (isBlank(self.name)) return errors.Error.MissingName;
    }

    pub fn deinit(self: *Self, allocator: mem.Allocator) void {
        if (self._name_owned) allocator.free(@constCast(self.name));
        if (self._data_owned and self.data != null) allocator.free(@constCast(self.data.?));
        self.* = .{};
    }
};

const EncodedRPCError = struct {
    code: i32,
    message: []const u8,
    data: ?json.Value = null,
};

const EncodedRPCRequest = struct {
    v: i32,
    id: []const u8,
    method: []const u8,
    params: ?json.Value = null,
};

const EncodedRPCResponse = struct {
    v: i32,
    id: []const u8,
    result: ?json.Value = null,
    @"error": ?EncodedRPCError = null,
};

const EncodedEvent = struct {
    v: i32,
    name: []const u8,
    data: ?json.Value = null,
};

const DecodedRPCError = struct {
    code: i32 = 0,
    message: []const u8 = "",
    data: ?json.Value = null,
};

const DecodedRPCRequest = struct {
    v: i32 = 0,
    id: []const u8 = "",
    method: []const u8 = "",
    params: ?json.Value = null,
};

const DecodedRPCResponse = struct {
    v: i32 = 0,
    id: []const u8 = "",
    result: ?json.Value = null,
    @"error": ?DecodedRPCError = null,
};

const DecodedEvent = struct {
    v: i32 = 0,
    name: []const u8 = "",
    data: ?json.Value = null,
};

pub fn encodeRPCRequest(allocator: mem.Allocator, request: RPCRequest) ![]u8 {
    try request.validate();

    var parsed_params: ?json.Parsed(json.Value) = null;
    defer deinitParsedValue(&parsed_params);

    if (request.params) |raw| {
        parsed_params = try parseRawJSONValue(allocator, raw);
    }

    return try fmt.allocPrint(allocator, "{f}", .{json.fmt(EncodedRPCRequest{
        .v = request.v,
        .id = request.id,
        .method = request.method,
        .params = if (parsed_params) |parsed| parsed.value else null,
    }, stringify_options)});
}

pub fn decodeRPCRequest(allocator: mem.Allocator, data: []const u8) !RPCRequest {
    const parsed = json.parseFromSlice(DecodedRPCRequest, allocator, data, parse_options) catch {
        return errors.Error.InvalidJSON;
    };
    defer parsed.deinit();

    var request = RPCRequest{};
    errdefer request.deinit(allocator);

    request.v = parsed.value.v;
    request.id = try dupeBytes(allocator, parsed.value.id);
    request._id_owned = true;
    request.method = try dupeBytes(allocator, parsed.value.method);
    request._method_owned = true;
    if (parsed.value.params) |value| {
        request.params = try stringifyJSONValue(allocator, value);
        request._params_owned = true;
    }

    try request.validate();
    return request;
}

pub fn encodeRPCResponse(allocator: mem.Allocator, response: RPCResponse) ![]u8 {
    try response.validate();

    var parsed_result: ?json.Parsed(json.Value) = null;
    defer deinitParsedValue(&parsed_result);

    var parsed_error_data: ?json.Parsed(json.Value) = null;
    defer deinitParsedValue(&parsed_error_data);

    if (response.result) |raw| {
        parsed_result = try parseRawJSONValue(allocator, raw);
    }

    var encoded_error: ?EncodedRPCError = null;
    if (response.@"error") |rpc_error| {
        if (rpc_error.data) |raw| {
            parsed_error_data = try parseRawJSONValue(allocator, raw);
        }
        encoded_error = .{
            .code = rpc_error.code,
            .message = rpc_error.message,
            .data = if (parsed_error_data) |parsed| parsed.value else null,
        };
    }

    return try fmt.allocPrint(allocator, "{f}", .{json.fmt(EncodedRPCResponse{
        .v = response.v,
        .id = response.id,
        .result = if (parsed_result) |parsed| parsed.value else null,
        .@"error" = encoded_error,
    }, stringify_options)});
}

pub fn decodeRPCResponse(allocator: mem.Allocator, data: []const u8) !RPCResponse {
    const parsed = json.parseFromSlice(DecodedRPCResponse, allocator, data, parse_options) catch {
        return errors.Error.InvalidJSON;
    };
    defer parsed.deinit();

    var response = RPCResponse{};
    errdefer response.deinit(allocator);

    response.v = parsed.value.v;
    response.id = try dupeBytes(allocator, parsed.value.id);
    response._id_owned = true;
    if (parsed.value.result) |value| {
        response.result = try stringifyJSONValue(allocator, value);
        response._result_owned = true;
    }
    if (parsed.value.@"error") |rpc_error| {
        var decoded_error = RPCError{
            .code = rpc_error.code,
        };
        decoded_error.message = try dupeBytes(allocator, rpc_error.message);
        decoded_error._message_owned = true;
        if (rpc_error.data) |value| {
            decoded_error.data = try stringifyJSONValue(allocator, value);
            decoded_error._data_owned = true;
        }
        response.@"error" = decoded_error;
    }

    try response.validate();
    return response;
}

pub fn encodeEvent(allocator: mem.Allocator, event: Event) ![]u8 {
    try event.validate();

    var parsed_data: ?json.Parsed(json.Value) = null;
    defer deinitParsedValue(&parsed_data);

    if (event.data) |raw| {
        parsed_data = try parseRawJSONValue(allocator, raw);
    }

    return try fmt.allocPrint(allocator, "{f}", .{json.fmt(EncodedEvent{
        .v = event.v,
        .name = event.name,
        .data = if (parsed_data) |parsed| parsed.value else null,
    }, stringify_options)});
}

pub fn decodeEvent(allocator: mem.Allocator, data: []const u8) !Event {
    const parsed = json.parseFromSlice(DecodedEvent, allocator, data, parse_options) catch {
        return errors.Error.InvalidJSON;
    };
    defer parsed.deinit();

    var event = Event{};
    errdefer event.deinit(allocator);

    event.v = parsed.value.v;
    event.name = try dupeBytes(allocator, parsed.value.name);
    event._name_owned = true;
    if (parsed.value.data) |value| {
        event.data = try stringifyJSONValue(allocator, value);
        event._data_owned = true;
    }

    try event.validate();
    return event;
}

fn parseRawJSONValue(allocator: mem.Allocator, raw: []const u8) !json.Parsed(json.Value) {
    return json.parseFromSlice(json.Value, allocator, raw, .{}) catch {
        return errors.Error.InvalidJSON;
    };
}

fn stringifyJSONValue(allocator: mem.Allocator, value: json.Value) ![]u8 {
    return try fmt.allocPrint(allocator, "{f}", .{json.fmt(value, stringify_options)});
}

fn deinitParsedValue(parsed: *?json.Parsed(json.Value)) void {
    if (parsed.*) |*value| value.deinit();
}

fn dupeBytes(allocator: mem.Allocator, value: []const u8) ![]u8 {
    const owned = try allocator.alloc(u8, value.len);
    @memcpy(owned, value);
    return owned;
}

fn isBlank(value: []const u8) bool {
    var index: usize = 0;
    while (index < value.len) {
        const decoded = decodeUtf8(value[index..]) orelse return false;
        if (!isUnicodeSpace(decoded.codepoint)) return false;
        index += decoded.len;
    }
    return true;
}

const DecodedUtf8 = struct {
    codepoint: u21,
    len: usize,
};

fn decodeUtf8(bytes: []const u8) ?DecodedUtf8 {
    if (bytes.len == 0) return null;

    const b0 = bytes[0];
    if (b0 < 0x80) {
        return .{
            .codepoint = b0,
            .len = 1,
        };
    }

    if ((b0 & 0xe0) == 0xc0) {
        if (bytes.len < 2) return null;
        const b1 = bytes[1];
        if ((b1 & 0xc0) != 0x80) return null;

        const codepoint = (@as(u21, b0 & 0x1f) << 6) | @as(u21, b1 & 0x3f);
        if (codepoint < 0x80) return null;
        return .{
            .codepoint = codepoint,
            .len = 2,
        };
    }

    if ((b0 & 0xf0) == 0xe0) {
        if (bytes.len < 3) return null;
        const b1 = bytes[1];
        const b2 = bytes[2];
        if ((b1 & 0xc0) != 0x80 or (b2 & 0xc0) != 0x80) return null;

        const codepoint = (@as(u21, b0 & 0x0f) << 12) |
            (@as(u21, b1 & 0x3f) << 6) |
            @as(u21, b2 & 0x3f);
        if (codepoint < 0x800) return null;
        return .{
            .codepoint = codepoint,
            .len = 3,
        };
    }

    if ((b0 & 0xf8) == 0xf0) {
        if (bytes.len < 4) return null;
        const b1 = bytes[1];
        const b2 = bytes[2];
        const b3 = bytes[3];
        if ((b1 & 0xc0) != 0x80 or (b2 & 0xc0) != 0x80 or (b3 & 0xc0) != 0x80) return null;

        const codepoint = (@as(u21, b0 & 0x07) << 18) |
            (@as(u21, b1 & 0x3f) << 12) |
            (@as(u21, b2 & 0x3f) << 6) |
            @as(u21, b3 & 0x3f);
        if (codepoint < 0x10000 or codepoint > 0x10ffff) return null;
        return .{
            .codepoint = codepoint,
            .len = 4,
        };
    }

    return null;
}

fn isUnicodeSpace(codepoint: u21) bool {
    return switch (codepoint) {
        0x0009...0x000d,
        0x0020,
        0x0085,
        0x00a0,
        0x1680,
        0x2000...0x200a,
        0x2028,
        0x2029,
        0x202f,
        0x205f,
        0x3000,
        => true,
        else => false,
    };
}
