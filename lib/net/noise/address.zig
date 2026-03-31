const embed = @import("embed");
const mem = embed.mem;

const errors = @import("errors.zig");

pub const Type = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

pub const Domain = struct {
    len: u8,
    bytes: [255]u8 = [_]u8{0} ** 255,

    pub fn fromSlice(input: []const u8) errors.MessageError!Domain {
        if (input.len == 0 or input.len > 255) return errors.MessageError.InvalidAddress;

        var out = Domain{ .len = @intCast(input.len) };
        @memcpy(out.bytes[0..input.len], input);
        return out;
    }

    pub fn slice(self: *const Domain) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Host = union(Type) {
    ipv4: [4]u8,
    domain: Domain,
    ipv6: [16]u8,
};

const Self = @This();

host: Host,
port: u16,

pub fn fromIpv4(host: [4]u8, port: u16) Self {
    return .{ .host = .{ .ipv4 = host }, .port = port };
}

pub fn fromDomain(host: []const u8, port: u16) errors.MessageError!Self {
    return .{ .host = .{ .domain = try Domain.fromSlice(host) }, .port = port };
}

pub fn fromIpv6(host: [16]u8, port: u16) Self {
    return .{ .host = .{ .ipv6 = host }, .port = port };
}

pub fn kind(self: Self) Type {
    return switch (self.host) {
        .ipv4 => .ipv4,
        .domain => .domain,
        .ipv6 => .ipv6,
    };
}

pub fn encode(self: Self, out: []u8) errors.MessageError!usize {
    switch (self.host) {
        .ipv4 => |ip| {
            if (out.len < 7) return errors.MessageError.TooShort;
            out[0] = @intFromEnum(Type.ipv4);
            @memcpy(out[1..5], &ip);
            mem.writeInt(u16, out[5..7], self.port, .big);
            return 7;
        },
        .domain => |domain| {
            const needed = 1 + 1 + domain.len + 2;
            if (out.len < needed) return errors.MessageError.TooShort;
            out[0] = @intFromEnum(Type.domain);
            out[1] = domain.len;
            @memcpy(out[2 .. 2 + domain.len], domain.slice());
            var port_buf: [2]u8 = undefined;
            mem.writeInt(u16, &port_buf, self.port, .big);
            @memcpy(out[2 + domain.len .. 4 + domain.len], &port_buf);
            return needed;
        },
        .ipv6 => |ip| {
            if (out.len < 19) return errors.MessageError.TooShort;
            out[0] = @intFromEnum(Type.ipv6);
            @memcpy(out[1..17], &ip);
            mem.writeInt(u16, out[17..19], self.port, .big);
            return 19;
        },
    }
}

pub fn decode(data: []const u8) errors.MessageError!struct { address: Self, n: usize } {
    if (data.len < 1) return errors.MessageError.InvalidAddress;

    switch (@as(Type, @enumFromInt(data[0]))) {
        .ipv4 => {
            if (data.len < 7) return errors.MessageError.InvalidAddress;
            return .{
                .address = fromIpv4(data[1..5].*, mem.readInt(u16, data[5..7], .big)),
                .n = 7,
            };
        },
        .domain => {
            if (data.len < 2) return errors.MessageError.InvalidAddress;
            const domain_len = data[1];
            if (domain_len == 0 or data.len < 2 + domain_len + 2) return errors.MessageError.InvalidAddress;
            const port_bytes: *const [2]u8 = @ptrCast(data[2 + domain_len .. 4 + domain_len].ptr);
            return .{
                .address = try fromDomain(data[2 .. 2 + domain_len], mem.readInt(u16, port_bytes, .big)),
                .n = 4 + domain_len,
            };
        },
        .ipv6 => {
            if (data.len < 19) return errors.MessageError.InvalidAddress;
            return .{
                .address = fromIpv6(data[1..17].*, mem.readInt(u16, data[17..19], .big)),
                .n = 19,
            };
        },
    }
}

pub fn testAll(testing: anytype) !void {
    var buf: [64]u8 = undefined;

    const ipv4 = fromIpv4(.{ 127, 0, 0, 1 }, 8080);
    const ipv4_len = try ipv4.encode(&buf);
    const parsed_ipv4 = try decode(buf[0..ipv4_len]);
    try testing.expectEqual(@as(usize, 7), parsed_ipv4.n);
    try testing.expectEqual(@as(Type, .ipv4), parsed_ipv4.address.kind());

    const domain = try fromDomain("example.com", 443);
    const domain_len = try domain.encode(&buf);
    const parsed_domain = try decode(buf[0..domain_len]);
    try testing.expectEqual(@as(Type, .domain), parsed_domain.address.kind());
    try testing.expectEqualStrings("example.com", parsed_domain.address.host.domain.slice());

    const ipv6 = fromIpv6(.{ 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 }, 53);
    const ipv6_len = try ipv6.encode(&buf);
    const parsed_ipv6 = try decode(buf[0..ipv6_len]);
    try testing.expectEqual(@as(Type, .ipv6), parsed_ipv6.address.kind());

    try testing.expectError(errors.MessageError.InvalidAddress, fromDomain("", 1));
    try testing.expectError(errors.MessageError.InvalidAddress, decode(&[_]u8{}));
}
