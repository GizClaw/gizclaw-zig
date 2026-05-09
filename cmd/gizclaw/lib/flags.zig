const std = @import("std");

pub const Parsed = struct {
    positionals_buf: [16][]const u8 = undefined,
    positionals_len: usize = 0,
    flags_buf: [16]Flag = undefined,
    flags_len: usize = 0,

    pub const Flag = struct {
        name: []const u8,
        value: []const u8,
    };

    pub fn positionals(self: *const Parsed) []const []const u8 {
        return self.positionals_buf[0..self.positionals_len];
    }

    pub fn flags(self: *const Parsed) []const Flag {
        return self.flags_buf[0..self.flags_len];
    }

    pub fn value(self: Parsed, name: []const u8) ?[]const u8 {
        for (self.flags()) |flag| {
            if (std.mem.eql(u8, flag.name, name)) return flag.value;
        }
        return null;
    }
};

pub fn parse(args: []const []const u8) !Parsed {
    var parsed = Parsed{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (!std.mem.startsWith(u8, arg, "--")) {
            if (parsed.positionals_len == parsed.positionals_buf.len) return error.TooManyArguments;
            parsed.positionals_buf[parsed.positionals_len] = arg;
            parsed.positionals_len += 1;
            continue;
        }
        const raw = arg[2..];
        if (raw.len == 0) return error.InvalidArguments;
        const eq = std.mem.indexOfScalar(u8, raw, '=');
        const name = if (eq) |pos| raw[0..pos] else raw;
        const value = if (eq) |pos| raw[pos + 1 ..] else blk: {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            break :blk args[index];
        };
        if (parsed.flags_len == parsed.flags_buf.len) return error.TooManyArguments;
        parsed.flags_buf[parsed.flags_len] = .{ .name = name, .value = value };
        parsed.flags_len += 1;
    }
    return parsed;
}

pub fn normalizeLegacyLongFlags(allocator: std.mem.Allocator, args: []const []const u8) ![][]u8 {
    const out = try allocator.alloc([]u8, args.len);
    errdefer allocator.free(out);
    for (args, 0..) |arg, index| {
        if (std.mem.startsWith(u8, arg, "-") and
            !std.mem.startsWith(u8, arg, "--") and
            arg.len > 2 and
            std.ascii.isAlphabetic(arg[1]))
        {
            out[index] = try std.fmt.allocPrint(allocator, "-{s}", .{arg});
        } else {
            out[index] = try allocator.dupe(u8, arg);
        }
    }
    return out;
}

pub fn isHelp(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help");
}
