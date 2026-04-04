const dep = @import("dep");
const mem = dep.embed.mem;

const errors = @import("errors.zig");

pub const OpusFrameVersion: u8 = 1;
pub const opus_frame_header_size: usize = 8;
pub const max_timestamp: u64 = 0x00ff_ffff_ffff_ffff;

pub const EpochMillis = i64;

pub const StampedOpusFrame = struct {
    bytes: []const u8 = &.{},
    owned: ?[]u8 = null,

    const Self = @This();

    pub fn init(bytes: []const u8) Self {
        return .{ .bytes = bytes };
    }

    pub fn deinit(self: *Self, allocator: mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
        self.* = .{};
    }

    pub fn version(self: Self) u8 {
        return if (self.bytes.len == 0) 0 else self.bytes[0];
    }

    pub fn stamp(self: Self) EpochMillis {
        if (self.bytes.len < opus_frame_header_size) return 0;
        var value: u64 = 0;
        var index: usize = 1;
        while (index < opus_frame_header_size) : (index += 1) {
            value = (value << 8) | self.bytes[index];
        }
        return @intCast(value);
    }

    pub fn frame(self: Self) []const u8 {
        return if (self.bytes.len < opus_frame_header_size) &.{} else self.bytes[opus_frame_header_size..];
    }

    pub fn validate(self: Self) errors.Error!void {
        // Match Go peer/opus_frame.go: header-only stamped frames are invalid.
        if (self.bytes.len < opus_frame_header_size + 1) return errors.Error.OpusFrameTooShort;
        if (self.version() != OpusFrameVersion) return errors.Error.InvalidOpusFrameVersion;
    }
};

pub fn stampOpusFrame(
    allocator: mem.Allocator,
    frame: []const u8,
    stamp: EpochMillis,
) !StampedOpusFrame {
    const owned = try allocator.alloc(u8, opus_frame_header_size + frame.len);
    owned[0] = OpusFrameVersion;
    const stamp_bits: u64 = @bitCast(stamp);
    var shift: u6 = 48;
    var index: usize = 1;
    while (index < opus_frame_header_size) : (index += 1) {
        owned[index] = @intCast((stamp_bits >> shift) & 0xff);
        shift -%= 8;
    }
    @memcpy(owned[opus_frame_header_size..], frame);
    return .{
        .bytes = owned,
        .owned = owned,
    };
}

pub fn parseStampedOpusFrame(
    allocator: mem.Allocator,
    data: []const u8,
) !StampedOpusFrame {
    var frame = StampedOpusFrame.init(data);
    try frame.validate();
    const owned = try allocator.alloc(u8, data.len);
    @memcpy(owned, data);
    return .{
        .bytes = owned,
        .owned = owned,
    };
}
