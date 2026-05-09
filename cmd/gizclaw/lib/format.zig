const std = @import("std");

pub fn unixMilli(buf: []u8, millis: i64) ![]const u8 {
    if (millis < 0) return error.InvalidTime;
    const secs: u64 = @intCast(@divTrunc(millis, 1000));
    const ms: u16 = @intCast(@mod(millis, 1000));
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = secs };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    return try std.fmt.bufPrint(
        buf,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
            ms,
        },
    );
}

pub fn duration(buf: []u8, nanos: i128) ![]const u8 {
    const sign = if (nanos < 0) "-" else "";
    const magnitude: u128 = @intCast(if (nanos < 0) -nanos else nanos);
    if (magnitude >= std.time.ns_per_s) {
        return try std.fmt.bufPrint(buf, "{s}{d}.{d:0>3}s", .{ sign, magnitude / std.time.ns_per_s, (magnitude % std.time.ns_per_s) / std.time.ns_per_ms });
    }
    if (magnitude >= std.time.ns_per_ms) {
        return try std.fmt.bufPrint(buf, "{s}{d}.{d:0>3}ms", .{ sign, magnitude / std.time.ns_per_ms, (magnitude % std.time.ns_per_ms) / std.time.ns_per_us });
    }
    return try std.fmt.bufPrint(buf, "{s}{d}us", .{ sign, magnitude / std.time.ns_per_us });
}
