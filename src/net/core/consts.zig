const std = @import("std");

pub const rekey_after_time_ms: u64 = 120_000;
pub const reject_after_time_ms: u64 = 180_000;
pub const rekey_attempt_time_ms: u64 = 90_000;
pub const rekey_timeout_ms: u64 = 5_000;
pub const keepalive_timeout_ms: u64 = 10_000;
pub const rekey_on_recv_threshold_ms: u64 = 165_000;
pub const session_cleanup_time_ms: u64 = 540_000;

pub const rekey_after_messages: u64 = 1 << 60;
pub const reject_after_messages: u64 = std.math.maxInt(u64) - (1 << 13);

pub const raw_chan_size: usize = 4096;
pub const decrypted_chan_size: usize = 256;
pub const inbound_chan_size: usize = 8192;

test "time constants" {
    try std.testing.expectEqual(reject_after_time_ms - keepalive_timeout_ms - rekey_timeout_ms, rekey_on_recv_threshold_ms);
    try std.testing.expectEqual(reject_after_time_ms * 3, session_cleanup_time_ms);
}

test "message constants" {
    try std.testing.expectEqual(@as(u64, 1 << 60), rekey_after_messages);
    try std.testing.expectEqual(std.math.maxInt(u64) - (1 << 13), reject_after_messages);
}
