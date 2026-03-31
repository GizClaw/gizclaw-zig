pub const rekey_after_time_ms: u64 = 120_000;
pub const reject_after_time_ms: u64 = 180_000;
pub const rekey_attempt_time_ms: u64 = 90_000;
pub const rekey_timeout_ms: u64 = 5_000;
pub const keepalive_timeout_ms: u64 = 10_000;
pub const rekey_on_recv_threshold_ms: u64 = reject_after_time_ms - keepalive_timeout_ms - rekey_timeout_ms;
pub const session_cleanup_time_ms: u64 = reject_after_time_ms * 3;

pub const rekey_after_messages: u64 = 1 << 60;
pub const reject_after_messages: u64 = ~@as(u64, 0) - (1 << 13);

pub const raw_queue_size: usize = 4096;
pub const decrypted_queue_size: usize = 256;
pub const inbound_queue_size: usize = 8192;
pub const default_accept_queue_size: usize = 16;
