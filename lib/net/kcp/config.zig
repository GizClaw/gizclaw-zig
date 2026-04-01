pub const Output = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, data: []const u8) anyerror!void,
};

pub const Conn = struct {
    output: Output,
    mtu: u32 = 1400,
    snd_wnd: u32 = 4096,
    rcv_wnd: u32 = 4096,
    nodelay: i32 = 2,
    interval: i32 = 1,
    resend: i32 = 2,
    nc: i32 = 1,
};

pub const Mux = struct {
    is_client: bool = false,
    output: Output,
    close_ack_timeout_ms: u64 = 15_000,
    idle_stream_timeout_ms: u64 = 60_000,
    accept_backlog: usize = 32,
    max_active_streams: usize = 32,
    mtu: u32 = 1400,
    snd_wnd: u32 = 4096,
    rcv_wnd: u32 = 4096,
    nodelay: i32 = 2,
    interval: i32 = 1,
    resend: i32 = 2,
    nc: i32 = 1,
};
