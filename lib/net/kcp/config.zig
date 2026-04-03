pub const default_idle_timeout_ms: u64 = 15_000;
pub const default_idle_timeout_pure_ms: u64 = 30_000;
pub const default_mtu: u32 = 1400;
pub const default_snd_wnd: u32 = 4096;
pub const default_rcv_wnd: u32 = 4096;
pub const default_nodelay: i32 = 2;
pub const default_interval: i32 = 1;
pub const default_resend: i32 = 2;
pub const default_nc: i32 = 1;

pub const default_close_ack_timeout_ms: u64 = 15_000;
pub const default_idle_stream_timeout_ms: u64 = 60_000;
pub const default_accept_backlog: usize = 32;
pub const default_max_active_streams: usize = 32;

pub const Output = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, data: []const u8) anyerror!void,
};

pub const Conn = struct {
    output: Output,
    idle_timeout_ms: u64 = default_idle_timeout_ms,
    idle_timeout_pure_ms: u64 = default_idle_timeout_pure_ms,
    mtu: u32 = default_mtu,
    snd_wnd: u32 = default_snd_wnd,
    rcv_wnd: u32 = default_rcv_wnd,
    nodelay: i32 = default_nodelay,
    interval: i32 = default_interval,
    resend: i32 = default_resend,
    nc: i32 = default_nc,
};

pub const Mux = struct {
    is_client: bool = false,
    output: Output,
    close_ack_timeout_ms: u64 = default_close_ack_timeout_ms,
    idle_stream_timeout_ms: u64 = default_idle_stream_timeout_ms,
    accept_backlog: usize = default_accept_backlog,
    max_active_streams: usize = default_max_active_streams,
    mtu: u32 = default_mtu,
    snd_wnd: u32 = default_snd_wnd,
    rcv_wnd: u32 = default_rcv_wnd,
    nodelay: i32 = default_nodelay,
    interval: i32 = default_interval,
    resend: i32 = default_resend,
    nc: i32 = default_nc,
};

pub fn normalizeConn(cfg_in: Conn) Conn {
    var cfg = cfg_in;
    if (cfg.idle_timeout_ms == 0) cfg.idle_timeout_ms = default_idle_timeout_ms;
    if (cfg.idle_timeout_pure_ms == 0) cfg.idle_timeout_pure_ms = default_idle_timeout_pure_ms;
    if (cfg.mtu == 0) cfg.mtu = default_mtu;
    if (cfg.snd_wnd == 0) cfg.snd_wnd = default_snd_wnd;
    if (cfg.rcv_wnd == 0) cfg.rcv_wnd = default_rcv_wnd;
    if (cfg.nodelay == 0) cfg.nodelay = default_nodelay;
    if (cfg.interval == 0) cfg.interval = default_interval;
    if (cfg.resend == 0) cfg.resend = default_resend;
    if (cfg.nc == 0) cfg.nc = default_nc;
    return cfg;
}

pub fn normalizeMux(cfg_in: Mux) Mux {
    var cfg = cfg_in;
    if (cfg.close_ack_timeout_ms == 0) cfg.close_ack_timeout_ms = default_close_ack_timeout_ms;
    if (cfg.idle_stream_timeout_ms == 0) cfg.idle_stream_timeout_ms = default_idle_stream_timeout_ms;
    if (cfg.accept_backlog == 0) cfg.accept_backlog = default_accept_backlog;
    if (cfg.max_active_streams == 0) cfg.max_active_streams = default_max_active_streams;
    if (cfg.mtu == 0) cfg.mtu = default_mtu;
    if (cfg.snd_wnd == 0) cfg.snd_wnd = default_snd_wnd;
    if (cfg.rcv_wnd == 0) cfg.rcv_wnd = default_rcv_wnd;
    if (cfg.nodelay == 0) cfg.nodelay = default_nodelay;
    if (cfg.interval == 0) cfg.interval = default_interval;
    if (cfg.resend == 0) cfg.resend = default_resend;
    if (cfg.nc == 0) cfg.nc = default_nc;
    return cfg;
}
