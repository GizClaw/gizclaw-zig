const giznet = @import("giznet");
const giznoise = @import("giznoise");

const Client = @import("Client.zig");

pub const max_kcp_mux_data_header: usize = 1 + 10 + 1;
pub const default_packet_mtu: usize = 1400;
pub const default_kcp_mtu: usize = default_packet_mtu;
pub const default_packet_size_capacity: usize = giznoise.min_packet_size_capacity + max_kcp_mux_data_header + default_packet_mtu;

pub const Config = struct {
    packet_size_capacity: usize = default_packet_size_capacity,
    cipher_kind: giznoise.noise.Cipher.Kind = giznoise.default_cipher_kind,
};

pub fn make(comptime grt: type, comptime config: Config) type {
    const GizNoise = giznoise.GizNoise.make(grt, config.packet_size_capacity, config.cipher_kind);

    return struct {
        pub const NoiseBackend = GizNoise;

        pub const InitNoiseOptions = struct {
            allocator: grt.std.mem.Allocator,
            key_pair: giznet.KeyPair,
            server_key: giznet.Key,
            runtime_options: Client.RuntimeOptions = .{},
            on_error: GizNoise.OnError = .{},
        };

        pub fn initNoiseGizNet(options: InitNoiseOptions) !giznet.GizNet {
            var packet_conn = try grt.net.listenPacket(.{
                .allocator = options.allocator,
                .address = giznet.AddrPort.from4(.{ 0, 0, 0, 0 }, 0),
            });
            errdefer {
                packet_conn.close();
                packet_conn.deinit();
            }

            var runtime_config = runtimeConfig(options.key_pair);
            applyRuntimeOptions(&runtime_config, options.runtime_options);
            runtime_config.on_error = options.on_error;

            const backend = try GizNoise.init(
                options.allocator,
                packet_conn,
                runtime_config,
                .{
                    .drive_task_options = options.runtime_options.drive_task_options,
                    .read_task_options = options.runtime_options.read_task_options,
                    .timer_task_options = options.runtime_options.timer_task_options,
                },
                .{ .allowed_peer_key = options.server_key },
            );
            return backend.asGizNet();
        }

        pub fn runtimeConfig(key_pair: giznet.KeyPair) GizNoise.Config {
            return .{
                .local_static = key_pair,
            };
        }

        pub fn applyRuntimeOptions(runtime_config: *GizNoise.Config, options: Client.RuntimeOptions) void {
            if (options.channel_capacity) |value| runtime_config.channel_capacity = value;
            if (options.accept_channel_capacity) |value| runtime_config.accept_channel_capacity = value;

            const stream_options = options.kcp_stream;
            const stream = &runtime_config.service.kcp_stream.stream;
            if (stream_options.channel_capacity) |value| stream.channel_capacity = value;
            if (stream_options.kcp_nodelay) |value| stream.kcp_nodelay = value;
            if (stream_options.kcp_interval) |value| stream.kcp_interval = value;
            if (stream_options.kcp_resend) |value| stream.kcp_resend = value;
            if (stream_options.kcp_no_congestion_control) |value| stream.kcp_no_congestion_control = value;
            if (stream_options.kcp_send_window) |value| stream.kcp_send_window = value;
            if (stream_options.kcp_recv_window) |value| stream.kcp_recv_window = value;
        }
    };
}
