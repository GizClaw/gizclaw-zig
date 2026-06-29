const glib = @import("glib");
const giznet = @import("giznet");

const Rpc = @import("Rpc.zig");
const models = @import("models.zig");
const peer_stream = @import("peer_stream.zig");
const service = @import("service.zig");

pub const ConnectOptions = struct {
    server_key: giznet.Key,
    server_addr: []const u8,
    connect_timeout: ?glib.time.duration.Duration = null,
};

pub const InitConfig = struct {
    key_pair: giznet.KeyPair,
    device_info: models.DeviceInfo = .{},
    runtime_options: RuntimeOptions = .{},
};

pub const RuntimeOptions = struct {
    channel_capacity: ?usize = null,
    accept_channel_capacity: ?usize = null,
    serve_rpc: bool = true,
    drive_task_options: glib.task.Options = .{},
    read_task_options: glib.task.Options = .{},
    timer_task_options: glib.task.Options = .{},
    rpc_task_options: glib.task.Options = .{},
    kcp_stream: KcpStreamOptions = .{},
};

pub const KcpStreamOptions = struct {
    channel_capacity: ?usize = null,
    kcp_nodelay: ?i32 = null,
    kcp_interval: ?i32 = null,
    kcp_resend: ?i32 = null,
    kcp_no_congestion_control: ?i32 = null,
    kcp_send_window: ?u32 = null,
    kcp_recv_window: ?u32 = null,
};

pub const default_packet_mtu: usize = 1400;
pub const default_kcp_mtu: usize = default_packet_mtu;
const max_kcp_mux_data_header: usize = 1 + 10 + 1;
pub const default_packet_size_capacity: usize = giznet.noise.min_packet_size_capacity + max_kcp_mux_data_header + default_packet_mtu;

pub const Config = struct {
    packet_size_capacity: usize = default_packet_size_capacity,
    cipher_kind: giznet.noise.Cipher.Kind = giznet.noise.default_cipher_kind,
};

pub fn make(comptime grt: type, comptime config: Config) type {
    const Allocator = grt.std.mem.Allocator;
    const RuntimePackage = giznet.runtime.make(grt, config.packet_size_capacity, config.cipher_kind);
    const RuntimeGizNet = RuntimePackage.GizNet;
    const RpcRuntime = Rpc.make(grt);
    const PeerStreamRuntime = peer_stream.make(grt);
    const Http = grt.net.http;
    const ServerInfo = models.ServerInfo;
    const DeviceInfo = models.DeviceInfo;
    const HardwareInfo = models.HardwareInfo;
    const GearIMEI = models.GearIMEI;
    const GearLabel = models.GearLabel;
    const RuntimeStatus = models.Runtime;
    const default_connect_timeout = 5 * glib.time.duration.Second;
    const request_timeout = 5 * glib.time.duration.Second;
    const stream_accept_timeout = 200 * glib.time.duration.MilliSecond;
    const default_speed_test_timeout = 30 * glib.time.duration.Second;

    return struct {
        pub const Runtime = RuntimePackage;
        pub const GizNetImpl = RuntimeGizNet;
        pub const SpeedTestResult = RpcRuntime.SpeedTestResult;
        pub const SpeedTestProgress = RpcRuntime.SpeedTestProgress;
        pub const SpeedTestProgressSnapshot = RpcRuntime.SpeedTestProgressSnapshot;
        pub const OpenPeerStreamOptions = peer_stream.OpenPeerStreamOptions;
        pub const PeerAudioTurnOptions = peer_stream.PeerAudioTurnOptions;
        pub const PeerEventStream = PeerStreamRuntime.PeerEventStream;
        pub const PeerStream = PeerStreamRuntime.PeerStream;
        pub const PeerStreamChunk = peer_stream.PeerStreamChunk;
        pub const PeerStreamChunkReadResult = PeerStreamRuntime.PeerStreamChunkReadResult;
        pub const PeerStreamEvent = peer_stream.PeerStreamEvent;
        pub const PeerStreamEventType = peer_stream.PeerStreamEventType;
        pub const PeerStreamKind = peer_stream.PeerStreamKind;
        pub const StampedOpusFrame = peer_stream.StampedOpusFrame;
        pub const StampedOpusSubscribeOptions = peer_stream.StampedOpusSubscribeOptions;
        pub const StampedOpusSubscriber = PeerStreamRuntime.StampedOpusSubscriber;
        pub const VoiceListRequest = struct {
            cursor: ?[]const u8 = null,
            limit: ?i64 = null,
            source: ?models.VoiceSource = null,
            provider_kind: ?models.VoiceProviderKind = null,
            provider_name: ?[]const u8 = null,
        };
        pub const VoiceGetRequest = struct {
            id: []const u8,
        };
        pub const SpeechRequest = struct {
            input: []const u8,
            model: []const u8,
            voice: []const u8,
            response_format: []const u8 = "opus",
        };
        pub const FirmwareDownloadResult = struct {
            metadata: grt.std.json.Parsed(models.FirmwareDownloadResponse),
            bytes: i64,

            pub fn deinit(self: *FirmwareDownloadResult) void {
                self.metadata.deinit();
                self.* = undefined;
            }
        };
        pub const WorkspaceHistoryAudioGetResult = struct {
            metadata: grt.std.json.Parsed(models.WorkspaceHistoryAudioGetResponse),
            bytes: i64,

            pub fn deinit(self: *WorkspaceHistoryAudioGetResult) void {
                self.metadata.deinit();
                self.* = undefined;
            }
        };

        allocator: Allocator,
        key_pair: giznet.KeyPair,
        runtime_options: RuntimeOptions = .{},
        local_device_info: DeviceInfo = .{},
        server_key: giznet.Key = .{},
        packet_conn: ?grt.net.PacketConn = null,
        impl: ?*GizNetImpl = null,
        root: ?giznet.GizNet = null,
        conn: ?giznet.Conn = null,
        stream_thread: ?grt.task.Handle = null,
        closing: grt.std.atomic.Value(bool) = grt.std.atomic.Value(bool).init(false),

        const Self = @This();

        pub fn init(allocator: Allocator, init_config: InitConfig) !Self {
            var self = Self{
                .allocator = allocator,
                .key_pair = init_config.key_pair,
                .runtime_options = init_config.runtime_options,
            };
            errdefer deinitDeviceInfo(allocator, &self.local_device_info);
            self.local_device_info = try self.dupeDeviceInfo(init_config.device_info);
            return self;
        }

        pub fn runtimeConfig(key_pair: giznet.KeyPair, peer_policy: giznet.noise.Engine.PeerPolicy) giznet.runtime.Engine.Config {
            return .{
                .local_static = key_pair,
                .noise = .{
                    .peer_policy = peer_policy,
                },
            };
        }

        pub fn connect(self: *Self, options: ConnectOptions) !void {
            if (self.conn != null or self.impl != null) return error.ClientAlreadyConnected;
            self.server_key = options.server_key;
            errdefer self.server_key = .{};

            var packet_conn = try grt.net.listenPacket(.{
                .allocator = self.allocator,
                .address = giznet.AddrPort.from4(.{ 0, 0, 0, 0 }, 0),
            });
            var packet_conn_owned = true;
            errdefer if (packet_conn_owned) packet_conn.deinit();

            var runtime_config = runtimeConfig(self.key_pair, .{
                .ctx = self,
                .allow = allowServerPeer,
            });
            applyRuntimeOptions(&runtime_config, self.runtime_options);
            const impl = try RuntimeGizNet.init(self.allocator, packet_conn, runtime_config);
            var impl_owned = true;
            errdefer if (impl_owned) impl.deinit();

            const root = try impl.up(.{
                .drive_task_options = self.runtime_options.drive_task_options,
                .read_task_options = self.runtime_options.read_task_options,
                .timer_task_options = self.runtime_options.timer_task_options,
            });

            const endpoint = try parseAddrPort(options.server_addr);
            const connect_timeout = options.connect_timeout orelse default_connect_timeout;
            try root.dial(.{
                .remote_key = options.server_key,
                .endpoint = endpoint,
                .connect_timeout_ms = durationMillis(connect_timeout),
                .keepalive_ms = 15_000,
            });

            const conn = try impl.acceptTimeout(connect_timeout);
            var conn_owned = true;
            errdefer if (conn_owned) {
                conn.close() catch {};
                conn.deinit();
            };
            self.packet_conn = packet_conn;
            self.impl = impl;
            self.root = root;
            self.conn = conn;
            packet_conn_owned = false;
            impl_owned = false;
            conn_owned = false;
            errdefer self.disconnect();

            if (self.runtime_options.serve_rpc) try self.startServe(self.runtime_options.rpc_task_options);
        }

        fn allowServerPeer(ctx: ?*anyopaque, peer_key: giznet.Key) bool {
            const self: *Self = @ptrCast(@alignCast(ctx orelse return false));
            return peer_key.eql(self.server_key);
        }

        fn durationMillis(duration: glib.time.duration.Duration) u32 {
            const min_duration = @max(duration, glib.time.duration.MilliSecond);
            const rounded = @divFloor(min_duration + glib.time.duration.MilliSecond - 1, glib.time.duration.MilliSecond);
            return @intCast(@min(rounded, grt.std.math.maxInt(u32)));
        }

        fn applyRuntimeOptions(runtime_config: *giznet.runtime.Engine.Config, options: RuntimeOptions) void {
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

        pub fn attach(
            self: *Self,
            server_key: giznet.Key,
            conn: giznet.Conn,
            stream_task_options: glib.task.Options,
        ) !void {
            if (self.conn != null) return error.ClientAlreadyConnected;
            self.server_key = server_key;
            self.conn = conn;
            errdefer {
                self.conn = null;
                self.server_key = .{};
            }

            if (self.runtime_options.serve_rpc) try self.startServe(stream_task_options);
        }

        pub fn deinit(self: *Self) void {
            self.disconnect();
            deinitDeviceInfo(self.allocator, &self.local_device_info);
            self.* = undefined;
        }

        pub fn disconnect(self: *Self) void {
            self.closing.store(true, .release);

            if (self.stream_thread) |thread| {
                thread.join();
                self.stream_thread = null;
            }
            if (self.conn) |conn| conn.close() catch {};
            if (self.conn) |conn| {
                conn.deinit();
                self.conn = null;
            }
            if (self.root) |root| {
                root.deinit();
                self.root = null;
                self.impl = null;
            }
            if (self.packet_conn) |packet_conn| {
                packet_conn.close();
                packet_conn.deinit();
                self.packet_conn = null;
            }
        }

        fn startServe(self: *Self, stream_task_options: glib.task.Options) !void {
            self.closing.store(false, .release);
            self.stream_thread = try grt.task.go("gizclaw/rpc", stream_task_options, glib.task.Routine.init(self, streamLoop));
        }

        pub fn ping(self: *Self) !models.PingResponse {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.rpc);
            try setStreamDeadline(stream);
            var rpc = RpcRuntime.Rpc.init(self.allocator, stream);
            defer rpc.deinit();
            return try rpc.ping("ping");
        }

        pub fn speedTest(self: *Self, request: models.SpeedTestRequest, timeout: ?glib.time.duration.Duration) !SpeedTestResult {
            return try self.speedTestWithProgress(request, timeout, .{});
        }

        pub fn speedTestWithProgress(
            self: *Self,
            request: models.SpeedTestRequest,
            timeout: ?glib.time.duration.Duration,
            progress: SpeedTestProgress,
        ) !SpeedTestResult {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.rpc);
            try setStreamDeadlineFor(stream, timeout orelse default_speed_test_timeout);
            var rpc = RpcRuntime.Rpc.init(self.allocator, stream);
            defer rpc.deinit();
            return try rpc.speedTestWithProgress(Rpc.method_speed_test_run, request, progress);
        }

        pub fn getServerInfo(self: *Self) !grt.std.json.Parsed(models.ServerGetInfoResponse) {
            return try self.callRpcParsed(models.ServerGetInfoResponse, "server-info-get", Rpc.method_server_info_get, models.ServerGetInfoRequest{});
        }

        pub fn putServerInfo(self: *Self, request: models.ServerPutInfoRequest) !grt.std.json.Parsed(models.ServerPutInfoResponse) {
            return try self.callRpcParsed(models.ServerPutInfoResponse, "server-info-put", Rpc.method_server_info_put, request);
        }

        pub fn getServerRuntime(self: *Self) !grt.std.json.Parsed(models.ServerGetRuntimeResponse) {
            return try self.callRpcParsed(models.ServerGetRuntimeResponse, "server-runtime-get", Rpc.method_server_runtime_get, models.ServerGetRuntimeRequest{});
        }

        pub fn getServerStatus(self: *Self) !grt.std.json.Parsed(models.ServerGetStatusResponse) {
            return try self.callRpcParsed(models.ServerGetStatusResponse, "server-status-get", Rpc.method_server_status_get, models.ServerGetStatusRequest{});
        }

        pub fn putServerStatus(self: *Self, request: models.ServerPutStatusRequest) !grt.std.json.Parsed(models.ServerPutStatusResponse) {
            return try self.callRpcParsed(models.ServerPutStatusResponse, "server-status-put", Rpc.method_server_status_put, request);
        }

        pub fn getServerRunAgent(self: *Self) !grt.std.json.Parsed(models.ServerGetRunAgentResponse) {
            return try self.callRpcParsed(models.ServerGetRunAgentResponse, "server-run-agent-get", Rpc.method_server_run_agent_get, models.ServerGetRunAgentRequest{});
        }

        pub fn setServerRunAgent(self: *Self, request: models.ServerSetRunAgentRequest) !grt.std.json.Parsed(models.ServerSetRunAgentResponse) {
            return try self.callRpcParsed(models.ServerSetRunAgentResponse, "server-run-agent-set", Rpc.method_server_run_agent_set, request);
        }

        pub fn getServerRunWorkspace(self: *Self) !grt.std.json.Parsed(models.ServerGetRunWorkspaceResponse) {
            return try self.callRpcParsed(models.ServerGetRunWorkspaceResponse, "server-run-workspace-get", Rpc.method_server_run_workspace_get, models.ServerGetRunWorkspaceRequest{});
        }

        pub fn setServerRunWorkspace(self: *Self, request: models.ServerSetRunWorkspaceRequest) !grt.std.json.Parsed(models.ServerSetRunWorkspaceResponse) {
            return try self.callRpcParsed(models.ServerSetRunWorkspaceResponse, "server-run-workspace-set", Rpc.method_server_run_workspace_set, request);
        }

        pub fn reloadServerRunWorkspace(self: *Self) !grt.std.json.Parsed(models.ServerReloadRunWorkspaceResponse) {
            return try self.callRpcParsed(models.ServerReloadRunWorkspaceResponse, "server-run-workspace-reload", Rpc.method_server_run_workspace_reload, models.ServerReloadRunWorkspaceRequest{});
        }

        pub fn listServerRunWorkspaceHistory(self: *Self, request: models.ServerListRunWorkspaceHistoryRequest) !grt.std.json.Parsed(models.ServerListRunWorkspaceHistoryResponse) {
            return try self.callRpcParsed(models.ServerListRunWorkspaceHistoryResponse, "server-run-workspace-history", Rpc.method_server_run_workspace_history, request);
        }

        pub fn playServerRunWorkspaceHistory(self: *Self, request: models.ServerPlayRunWorkspaceHistoryRequest) !grt.std.json.Parsed(models.ServerPlayRunWorkspaceHistoryResponse) {
            return try self.callRpcParsed(models.ServerPlayRunWorkspaceHistoryResponse, "server-run-workspace-history-play", Rpc.method_server_run_workspace_history_play, request);
        }

        pub fn getServerRunWorkspaceMemoryStats(self: *Self, request: models.ServerGetRunWorkspaceMemoryStatsRequest) !grt.std.json.Parsed(models.ServerGetRunWorkspaceMemoryStatsResponse) {
            return try self.callRpcParsed(models.ServerGetRunWorkspaceMemoryStatsResponse, "server-run-workspace-memory-stats", Rpc.method_server_run_workspace_memory_stats, request);
        }

        pub fn serverRunWorkspaceRecall(self: *Self, request: models.ServerRunWorkspaceRecallRequest) !grt.std.json.Parsed(models.ServerRunWorkspaceRecallResponse) {
            return try self.callRpcParsed(models.ServerRunWorkspaceRecallResponse, "server-run-workspace-recall", Rpc.method_server_run_workspace_recall, request);
        }

        pub fn reloadServerRun(self: *Self) !grt.std.json.Parsed(models.ServerReloadRunResponse) {
            return try self.callRpcParsed(models.ServerReloadRunResponse, "server-run-reload", Rpc.method_server_run_reload, models.ServerReloadRunRequest{});
        }

        pub fn getServerRunStatus(self: *Self, request: models.ServerGetRunStatusRequest) !grt.std.json.Parsed(models.ServerGetRunStatusResponse) {
            return try self.callRpcParsed(models.ServerGetRunStatusResponse, "server-run-status", Rpc.method_server_run_status, request);
        }

        pub fn stopServerRun(self: *Self) !grt.std.json.Parsed(models.ServerStopRunResponse) {
            return try self.callRpcParsed(models.ServerStopRunResponse, "server-run-stop", Rpc.method_server_run_stop, models.ServerStopRunRequest{});
        }

        pub fn serverRunSay(self: *Self, request: models.ServerRunSayRequest) !grt.std.json.Parsed(models.ServerRunSayResponse) {
            return try self.callRpcParsed(models.ServerRunSayResponse, "server-run-say", Rpc.method_server_run_say, request);
        }

        pub fn listWorkspaces(self: *Self, request: models.WorkspaceListRequest) !grt.std.json.Parsed(models.WorkspaceListResponse) {
            return try self.callRpcParsed(models.WorkspaceListResponse, "workspace-list", Rpc.method_server_workspace_list, request);
        }

        pub fn getWorkspace(self: *Self, request: models.WorkspaceGetRequest) !grt.std.json.Parsed(models.WorkspaceGetResponse) {
            return try self.callRpcParsed(models.WorkspaceGetResponse, "workspace-get", Rpc.method_server_workspace_get, request);
        }

        pub fn createWorkspace(self: *Self, request: models.WorkspaceCreateRequest) !grt.std.json.Parsed(models.WorkspaceCreateResponse) {
            return try self.callRpcParsed(models.WorkspaceCreateResponse, "workspace-create", Rpc.method_server_workspace_create, request);
        }

        pub fn putWorkspace(self: *Self, request: models.WorkspacePutRequest) !grt.std.json.Parsed(models.WorkspacePutResponse) {
            return try self.callRpcParsed(models.WorkspacePutResponse, "workspace-put", Rpc.method_server_workspace_put, request);
        }

        pub fn deleteWorkspace(self: *Self, request: models.WorkspaceDeleteRequest) !grt.std.json.Parsed(models.WorkspaceDeleteResponse) {
            return try self.callRpcParsed(models.WorkspaceDeleteResponse, "workspace-delete", Rpc.method_server_workspace_delete, request);
        }

        pub fn listWorkspaceHistory(self: *Self, request: models.WorkspaceHistoryListRequest) !grt.std.json.Parsed(models.WorkspaceHistoryListResponse) {
            return try self.callRpcParsed(models.WorkspaceHistoryListResponse, "workspace-history-list", Rpc.method_server_workspace_history_list, request);
        }

        pub fn getWorkspaceHistory(self: *Self, request: models.WorkspaceHistoryGetRequest) !grt.std.json.Parsed(models.WorkspaceHistoryGetResponse) {
            return try self.callRpcParsed(models.WorkspaceHistoryGetResponse, "workspace-history-get", Rpc.method_server_workspace_history_get, request);
        }

        pub fn getWorkspaceHistoryAudio(self: *Self, request: models.WorkspaceHistoryAudioGetRequest, writer: anytype) !WorkspaceHistoryAudioGetResult {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.rpc);
            try setStreamDeadline(stream);
            var rpc = RpcRuntime.Rpc.init(self.allocator, stream);
            defer rpc.deinit();

            const params = try models.toJson(self.allocator, request);
            defer self.allocator.free(params);
            const rpc_request = try RpcRuntime.buildRequest(self.allocator, "workspace-history-audio-get", Rpc.method_server_workspace_history_audio_get, params);
            defer self.allocator.free(rpc_request);

            try rpc.writeJsonFrame(rpc_request);
            try rpc.writeEOS();

            const response_data = try rpc.readJsonFrame();
            defer self.allocator.free(response_data);
            const metadata = try self.parseRpcResultParsed(models.WorkspaceHistoryAudioGetResponse, response_data);
            errdefer metadata.deinit();
            const bytes = try copyBinaryFramesToWriter(&rpc, writer);
            return .{
                .metadata = metadata,
                .bytes = bytes,
            };
        }

        pub fn listWorkflows(self: *Self, request: models.WorkflowListRequest) !grt.std.json.Parsed(models.WorkflowListResponse) {
            return try self.callRpcParsed(models.WorkflowListResponse, "workflow-list", Rpc.method_server_workflow_list, request);
        }

        pub fn getWorkflow(self: *Self, request: models.WorkflowGetRequest) !grt.std.json.Parsed(models.WorkflowGetResponse) {
            return try self.callRpcParsed(models.WorkflowGetResponse, "workflow-get", Rpc.method_server_workflow_get, request);
        }

        pub fn createWorkflow(self: *Self, request: models.WorkflowCreateRequest) !grt.std.json.Parsed(models.WorkflowCreateResponse) {
            return try self.callRpcParsed(models.WorkflowCreateResponse, "workflow-create", Rpc.method_server_workflow_create, request);
        }

        pub fn putWorkflow(self: *Self, request: models.WorkflowPutRequest) !grt.std.json.Parsed(models.WorkflowPutResponse) {
            return try self.callRpcParsed(models.WorkflowPutResponse, "workflow-put", Rpc.method_server_workflow_put, request);
        }

        pub fn deleteWorkflow(self: *Self, request: models.WorkflowDeleteRequest) !grt.std.json.Parsed(models.WorkflowDeleteResponse) {
            return try self.callRpcParsed(models.WorkflowDeleteResponse, "workflow-delete", Rpc.method_server_workflow_delete, request);
        }

        pub fn listModels(self: *Self, request: models.ModelListRequest) !grt.std.json.Parsed(models.ModelListResponse) {
            return try self.callRpcParsed(models.ModelListResponse, "model-list", Rpc.method_server_model_list, request);
        }

        pub fn getModel(self: *Self, request: models.ModelGetRequest) !grt.std.json.Parsed(models.ModelGetResponse) {
            return try self.callRpcParsed(models.ModelGetResponse, "model-get", Rpc.method_server_model_get, request);
        }

        pub fn createModel(self: *Self, request: models.ModelCreateRequest) !grt.std.json.Parsed(models.ModelCreateResponse) {
            return try self.callRpcParsed(models.ModelCreateResponse, "model-create", Rpc.method_server_model_create, request);
        }

        pub fn putModel(self: *Self, request: models.ModelPutRequest) !grt.std.json.Parsed(models.ModelPutResponse) {
            return try self.callRpcParsed(models.ModelPutResponse, "model-put", Rpc.method_server_model_put, request);
        }

        pub fn deleteModel(self: *Self, request: models.ModelDeleteRequest) !grt.std.json.Parsed(models.ModelDeleteResponse) {
            return try self.callRpcParsed(models.ModelDeleteResponse, "model-delete", Rpc.method_server_model_delete, request);
        }

        pub fn listCredentials(self: *Self, request: models.CredentialListRequest) !grt.std.json.Parsed(models.CredentialListResponse) {
            return try self.callRpcParsed(models.CredentialListResponse, "credential-list", Rpc.method_server_credential_list, request);
        }

        pub fn getCredential(self: *Self, request: models.CredentialGetRequest) !grt.std.json.Parsed(models.CredentialGetResponse) {
            return try self.callRpcParsed(models.CredentialGetResponse, "credential-get", Rpc.method_server_credential_get, request);
        }

        pub fn createCredential(self: *Self, request: models.CredentialCreateRequest) !grt.std.json.Parsed(models.CredentialCreateResponse) {
            return try self.callRpcParsed(models.CredentialCreateResponse, "credential-create", Rpc.method_server_credential_create, request);
        }

        pub fn putCredential(self: *Self, request: models.CredentialPutRequest) !grt.std.json.Parsed(models.CredentialPutResponse) {
            return try self.callRpcParsed(models.CredentialPutResponse, "credential-put", Rpc.method_server_credential_put, request);
        }

        pub fn deleteCredential(self: *Self, request: models.CredentialDeleteRequest) !grt.std.json.Parsed(models.CredentialDeleteResponse) {
            return try self.callRpcParsed(models.CredentialDeleteResponse, "credential-delete", Rpc.method_server_credential_delete, request);
        }

        pub fn listVoices(self: *Self, request: VoiceListRequest) !grt.std.json.Parsed(models.ClientVoiceListResponse) {
            var url = grt.std.Io.Writer.Allocating.init(self.allocator);
            defer url.deinit();
            try url.writer.writeAll("http://gizclaw.local/v1/voices");
            try appendVoiceListQuery(self.allocator, &url, request);
            const owned_url = try url.toOwnedSlice();
            defer self.allocator.free(owned_url);
            return try self.peerHttpGetParsed(models.ClientVoiceListResponse, owned_url);
        }

        pub fn getVoice(self: *Self, request: VoiceGetRequest) !grt.std.json.Parsed(models.Voice) {
            var page_request = VoiceListRequest{
                .limit = 100,
            };
            while (true) {
                var page = try self.listVoices(page_request);
                defer page.deinit();

                for (page.value.data) |voice| {
                    if (grt.std.mem.eql(u8, voice.id, request.id)) {
                        const voice_json = try models.toJson(self.allocator, voice);
                        defer self.allocator.free(voice_json);
                        return try models.fromJson(models.Voice, self.allocator, voice_json);
                    }
                }

                if (!page.value.has_next) return error.GearNotFound;
                page_request.cursor = page.value.next_cursor orelse return error.GearNotFound;
            }
        }

        pub fn createSpeech(self: *Self, request: SpeechRequest) ![]u8 {
            const body = try models.toJson(self.allocator, request);
            defer self.allocator.free(body);
            return try self.peerHttpPostJsonAlloc("http://gizclaw.local/v1/audio/speech", body);
        }

        pub fn listFirmwares(self: *Self, request: models.FirmwareListRequest) !grt.std.json.Parsed(models.FirmwareListResponse) {
            return try self.callRpcParsed(models.FirmwareListResponse, "firmware-list", Rpc.method_server_firmware_list, request);
        }

        pub fn getFirmware(self: *Self, request: models.FirmwareGetRequest) !grt.std.json.Parsed(models.FirmwareGetResponse) {
            return try self.callRpcParsed(models.FirmwareGetResponse, "firmware-get", Rpc.method_server_firmware_get, request);
        }

        pub fn listContacts(self: *Self, request: models.ContactListRequest) !grt.std.json.Parsed(models.ContactListResponse) {
            return try self.callRpcParsed(models.ContactListResponse, "contact-list", Rpc.method_server_contact_list, request);
        }

        pub fn getContact(self: *Self, request: models.ContactGetRequest) !grt.std.json.Parsed(models.ContactGetResponse) {
            return try self.callRpcParsed(models.ContactGetResponse, "contact-get", Rpc.method_server_contact_get, request);
        }

        pub fn createContact(self: *Self, request: models.ContactCreateRequest) !grt.std.json.Parsed(models.ContactCreateResponse) {
            return try self.callRpcParsed(models.ContactCreateResponse, "contact-create", Rpc.method_server_contact_create, request);
        }

        pub fn putContact(self: *Self, request: models.ContactPutRequest) !grt.std.json.Parsed(models.ContactPutResponse) {
            return try self.callRpcParsed(models.ContactPutResponse, "contact-put", Rpc.method_server_contact_put, request);
        }

        pub fn deleteContact(self: *Self, request: models.ContactDeleteRequest) !grt.std.json.Parsed(models.ContactDeleteResponse) {
            return try self.callRpcParsed(models.ContactDeleteResponse, "contact-delete", Rpc.method_server_contact_delete, request);
        }

        pub fn getFriendInviteToken(self: *Self, request: models.FriendInviteTokenGetRequest) !grt.std.json.Parsed(models.FriendInviteTokenGetResponse) {
            return try self.callRpcParsed(models.FriendInviteTokenGetResponse, "friend-invite-token-get", Rpc.method_server_friend_invite_token_get, request);
        }

        pub fn createFriendInviteToken(self: *Self, request: models.FriendInviteTokenCreateRequest) !grt.std.json.Parsed(models.FriendInviteTokenCreateResponse) {
            return try self.callRpcParsed(models.FriendInviteTokenCreateResponse, "friend-invite-token-create", Rpc.method_server_friend_invite_token_create, request);
        }

        pub fn clearFriendInviteToken(self: *Self, request: models.FriendInviteTokenClearRequest) !grt.std.json.Parsed(models.FriendInviteTokenClearResponse) {
            return try self.callRpcParsed(models.FriendInviteTokenClearResponse, "friend-invite-token-clear", Rpc.method_server_friend_invite_token_clear, request);
        }

        pub fn addFriend(self: *Self, request: models.FriendAddRequest) !grt.std.json.Parsed(models.FriendAddResponse) {
            return try self.callRpcParsed(models.FriendAddResponse, "friend-add", Rpc.method_server_friend_add, request);
        }

        pub fn listFriends(self: *Self, request: models.FriendListRequest) !grt.std.json.Parsed(models.FriendListResponse) {
            return try self.callRpcParsed(models.FriendListResponse, "friend-list", Rpc.method_server_friend_list, request);
        }

        pub fn deleteFriend(self: *Self, request: models.FriendDeleteRequest) !grt.std.json.Parsed(models.FriendDeleteResponse) {
            return try self.callRpcParsed(models.FriendDeleteResponse, "friend-delete", Rpc.method_server_friend_delete, request);
        }

        pub fn listFriendGroups(self: *Self, request: models.FriendGroupListRequest) !grt.std.json.Parsed(models.FriendGroupListResponse) {
            return try self.callRpcParsed(models.FriendGroupListResponse, "friend-group-list", Rpc.method_server_friend_group_list, request);
        }

        pub fn getFriendGroup(self: *Self, request: models.FriendGroupGetRequest) !grt.std.json.Parsed(models.FriendGroupGetResponse) {
            return try self.callRpcParsed(models.FriendGroupGetResponse, "friend-group-get", Rpc.method_server_friend_group_get, request);
        }

        pub fn createFriendGroup(self: *Self, request: models.FriendGroupCreateRequest) !grt.std.json.Parsed(models.FriendGroupCreateResponse) {
            return try self.callRpcParsed(models.FriendGroupCreateResponse, "friend-group-create", Rpc.method_server_friend_group_create, request);
        }

        pub fn putFriendGroup(self: *Self, request: models.FriendGroupPutRequest) !grt.std.json.Parsed(models.FriendGroupPutResponse) {
            return try self.callRpcParsed(models.FriendGroupPutResponse, "friend-group-put", Rpc.method_server_friend_group_put, request);
        }

        pub fn deleteFriendGroup(self: *Self, request: models.FriendGroupDeleteRequest) !grt.std.json.Parsed(models.FriendGroupDeleteResponse) {
            return try self.callRpcParsed(models.FriendGroupDeleteResponse, "friend-group-delete", Rpc.method_server_friend_group_delete, request);
        }

        pub fn getFriendGroupInviteToken(self: *Self, request: models.FriendGroupInviteTokenGetRequest) !grt.std.json.Parsed(models.FriendGroupInviteTokenGetResponse) {
            return try self.callRpcParsed(models.FriendGroupInviteTokenGetResponse, "friend-group-invite-token-get", Rpc.method_server_friend_group_invite_token_get, request);
        }

        pub fn createFriendGroupInviteToken(self: *Self, request: models.FriendGroupInviteTokenCreateRequest) !grt.std.json.Parsed(models.FriendGroupInviteTokenCreateResponse) {
            return try self.callRpcParsed(models.FriendGroupInviteTokenCreateResponse, "friend-group-invite-token-create", Rpc.method_server_friend_group_invite_token_create, request);
        }

        pub fn clearFriendGroupInviteToken(self: *Self, request: models.FriendGroupInviteTokenClearRequest) !grt.std.json.Parsed(models.FriendGroupInviteTokenClearResponse) {
            return try self.callRpcParsed(models.FriendGroupInviteTokenClearResponse, "friend-group-invite-token-clear", Rpc.method_server_friend_group_invite_token_clear, request);
        }

        pub fn joinFriendGroup(self: *Self, request: models.FriendGroupJoinRequest) !grt.std.json.Parsed(models.FriendGroupJoinResponse) {
            return try self.callRpcParsed(models.FriendGroupJoinResponse, "friend-group-join", Rpc.method_server_friend_group_join, request);
        }

        pub fn listFriendGroupMembers(self: *Self, request: models.FriendGroupMemberListRequest) !grt.std.json.Parsed(models.FriendGroupMemberListResponse) {
            return try self.callRpcParsed(models.FriendGroupMemberListResponse, "friend-group-members-list", Rpc.method_server_friend_group_members_list, request);
        }

        pub fn addFriendGroupMember(self: *Self, request: models.FriendGroupMemberAddRequest) !grt.std.json.Parsed(models.FriendGroupMemberAddResponse) {
            return try self.callRpcParsed(models.FriendGroupMemberAddResponse, "friend-group-members-add", Rpc.method_server_friend_group_members_add, request);
        }

        pub fn putFriendGroupMember(self: *Self, request: models.FriendGroupMemberPutRequest) !grt.std.json.Parsed(models.FriendGroupMemberPutResponse) {
            return try self.callRpcParsed(models.FriendGroupMemberPutResponse, "friend-group-members-put", Rpc.method_server_friend_group_members_put, request);
        }

        pub fn deleteFriendGroupMember(self: *Self, request: models.FriendGroupMemberDeleteRequest) !grt.std.json.Parsed(models.FriendGroupMemberDeleteResponse) {
            return try self.callRpcParsed(models.FriendGroupMemberDeleteResponse, "friend-group-members-delete", Rpc.method_server_friend_group_members_delete, request);
        }

        pub fn listFriendGroupMessages(self: *Self, request: models.FriendGroupMessageListRequest) !grt.std.json.Parsed(models.FriendGroupMessageListResponse) {
            return try self.callRpcParsed(models.FriendGroupMessageListResponse, "friend-group-messages-list", Rpc.method_server_friend_group_messages_list, request);
        }

        pub fn getFriendGroupMessage(self: *Self, request: models.FriendGroupMessageGetRequest) !grt.std.json.Parsed(models.FriendGroupMessageGetResponse) {
            return try self.callRpcParsed(models.FriendGroupMessageGetResponse, "friend-group-messages-get", Rpc.method_server_friend_group_messages_get, request);
        }

        pub fn sendFriendGroupMessage(self: *Self, request: models.FriendGroupMessageSendRequest) !grt.std.json.Parsed(models.FriendGroupMessageSendResponse) {
            return try self.callRpcParsed(models.FriendGroupMessageSendResponse, "friend-group-messages-send", Rpc.method_server_friend_group_messages_send, request);
        }

        pub fn downloadFirmware(self: *Self, request: models.FirmwareDownloadRequest, writer: anytype) !FirmwareDownloadResult {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.rpc);
            try setStreamDeadline(stream);
            var rpc = RpcRuntime.Rpc.init(self.allocator, stream);
            defer rpc.deinit();

            const params = try models.toJson(self.allocator, request);
            defer self.allocator.free(params);
            const rpc_request = try RpcRuntime.buildRequest(self.allocator, "firmware-download", Rpc.method_server_firmware_download, params);
            defer self.allocator.free(rpc_request);

            try rpc.writeJsonFrame(rpc_request);
            try rpc.writeEOS();

            const response_data = try rpc.readJsonFrame();
            defer self.allocator.free(response_data);
            const metadata = try self.parseRpcResultParsed(models.FirmwareDownloadResponse, response_data);
            errdefer metadata.deinit();
            const bytes = try copyBinaryFramesToWriter(&rpc, writer);
            return .{
                .metadata = metadata,
                .bytes = bytes,
            };
        }

        pub fn openPeerEventStream(self: *Self) !PeerEventStream {
            const conn = self.conn orelse return error.ClientNotConnected;
            var stream = try PeerStreamRuntime.openPeerEventStream(self.allocator, conn);
            errdefer stream.deinit();
            try setStreamDeadline(stream.stream);
            return stream;
        }

        pub fn readPeerStreamEvent(self: *Self, stream: *PeerEventStream) !grt.std.json.Parsed(PeerStreamEvent) {
            _ = self;
            return try stream.read();
        }

        pub fn writePeerStreamEvent(self: *Self, stream: *PeerEventStream, event: PeerStreamEvent) !void {
            _ = self;
            try stream.write(event);
        }

        pub fn closePeerEventStream(self: *Self, stream: *PeerEventStream) void {
            _ = self;
            stream.close();
        }

        pub fn openPeerStream(self: *Self, options: OpenPeerStreamOptions) !PeerStream {
            const conn = self.conn orelse return error.ClientNotConnected;
            var stream = try PeerStreamRuntime.openPeerStream(self.allocator, conn, options);
            errdefer stream.deinit();
            return stream;
        }

        pub fn readPeerStreamChunk(self: *Self, stream: *PeerStream, buf: []u8) !PeerStreamChunkReadResult {
            _ = self;
            return try stream.readChunk(buf);
        }

        pub fn beginPeerAudio(self: *Self, stream: *PeerStream, options: PeerAudioTurnOptions) !void {
            _ = self;
            try stream.beginAudio(options);
        }

        pub fn writePeerAudio(self: *Self, stream: *PeerStream, frame: StampedOpusFrame) !void {
            _ = self;
            try stream.writeAudio(frame);
        }

        pub fn endPeerAudio(self: *Self, stream: *PeerStream, options: PeerAudioTurnOptions) !void {
            _ = self;
            try stream.endAudio(options);
        }

        pub fn readPeerAudio(self: *Self, stream: *PeerStream, buf: []u8) !StampedOpusFrame {
            _ = self;
            return try stream.readAudio(buf);
        }

        pub fn pushPeerStreamChunk(self: *Self, stream: *PeerStream, chunk: PeerStreamChunk) !void {
            const conn = self.conn orelse return error.ClientNotConnected;
            try PeerStreamRuntime.writePeerStreamChunk(self.allocator, conn, stream.event_stream.stream, chunk);
        }

        pub fn subscribeStampedOpus(self: *Self, options: StampedOpusSubscribeOptions) !StampedOpusSubscriber {
            const conn = self.conn orelse return error.ClientNotConnected;
            return PeerStreamRuntime.subscribeStampedOpus(conn, options);
        }

        pub fn readStampedOpus(self: *Self, subscriber: *StampedOpusSubscriber, buf: []u8) !StampedOpusFrame {
            _ = self;
            return try subscriber.read(buf);
        }

        pub fn writeStampedOpus(self: *Self, frame: StampedOpusFrame) !void {
            const conn = self.conn orelse return error.ClientNotConnected;
            try PeerStreamRuntime.writeStampedOpus(self.allocator, conn, frame);
        }

        pub fn serverInfo(self: *Self) !ServerInfo {
            const response_data = try self.rpcCall("server-info-get", Rpc.method_server_info_get, "{}");
            defer self.allocator.free(response_data);
            return try self.parseRpcServerInfo(response_data);
        }

        pub fn peerInfo(self: *Self) !DeviceInfo {
            const response_data = try self.rpcCall("peer-info-get", Rpc.method_peer_info_get, "{}");
            defer self.allocator.free(response_data);
            return try self.parseRpcDeviceInfo(response_data);
        }

        pub fn putPeerInfo(self: *Self, info: DeviceInfo) !DeviceInfo {
            const body = try models.toJson(self.allocator, info);
            defer self.allocator.free(body);
            const response_data = try self.rpcCall("peer-info-put", Rpc.method_peer_info_put, body);
            defer self.allocator.free(response_data);
            return try self.parseRpcDeviceInfo(response_data);
        }

        pub fn putLocalPeerInfo(self: *Self) !DeviceInfo {
            return try self.putPeerInfo(self.local_device_info);
        }

        pub fn peerRuntime(self: *Self) !RuntimeStatus {
            const response_data = try self.rpcCall("peer-runtime-get", Rpc.method_peer_runtime_get, "{}");
            defer self.allocator.free(response_data);
            return try self.parseRpcPeerRuntime(response_data);
        }

        pub fn setPeerName(self: *Self, name: []const u8) !DeviceInfo {
            if (self.peerInfo()) |existing| {
                var info = existing;
                defer deinitDeviceInfo(self.allocator, &info);
                if (info.name) |old| {
                    self.allocator.free(old);
                    info.name = null;
                }
                info.name = try self.allocator.dupe(u8, name);
                return try self.putPeerInfo(info);
            } else |err| {
                if (err == error.GearNotFound) return try self.putPeerInfo(.{ .name = name });
                return err;
            }
        }

        pub fn deinitServerInfo(allocator: Allocator, info: *ServerInfo) void {
            allocator.free(info.public_key);
            allocator.free(info.build_commit);
            info.* = undefined;
        }

        pub fn deinitRuntime(allocator: Allocator, runtime: *RuntimeStatus) void {
            allocator.free(runtime.last_seen_at);
            if (runtime.last_addr) |value| allocator.free(value);
            runtime.* = undefined;
        }

        pub fn deinitDeviceInfo(allocator: Allocator, info: *DeviceInfo) void {
            if (info.name) |value| allocator.free(value);
            if (info.sn) |value| allocator.free(value);
            if (info.hardware) |*hardware| deinitHardwareInfo(allocator, hardware);
            info.* = undefined;
        }

        fn setStreamDeadline(stream: giznet.Stream) !void {
            try setStreamDeadlineFor(stream, request_timeout);
        }

        fn setStreamDeadlineFor(stream: giznet.Stream, timeout: glib.time.duration.Duration) !void {
            const deadline = grt.time.instant.add(grt.time.instant.now(), timeout);
            try stream.setReadDeadline(deadline);
            try stream.setWriteDeadline(deadline);
        }

        fn streamLoop(self: *Self) void {
            while (!self.closing.load(.acquire)) {
                const conn = self.conn orelse return;
                self.acceptOneStream(conn) catch |err| {
                    if (err == error.Timeout) continue;
                    if (isClosedError(err) or self.closing.load(.acquire)) return;
                };
            }
        }

        fn acceptOneStream(self: *Self, conn: giznet.Conn) !void {
            var stream = try conn.accept(stream_accept_timeout);
            errdefer stream.deinit();
            errdefer stream.close() catch {};
            try setStreamDeadline(stream);
            switch (stream.service) {
                service.rpc => self.serveRpc(stream) catch {},
                else => {
                    defer stream.deinit();
                    defer stream.close() catch {};
                },
            }
        }

        fn serveRpc(self: *Self, stream: giznet.Stream) !void {
            var rpc = RpcRuntime.Rpc.init(self.allocator, stream);
            defer rpc.deinit();

            const data = try rpc.readJsonFrame();
            defer self.allocator.free(data);
            try rpc.readEOS();

            const Request = struct {
                v: i64,
                id: []const u8,
                method: []const u8,
            };
            const parsed = try grt.std.json.parseFromSlice(Request, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;

            const response = self.servePeerService(parsed.value.id, parsed.value.method) catch |peer_err| switch (peer_err) {
                error.RpcMethodNotFound => self.serveClientService(parsed.value.id, parsed.value.method) catch |client_err| switch (client_err) {
                    error.RpcMethodNotFound => self.serveDeviceService(parsed.value.id, parsed.value.method) catch |device_err| switch (device_err) {
                        error.RpcMethodNotFound => try buildRpcErrorResponse(self.allocator, parsed.value.id, -32601, "method not found"),
                        else => return device_err,
                    },
                    else => return client_err,
                },
                else => return peer_err,
            };
            defer self.allocator.free(response);
            try rpc.writeJsonFrame(response);
            try rpc.writeEOS();
        }

        fn servePeerService(self: *Self, id: []const u8, method: []const u8) ![]u8 {
            if (grt.std.mem.eql(u8, method, Rpc.method_ping)) {
                return try buildRpcPingResponse(self.allocator, id);
            }
            return error.RpcMethodNotFound;
        }

        fn serveClientService(self: *Self, id: []const u8, method: []const u8) ![]u8 {
            if (grt.std.mem.eql(u8, method, Rpc.method_client_info_get)) {
                return try self.buildRpcClientInfoResponse(id);
            }
            if (grt.std.mem.eql(u8, method, Rpc.method_client_identifiers_get)) {
                return try self.buildRpcClientIdentifiersResponse(id);
            }
            return error.RpcMethodNotFound;
        }

        fn serveDeviceService(self: *Self, id: []const u8, method: []const u8) ![]u8 {
            if (grt.std.mem.eql(u8, method, Rpc.method_device_info_get)) {
                return try self.buildRpcDeviceInfoResponse(id);
            }
            if (grt.std.mem.eql(u8, method, Rpc.method_device_identifiers_get)) {
                return try self.buildRpcDeviceIdentifiersResponse(id);
            }
            return error.RpcMethodNotFound;
        }

        fn deinitHardwareInfo(allocator: Allocator, hardware: *HardwareInfo) void {
            if (hardware.manufacturer) |value| allocator.free(value);
            if (hardware.model) |value| allocator.free(value);
            if (hardware.hardware_revision) |value| allocator.free(value);
            if (hardware.imeis) |items| {
                for (items) |item| deinitGearIMEI(allocator, item);
                allocator.free(items);
            }
            if (hardware.labels) |items| {
                for (items) |item| deinitGearLabel(allocator, item);
                allocator.free(items);
            }
            hardware.* = undefined;
        }

        fn deinitGearIMEI(allocator: Allocator, item: GearIMEI) void {
            allocator.free(item.tac);
            allocator.free(item.serial);
            if (item.name) |value| allocator.free(value);
        }

        fn deinitGearLabel(allocator: Allocator, item: GearLabel) void {
            allocator.free(item.key);
            allocator.free(item.value);
        }

        fn rpcCall(self: *Self, id: []const u8, method: []const u8, params_json: []const u8) ![]u8 {
            const conn = self.conn orelse return error.ClientNotConnected;
            const stream = try conn.openStream(service.rpc);
            try setStreamDeadline(stream);
            var rpc = RpcRuntime.Rpc.init(self.allocator, stream);
            defer rpc.deinit();
            return try rpc.call(id, method, params_json);
        }

        fn callRpcParsed(
            self: *Self,
            comptime Response: type,
            id: []const u8,
            method: []const u8,
            request: anytype,
        ) !grt.std.json.Parsed(Response) {
            const params = try models.toJson(self.allocator, request);
            defer self.allocator.free(params);
            const response_data = try self.rpcCall(id, method, params);
            defer self.allocator.free(response_data);
            return try self.parseRpcResultParsed(Response, response_data);
        }

        fn parseRpcResultParsed(self: *Self, comptime Response: type, data: []const u8) !grt.std.json.Parsed(Response) {
            const Envelope = struct {
                v: i64,
                id: []const u8,
                result: ?grt.std.json.Value = null,
                @"error": ?models.RPCError = null,
            };
            const parsed = try grt.std.json.parseFromSlice(Envelope, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;
            _ = parsed.value.id;
            if (parsed.value.@"error") |rpc_error| {
                const log = grt.std.log.scoped(.gizclaw_client);
                log.err("rpc response error id={s} code={d} message={s}", .{
                    parsed.value.id,
                    rpc_error.code,
                    rpc_error.message,
                });
                return rpcResponseError(rpc_error);
            }
            const result = parsed.value.result orelse return error.MissingRpcResult;

            var out = grt.std.Io.Writer.Allocating.init(self.allocator);
            defer out.deinit();
            try grt.std.json.Stringify.value(result, .{}, &out.writer);
            const result_json = try out.toOwnedSlice();
            defer self.allocator.free(result_json);
            return try models.fromJson(Response, self.allocator, result_json);
        }

        fn peerHttpGetParsed(self: *Self, comptime Response: type, url: []const u8) !grt.std.json.Parsed(Response) {
            const conn = self.conn orelse return error.NotConnected;
            var transport = giznet.HttpTransport.make(grt).init(self.allocator, conn, service.openai);
            defer transport.deinit();
            var http_client = try Http.Client.init(self.allocator, .{ .round_tripper = transport.roundTripper() });
            defer http_client.deinit();

            var response = try http_client.get(url);
            defer response.deinit();
            const body = try self.readHttpBodyAlloc(response.body());
            defer self.allocator.free(body);
            if (response.status_code == 404) return error.GearNotFound;
            if (response.status_code < 200 or response.status_code >= 300) return error.HttpStatus;
            return try models.fromJson(Response, self.allocator, body);
        }

        fn peerHttpPostJsonAlloc(self: *Self, url: []const u8, json_body: []const u8) ![]u8 {
            const conn = self.conn orelse return error.NotConnected;
            var transport = giznet.HttpTransport.make(grt).init(self.allocator, conn, service.openai);
            defer transport.deinit();
            var http_client = try Http.Client.init(self.allocator, .{ .round_tripper = transport.roundTripper() });
            defer http_client.deinit();

            var body = SliceReadCloser{ .data = json_body };
            var request = try Http.Request.init(self.allocator, "POST", url);
            defer request.deinit();
            request = request.withBody(Http.ReadCloser.init(&body));
            request.content_length = @intCast(json_body.len);
            try request.addHeader(Http.Header.content_type, "application/json");
            try request.addHeader(Http.Header.authorization, "Bearer gizclaw-peer");

            var response = try http_client.do(&request);
            defer response.deinit();
            const response_body = try self.readHttpBodyAlloc(response.body());
            errdefer self.allocator.free(response_body);
            if (response.status_code == 404) return error.GearNotFound;
            if (response.status_code < 200 or response.status_code >= 300) {
                const log = grt.std.log.scoped(.gizclaw_client);
                log.err("peer http post failed status={d} body={s}", .{ response.status_code, response_body });
                return error.HttpStatus;
            }
            return response_body;
        }

        fn readHttpBodyAlloc(self: *Self, body: ?Http.ReadCloser) ![]u8 {
            var reader = body orelse return try self.allocator.dupe(u8, "");
            var out = grt.std.ArrayList(u8){};
            errdefer out.deinit(self.allocator);
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = try reader.read(&buf);
                if (n == 0) break;
                if (out.items.len + n > 16 * 1024 * 1024) return error.ResponseTooLarge;
                try out.appendSlice(self.allocator, buf[0..n]);
            }
            return try out.toOwnedSlice(self.allocator);
        }

        const SliceReadCloser = struct {
            data: []const u8,
            offset: usize = 0,
            closed: bool = false,

            pub fn read(self: *@This(), buf: []u8) !usize {
                if (self.closed) return 0;
                const remaining = self.data[self.offset..];
                const n = @min(buf.len, remaining.len);
                @memcpy(buf[0..n], remaining[0..n]);
                self.offset += n;
                return n;
            }

            pub fn close(self: *@This()) void {
                self.closed = true;
            }
        };

        fn copyBinaryFramesToWriter(rpc: *RpcRuntime.Rpc, writer: anytype) !i64 {
            var written: i64 = 0;
            while (true) {
                var frame = try rpc.readFrame();
                defer frame.deinit(rpc.allocator);
                if (frame.type == .eos) return written;
                if (frame.type != .binary) return error.ExpectedRpcBinaryFrame;
                try writer.writeAll(frame.payload);
                written += @intCast(frame.payload.len);
            }
        }

        fn buildRpcPingResponse(allocator: Allocator, id: []const u8) ![]u8 {
            const result = models.PingResponse{ .server_time = grt.time.now().unixMilli() };
            const result_json = try models.toJson(allocator, result);
            defer allocator.free(result_json);
            return try buildRpcResultResponse(allocator, id, result_json);
        }

        fn appendVoiceListQuery(allocator: Allocator, out: *grt.std.Io.Writer.Allocating, request: VoiceListRequest) !void {
            var first = true;
            if (request.cursor) |value| try appendQueryParam(out, &first, "cursor", value);
            if (request.limit) |value| {
                const text = try grt.std.fmt.allocPrint(allocator, "{d}", .{value});
                defer allocator.free(text);
                try appendQueryParam(out, &first, "limit", text);
            }
            if (request.source) |value| try appendQueryParam(out, &first, "source", value);
            if (request.provider_kind) |value| try appendQueryParam(out, &first, "provider_kind", value);
            if (request.provider_name) |value| try appendQueryParam(out, &first, "provider_name", value);
        }

        fn appendQueryParam(
            out: *grt.std.Io.Writer.Allocating,
            first: *bool,
            name: []const u8,
            value: []const u8,
        ) !void {
            try out.writer.writeByte(if (first.*) '?' else '&');
            first.* = false;
            try appendQueryEscaped(out, name);
            try out.writer.writeByte('=');
            try appendQueryEscaped(out, value);
        }

        fn appendQueryEscaped(out: *grt.std.Io.Writer.Allocating, value: []const u8) !void {
            const hex = "0123456789ABCDEF";
            for (value) |ch| {
                if (isQueryUnreserved(ch)) {
                    try out.writer.writeByte(ch);
                } else {
                    try out.writer.writeByte('%');
                    try out.writer.writeByte(hex[ch >> 4]);
                    try out.writer.writeByte(hex[ch & 0x0f]);
                }
            }
        }

        fn isQueryUnreserved(ch: u8) bool {
            return (ch >= 'a' and ch <= 'z') or
                (ch >= 'A' and ch <= 'Z') or
                (ch >= '0' and ch <= '9') or
                ch == '-' or ch == '.' or ch == '_' or ch == '~';
        }

        fn buildRpcDeviceInfoResponse(self: *Self, id: []const u8) ![]u8 {
            const local = self.local_device_info;
            var result = models.RefreshInfo{
                .name = local.name,
            };
            if (local.hardware) |hardware| {
                result.manufacturer = hardware.manufacturer;
                result.model = hardware.model;
                result.hardware_revision = hardware.hardware_revision;
            }

            const result_json = try models.toJson(self.allocator, result);
            defer self.allocator.free(result_json);
            return try buildRpcResultResponse(self.allocator, id, result_json);
        }

        fn buildRpcClientInfoResponse(self: *Self, id: []const u8) ![]u8 {
            const local = self.local_device_info;
            var result = models.ClientGetInfoResponse{
                .name = local.name,
            };
            if (local.hardware) |hardware| {
                result.manufacturer = hardware.manufacturer;
                result.model = hardware.model;
                result.hardware_revision = hardware.hardware_revision;
            }

            const result_json = try models.toJson(self.allocator, result);
            defer self.allocator.free(result_json);
            return try buildRpcResultResponse(self.allocator, id, result_json);
        }

        fn buildRpcClientIdentifiersResponse(self: *Self, id: []const u8) ![]u8 {
            const local = self.local_device_info;
            var result = models.ClientGetIdentifiersResponse{
                .sn = local.sn,
            };
            if (local.hardware) |hardware| {
                result.imeis = hardware.imeis;
                result.labels = hardware.labels;
            }

            const result_json = try models.toJson(self.allocator, result);
            defer self.allocator.free(result_json);
            return try buildRpcResultResponse(self.allocator, id, result_json);
        }

        fn buildRpcDeviceIdentifiersResponse(self: *Self, id: []const u8) ![]u8 {
            const local = self.local_device_info;
            var result = models.RefreshIdentifiers{
                .sn = local.sn,
            };
            if (local.hardware) |hardware| {
                result.imeis = hardware.imeis;
                result.labels = hardware.labels;
            }

            const result_json = try models.toJson(self.allocator, result);
            defer self.allocator.free(result_json);
            return try buildRpcResultResponse(self.allocator, id, result_json);
        }

        fn buildRpcResultResponse(allocator: Allocator, id: []const u8, result_json: []const u8) ![]u8 {
            var out = grt.std.Io.Writer.Allocating.init(allocator);
            errdefer out.deinit();
            try out.writer.writeAll("{\"v\":1,\"id\":");
            try grt.std.json.Stringify.value(id, .{}, &out.writer);
            try out.writer.writeAll(",\"result\":");
            try out.writer.writeAll(result_json);
            try out.writer.writeAll("}");
            return try out.toOwnedSlice();
        }

        fn buildRpcErrorResponse(allocator: Allocator, id: []const u8, code: i64, message: []const u8) ![]u8 {
            var out = grt.std.Io.Writer.Allocating.init(allocator);
            errdefer out.deinit();
            try out.writer.writeAll("{\"v\":1,\"id\":");
            try grt.std.json.Stringify.value(id, .{}, &out.writer);
            try out.writer.print(",\"error\":{{\"code\":{d},\"message\":", .{code});
            try grt.std.json.Stringify.value(message, .{}, &out.writer);
            try out.writer.writeAll("}}");
            return try out.toOwnedSlice();
        }

        fn isClosedError(err: anyerror) bool {
            return switch (err) {
                error.ConnClosed,
                error.EndOfStream,
                error.RuntimeAcceptChannelClosed,
                error.RuntimeChannelClosed,
                error.RuntimeEngineClosed,
                error.ServiceMuxClosed,
                error.UDPClosed,
                => true,
                else => false,
            };
        }

        pub fn parseAddrPort(input: []const u8) !giznet.AddrPort {
            const text = grt.std.mem.trim(u8, input, " \t\r\n");
            if (text.len == 0) return error.InvalidServerAddress;

            if (text[0] == '[') {
                const close = grt.std.mem.indexOfScalar(u8, text, ']') orelse return error.InvalidServerAddress;
                if (close + 2 > text.len or text[close + 1] != ':') return error.InvalidServerAddress;
                const host = text[1..close];
                const port = try grt.std.fmt.parseInt(u16, text[close + 2 ..], 10);
                return giznet.AddrPort.init(try glib.net.netip.Addr.parse(host), port);
            }

            const colon = grt.std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidServerAddress;
            const host = text[0..colon];
            const port = try grt.std.fmt.parseInt(u16, text[colon + 1 ..], 10);
            return giznet.AddrPort.init(try glib.net.netip.Addr.parse(host), port);
        }

        fn parseRpcDeviceInfo(self: *Self, data: []const u8) !DeviceInfo {
            const Response = struct {
                v: i64,
                id: []const u8,
                result: ?DeviceInfo = null,
                @"error": ?models.RPCError = null,
            };
            const parsed = try grt.std.json.parseFromSlice(Response, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;
            _ = parsed.value.id;
            if (parsed.value.@"error") |rpc_error| return rpcResponseError(rpc_error);
            return try self.dupeDeviceInfo(parsed.value.result orelse return error.MissingRpcResult);
        }

        fn parseRpcPeerRuntime(self: *Self, data: []const u8) !RuntimeStatus {
            const Response = struct {
                v: i64,
                id: []const u8,
                result: ?RuntimeStatus = null,
                @"error": ?models.RPCError = null,
            };
            const parsed = try grt.std.json.parseFromSlice(Response, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;
            _ = parsed.value.id;
            if (parsed.value.@"error") |rpc_error| {
                const log = grt.std.log.scoped(.gizclaw_client);
                log.err("rpc response error id={s} code={d} message={s}", .{
                    parsed.value.id,
                    rpc_error.code,
                    rpc_error.message,
                });
                return rpcResponseError(rpc_error);
            }
            return try self.dupeRuntime(parsed.value.result orelse return error.MissingRpcResult);
        }

        fn parseRpcServerInfo(self: *Self, data: []const u8) !ServerInfo {
            const Response = struct {
                v: i64,
                id: []const u8,
                result: ?ServerInfo = null,
                @"error": ?models.RPCError = null,
            };
            const parsed = try grt.std.json.parseFromSlice(Response, self.allocator, data, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            _ = parsed.value.v;
            _ = parsed.value.id;
            if (parsed.value.@"error") |rpc_error| {
                const log = grt.std.log.scoped(.gizclaw_client);
                log.err("rpc response error id={s} code={d} message={s}", .{
                    parsed.value.id,
                    rpc_error.code,
                    rpc_error.message,
                });
                return rpcResponseError(rpc_error);
            }
            return try self.dupeServerInfo(parsed.value.result orelse return error.MissingRpcResult);
        }

        fn rpcResponseError(rpc_error: models.RPCError) anyerror {
            if (rpc_error.code == -1) return error.RpcMethodNotFound;
            if (rpc_error.code == -32600) return error.RpcInvalidRequest;
            if (rpc_error.code == -32601) return error.RpcMethodNotFound;
            if (rpc_error.code == -32602) return error.RpcInvalidParams;
            if (rpc_error.code == -32603) return error.RpcInternalError;
            if (rpc_error.code == 404) return error.GearNotFound;
            if (rpc_error.code == 409) return error.GearAlreadyExists;
            if (rpc_error.code == 400) return error.BadRequest;
            return error.RpcError;
        }

        fn dupeDeviceInfo(self: *Self, info: DeviceInfo) !DeviceInfo {
            var out = DeviceInfo{};
            errdefer deinitDeviceInfo(self.allocator, &out);
            out.name = try dupeOptional(self.allocator, info.name);
            out.sn = try dupeOptional(self.allocator, info.sn);
            if (info.hardware) |hardware| {
                out.hardware = HardwareInfo{};
                out.hardware.?.manufacturer = try dupeOptional(self.allocator, hardware.manufacturer);
                out.hardware.?.model = try dupeOptional(self.allocator, hardware.model);
                out.hardware.?.hardware_revision = try dupeOptional(self.allocator, hardware.hardware_revision);
                out.hardware.?.imeis = try self.dupeGearIMEIs(hardware.imeis);
                out.hardware.?.labels = try self.dupeGearLabels(hardware.labels);
            }
            return out;
        }

        fn dupeServerInfo(self: *Self, info: ServerInfo) !ServerInfo {
            return .{
                .public_key = try self.allocator.dupe(u8, info.public_key),
                .server_time = info.server_time,
                .build_commit = try self.allocator.dupe(u8, info.build_commit),
            };
        }

        fn dupeRuntime(self: *Self, runtime: RuntimeStatus) !RuntimeStatus {
            return .{
                .online = runtime.online,
                .last_seen_at = try self.allocator.dupe(u8, runtime.last_seen_at),
                .last_addr = try dupeOptional(self.allocator, runtime.last_addr),
                .rx_bytes = runtime.rx_bytes,
                .tx_bytes = runtime.tx_bytes,
            };
        }

        fn dupeGearIMEIs(self: *Self, value: ?[]const GearIMEI) !?[]const GearIMEI {
            const items = value orelse return null;
            const out = try self.allocator.alloc(GearIMEI, items.len);
            errdefer self.allocator.free(out);
            var filled: usize = 0;
            errdefer {
                for (out[0..filled]) |item| deinitGearIMEI(self.allocator, item);
            }
            for (items, 0..) |item, index| {
                out[index] = .{
                    .tac = try self.allocator.dupe(u8, item.tac),
                    .serial = try self.allocator.dupe(u8, item.serial),
                    .name = try dupeOptional(self.allocator, item.name),
                };
                filled += 1;
            }
            return out;
        }

        fn dupeGearLabels(self: *Self, value: ?[]const GearLabel) !?[]const GearLabel {
            const items = value orelse return null;
            const out = try self.allocator.alloc(GearLabel, items.len);
            errdefer self.allocator.free(out);
            var filled: usize = 0;
            errdefer {
                for (out[0..filled]) |item| deinitGearLabel(self.allocator, item);
            }
            for (items, 0..) |item, index| {
                out[index] = .{
                    .key = try self.allocator.dupe(u8, item.key),
                    .value = try self.allocator.dupe(u8, item.value),
                };
                filled += 1;
            }
            return out;
        }

        fn dupeOptional(allocator: Allocator, value: ?[]const u8) !?[]u8 {
            if (value) |text| return try allocator.dupe(u8, text);
            return null;
        }
    };
}
