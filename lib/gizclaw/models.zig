const glib = @import("glib");
const openapi = @import("openapi");
const codegen = @import("codegen");
const options = @import("gizclaw_models_options");

fn files() openapi.Files {
    return .{
        .items = &.{
            apiFileAs("client_service_zig.json", "client_service.json"),
            apiFileAs("rpc/zig.json", "rpc.json"),
            apiFile("rpc/all.json"),
            apiFile("rpc/client.json"),
            apiFile("rpc/zig_server.json"),
            apiFile("type/agent_selection.json"),
            apiFile("type/device_info.json"),
            apiFile("type/error_payload.json"),
            apiFile("type/error_response.json"),
            apiFile("type/firmware.json"),
            apiFile("type/firmware_artifact.json"),
            apiFile("type/firmware_artifact_kind.json"),
            apiFile("type/firmware_slot.json"),
            apiFile("type/firmware_slots.json"),
            apiFile("type/hardware_info.json"),
            apiFile("type/peer_imei.json"),
            apiFile("type/peer_label.json"),
            apiFile("type/peer_run_agent.json"),
            apiFile("type/peer_run_status.json"),
            apiFile("type/peer_run_workspace.json"),
            apiFile("type/peer_status.json"),
            apiFile("type/peer_stream_event.json"),
            apiFile("type/refresh_info.json"),
            apiFile("type/refresh_identifiers.json"),
            apiFile("type/runtime.json"),
            apiFile("type/server_info.json"),
            apiFile("type/voice_provider_kind.json"),
            apiFile("type/voice_source.json"),
        },
    };
}

fn apiFile(comptime path: []const u8) openapi.Files.Entry {
    return .{
        .name = "./" ++ path,
        .spec = openapi.json.parse(@field(options, apiOptionName(path))),
    };
}

fn apiFileAs(comptime path: []const u8, comptime name: []const u8) openapi.Files.Entry {
    return .{
        .name = "./" ++ name,
        .spec = openapi.json.parse(@field(options, apiOptionName(path))),
    };
}

fn apiOptionName(comptime path: []const u8) []const u8 {
    comptime var buf: [path.len + 5]u8 = undefined;
    inline for (path, 0..) |ch, i| {
        buf[i] = switch (ch) {
            '/', '.', '-' => '_',
            else => ch,
        };
    }
    buf[path.len + 0] = '_';
    buf[path.len + 1] = 'j';
    buf[path.len + 2] = 's';
    buf[path.len + 3] = 'o';
    buf[path.len + 4] = 'n';
    const final = buf;
    return &final;
}

const Models = blk: {
    @setEvalBranchQuota(50_000_000);
    break :blk codegen.models.make(glib.std, files());
};

pub const toJson = Models.toJson;
pub const fromJson = Models.fromJson;

pub const AgentSelection = Models.AgentSelection;
pub const ClientGetIdentifiersRequest = Models.ClientGetIdentifiersRequest;
pub const ClientGetIdentifiersResponse = Models.ClientGetIdentifiersResponse;
pub const ClientGetInfoRequest = Models.ClientGetInfoRequest;
pub const ClientGetInfoResponse = Models.ClientGetInfoResponse;
pub const ClientVoiceListResponse = Models.ClientVoiceListResponse;
pub const ContactCreateRequest = Models.ContactCreateRequest;
pub const ContactCreateResponse = Models.ContactCreateResponse;
pub const ContactDeleteRequest = Models.ContactDeleteRequest;
pub const ContactDeleteResponse = Models.ContactDeleteResponse;
pub const ContactGetRequest = Models.ContactGetRequest;
pub const ContactGetResponse = Models.ContactGetResponse;
pub const ContactListRequest = Models.ContactListRequest;
pub const ContactListResponse = Models.ContactListResponse;
pub const ContactObject = Models.ContactObject;
pub const ContactPutRequest = Models.ContactPutRequest;
pub const ContactPutResponse = Models.ContactPutResponse;
pub const CredentialGetRequest = Models.CredentialGetRequest;
pub const CredentialGetResponse = Models.CredentialGetResponse;
pub const CredentialListRequest = Models.CredentialListRequest;
pub const CredentialListResponse = Models.CredentialListResponse;
pub const CredentialObject = Models.CredentialObject;
pub const DeviceInfo = Models.DeviceInfo;
pub const DoubaoRealtimeOutputObject = Models.DoubaoRealtimeOutputObject;
pub const DoubaoRealtimeRuntimeObject = Models.DoubaoRealtimeRuntimeObject;
pub const DoubaoRealtimeSessionObject = Models.DoubaoRealtimeSessionObject;
pub const DoubaoRealtimeWorkflowObject = Models.DoubaoRealtimeWorkflowObject;
pub const ErrorPayload = Models.ErrorPayload;
pub const ErrorResponse = Models.ErrorResponse;
pub const Firmware = Models.Firmware;
pub const FirmwareArtifact = Models.FirmwareArtifact;
pub const FirmwareArtifactKind = Models.FirmwareArtifactKind;
pub const FirmwareBinMetadata = Models.FirmwareBinMetadata;
pub const FirmwareChannelName = Models.FirmwareChannelName;
pub const FirmwareDownloadRequest = Models.FirmwareDownloadRequest;
pub const FirmwareDownloadResponse = Models.FirmwareDownloadResponse;
pub const FirmwareGetRequest = Models.FirmwareGetRequest;
pub const FirmwareGetResponse = Models.FirmwareGetResponse;
pub const FirmwareListRequest = Models.FirmwareListRequest;
pub const FirmwareListResponse = Models.FirmwareListResponse;
pub const FirmwareSlot = Models.FirmwareSlot;
pub const FirmwareSlots = Models.FirmwareSlots;
pub const FriendAddRequest = Models.FriendAddRequest;
pub const FriendAddResponse = Models.FriendAddResponse;
pub const FriendDeleteRequest = Models.FriendDeleteRequest;
pub const FriendDeleteResponse = Models.FriendDeleteResponse;
pub const FriendGroupCreateRequest = Models.FriendGroupCreateRequest;
pub const FriendGroupCreateResponse = Models.FriendGroupCreateResponse;
pub const FriendGroupDeleteRequest = Models.FriendGroupDeleteRequest;
pub const FriendGroupDeleteResponse = Models.FriendGroupDeleteResponse;
pub const FriendGroupGetRequest = Models.FriendGroupGetRequest;
pub const FriendGroupGetResponse = Models.FriendGroupGetResponse;
pub const FriendGroupInviteTokenClearRequest = Models.FriendGroupInviteTokenClearRequest;
pub const FriendGroupInviteTokenClearResponse = Models.FriendGroupInviteTokenClearResponse;
pub const FriendGroupInviteTokenCreateRequest = Models.FriendGroupInviteTokenCreateRequest;
pub const FriendGroupInviteTokenCreateResponse = Models.FriendGroupInviteTokenCreateResponse;
pub const FriendGroupInviteTokenGetRequest = Models.FriendGroupInviteTokenGetRequest;
pub const FriendGroupInviteTokenGetResponse = Models.FriendGroupInviteTokenGetResponse;
pub const FriendGroupJoinRequest = Models.FriendGroupJoinRequest;
pub const FriendGroupJoinResponse = Models.FriendGroupJoinResponse;
pub const FriendGroupListRequest = Models.FriendGroupListRequest;
pub const FriendGroupListResponse = Models.FriendGroupListResponse;
pub const FriendGroupMemberAddRequest = Models.FriendGroupMemberAddRequest;
pub const FriendGroupMemberAddResponse = Models.FriendGroupMemberAddResponse;
pub const FriendGroupMemberDeleteRequest = Models.FriendGroupMemberDeleteRequest;
pub const FriendGroupMemberDeleteResponse = Models.FriendGroupMemberDeleteResponse;
pub const FriendGroupMemberListRequest = Models.FriendGroupMemberListRequest;
pub const FriendGroupMemberListResponse = Models.FriendGroupMemberListResponse;
pub const FriendGroupMemberMutableRole = Models.FriendGroupMemberMutableRole;
pub const FriendGroupMemberObject = Models.FriendGroupMemberObject;
pub const FriendGroupMemberPutRequest = Models.FriendGroupMemberPutRequest;
pub const FriendGroupMemberPutResponse = Models.FriendGroupMemberPutResponse;
pub const FriendGroupMemberRole = Models.FriendGroupMemberRole;
pub const FriendGroupMessageGetRequest = Models.FriendGroupMessageGetRequest;
pub const FriendGroupMessageGetResponse = Models.FriendGroupMessageGetResponse;
pub const FriendGroupMessageListRequest = Models.FriendGroupMessageListRequest;
pub const FriendGroupMessageListResponse = Models.FriendGroupMessageListResponse;
pub const FriendGroupMessageObject = Models.FriendGroupMessageObject;
pub const FriendGroupMessageSendRequest = Models.FriendGroupMessageSendRequest;
pub const FriendGroupMessageSendResponse = Models.FriendGroupMessageSendResponse;
pub const FriendGroupObject = Models.FriendGroupObject;
pub const FriendGroupPutRequest = Models.FriendGroupPutRequest;
pub const FriendGroupPutResponse = Models.FriendGroupPutResponse;
pub const FriendListRequest = Models.FriendListRequest;
pub const FriendListResponse = Models.FriendListResponse;
pub const FriendObject = Models.FriendObject;
pub const FriendInviteTokenClearRequest = Models.FriendInviteTokenClearRequest;
pub const FriendInviteTokenClearResponse = Models.FriendInviteTokenClearResponse;
pub const FriendInviteTokenCreateRequest = Models.FriendInviteTokenCreateRequest;
pub const FriendInviteTokenCreateResponse = Models.FriendInviteTokenCreateResponse;
pub const FriendInviteTokenGetRequest = Models.FriendInviteTokenGetRequest;
pub const FriendInviteTokenGetResponse = Models.FriendInviteTokenGetResponse;
pub const HardwareInfo = Models.HardwareInfo;
pub const ModelGetRequest = Models.ModelGetRequest;
pub const ModelGetResponse = Models.ModelGetResponse;
pub const ModelListRequest = Models.ModelListRequest;
pub const ModelListResponse = Models.ModelListResponse;
pub const ModelObject = Models.ModelObject;
pub const PeerIMEI = Models.PeerIMEI;
pub const PeerLabel = Models.PeerLabel;
pub const PeerRunAgent = Models.PeerRunAgent;
pub const PeerRunHistoryEntry = Models.PeerRunHistoryEntry;
pub const PeerRunHistoryListRequest = Models.PeerRunHistoryListRequest;
pub const PeerRunHistoryListResponse = Models.PeerRunHistoryListResponse;
pub const PeerRunHistoryPlayRequest = Models.PeerRunHistoryPlayRequest;
pub const PeerRunHistoryPlayResponse = Models.PeerRunHistoryPlayResponse;
pub const PeerRunMemoryStatsRequest = Models.PeerRunMemoryStatsRequest;
pub const PeerRunMemoryStatsResponse = Models.PeerRunMemoryStatsResponse;
pub const PeerRunRecallHit = Models.PeerRunRecallHit;
pub const PeerRunRecallRequest = Models.PeerRunRecallRequest;
pub const PeerRunRecallResponse = Models.PeerRunRecallResponse;
pub const PeerRunStatus = Models.PeerRunStatus;
pub const PeerRunStatusState = Models.PeerRunStatusState;
pub const PeerRunWorkspaceState = Models.PeerRunWorkspaceState;
pub const PeerStatus = Models.PeerStatus;
pub const PeerStreamEvent = Models.PeerStreamEvent;
pub const PeerStreamEventType = Models.PeerStreamEventType;
pub const PeerStreamKind = Models.PeerStreamKind;
pub const PingRequest = Models.PingRequest;
pub const PingResponse = Models.PingResponse;
pub const PlayVoiceStreamEvent = Models.PlayVoiceStreamEvent;
pub const RPCError = Models.RPCError;
pub const RPCErrorCode = Models.RPCErrorCode;
pub const RPCMethod = Models.RPCMethod;
pub const RPCRequest = Models.RPCRequest;
pub const RPCResponse = Models.RPCResponse;
pub const RPCVersion = Models.RPCVersion;
pub const RefreshIdentifiers = Models.RefreshIdentifiers;
pub const RefreshInfo = Models.RefreshInfo;
pub const Runtime = Models.Runtime;
pub const ServerGetInfoRequest = Models.ServerGetInfoRequest;
pub const ServerGetInfoResponse = Models.ServerGetInfoResponse;
pub const ServerGetRunAgentRequest = Models.ServerGetRunAgentRequest;
pub const ServerGetRunAgentResponse = Models.ServerGetRunAgentResponse;
pub const ServerGetRunStatusRequest = Models.ServerGetRunStatusRequest;
pub const ServerGetRunStatusResponse = Models.ServerGetRunStatusResponse;
pub const ServerGetRunWorkspaceMemoryStatsRequest = Models.ServerGetRunWorkspaceMemoryStatsRequest;
pub const ServerGetRunWorkspaceMemoryStatsResponse = Models.ServerGetRunWorkspaceMemoryStatsResponse;
pub const ServerGetRunWorkspaceRequest = Models.ServerGetRunWorkspaceRequest;
pub const ServerGetRunWorkspaceResponse = Models.ServerGetRunWorkspaceResponse;
pub const ServerGetRuntimeRequest = Models.ServerGetRuntimeRequest;
pub const ServerGetRuntimeResponse = Models.ServerGetRuntimeResponse;
pub const ServerGetStatusRequest = Models.ServerGetStatusRequest;
pub const ServerGetStatusResponse = Models.ServerGetStatusResponse;
pub const ServerInfo = Models.ServerInfo;
pub const ServerListRunWorkspaceHistoryRequest = Models.ServerListRunWorkspaceHistoryRequest;
pub const ServerListRunWorkspaceHistoryResponse = Models.ServerListRunWorkspaceHistoryResponse;
pub const ServerPlayRunWorkspaceHistoryRequest = Models.ServerPlayRunWorkspaceHistoryRequest;
pub const ServerPlayRunWorkspaceHistoryResponse = Models.ServerPlayRunWorkspaceHistoryResponse;
pub const ServerPutInfoRequest = Models.ServerPutInfoRequest;
pub const ServerPutInfoResponse = Models.ServerPutInfoResponse;
pub const ServerPutStatusRequest = Models.ServerPutStatusRequest;
pub const ServerPutStatusResponse = Models.ServerPutStatusResponse;
pub const ServerReloadRunRequest = Models.ServerReloadRunRequest;
pub const ServerReloadRunResponse = Models.ServerReloadRunResponse;
pub const ServerReloadRunWorkspaceRequest = Models.ServerReloadRunWorkspaceRequest;
pub const ServerReloadRunWorkspaceResponse = Models.ServerReloadRunWorkspaceResponse;
pub const ServerRunSayRequest = Models.ServerRunSayRequest;
pub const ServerRunSayResponse = Models.ServerRunSayResponse;
pub const ServerRunWorkspaceRecallRequest = Models.ServerRunWorkspaceRecallRequest;
pub const ServerRunWorkspaceRecallResponse = Models.ServerRunWorkspaceRecallResponse;
pub const ServerSetRunAgentRequest = Models.ServerSetRunAgentRequest;
pub const ServerSetRunAgentResponse = Models.ServerSetRunAgentResponse;
pub const ServerSetRunWorkspaceRequest = Models.ServerSetRunWorkspaceRequest;
pub const ServerSetRunWorkspaceResponse = Models.ServerSetRunWorkspaceResponse;
pub const ServerStopRunRequest = Models.ServerStopRunRequest;
pub const ServerStopRunResponse = Models.ServerStopRunResponse;
pub const SpeedTestRequest = Models.SpeedTestRequest;
pub const SpeedTestResponse = Models.SpeedTestResponse;
pub const VoiceObject = Models.VoiceObject;
pub const VoiceProviderKind = Models.VoiceProviderKind;
pub const VoiceSource = Models.VoiceSource;
pub const WorkflowCreateRequest = Models.WorkflowCreateRequest;
pub const WorkflowCreateResponse = Models.WorkflowCreateResponse;
pub const WorkflowDeleteRequest = Models.WorkflowDeleteRequest;
pub const WorkflowDeleteResponse = Models.WorkflowDeleteResponse;
pub const WorkflowGetRequest = Models.WorkflowGetRequest;
pub const WorkflowGetResponse = Models.WorkflowGetResponse;
pub const WorkflowListRequest = Models.WorkflowListRequest;
pub const WorkflowListResponse = Models.WorkflowListResponse;
pub const WorkflowMetadataObject = Models.WorkflowMetadataObject;
pub const WorkflowObject = Models.WorkflowObject;
pub const WorkflowPutRequest = Models.WorkflowPutRequest;
pub const WorkflowPutResponse = Models.WorkflowPutResponse;
pub const WorkflowSpecObject = Models.WorkflowSpecObject;
pub const WorkspaceCreateRequest = Models.WorkspaceCreateRequest;
pub const WorkspaceCreateResponse = Models.WorkspaceCreateResponse;
pub const WorkspaceDeleteRequest = Models.WorkspaceDeleteRequest;
pub const WorkspaceDeleteResponse = Models.WorkspaceDeleteResponse;
pub const WorkspaceGetRequest = Models.WorkspaceGetRequest;
pub const WorkspaceGetResponse = Models.WorkspaceGetResponse;
pub const WorkspaceHistoryAudioGetRequest = Models.WorkspaceHistoryAudioGetRequest;
pub const WorkspaceHistoryAudioGetResponse = Models.WorkspaceHistoryAudioGetResponse;
pub const WorkspaceHistoryGetRequest = Models.WorkspaceHistoryGetRequest;
pub const WorkspaceHistoryGetResponse = Models.WorkspaceHistoryGetResponse;
pub const WorkspaceHistoryListRequest = Models.WorkspaceHistoryListRequest;
pub const WorkspaceHistoryListResponse = Models.WorkspaceHistoryListResponse;
pub const WorkspaceListRequest = Models.WorkspaceListRequest;
pub const WorkspaceListResponse = Models.WorkspaceListResponse;
pub const WorkspaceMusicObject = Models.WorkspaceMusicObject;
pub const WorkspaceObject = Models.WorkspaceObject;
pub const WorkspaceParametersObject = Models.WorkspaceParametersObject;
pub const WorkspacePutRequest = Models.WorkspacePutRequest;
pub const WorkspacePutResponse = Models.WorkspacePutResponse;
pub const WorkspaceSearchObject = Models.WorkspaceSearchObject;
pub const WorkspaceVoiceObject = Models.WorkspaceVoiceObject;

pub const Credential = Models.CredentialObject;
pub const Model = Models.ModelObject;
pub const Voice = Models.VoiceObject;
pub const Workspace = Models.WorkspaceObject;
pub const GearIMEI = Models.PeerIMEI;
pub const GearLabel = Models.PeerLabel;

pub const ModelCreateRequest = ModelObject;
pub const ModelCreateResponse = ModelObject;
pub const ModelPutRequest = struct {
    id: []const u8,
    body: ModelObject,
};
pub const ModelPutResponse = ModelObject;
pub const ModelDeleteRequest = struct {
    id: []const u8,
};
pub const ModelDeleteResponse = ModelObject;

pub const CredentialCreateRequest = CredentialObject;
pub const CredentialCreateResponse = CredentialObject;
pub const CredentialPutRequest = struct {
    name: []const u8,
    body: CredentialObject,
};
pub const CredentialPutResponse = CredentialObject;
pub const CredentialDeleteRequest = struct {
    name: []const u8,
};
pub const CredentialDeleteResponse = CredentialObject;

pub const RpcMethods = struct {
    pub const all_ping = rpcMethod("all.ping");
    pub const all_speed_test_run = rpcMethod("all.speed_test.run");
    pub const client_info_get = rpcMethod("client.info.get");
    pub const client_identifiers_get = rpcMethod("client.identifiers.get");
    pub const device_info_get = "device.info.get";
    pub const device_identifiers_get = "device.identifiers.get";
    pub const peer_info_get = "peer.info.get";
    pub const peer_info_put = "peer.info.put";
    pub const peer_runtime_get = "peer.runtime.get";
    pub const server_info_get = rpcMethod("server.info.get");
    pub const server_info_put = rpcMethod("server.info.put");
    pub const server_runtime_get = rpcMethod("server.runtime.get");
    pub const server_status_get = rpcMethod("server.status.get");
    pub const server_status_put = rpcMethod("server.status.put");
    pub const server_run_agent_get = rpcMethod("server.run.agent.get");
    pub const server_run_agent_set = rpcMethod("server.run.agent.set");
    pub const server_run_workspace_get = rpcMethod("server.run.workspace.get");
    pub const server_run_workspace_set = rpcMethod("server.run.workspace.set");
    pub const server_run_workspace_reload = rpcMethod("server.run.workspace.reload");
    pub const server_run_workspace_history = rpcMethod("server.run.workspace.history");
    pub const server_run_workspace_history_play = rpcMethod("server.run.workspace.history.play");
    pub const server_run_workspace_memory_stats = rpcMethod("server.run.workspace.memory.stats");
    pub const server_run_workspace_recall = rpcMethod("server.run.workspace.recall");
    pub const server_run_reload = rpcMethod("server.run.reload");
    pub const server_run_status = rpcMethod("server.run.status");
    pub const server_run_stop = rpcMethod("server.run.stop");
    pub const server_run_say = rpcMethod("server.run.say");
    pub const server_firmware_list = rpcMethod("server.firmware.list");
    pub const server_firmware_get = rpcMethod("server.firmware.get");
    pub const server_firmware_download = rpcMethod("server.firmware.download");
    pub const server_workspace_list = rpcMethod("server.workspace.list");
    pub const server_workspace_get = rpcMethod("server.workspace.get");
    pub const server_workspace_create = rpcMethod("server.workspace.create");
    pub const server_workspace_put = rpcMethod("server.workspace.put");
    pub const server_workspace_delete = rpcMethod("server.workspace.delete");
    pub const server_workspace_history_list = rpcMethod("server.workspace.history.list");
    pub const server_workspace_history_get = rpcMethod("server.workspace.history.get");
    pub const server_workspace_history_audio_get = rpcMethod("server.workspace.history.audio.get");
    pub const server_workflow_list = rpcMethod("server.workflow.list");
    pub const server_workflow_get = rpcMethod("server.workflow.get");
    pub const server_workflow_create = rpcMethod("server.workflow.create");
    pub const server_workflow_put = rpcMethod("server.workflow.put");
    pub const server_workflow_delete = rpcMethod("server.workflow.delete");
    pub const server_model_list = rpcMethod("server.model.list");
    pub const server_model_get = rpcMethod("server.model.get");
    pub const server_model_create = rpcMethod("server.model.create");
    pub const server_model_put = rpcMethod("server.model.put");
    pub const server_model_delete = rpcMethod("server.model.delete");
    pub const server_credential_list = rpcMethod("server.credential.list");
    pub const server_credential_get = rpcMethod("server.credential.get");
    pub const server_credential_create = rpcMethod("server.credential.create");
    pub const server_credential_put = rpcMethod("server.credential.put");
    pub const server_credential_delete = rpcMethod("server.credential.delete");
    pub const server_contact_list = rpcMethod("server.contact.list");
    pub const server_contact_get = rpcMethod("server.contact.get");
    pub const server_contact_create = rpcMethod("server.contact.create");
    pub const server_contact_put = rpcMethod("server.contact.put");
    pub const server_contact_delete = rpcMethod("server.contact.delete");
    pub const server_friend_invite_token_get = rpcMethod("server.friend.invite_token.get");
    pub const server_friend_invite_token_create = rpcMethod("server.friend.invite_token.create");
    pub const server_friend_invite_token_clear = rpcMethod("server.friend.invite_token.clear");
    pub const server_friend_add = rpcMethod("server.friend.add");
    pub const server_friend_list = rpcMethod("server.friend.list");
    pub const server_friend_delete = rpcMethod("server.friend.delete");
    pub const server_friend_group_list = rpcMethod("server.friend_group.list");
    pub const server_friend_group_get = rpcMethod("server.friend_group.get");
    pub const server_friend_group_create = rpcMethod("server.friend_group.create");
    pub const server_friend_group_put = rpcMethod("server.friend_group.put");
    pub const server_friend_group_delete = rpcMethod("server.friend_group.delete");
    pub const server_friend_group_invite_token_get = rpcMethod("server.friend_group.invite_token.get");
    pub const server_friend_group_invite_token_create = rpcMethod("server.friend_group.invite_token.create");
    pub const server_friend_group_invite_token_clear = rpcMethod("server.friend_group.invite_token.clear");
    pub const server_friend_group_join = rpcMethod("server.friend_group.join");
    pub const server_friend_group_members_list = rpcMethod("server.friend_group.members.list");
    pub const server_friend_group_members_add = rpcMethod("server.friend_group.members.add");
    pub const server_friend_group_members_put = rpcMethod("server.friend_group.members.put");
    pub const server_friend_group_members_delete = rpcMethod("server.friend_group.members.delete");
    pub const server_friend_group_messages_list = rpcMethod("server.friend_group.messages.list");
    pub const server_friend_group_messages_get = rpcMethod("server.friend_group.messages.get");
    pub const server_friend_group_messages_send = rpcMethod("server.friend_group.messages.send");
};

fn rpcMethod(comptime value: []const u8) Models.RPCMethod {
    const schema_or_ref = files().findSchema("./rpc.json", "RPCMethod") orelse
        @compileError("RPCMethod schema not found in ./rpc.json");
    const schema = switch (schema_or_ref) {
        .schema => |schema| schema,
        .reference => @compileError("RPCMethod schema must not be a reference"),
    };

    inline for (schema.enum_values) |enum_value| {
        switch (enum_value) {
            .string => |string| if (glib.std.mem.eql(u8, string, value)) return string,
            else => {},
        }
    }

    @compileError(glib.std.fmt.comptimePrint("RPC method '{s}' is not declared by api/rpc/zig.json", .{value}));
}
