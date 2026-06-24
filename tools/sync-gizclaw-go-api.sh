#!/usr/bin/env bash
set -euo pipefail

repo="${1:-${GIZCLAW_GO_DIR:-../gizclaw-go}}"
src="${repo%/}/api"

if [[ ! -d "$src" ]]; then
  echo "missing gizclaw-go api directory: $src" >&2
  exit 1
fi

mkdir -p api/rpc api/type

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
if [[ -f api/rpc/zig.json ]]; then
  cp api/rpc/zig.json "$tmp_dir/zig.json"
fi
if [[ -f api/rpc/zig_server.json ]]; then
  cp api/rpc/zig_server.json "$tmp_dir/zig_server.json"
fi
rm -rf api/rpc api/type
rm -f api/admin_service.json api/openai_service.json api/server_public.json api/types.json
rm -rf api/resource
mkdir -p api/rpc api/type
if [[ -f "$tmp_dir/zig.json" ]]; then
  cp "$tmp_dir/zig.json" api/rpc/zig.json
fi
if [[ -f "$tmp_dir/zig_server.json" ]]; then
  cp "$tmp_dir/zig_server.json" api/rpc/zig_server.json
fi

copy_file() {
  local from="$1"
  local to="$2"
  if [[ -f "$from" ]]; then
    cp "$from" "$to"
  fi
}

copy_glob() {
  local pattern="$1"
  local to_dir="$2"
  shopt -s nullglob
  local files=( $pattern )
  shopt -u nullglob
  if (( ${#files[@]} == 0 )); then
    echo "missing files for pattern: $pattern" >&2
    exit 1
  fi
  cp "${files[@]}" "$to_dir/"
}

copy_type() {
  local name="$1"
  copy_file "$src/type/$name.json" "api/type/$name.json"
}

copy_file "$src/client_service.json" api/client_service.json
copy_file "$src/rpc.json" api/rpc.json

copy_glob "$src/rpc/*.json" api/rpc
copy_type agent_selection
copy_type device_info
copy_type error_payload
copy_type error_response
copy_type firmware
copy_type firmware_artifact
copy_type firmware_artifact_kind
copy_type firmware_slot
copy_type firmware_slots
copy_type hardware_info
copy_type peer_imei
copy_type peer_label
copy_type peer_run_agent
copy_type peer_run_status
copy_type peer_run_workspace
copy_type peer_status
copy_type peer_stream_event
copy_type refresh_info
copy_type refresh_identifiers
copy_type runtime
copy_type server_info
copy_type voice_provider_kind
copy_type voice_source

if command -v jq >/dev/null 2>&1 && [[ -f api/rpc/server.json ]]; then
  jq '
    .components.schemas |= with_entries(select(.key | test("^(ClientVoiceListResponse|PlayVoiceStreamEvent)$")))
    | .components.schemas.VoiceObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "id":{"type":"string"},
          "source":{"type":"string"},
          "provider":{"type":"object","additionalProperties":true},
          "name":{"type":"string"},
          "description":{"type":"string"},
          "provider_data":{"type":"object","additionalProperties":true},
          "created_at":{"type":"string"},
          "updated_at":{"type":"string"}
        },
        "required":["id"]
      }
    | .components.schemas.ClientVoiceListResponse.properties.data.items = {"$ref":"#/components/schemas/VoiceObject"}
    | .components.schemas.ClientVoiceListResponse.properties.items.items = {"$ref":"#/components/schemas/VoiceObject"}
    | if .components.schemas.PlayVoiceStreamEvent then
        .components.schemas.PlayVoiceStreamEvent.properties.voice = {"$ref":"#/components/schemas/VoiceObject"}
      else . end
  ' api/client_service.json > api/client_service_zig.json

  jq '
    .components.schemas |= with_entries(select(.key | test("^(Server|Firmware|Workspace|Workflow|Model(List|Get)|Credential(List|Get)|Contact|Friend)")))
    | .components.schemas.WorkspaceObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"name":{"type":"string"}},
        "required":["name"]
      }
    | .components.schemas.WorkflowMetadataObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"name":{"type":"string"},"description":{"type":"string"}},
        "required":["name"]
      }
    | .components.schemas.DoubaoRealtimeSessionObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "auth_mode":{"type":"string"},
          "bot_name":{"type":"string"},
          "model":{"type":"string"},
          "resource_id":{"type":"string"},
          "system_role":{"type":"string"},
          "vad_window_ms":{"type":"integer"}
        }
      }
    | .components.schemas.DoubaoRealtimeOutputObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"speaker":{"type":"string"}}
      }
    | .components.schemas.DoubaoRealtimeRuntimeObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "session":{"$ref":"#/components/schemas/DoubaoRealtimeSessionObject"},
          "output":{"$ref":"#/components/schemas/DoubaoRealtimeOutputObject"}
        }
      }
    | .components.schemas.DoubaoRealtimeWorkflowObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "realtime_model":{"type":"string"},
          "model":{"type":"string"},
          "realtime":{"$ref":"#/components/schemas/DoubaoRealtimeRuntimeObject"},
          "realtime_config":{"$ref":"#/components/schemas/DoubaoRealtimeRuntimeObject"}
        }
      }
    | .components.schemas.WorkspaceVoiceObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"realtime_speaker_id":{"type":"string"},"speaker_id":{"type":"string"}}
      }
    | .components.schemas.WorkspaceSearchObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "enabled":{"type":"boolean"},
          "type":{"type":"string"},
          "result_count":{"type":"integer"},
          "no_result_message":{"type":"string"}
        }
      }
    | .components.schemas.WorkspaceMusicObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"enabled":{"type":"boolean"}}
      }
    | .components.schemas.WorkflowSpecObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "driver":{"type":"string"},
          "doubao_realtime":{"$ref":"#/components/schemas/DoubaoRealtimeWorkflowObject"},
          "flowcraft":{"type":"object","additionalProperties":true},
          "ast_translate":{"type":"object","additionalProperties":true}
        },
        "required":["driver"]
      }
    | .components.schemas.WorkflowObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"metadata":{"$ref":"#/components/schemas/WorkflowMetadataObject"}},
        "required":["metadata"]
      }
    | .components.schemas.WorkspaceParametersObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "agent_type":{"type":"string"},
          "realtime_model":{"type":"string"},
          "input":{"type":"string"},
          "voice":{"$ref":"#/components/schemas/WorkspaceVoiceObject"},
          "search":{"$ref":"#/components/schemas/WorkspaceSearchObject"},
          "music":{"$ref":"#/components/schemas/WorkspaceMusicObject"},
          "e2e":{"type":"boolean"}
        },
        "required":["agent_type"]
      }
    | .components.schemas.ModelObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "id":{"type":"string"},
          "kind":{"type":"string"},
          "source":{"type":"string"},
          "provider":{"type":"object","additionalProperties":true},
          "name":{"type":"string"},
          "description":{"type":"string"},
          "capabilities":{"type":"object","additionalProperties":true},
          "provider_data":{"type":"object","additionalProperties":true},
          "created_at":{"type":"string"},
          "updated_at":{"type":"string"}
        },
        "required":["id"]
      }
    | .components.schemas.CredentialObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "name":{"type":"string"},
          "provider":{"type":"string"},
          "body":{"type":"object","additionalProperties":true},
          "description":{"type":"string"},
          "created_at":{"type":"string"},
          "updated_at":{"type":"string"}
        },
        "required":["name","provider","body"]
      }
    | .components.schemas.ContactObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"id":{"type":"string"},"display_name":{"type":"string"},"phone_number":{"type":"string"}}
      }
    | .components.schemas.FriendRequestObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"id":{"type":"string"},"peer_id":{"type":"string"},"to_peer_id":{"type":"string"},"message":{"type":"string"}}
      }
    | .components.schemas.FriendObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"id":{"type":"string"},"peer_id":{"type":"string"}}
      }
    | .components.schemas.FriendGroupObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"}}
      }
    | .components.schemas.FriendGroupMemberObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{"id":{"type":"string"},"peer_id":{"type":"string"},"role":{"type":"string"}}
      }
    | .components.schemas.FriendGroupMessageObject = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "id":{"type":"string"},
          "friend_group_id":{"type":"string"},
          "audio_path":{"type":"string"},
          "audio_content_type":{"type":"string"},
          "audio_size_bytes":{"type":"integer"},
          "ttl_seconds":{"type":"integer"},
          "expires_at":{"type":"string"},
          "created_at":{"type":"string"}
        }
      }
    | .components.schemas.WorkspaceCreateRequest = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "name":{"type":"string"},
          "workflow_name":{"type":"string"},
          "parameters":{"$ref":"#/components/schemas/WorkspaceParametersObject"}
        },
        "required":["name","workflow_name","parameters"]
      }
    | .components.schemas.WorkspaceCreateResponse = {"$ref":"#/components/schemas/WorkspaceObject"}
    | .components.schemas.WorkspaceGetResponse = {"$ref":"#/components/schemas/WorkspaceObject"}
    | .components.schemas.WorkspacePutRequest.properties.body = {"$ref":"#/components/schemas/WorkspaceCreateRequest"}
    | .components.schemas.WorkspacePutResponse = {"$ref":"#/components/schemas/WorkspaceObject"}
    | .components.schemas.WorkspaceDeleteResponse = {"$ref":"#/components/schemas/WorkspaceObject"}
    | .components.schemas.WorkspaceListResponse.properties.items.items = {"$ref":"#/components/schemas/WorkspaceObject"}
    | .components.schemas.WorkflowCreateRequest = {
        "type":"object",
        "additionalProperties":true,
        "properties":{
          "metadata":{"$ref":"#/components/schemas/WorkflowMetadataObject"},
          "spec":{"$ref":"#/components/schemas/WorkflowSpecObject"}
        },
        "required":["metadata","spec"]
      }
    | .components.schemas.WorkflowCreateResponse = {"$ref":"#/components/schemas/WorkflowObject"}
    | .components.schemas.WorkflowGetResponse = {"$ref":"#/components/schemas/WorkflowObject"}
    | .components.schemas.WorkflowPutRequest.properties.body = {"$ref":"#/components/schemas/WorkflowCreateRequest"}
    | .components.schemas.WorkflowPutResponse = {"$ref":"#/components/schemas/WorkflowObject"}
    | .components.schemas.WorkflowDeleteResponse = {"$ref":"#/components/schemas/WorkflowObject"}
    | .components.schemas.WorkflowListResponse.properties.items.items = {"$ref":"#/components/schemas/WorkflowObject"}
    | .components.schemas.ModelListResponse.properties.items.items = {"$ref":"#/components/schemas/ModelObject"}
    | .components.schemas.ModelGetResponse = {"$ref":"#/components/schemas/ModelObject"}
    | .components.schemas.CredentialListResponse.properties.items.items = {"$ref":"#/components/schemas/CredentialObject"}
    | .components.schemas.CredentialGetResponse = {"$ref":"#/components/schemas/CredentialObject"}
    | .components.schemas.ContactCreateRequest = {"type":"object","additionalProperties":true,"properties":{"display_name":{"type":"string"},"phone_number":{"type":"string"}}}
    | .components.schemas.ContactPutRequest = {"type":"object","additionalProperties":true,"properties":{"id":{"type":"string"},"display_name":{"type":"string"},"phone_number":{"type":"string"}}}
    | .components.schemas.ContactGetRequest = {"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"]}
    | .components.schemas.ContactDeleteRequest = {"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"]}
    | .components.schemas.ContactCreateResponse = {"$ref":"#/components/schemas/ContactObject"}
    | .components.schemas.ContactPutResponse = {"$ref":"#/components/schemas/ContactObject"}
    | .components.schemas.ContactGetResponse = {"$ref":"#/components/schemas/ContactObject"}
    | .components.schemas.ContactDeleteResponse = {"$ref":"#/components/schemas/ContactObject"}
    | .components.schemas.ContactListResponse = {"type":"object","additionalProperties":false,"properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/ContactObject"}},"has_next":{"type":"boolean"},"next_cursor":{"type":"string"}},"required":["items","has_next"]}
    | .components.schemas.FriendRequestCreateRequest = {"type":"object","additionalProperties":true,"properties":{"to_peer_id":{"type":"string"},"code":{"type":"string"},"message":{"type":"string"}}}
    | .components.schemas.FriendRequestAcceptRequest = {"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"]}
    | .components.schemas.FriendRequestRejectRequest = {"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"]}
    | .components.schemas.FriendRequestCreateResponse = {"$ref":"#/components/schemas/FriendRequestObject"}
    | .components.schemas.FriendRequestAcceptResponse = {"$ref":"#/components/schemas/FriendRequestObject"}
    | .components.schemas.FriendRequestRejectResponse = {"$ref":"#/components/schemas/FriendRequestObject"}
    | .components.schemas.FriendRequestListResponse = {"type":"object","additionalProperties":false,"properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/FriendRequestObject"}},"has_next":{"type":"boolean"},"next_cursor":{"type":"string"}},"required":["items","has_next"]}
    | .components.schemas.FriendDeleteRequest = {"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"]}
    | .components.schemas.FriendDeleteResponse = {"$ref":"#/components/schemas/FriendObject"}
    | .components.schemas.FriendListResponse = {"type":"object","additionalProperties":false,"properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/FriendObject"}},"has_next":{"type":"boolean"},"next_cursor":{"type":"string"}},"required":["items","has_next"]}
    | .components.schemas.FriendGroupCreateRequest = {"type":"object","additionalProperties":true,"properties":{"name":{"type":"string"},"description":{"type":"string"}}}
    | .components.schemas.FriendGroupPutRequest = {"type":"object","additionalProperties":true,"properties":{"id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"}}}
    | .components.schemas.FriendGroupGetRequest = {"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"]}
    | .components.schemas.FriendGroupDeleteRequest = {"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"]}
    | .components.schemas.FriendGroupCreateResponse = {"$ref":"#/components/schemas/FriendGroupObject"}
    | .components.schemas.FriendGroupPutResponse = {"$ref":"#/components/schemas/FriendGroupObject"}
    | .components.schemas.FriendGroupGetResponse = {"$ref":"#/components/schemas/FriendGroupObject"}
    | .components.schemas.FriendGroupDeleteResponse = {"$ref":"#/components/schemas/FriendGroupObject"}
    | .components.schemas.FriendGroupListResponse = {"type":"object","additionalProperties":false,"properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/FriendGroupObject"}},"has_next":{"type":"boolean"},"next_cursor":{"type":"string"}},"required":["items","has_next"]}
    | .components.schemas.FriendGroupMemberAddRequest = {"type":"object","additionalProperties":true,"properties":{"friend_group_id":{"type":"string"},"peer_id":{"type":"string"},"role":{"type":"string"}}}
    | .components.schemas.FriendGroupMemberPutRequest = {"type":"object","additionalProperties":true,"properties":{"friend_group_id":{"type":"string"},"id":{"type":"string"},"role":{"type":"string"}}}
    | .components.schemas.FriendGroupMemberDeleteRequest = {"type":"object","additionalProperties":false,"properties":{"friend_group_id":{"type":"string"},"id":{"type":"string"}},"required":["friend_group_id","id"]}
    | .components.schemas.FriendGroupMemberListRequest = {"type":"object","additionalProperties":true,"properties":{"friend_group_id":{"type":"string"},"limit":{"type":"integer"},"cursor":{"type":"string"}},"required":["friend_group_id"]}
    | .components.schemas.FriendGroupMemberAddResponse = {"$ref":"#/components/schemas/FriendGroupMemberObject"}
    | .components.schemas.FriendGroupMemberPutResponse = {"$ref":"#/components/schemas/FriendGroupMemberObject"}
    | .components.schemas.FriendGroupMemberDeleteResponse = {"$ref":"#/components/schemas/FriendGroupMemberObject"}
    | .components.schemas.FriendGroupMemberListResponse = {"type":"object","additionalProperties":false,"properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/FriendGroupMemberObject"}},"has_next":{"type":"boolean"},"next_cursor":{"type":"string"}},"required":["items","has_next"]}
    | .components.schemas.FriendGroupMessageSendRequest = {"type":"object","additionalProperties":true,"properties":{"friend_group_id":{"type":"string"},"audio_base64":{"type":"string"},"audio_content_type":{"type":"string"}}}
    | .components.schemas.FriendGroupMessageGetRequest = {"type":"object","additionalProperties":false,"properties":{"friend_group_id":{"type":"string"},"id":{"type":"string"}},"required":["friend_group_id","id"]}
    | .components.schemas.FriendGroupMessageListRequest = {"type":"object","additionalProperties":true,"properties":{"friend_group_id":{"type":"string"},"limit":{"type":"integer"},"cursor":{"type":"string"}},"required":["friend_group_id"]}
    | .components.schemas.FriendGroupMessageSendResponse = {"$ref":"#/components/schemas/FriendGroupMessageObject"}
    | .components.schemas.FriendGroupMessageGetResponse = {"$ref":"#/components/schemas/FriendGroupMessageObject"}
    | .components.schemas.FriendGroupMessageListResponse = {"type":"object","additionalProperties":false,"properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/FriendGroupMessageObject"}},"has_next":{"type":"boolean"},"next_cursor":{"type":"string"}},"required":["items","has_next"]}
  ' api/rpc/server.json > api/rpc/zig_server.json
  jq '
    def keep_ref:
      ((.["$ref"] // "") | test("/(Pet|Reward|Wallet)[A-Za-z0-9_]*$|#/components/schemas/(Pet|Reward|Wallet)") | not);
    .components.schemas.RPCRequest.properties.params.oneOf |= map(select(keep_ref))
    | .components.schemas.RPCResponse.properties.result.oneOf |= map(select(keep_ref))
    | .components.schemas.RPCMethod.enum |= map(select((test("^server\\.(pet|reward|wallet)\\.") | not) and . != "server.wallet.get"))
    | .components.schemas.RPCRequest.properties.params = {"type":"object","additionalProperties":true}
    | .components.schemas.RPCResponse.properties.result = {"type":"object","additionalProperties":true}
  ' api/rpc.json > api/rpc/zig.json
  sed -i.bak 's#\./rpc/server\.json#./rpc/zig_server.json#g' api/rpc/zig.json
  rm -f api/rpc/zig.json.bak
fi

echo "synced OpenAPI schemas from $src"
echo "note: api/rpc/zig.json and api/rpc/zig_server.json are Zig codegen subsets and are preserved"
