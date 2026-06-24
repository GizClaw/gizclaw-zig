# GizClaw RPC E2E

This binary exercises the typed Zig GizClaw client RPC wrappers against a real
GizClaw server. It does not call raw RPC method strings from the test body; each
check uses the public client wrapper that firmware code would call.

## Last Verified Run

The latest local verification used a Go setup-backed temporary server with an
extra firmware object store and a tar firmware artifact seeded by
`test/gizclaw-e2e/fixtures/seed-firmware.sh`. Workflow mutation coverage also
requires the test role to include `workflow.admin`.

```sh
zig build run-gizclaw-e2e-rpc -- \
  --context /tmp/gizclaw-zig-rpc.TqT3zi/context/gizclaw/e2e-client \
  --firmware-id zig-e2e-devkit \
  --firmware-channel stable \
  --firmware-artifact main
```

Result:

```text
SUMMARY pass=42 skip=47 fail=0
```

The skipped checks are fixture-dependent paths or intentionally deferred social
RPC groups. They are reported explicitly instead of being silently omitted.

## Test Results

### Connection and Common RPC

| Test | Result | Notes |
| --- | --- | --- |
| `Connect` | PASS | Connected through the Go setup context. |
| `Ping` | PASS | `all.ping`. |

### Server Metadata and Status

| Test | Result | Notes |
| --- | --- | --- |
| `GetServerInfo` | PASS | `server.info.get`. |
| `GetServerRuntime` | PASS | `server.runtime.get`. |
| `GetServerStatus` | PASS | `server.status.get`. |
| `PutServerInfo` | SKIP | Mutates server-side peer info; requires `--allow-mutations` and fixture data. |
| `PutServerStatus` | SKIP | Mutates server-side peer status; requires `--allow-mutations`. |

### Server Run and Workspace Runtime

| Test | Result | Notes |
| --- | --- | --- |
| `GetServerRunAgent` | PASS | `server.run.agent.get`. |
| `GetServerRunStatus` | PASS | `server.run.status`. |
| `GetServerRunWorkspace` | PASS | `server.run.workspace.get`. |
| `ListServerRunWorkspaceHistory` | PASS | `server.run.workspace.history`. |
| `ListServerRunWorkspaceHistory pagination` | SKIP | Fixture did not expose a second page. |
| `PlayServerRunWorkspaceHistory` | SKIP | Run history returned no replayable fixture rows. |
| `GetServerRunWorkspaceMemoryStats` | PASS | `server.run.workspace.memory.stats`. |
| `ServerRunWorkspaceRecall` | PASS | `server.run.workspace.recall`. |
| `SetServerRunAgent` | SKIP | Requires `--workspace` fixture. |
| `SetServerRunWorkspace` | SKIP | Requires `--workspace` fixture. |
| `ReloadServerRun` | SKIP | Requires `--workspace` fixture. |
| `ReloadServerRunWorkspace` | SKIP | Requires `--workspace` fixture. |
| `WaitServerRunWorkspace` | SKIP | Requires `--workspace` fixture. |
| `ServerRunSay` | SKIP | Requires `--voice-id` fixture and running audio path. |
| `StopServerRun` | SKIP | Requires `--workspace` fixture. |

### Workspace RPC

| Test | Result | Notes |
| --- | --- | --- |
| `ListWorkspaces` | PASS | `server.workspace.list`. |
| `ListWorkspaces pagination` | SKIP | Fixture did not expose a second page. |
| `GetWorkspace` | SKIP | `ListWorkspaces` returned no pre-existing fixture rows. |
| `ListWorkspaceHistory` | SKIP | Requires `--workspace` fixture. |
| `GetWorkspaceHistory` | SKIP | Requires `--workspace` fixture. |
| `GetWorkspaceHistoryAudio` | SKIP | Requires `--workspace` fixture. |
| `CreateWorkspace` | PASS | Creates an isolated Flowcraft workspace fixture using an existing workflow. |
| `CreateWorkspace pagination fixture` | PASS | Creates a second workspace so pagination can be asserted. |
| `PutWorkspace` | PASS | Updates the isolated workspace fixture. |
| `GetWorkspace created fixture` | PASS | Reads the isolated workspace fixture after update. |
| `ListWorkspaces after create` | PASS | Lists after fixture creation. |
| `ListWorkspaces pagination after create` | PASS | Two isolated fixtures expose a second page with `limit=1`. |
| `DeleteWorkspace` | PASS | Deletes the secondary workspace fixture. |
| `DeleteWorkspace cleanup primary` | PASS | Deletes the primary workspace fixture. |

### Workflow RPC

| Test | Result | Notes |
| --- | --- | --- |
| `ListWorkflows` | PASS | `server.workflow.list`. |
| `ListWorkflows pagination` | PASS | First page exposed `has_next`. |
| `ListWorkflows next page` | PASS | Next page was requested with `next_cursor`. |
| `GetWorkflow` | PASS | Uses a workflow returned by `ListWorkflows`. |
| `CreateWorkflow` | PASS | Creates an isolated Flowcraft workflow fixture. |
| `CreateWorkflow pagination fixture` | PASS | Creates a second workflow so pagination can be asserted. |
| `PutWorkflow` | PASS | Updates the isolated workflow fixture. |
| `GetWorkflow created fixture` | PASS | Reads the isolated workflow fixture after update. |
| `ListWorkflows after create` | PASS | Lists after fixture creation. |
| `ListWorkflows pagination after create` | PASS | Two isolated fixtures expose a second page with `limit=1`. |
| `DeleteWorkflow` | PASS | Deletes the secondary workflow fixture. |
| `DeleteWorkflow cleanup primary` | PASS | Deletes the primary workflow fixture. |

### Model RPC

| Test | Result | Notes |
| --- | --- | --- |
| `ListModels` | PASS | `server.model.list`. |
| `ListModels pagination` | PASS | First page exposed `has_next`. |
| `ListModels next page` | PASS | Next page was requested with `next_cursor`. |
| `GetModel` | PASS | Uses a model returned by `ListModels`. |

### Credential RPC

| Test | Result | Notes |
| --- | --- | --- |
| `ListCredentials` | PASS | `server.credential.list`. |
| `ListCredentials pagination` | SKIP | Fixture did not expose a second page. |
| `GetCredential` | PASS | Uses a credential returned by `ListCredentials`. |

### Voice Helper Coverage

| Test | Result | Notes |
| --- | --- | --- |
| `ListVoices` | PASS | Typed voice helper backed by the peer OpenAI-compatible voice HTTP surface. |
| `ListVoices pagination` | SKIP | Fixture did not expose a second page. |
| `GetVoice` | SKIP | `ListVoices` returned no fixture rows. |

### Firmware RPC

| Test | Result | Notes |
| --- | --- | --- |
| `ListFirmwares` | PASS | `server.firmware.list`. |
| `ListFirmwares pagination` | SKIP | Fixture did not expose a second page. |
| `GetFirmware` | PASS | Uses `zig-e2e-devkit` seeded by the firmware fixture script. |
| `DownloadFirmware` | PASS | Downloads the tar artifact uploaded as `stable/main`. |

### Contact RPC

| Test | Result | Notes |
| --- | --- | --- |
| `ListContacts` | SKIP | Social RPC coverage is intentionally deferred. |
| `ListContacts pagination` | SKIP | Social RPC coverage is intentionally deferred. |
| `GetContact` | SKIP | Social RPC coverage is intentionally deferred. |
| `CreateContact` | SKIP | Social RPC coverage is intentionally deferred. |
| `PutContact` | SKIP | Social RPC coverage is intentionally deferred. |
| `DeleteContact` | SKIP | Social RPC coverage is intentionally deferred. |

### Friend Invite and Friend RPC

| Test | Result | Notes |
| --- | --- | --- |
| `GetFriendInviteToken` | SKIP | Social RPC coverage is intentionally deferred. |
| `CreateFriendInviteToken` | SKIP | Social RPC coverage is intentionally deferred. |
| `ClearFriendInviteToken` | SKIP | Social RPC coverage is intentionally deferred. |
| `AddFriend` | SKIP | Social RPC coverage is intentionally deferred. |
| `ListFriends` | SKIP | Social RPC coverage is intentionally deferred. |
| `ListFriends pagination` | SKIP | Social RPC coverage is intentionally deferred. |
| `DeleteFriend` | SKIP | Social RPC coverage is intentionally deferred. |

### Friend Group RPC

| Test | Result | Notes |
| --- | --- | --- |
| `ListFriendGroups` | SKIP | Social RPC coverage is intentionally deferred. |
| `ListFriendGroups pagination` | SKIP | Social RPC coverage is intentionally deferred. |
| `GetFriendGroup` | SKIP | Social RPC coverage is intentionally deferred. |
| `CreateFriendGroup` | SKIP | Social RPC coverage is intentionally deferred. |
| `PutFriendGroup` | SKIP | Social RPC coverage is intentionally deferred. |
| `DeleteFriendGroup` | SKIP | Social RPC coverage is intentionally deferred. |
| `GetFriendGroupInviteToken` | SKIP | Social RPC coverage is intentionally deferred. |
| `CreateFriendGroupInviteToken` | SKIP | Social RPC coverage is intentionally deferred. |
| `ClearFriendGroupInviteToken` | SKIP | Social RPC coverage is intentionally deferred. |
| `JoinFriendGroup` | SKIP | Social RPC coverage is intentionally deferred. |
| `ListFriendGroupMembers` | SKIP | Social RPC coverage is intentionally deferred. |
| `AddFriendGroupMember` | SKIP | Social RPC coverage is intentionally deferred. |
| `PutFriendGroupMember` | SKIP | Social RPC coverage is intentionally deferred. |
| `DeleteFriendGroupMember` | SKIP | Social RPC coverage is intentionally deferred. |
| `ListFriendGroupMessages` | SKIP | Social RPC coverage is intentionally deferred. |
| `GetFriendGroupMessage` | SKIP | Social RPC coverage is intentionally deferred. |
| `SendFriendGroupMessage` | SKIP | Social RPC coverage is intentionally deferred. |

## Fixture Notes

- Workspace run-control and history checks require `--workspace`.
- `ServerRunSay` requires `--voice-id`.
- Workflow create/update/delete checks require `workflow.admin` on the caller's
  ACL role. The stock Go setup `e2e-client` role is read/use-only for workflows;
  add `workflow.admin` for full Workflow RPC mutation coverage.
- Workspace history RPCs require `workspace.read` for the caller public-key
  subject (`kind=pk`); the shared ACL view binding alone is not enough for that
  Go server path.
- Firmware download requires explicit firmware artifact flags, server-side
  firmware asset storage, and a seeded artifact. The current fixture uploads a
  locally generated tar file as `stable/main`.
- Contact, friend invite, friend, and friend group RPCs are intentionally
  deferred and reported as skips.
- Workspace and workflow mutation coverage creates isolated fixtures and cleans
  them up in the same run.
