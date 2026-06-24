# GizClaw E2E

These binaries exercise the Zig GizClaw client against a real GizClaw server.
They reuse the Go e2e setup resources instead of recreating provider
credentials, models, voices, workflows, or ACL views. The default Zig e2e
client context is committed under `test/gizclaw-e2e/testdata/client-context`.

## Shared Setup

Start and seed the local Go setup server first:

```sh
../gizclaw-go/test/gizclaw-e2e/setup/start-server.sh
../gizclaw-go/test/gizclaw-e2e/setup/reset_data.sh
```

The Zig runners use this context by default:

```sh
test/gizclaw-e2e/testdata/client-context
```

The committed context uses its own Zig peer key and the Go setup server public
key. It is expected to be attached to the shared Go e2e ACL view by the Go setup
resources. Use `test/gizclaw-e2e/setup/apply_client_view.sh` only when creating
an isolated temporary Zig peer/context.
Context files store the remote server public key as `server.public-key`. They
must not require the server private key.

The context supplies the client identity. The server endpoint can still be
overridden when a context points at a local service:

```sh
zig build run-gizclaw-e2e-rpc -- \
  --server-addr SERVER_HOST:PORT \
  --server-key SERVER_PUBLIC_KEY
```

To bypass the Go context entirely, pass `--no-context`, `--client-key`,
`--server-addr`, and `--server-key`.

Use `--connect-timeout-ms N` when the GizNet handshake needs more than the
default 5000 ms. This only changes the client-side wait for the connection to be
accepted; it does not change server configuration.

## RPC Runner

```sh
zig build run-gizclaw-e2e-rpc -- [options]
```

The RPC runner actively calls read-only server RPC methods, verifies list
pagination metadata, and reports fixture-dependent or mutating methods as
explicit skips unless the required fixture flags are supplied.

Optional fixtures:

```sh
--workspace NAME
--voice-id ID
--firmware-id ID --firmware-channel NAME --firmware-artifact NAME
--friend-group-id ID --audio-base64 PAYLOAD
--peer-context DIR
--allow-mutations
```

With `--allow-mutations`, the RPC runner creates isolated contact and
friend-group fixtures, validates create/update/list/get/delete behavior, and
cleans those fixtures up before exit. Friend-group audio message upload is run
when an explicit `--friend-group-id --audio-base64` fixture is supplied, or when
the isolated friend-group fixture can use the server message asset store. If the
Go setup server has no friend-group message asset store configured, that upload
path is reported as a skip with a concrete reason.

Voice catalog reads are not `server.voice.*` RPC methods in the synced Go
swagger. The Zig client exposes typed `ListVoices` and `GetVoice` helpers backed
by the Go-compatible peer OpenAI HTTP service (`/v1/voices`), and the RPC runner
covers those typed helpers alongside the RPC methods.

Workspace history RPCs require `workspace.read` for the caller public key
subject, not only the shared ACL view. For the default doubao workspace fixture,
add this binding after the Go setup resources are applied:

```sh
printf '%s\n' \
  '{"apiVersion":"gizclaw.admin/v1alpha1","kind":"ACLPolicyBinding","metadata":{"name":"pk-e2e-client-workspace-doubao-realtime"},"spec":{"subject":{"kind":"pk","id":"'"${GIZCLAW_E2E_CLIENT_PUBLIC_KEY}"'"},"resource":{"kind":"workspace","id":"doubao-realtime"},"role":"e2e-client"}}' |
  gizclaw admin apply --context "${GIZCLAW_E2E_ADMIN_CONTEXT:-e2e-admin}" -f -
```

To cover firmware download on a local Go setup server, seed an isolated firmware
fixture with the Go admin CLI and pass the printed flags to the RPC runner:

```sh
test/gizclaw-e2e/fixtures/seed-firmware.sh \
  --context e2e-admin

zig build run-gizclaw-e2e-rpc -- \
  --firmware-id zig-e2e-devkit \
  --firmware-channel stable \
  --firmware-artifact main
```

The local Go server must expose an object store named `firmware-assets`; without
it the Go admin upload command returns `FIRMWARE_ASSETS_NOT_CONFIGURED`. To fully
cover friend-group audio message upload in `--allow-mutations`, the server must
also expose `friend-group-message-assets`.

By default the firmware fixture grants `firmware.read` to the shared ACL view.
When testing against a temporary server without the Go setup `PeerConfig` view,
grant the current client directly:

```sh
test/gizclaw-e2e/fixtures/seed-firmware.sh \
  --context e2e-client \
  --xdg-config-home /tmp/gizclaw-zig-e2e.XXXXXX/context \
  --subject-kind pk \
  --subject-id <client-public-key>
```

When using a temporary setup workspace, pass its context root explicitly:

```sh
test/gizclaw-e2e/fixtures/seed-firmware.sh \
  --context e2e-client \
  --xdg-config-home /tmp/gizclaw-zig-e2e.XXXXXX/context
```

Use `--peer-context DIR` with `--allow-mutations` to cover second-peer social
RPCs: friend request accept/reject/delete and friend-group member
add/update/list/delete. The peer context must point at the same server.

## Workspace Runner

```sh
zig build run-gizclaw-e2e-workspace -- \
  --context test/gizclaw-e2e/testdata/client-context \
  --config ../gizclaw-go/test/gizclaw-e2e/testdata/workspaces/doubao-realtime.json \
  --workspace e2e-doubao-realtime-push-to-talk-roundtrip
```

The workspace runner uses a Go workspace e2e config, upserts the workflow, stops
the active server run, deletes any old workspace with the selected name, and
creates the workspace again before each run. The Go setup owns shared
credentials, provider tenants, models, voices, and ACL view resources.
Use `--workspace NAME` so Zig e2e owns a workspace name that does not collide
with the Go workspace e2e programs.

After upsert, the runner selects the workspace, reloads the run agent, waits for
`GetServerRunStatus` to report `state=running` for the expected workspace, opens
and closes the peer event stream, and calls `ServerRunSay` with the configured
voice fixture.

Use `--conversation-smoke` with `--opus-packets-base64-file FILE` to open the
typed peer stream, send a real speech turn as BOS/stamped-Opus/EOS, and perform
bounded reads from the combined event and stamped Opus downlink. The fixture file
contains one base64-encoded Opus packet per line; blank lines and `#` comments
are ignored. The smoke passes only when the live workspace emits at least one
peer event and at least one audio packet. Without the Opus fixture, the runner
records `StampedOpusConversation` as an explicit skip instead of sending invalid
silence. Use `--conversation-timeout-ms N` to override the observation window.

On macOS with `ffmpeg`, generate a short real speech fixture with a matching
language voice:

```sh
test/gizclaw-e2e/fixtures/make-opus-packets.sh \
  --voice Tingting \
  --out /tmp/gizclaw-zig-opus-packets.txt \
  --text "今天天气很好，请回复收到。"
```

Use `--run-timeout-ms N` to override the run-status wait. Use
`--skip-run-control` to stop after workflow/workspace upsert.

Latest local Doubao realtime validation against the Go setup server:

```text
zig build run-gizclaw-e2e-workspace -- \
  --context test/gizclaw-e2e/testdata/client-context \
  --config ../gizclaw-go/test/gizclaw-e2e/testdata/workspaces/doubao-realtime.json \
  --workspace e2e-doubao-realtime-push-to-talk-roundtrip \
  --conversation-smoke \
  --opus-packets-base64-file /tmp/gizclaw-tingting-opus/packets.txt \
  --conversation-timeout-ms 240000 \
  --run-timeout-ms 90000

SUMMARY pass=11 skip=0 fail=0
input_packets=163 workspace_uplink_send_ms=3806
after_eos_transcript_start_ms=531 after_eos_transcript_done_ms=563
after_eos_text_first_ms=1182 assistant_text_done_ms=1182
after_eos_audio_first_ms=1411
events=8 transcript_events=3 assistant_events=3 history_events=2
audio_packets=40 audio_bytes=7821
```

## Runtime Parameters

The Zig e2e client uses the same KCP tuning expected by firmware-oriented tests:

```text
nodelay=1 interval=10ms resend=2 nc=0 snd_wnd=256 rcv_wnd=256
```
