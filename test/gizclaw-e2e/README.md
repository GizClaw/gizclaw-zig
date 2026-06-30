# GizClaw E2E

These binaries exercise the Zig GizClaw client against a real GizClaw server.
They are thin host entrypoints around reusable runners under
`test/gizclaw-e2e/client/`.

## Default Setup

By default, the Zig e2e runners use committed client contexts in this repo:

```text
test/gizclaw-e2e/testdata/config-home-giznet/gizclaw/gear1
```

The context format matches `gizclaw-go` e2e contexts:

```yaml
server:
  host: 127.0.0.1
  public-api-port: 9820
  noise-udp-port: 9820
  public-key: ...
  transport: noise
  cipher-mode: chacha_poly
```

Zig e2e is client-side only. It does not build, start, stop, reset, or seed the
server. Prepare the local Go e2e server separately before running these checks.

## Standard Flow

Run the giznet transport suite:

```sh
./test/gizclaw-e2e/run_giznet_tests.sh
```

The script selects `testdata/config-home-giznet` and runs the Zig e2e build
steps with the committed `gear1` context. The default gate covers RPC smoke,
server-run RPCs, resource RPCs, and speed test. It intentionally does not run
the live chat roundtrip because that depends on the provider-backed chat
resource set being fully initialized.

To include chat explicitly:

```sh
GIZCLAW_ZIG_E2E_INCLUDE_CHAT=1 ./test/gizclaw-e2e/run_giznet_tests.sh
```

Transport parity entrypoints use the same names as `gizclaw-go`:

```sh
./test/gizclaw-e2e/run_giznet_tests.sh
./test/gizclaw-e2e/run_webrtc_tests.sh
./test/gizclaw-e2e/run_tests_all.sh
```

The WebRTC entrypoint selects the committed WebRTC context but currently exits
with an explicit skip because the Zig e2e client only has the giznet/noise
transport path wired.

## Remote Overrides

Use build options when testing against a remote service:

```sh
zig build run-gizclaw-e2e-rpc \
  -Dgizclaw_e2e_server_addr=HOST:PORT \
  -Dgizclaw_e2e_server_pub_key=SERVER_PUBLIC_KEY \
  -Dgizclaw_e2e_client_pri_key=CLIENT_PRIVATE_KEY
```

The same options apply to the split RPC runners, `run-gizclaw-e2e-chat`, and
`run-gizclaw-e2e-speed`.

Runtime flags can still override the same values:

```sh
zig build run-gizclaw-e2e-rpc -- \
  --server-addr HOST:PORT \
  --server-pub-key SERVER_PUBLIC_KEY \
  --client-pri-key CLIENT_PRIVATE_KEY
```

## RPC Runner

```sh
zig build run-gizclaw-e2e-rpc -- --connect-timeout-ms 5000
```

The default RPC runner is the small smoke slice:

- connect
- ping
- server info
- server runtime
- server status

Heavier domains are separate steps:

```sh
zig build run-gizclaw-e2e-rpc-server-run -- --connect-timeout-ms 5000
zig build run-gizclaw-e2e-rpc-resources -- --connect-timeout-ms 5000
```

The RPC fixture defaults match the shared `gizclaw-go` resource catalog:

- workspace: `family-circle-chatroom-workspace`
- run workspace: `direct-chatroom-workspace`
- credential: `openai-main-credential`
- voice: `minimax-narrator-clone`
- firmware: `devkit-firmware-main`

Override them with `--workspace`, `--run-workspace`, `--credential-name`,
`--voice-id`, and `--firmware-id` when testing a different catalog.

## Chat Runner

```sh
zig build run-gizclaw-e2e-chat -- --connect-timeout-ms 5000
```

The chat runner is the replacement for the old workspace runner. It validates
the shared connection path and carries the new chat configuration surface:

- connect / ping
- optional workspace select/reload/wait
- peer stream open/close smoke
- workspace config path
- workspace name
- mode: `push_to_talk` or `realtime`
- audio manifest path
- rounds
- run/conversation timeouts

The chat roundtrip suites use fixed Ogg/Opus files for both push-to-talk and
realtime modes. Realtime mode sends the same packets with microphone-like frame
cadence.

```text
test/gizclaw-e2e/testdata/chat/roundtrip/
├── manifest.json
├── round-01.ogg
├── round-02.ogg
└── round-03.ogg
```

Host tests may load the files from disk. zux/devkit tests should be able to
embed the same bytes with Zig `@embedFile`.

## Speed Runner

```sh
zig build run-gizclaw-e2e-speed -- --connect-timeout-ms 5000
```

The speed runner is also split into a host CLI wrapper and reusable
`client/speed/TestRunner.zig`. It reports ping RTT plus upload/download bytes,
duration, and Mbps.

## Build Steps

```sh
zig build --list-steps | rg gizclaw-e2e
```

Expected steps:

```text
run-gizclaw-e2e-rpc
run-gizclaw-e2e-rpc-server-run
run-gizclaw-e2e-rpc-resources
run-gizclaw-e2e-speed
run-gizclaw-e2e-chat
```
