#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
zig_repo_root="$(cd "$script_dir/../../.." && pwd)"
go_repo="$zig_repo_root/../gizclaw-go"

env_file=""
env_explicit=0
use_env=1
context_name=""
context_home=""
gizclaw_bin=""
firmware_id=""
channel=""
artifact=""
payload=""
subject_kind=""
subject_id=""

usage() {
  cat <<'EOF'
usage: seed-firmware.sh [options]

Options:
  --go-repo DIR             gizclaw-go checkout path
  --env FILE                Source Go e2e setup env file
  --no-env                  Do not source an env file
  --context NAME            Go CLI admin context name
  --xdg-config-home DIR     XDG_CONFIG_HOME that contains gizclaw contexts
  --gizclaw-bin FILE        Go gizclaw CLI binary
  --firmware-id ID          Firmware id to create
  --channel NAME            Firmware channel to upload
  --artifact NAME           Firmware artifact name to upload
  --payload TEXT            Firmware payload text
  --subject-kind KIND       ACL subject kind: view or pk
  --subject-id ID           ACL subject id
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --go-repo)
      go_repo="$2"
      shift 2
      ;;
    --env|-e)
      env_file="$2"
      env_explicit=1
      shift 2
      ;;
    --no-env)
      use_env=0
      shift
      ;;
    --context)
      context_name="$2"
      shift 2
      ;;
    --xdg-config-home)
      context_home="$2"
      shift 2
      ;;
    --gizclaw-bin)
      gizclaw_bin="$2"
      shift 2
      ;;
    --firmware-id)
      firmware_id="$2"
      shift 2
      ;;
    --channel)
      channel="$2"
      shift 2
      ;;
    --artifact)
      artifact="$2"
      shift 2
      ;;
    --payload)
      payload="$2"
      shift 2
      ;;
    --subject-kind)
      subject_kind="$2"
      shift 2
      ;;
    --subject-id)
      subject_id="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unexpected argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

go_repo="$(cd "$go_repo" && pwd)"

if [[ "$use_env" == "1" ]]; then
  if [[ -z "$env_file" ]]; then
    env_file="${GIZCLAW_E2E_ENV:-$go_repo/test/gizclaw-e2e/setup/.env}"
  fi
  if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  elif [[ "$env_explicit" == "1" ]]; then
    echo "env file not found: $env_file" >&2
    exit 2
  fi
fi

context_name="${context_name:-${GIZCLAW_E2E_ADMIN_CONTEXT:-e2e-admin}}"
context_home="${context_home:-${GIZCLAW_E2E_CONTEXT_HOME:-$go_repo/test/gizclaw-e2e/.testbench/context}}"
gizclaw_bin="${gizclaw_bin:-${GIZCLAW_BIN:-$go_repo/test/gizclaw-e2e/.testbench/bin/gizclaw}}"
firmware_id="${firmware_id:-${GIZCLAW_ZIG_E2E_FIRMWARE_ID:-zig-e2e-devkit}}"
channel="${channel:-${GIZCLAW_ZIG_E2E_FIRMWARE_CHANNEL:-stable}}"
artifact="${artifact:-${GIZCLAW_ZIG_E2E_FIRMWARE_ARTIFACT:-main}}"
payload="${payload:-${GIZCLAW_ZIG_E2E_FIRMWARE_PAYLOAD:-zig e2e firmware payload}}"
subject_kind="${subject_kind:-${GIZCLAW_ZIG_E2E_FIRMWARE_SUBJECT_KIND:-view}}"
subject_id="${subject_id:-${GIZCLAW_ZIG_E2E_FIRMWARE_SUBJECT_ID:-${GIZCLAW_E2E_ACL_VIEW:-e2e-client}}}"

if [[ "$subject_kind" != "view" && "$subject_kind" != "pk" ]]; then
  echo "--subject-kind must be view or pk" >&2
  exit 2
fi
if [[ "$subject_kind" == "pk" && -z "$subject_id" ]]; then
  subject_id="${GIZCLAW_E2E_CLIENT_PUBLIC_KEY:-}"
fi
if [[ -z "$subject_id" ]]; then
  echo "missing ACL subject id; pass --subject-id or set GIZCLAW_E2E_ACL_VIEW/GIZCLAW_E2E_CLIENT_PUBLIC_KEY" >&2
  exit 2
fi

if [[ ! -x "$gizclaw_bin" ]]; then
  mkdir -p "$(dirname "$gizclaw_bin")"
  (cd "$go_repo" && go build -o "$gizclaw_bin" ./cmd/gizclaw)
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

firmware_json="$tmp_dir/firmware.json"
tar_root="$tmp_dir/tar-root"
payload_bin="$tmp_dir/$artifact.tar"
acl_json="$tmp_dir/firmware-acl.json"

python3 - "$firmware_json" "$firmware_id" "$channel" "$artifact" <<'PY'
import json
import sys

path, firmware_id, channel, artifact = sys.argv[1:5]
doc = {
    "name": firmware_id,
    "description": "gizclaw-zig e2e firmware fixture",
    "slots": {
        channel: {
            "version": "1.0.0",
            "artifacts": [{"name": artifact, "kind": "app"}],
        }
    },
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, separators=(",", ":"))
PY

mkdir -p "$tar_root"
printf '%s\n' "$payload" > "$tar_root/payload.txt"
cat > "$tar_root/manifest.json" <<EOF
{"firmware_id":"$firmware_id","channel":"$channel","artifact":"$artifact","format":"tar","source":"gizclaw-zig-rpc-e2e"}
EOF
tar -cf "$payload_bin" -C "$tar_root" .

python3 - "$acl_json" "$firmware_id" "$subject_kind" "$subject_id" <<'PY'
import json
import sys

path, firmware_id, subject_kind, subject_id = sys.argv[1:5]
role = "zig-e2e-firmware-reader"
doc = {
    "apiVersion": "gizclaw.admin/v1alpha1",
    "kind": "ResourceList",
    "metadata": {"name": "zig-e2e-firmware-fixture"},
    "spec": {
        "items": [
            {
                "apiVersion": "gizclaw.admin/v1alpha1",
                "kind": "ACLRole",
                "metadata": {"name": role},
                "spec": {"permissions": ["firmware.read"]},
            },
            {
                "apiVersion": "gizclaw.admin/v1alpha1",
                "kind": "ACLPolicyBinding",
                "metadata": {"name": f"zig-e2e-firmware-read-{firmware_id}"},
                "spec": {
                    "subject": {"kind": subject_kind, "id": subject_id},
                    "resource": {"kind": "firmware", "id": firmware_id},
                    "role": role,
                },
            },
        ]
    },
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, separators=(",", ":"))
PY

export XDG_CONFIG_HOME="$context_home"

"$gizclaw_bin" admin firmwares put "$firmware_id" -f "$firmware_json" --context "$context_name" >/dev/null
"$gizclaw_bin" admin firmwares upload-bin "$firmware_id" --channel "$channel" --bin "$artifact" -f "$payload_bin" --context "$context_name" >/dev/null
"$gizclaw_bin" admin apply --context "$context_name" -f "$acl_json" >/dev/null

cat <<EOF
Seeded firmware fixture:
  context=$context_name
  xdg_config_home=$context_home
  firmware_id=$firmware_id
  channel=$channel
  artifact=$artifact
  acl_subject=$subject_kind:$subject_id

Run the Zig RPC e2e with:
  zig build run-gizclaw-e2e-rpc-resources -- --firmware-id $firmware_id
EOF
