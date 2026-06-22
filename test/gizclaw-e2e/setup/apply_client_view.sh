#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../../.." && pwd)"
go_repo_default="$repo_root/../gizclaw-go"
go_repo="${GIZCLAW_GO_REPO:-$go_repo_default}"

env_file="${GIZCLAW_E2E_ENV:-$go_repo/test/gizclaw-e2e/setup/.env}"
env_explicit=0
opt_go_repo=""
opt_context_home=""
opt_server_workspace=""
opt_server_addr=""
opt_cipher_mode=""
opt_context_name=""
opt_admin_context=""
opt_acl_view=""
opt_private_key_file=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env|-e)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      env_file="$2"
      env_explicit=1
      shift 2
      ;;
    --no-env)
      env_file=""
      shift
      ;;
    --go-repo)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      opt_go_repo="$2"
      go_repo="$2"
      if [[ "$env_file" == "$go_repo_default/test/gizclaw-e2e/setup/.env" ]]; then
        env_file="$go_repo/test/gizclaw-e2e/setup/.env"
      fi
      shift 2
      ;;
    --context-home)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      opt_context_home="$2"
      shift 2
      ;;
    --server-workspace)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      opt_server_workspace="$2"
      shift 2
      ;;
    --server-addr)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      opt_server_addr="$2"
      shift 2
      ;;
    --cipher-mode)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      opt_cipher_mode="$2"
      shift 2
      ;;
    --context-name)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      opt_context_name="$2"
      shift 2
      ;;
    --admin-context)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      opt_admin_context="$2"
      shift 2
      ;;
    --acl-view)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      opt_acl_view="$2"
      shift 2
      ;;
    --private-key-file)
      if [[ $# -lt 2 ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      opt_private_key_file="$2"
      shift 2
      ;;
    --help|-h)
      cat <<'USAGE'
usage: apply_client_view.sh [options]

Creates a Zig e2e client context and applies a PeerConfig that attaches the
Zig client public key to the shared Go e2e ACL view.

Options:
  --env FILE              Source a Go setup env file
  --no-env                Do not source an env file
  --go-repo DIR           gizclaw-go checkout, default ../gizclaw-go
  --context-home DIR      XDG config home for Go/Zig e2e contexts
  --server-workspace DIR  Go setup server workspace directory
  --server-addr ADDR      Go setup server address
  --cipher-mode MODE      chacha_poly, aes_256_gcm, or plaintext
  --context-name NAME     Zig client context name, default zig-e2e-client
  --admin-context NAME    Admin context used for apply, default e2e-admin
  --acl-view NAME         ACL view to join, default e2e-client
  --private-key-file FILE Persisted Zig private key text
USAGE
      exit 0
      ;;
    *)
      echo "unexpected argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "$env_file" ]]; then
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

go_repo="${opt_go_repo:-${GIZCLAW_GO_REPO:-$go_repo_default}}"
[[ -n "$opt_context_home" ]] && GIZCLAW_E2E_CONTEXT_HOME="$opt_context_home"
[[ -n "$opt_server_workspace" ]] && GIZCLAW_E2E_SERVER_WORKSPACE="$opt_server_workspace"
[[ -n "$opt_server_addr" ]] && GIZCLAW_E2E_SERVER_ADDR="$opt_server_addr"
[[ -n "$opt_cipher_mode" ]] && GIZCLAW_E2E_SERVER_CIPHER_MODE="$opt_cipher_mode"
[[ -n "$opt_context_name" ]] && GIZCLAW_ZIG_E2E_CLIENT_CONTEXT="$opt_context_name"
[[ -n "$opt_admin_context" ]] && GIZCLAW_E2E_ADMIN_CONTEXT="$opt_admin_context"
[[ -n "$opt_acl_view" ]] && GIZCLAW_E2E_ACL_VIEW="$opt_acl_view"
[[ -n "$opt_private_key_file" ]] && GIZCLAW_ZIG_E2E_CLIENT_PRIVATE_KEY_FILE="$opt_private_key_file"

testbench_dir="${GIZCLAW_E2E_TESTBENCH:-$repo_root/test/gizclaw-e2e/.testbench}"
context_home="${GIZCLAW_E2E_CONTEXT_HOME:-$testbench_dir/context}"
workspace_dir="${GIZCLAW_E2E_SERVER_WORKSPACE:-$testbench_dir/workspace}"
listen_addr="${GIZCLAW_E2E_SERVER_ADDR:-127.0.0.1:9820}"
cipher_mode="${GIZCLAW_E2E_SERVER_CIPHER_MODE:-chacha_poly}"
context_name="${GIZCLAW_ZIG_E2E_CLIENT_CONTEXT:-zig-e2e-client}"
admin_context="${GIZCLAW_E2E_ADMIN_CONTEXT:-e2e-admin}"
acl_view="${GIZCLAW_E2E_ACL_VIEW:-e2e-client}"
gizclaw_bin="${GIZCLAW_BIN:-$testbench_dir/bin/gizclaw}"
private_key_file="${GIZCLAW_ZIG_E2E_CLIENT_PRIVATE_KEY_FILE:-$testbench_dir/setup/zig-client.private-key}"

if [[ ! -d "$go_repo" ]]; then
  echo "gizclaw-go repo not found: $go_repo" >&2
  exit 2
fi

mkdir -p "$testbench_dir/bin" "$(dirname "$private_key_file")"
if [[ ! -x "$gizclaw_bin" ]]; then
  (cd "$go_repo" && go build -o "$gizclaw_bin" ./cmd/gizclaw)
fi

client_private="${GIZCLAW_ZIG_E2E_CLIENT_PRIVATE_KEY:-}"
if [[ -z "$client_private" && -f "$private_key_file" ]]; then
  client_private="$(<"$private_key_file")"
fi
if [[ -z "$client_private" ]]; then
  client_private="$("$gizclaw_bin" gen-key)"
  umask 077
  printf '%s\n' "$client_private" >"$private_key_file"
fi

(cd "$go_repo" && go run ./test/gizclaw-e2e/setup/write_context_config.go \
  --context-home "$context_home" \
  --server-workspace "$workspace_dir" \
  --server-addr "$listen_addr" \
  --cipher-mode "$cipher_mode" \
  --context-name "$context_name" \
  --client-private-key "$client_private")

context_json="$(XDG_CONFIG_HOME="$context_home" "$gizclaw_bin" context show "$context_name")"
client_public="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["identity_public"])' <<<"$context_json")"

# The admin PeerConfig API updates an existing peer record. A lightweight ping
# registers the freshly generated Zig peer before attaching it to the view.
XDG_CONFIG_HOME="$context_home" "$gizclaw_bin" connect ping --context "$context_name" >/dev/null

resource_file="$(mktemp "${TMPDIR:-/tmp}/gizclaw-zig-peer-config.XXXXXX.json")"
trap 'rm -f "$resource_file"' EXIT
python3 - "$resource_file" "$client_public" "$acl_view" <<'PY'
import json
import pathlib
import sys

out, public_key, view = sys.argv[1:4]
resource = {
    "apiVersion": "gizclaw.admin/v1alpha1",
    "kind": "PeerConfig",
    "metadata": {"name": public_key},
    "spec": {"view": view},
}
pathlib.Path(out).write_text(json.dumps(resource, separators=(",", ":")) + "\n")
PY

XDG_CONFIG_HOME="$context_home" "$gizclaw_bin" admin apply --context "$admin_context" -f "$resource_file" >/dev/null

echo "Applied Zig e2e client view binding"
echo "context_home=$context_home"
echo "context_name=$context_name"
echo "context_dir=$context_home/gizclaw/$context_name"
echo "client_public_key=$client_public"
echo "acl_view=$acl_view"
