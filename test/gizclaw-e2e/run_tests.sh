#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
config_home="${GIZCLAW_E2E_CONFIG_HOME:-$script_dir/testdata/config-home-giznet}"
context_name="${GIZCLAW_E2E_GEAR1_CONTEXT:-gear1}"
context_dir="$config_home/gizclaw/$context_name"
zig_build_args=(-Doptimize=ReleaseSafe)
runner_args=(--context "$context_dir" --connect-timeout-ms 5000)

if [[ ! -f "$context_dir/config.yaml" ]]; then
  echo "missing e2e context config: $context_dir/config.yaml" >&2
  exit 2
fi
if [[ ! -f "$context_dir/identity.key" ]]; then
  echo "missing e2e context identity: $context_dir/identity.key" >&2
  exit 2
fi
transport="$(awk -F: '/^[[:space:]]*transport:/ { gsub(/[ \t\r"'\''"]/, "", $2); print $2; exit }' "$context_dir/config.yaml")"
if [[ -n "$transport" && "$transport" != "noise" ]]; then
  echo "SKIP transport=$transport: gizclaw-zig e2e currently supports only giznet/noise contexts" >&2
  exit 0
fi

unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy

run_step() {
  local step="$1"
  shift || true
  echo "==> zig build $step"
  (cd "$repo_root" && zig build "${zig_build_args[@]}" "$step" -- "${runner_args[@]}" "$@")
}

run_step run-gizclaw-e2e-rpc
run_step run-gizclaw-e2e-rpc-server-run
run_step run-gizclaw-e2e-rpc-resources
run_step run-gizclaw-e2e-speed
if [[ "${GIZCLAW_ZIG_E2E_INCLUDE_CHAT:-0}" == "1" ]]; then
  run_step run-gizclaw-e2e-chat
fi

echo "==> e2e run completed"
