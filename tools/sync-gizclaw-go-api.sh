#!/usr/bin/env bash
set -euo pipefail

repo="${1:-${GIZCLAW_GO_DIR:-../gizclaw-go}}"
src="${repo%/}/api"

if [[ ! -d "$src" ]]; then
  echo "missing gizclaw-go api directory: $src" >&2
  exit 1
fi

mkdir -p api/rpc api/resource api/type/workflows

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

copy_file "$src/admin_service.json" api/admin_service.json
copy_file "$src/client_service.json" api/client_service.json
copy_file "$src/rpc.json" api/rpc.json
copy_file "$src/server_public.json" api/server_public.json
copy_file "$src/types.json" api/types.json

if [[ -f "$src/openai_service.json" ]]; then
  cp "$src/openai_service.json" api/openai_service.json
elif [[ -f "$src/openai-compat/v1/service.json" ]]; then
  cp "$src/openai-compat/v1/service.json" api/openai_service.json
fi

copy_glob "$src/rpc/*.json" api/rpc
copy_glob "$src/resource/*.json" api/resource
copy_glob "$src/type/*.json" api/type
copy_glob "$src/type/workflows/*.json" api/type/workflows

echo "synced OpenAPI schemas from $src"
echo "note: api/rpc/zig.json and api/rpc/zig_server.json are Zig codegen subsets and are preserved"
