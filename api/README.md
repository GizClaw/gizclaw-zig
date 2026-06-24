# API Definitions

This directory contains the subset of GizClaw API specifications consumed by
the Zig client SDK. It is synced from `../gizclaw-go/api`, but intentionally
does not mirror the Go admin/public HTTP API packages.

## Layout

- `client_service.json` defines the local GizClaw client HTTP surface.
- `client_service_zig.json` is the Zig-friendly filtered client service input.
- `rpc.json` defines the internal framed peer RPC protocol.
- `rpc/*.json` contains reusable RPC method schema definitions.
- `type/*.json` contains reusable shared schema definitions required by the
  client service and peer RPC model generation.

Admin HTTP APIs such as `admin_service.json` and declarative admin resource
schemas under `resource/` belong to `gizclaw-go` and are intentionally not part
of this Zig client SDK mirror.

## Generated Code

Generated Go and TypeScript SDKs live in `gizclaw-go`; do not edit those
generated files from this repository. Change the source schema in
`../gizclaw-go/api`, regenerate it there, then sync the client subset here with:

```sh
tools/sync-gizclaw-go-api.sh ../gizclaw-go
```

## Maintenance Guidelines

- Treat files in `api/` as synced API contracts. Keep local Zig-only filtering
  in `tools/sync-gizclaw-go-api.sh` or `client_service_zig.json` generation.
- Prefer adding reusable schemas under `type/` and referencing them from
  top-level OpenAPI documents instead of duplicating inline schemas.
- Keep schema names, discriminator values, and path operation IDs stable unless
  the caller-facing contract is intentionally changing.
- When adding or changing an endpoint, update the OpenAPI document in
  `gizclaw-go`, regenerate the Go package there, sync this repo, and run the
  focused Zig client tests.
