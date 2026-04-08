# `lib/net/http_transport`

`http_transport` is the optional HTTP bridge above `lib/net/peer`.

It exists to adapt peer-managed service streams into the HTTP abstractions that
already live in `embed-zig`, instead of building a second local HTTP stack.
It should not be required for lower `lib/net` layers to build or test.

## What It Provides

- a service-scoped listener adapter over `peer.Conn`
- a stream adapter from `peer.Stream` to `embed` `net.Conn`
- a service-scoped HTTP round tripper over peer streams

## What It Depends On

- public `peer` package surfaces
- `embed-zig` `net` and `http`

## What It Does Not Own

- handshake, session, KCP, or raw service-routing internals
- lower-layer transport ownership

## Compatibility Anchor

This package is the Zig-side counterpart of:

- `~/giztoy-go/pkg/net/httptransport`

The Go package name stays `httptransport`, while the Zig package path follows
the underscore form `http_transport`.

## Notes

Use upstream `embed-zig` `http.Client` and `http.Server` directly with this
package's `Transport` and `Listener`.