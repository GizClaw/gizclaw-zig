# AGENTS.md

## Module Import Rules

The project exposes a single root module from `src/mod.zig`.
Each directory under `src/net/` is a self-contained package-like namespace.
Zig files within the **same directory** may freely `@import` each other using relative paths (e.g. `@import("conn.zig")`).

**Cross-directory imports are forbidden** for package implementation files.
Only the root aggregator `src/mod.zig` may import sub-package entry files such as `net/core/mod.zig`.
External dependencies still go through the build system via `@import("module_name")`.

### Module layout

```
src/mod.zig       → giztoy
src/net/core/     → `giztoy.core`
src/net/kcp/      → `giztoy.kcp`
src/net/noise/    → `giztoy.noise`
```

### External dependencies

External packages are imported at the **top level** by package name, and consumers access sub-parts via field access.
Do NOT import sub-modules of an external package directly — always go through the package root.

```
// Good: import the package, then access its sub-modules
const protocol = @import("kcp").protocol;

// Bad: importing a sub-module directly
const protocol = @import("protocol");
```

Current external packages declared in `build.zig`:

| Import name | Package                 | Usage                              |
|-------------|-------------------------|------------------------------------|
| `embed`     | `embed-zig/embed-zig`   | `@import("embed").runtime`, etc.   |
| `kcp`       | `jinzhongjia/zig-kcp`   | `@import("kcp").protocol`, etc.    |

### Allowed imports inside a `.zig` file

| Import form                      | Allowed? | Example                                    |
|----------------------------------|----------|--------------------------------------------|
| `@import("std")`                 | Yes      | Standard library                           |
| `@import("same_dir_file.zig")`   | Yes      | Same-directory sibling file                |
| `@import("package_name").member` | Yes      | External package declared in build.zig     |
| `@import("../other/foo.zig")`    | **No**   | Cross-directory relative import            |
