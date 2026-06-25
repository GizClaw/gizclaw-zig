# Chat Roundtrip Fixtures

This directory is the canonical fixture location for Zig chat e2e tests.

Expected files:

```text
manifest.json
round-01.ogg
round-02.ogg
round-03.ogg
```

The Ogg/Opus files should be fixed real-speech recordings and committed through
Git LFS. Host e2e can load them from disk. zux/devkit builds can embed the same
bytes with Zig `@embedFile`.
