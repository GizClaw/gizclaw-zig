# giztoy-zig

[![CI](https://github.com/GizClaw/gizclaw-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/GizClaw/gizclaw-zig/actions/workflows/ci.yml)

[English](README.md)

`giztoy-zig` 提供 GizClaw 的 Zig 组件，基于 `embed-zig` 构建，面向 MCU 级别
设备以及其他嵌入式环境。

仓库目前包含 `giznet`，这是 GizClaw 组件使用的嵌入式传输基础。

## 目录

- [环境要求](#环境要求)
- [构建与测试](#构建与测试)
- [目录结构](#目录结构)

## 环境要求

- Zig `0.15.2` 或更新版本

依赖通过 `build.zig.zon` 管理。

## 构建与测试

运行全部已配置测试：

```sh
zig build test
```

按测试类型运行：

```sh
zig build test-unit
zig build test-integration
zig build test-benchmark
```

只运行 `giznet` 相关测试：

```sh
zig build test-unit-giznet
zig build test-integration-giznet
zig build -Doptimize=ReleaseSafe test-benchmark-giznet
```

## 目录结构

- `lib/giznet/README.md`：`giznet` 架构和测试说明
