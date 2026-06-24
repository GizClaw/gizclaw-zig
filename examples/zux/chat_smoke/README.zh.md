# GizClaw Chat Smoke

`chat_smoke` 是固件侧 GizClaw 对话链路的 smoke app。

当前目录先固定应用边界和文件拆分，后续实现围绕 #17 逐步补齐：

- WiFi 先连接，再启动 GizClaw。
- GizClaw context 从 preferences 和 build config 初始化。
- 缺少 client identity 时生成并持久化。
- 支持 push-to-talk 和 realtime 两种模式。
- 使用 `lib/gizclaw` SDK API，不在 app 内手写 RPC method 或 stream frame。

## Build Options

- `wifi_ssid`
- `wifi_password`
- `gizclaw_server_addr`
- `gizclaw_server_key`
- `gizclaw_client_key`
- `chat_workspace`
- `chat_workflow`
- `chat_default_mode`
