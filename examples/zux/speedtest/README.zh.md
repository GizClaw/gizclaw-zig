# zux-speedtest User Story

## 基准用户故事

- 在应用启动完成的情况下，应用进入关机状态。
- 在应用处于关机状态的情况下，用户长按 `Btn` 满 3 秒，应用进入开机状态。
- 在应用处于开机状态且未请求 WiFi 连接的情况下，用户短按 `Btn`，应用请求 WiFi STA 连接。
- 在应用处于开机状态且已请求 WiFi 连接的情况下，用户短按 `Btn`，应用请求 WiFi STA 断开。
- 在应用处于开机状态的情况下，用户长按 `Btn` 满 3 秒，应用进入关机状态，并请求 WiFi STA 断开。
- 在 GizClaw 运行时开始连接服务器的情况下，应用把 GizClaw 状态改为 `connecting`。
- 在 GizClaw 运行时连接服务器成功的情况下，应用把 GizClaw 状态改为 `connected`。
- 在 GizClaw 运行时连接服务器断开的情况下，应用把 GizClaw 状态改为 `disconnected`。

## 状态定义

- `app_state` 表达应用开关机状态：`off` 表示关机，`on` 表示开机。
- `wifi_state` 表达应用对 WiFi STA 的连接意图：`off` 表示请求断开，`on` 表示请求连接。
- WiFi STA 组件自己的 state 表达底层 WiFi 连接结果，例如是否已连接、是否已经获得 IP。
- `gizclaw_state` 表达 GizClaw 客户端连接状态，取值为 `disconnected`、`connecting` 或 `connected`。
- `app_state` 不等同于 `wifi_state`；应用开机后不自动代表 WiFi STA 应该连接。
- `wifi_state` 不等同于 WiFi STA 底层连接状态；它只表示应用正在请求 WiFi STA 连接或断开。

## 覆盖用户故事

- `boot_app_state_starts_off`: 正向：应用刚启动时，`app_state` 为 `off`。
- `boot_wifi_state_starts_off`: 正向：应用刚启动时，`wifi_state` 为 `off`。
- `boot_does_not_connect`: 负向：应用刚启动后，如果用户没有操作，应用不会主动请求连接 WiFi。
- `off_short_click_keeps_app_off`: 负向：`app_state` 为 `off` 时，用户短按 `Btn`，`app_state` 保持 `off`。
- `off_short_click_keeps_wifi_off`: 负向：`app_state` 为 `off` 时，用户短按 `Btn`，`wifi_state` 保持 `off`。
- `off_short_click_does_not_request_connect`: 负向：`app_state` 为 `off` 时，用户短按 `Btn`，应用不会请求连接 WiFi。
- `off_hold_3s_sets_app_on`: 正向：`app_state` 为 `off` 时，用户长按 `Btn` 满 3 秒，`app_state` 进入 `on`。
- `off_hold_3s_keeps_wifi_off`: 负向：`app_state` 为 `off` 时，用户长按 `Btn` 满 3 秒开机后，`wifi_state` 仍保持 `off`。
- `off_hold_3s_does_not_request_connect`: 负向：`app_state` 为 `off` 时，用户长按 `Btn` 满 3 秒开机后，应用不会请求连接 WiFi。
- `off_hold_over_3s_fires_power_on_once`: 负向：`app_state` 为 `off` 时，用户持续按住 `Btn` 超过 3 秒，本次按住只触发一次开启动作，不会继续触发关闭。
- `off_hold_over_3s_keeps_app_on`: 负向：`app_state` 为 `off` 时，用户持续按住 `Btn` 超过 3 秒并进入 `on` 后，在用户松手前不会因为同一次按住继续切换应用状态。
- `off_hold_over_3s_keeps_wifi_off`: 负向：`app_state` 为 `off` 时，用户持续按住 `Btn` 超过 3 秒并进入 `on` 后，在用户松手前不会因为同一次按住把 `wifi_state` 改为 `on`。
- `off_hold_release_keeps_app_on`: 负向：`app_state` 为 `off` 时，长按进入 `on` 后如果松手阶段再次收到相同长按时长，`app_state` 仍保持 `on`。
- `off_hold_release_keeps_wifi_off`: 负向：`app_state` 为 `off` 时，长按进入 `on` 后如果松手阶段再次收到相同长按时长，`wifi_state` 仍保持 `off`。
- `off_hold_less_than_3s_keeps_app_off`: 负向：`app_state` 为 `off` 时，用户长按 `Btn` 不足 3 秒，`app_state` 保持 `off`。
- `off_hold_less_than_3s_keeps_wifi_off`: 负向：`app_state` 为 `off` 时，用户长按 `Btn` 不足 3 秒，`wifi_state` 保持 `off`。
- `on_click_requests_connect_when_wifi_off`: 正向：`app_state` 为 `on` 且 `wifi_state` 为 `off` 时，用户短按 `Btn`，应用请求连接 WiFi。
- `on_click_sets_wifi_on_when_wifi_off`: 正向：`app_state` 为 `on` 且 `wifi_state` 为 `off` 时，用户短按 `Btn` 后，`wifi_state` 进入 `on`。
- `on_click_keeps_app_on`: 负向：`app_state` 为 `on` 时，用户短按 `Btn`，`app_state` 保持 `on`。
- `on_click_requests_disconnect_when_wifi_on`: 正向：`app_state` 为 `on` 且 `wifi_state` 为 `on` 时，用户短按 `Btn`，应用请求 WiFi STA 断开。
- `on_click_sets_wifi_off_when_wifi_on`: 正向：`app_state` 为 `on` 且 `wifi_state` 为 `on` 时，用户短按 `Btn` 后，`wifi_state` 进入 `off`，不等待 WiFi STA 断开事件。
- `on_hold_3s_requests_disconnect_when_wifi_on`: 正向：`app_state` 为 `on` 且 `wifi_state` 为 `on` 时，用户长按 `Btn` 满 3 秒，应用请求 WiFi STA 断开。
- `on_hold_3s_enters_app_off`: 正向：`app_state` 为 `on` 时，用户长按 `Btn` 满 3 秒，`app_state` 进入 `off`。
- `on_hold_3s_sets_wifi_off`: 正向：`app_state` 为 `on` 时，用户长按 `Btn` 满 3 秒，`wifi_state` 进入 `off`。
- `on_hold_less_than_3s_keeps_app_on`: 负向：`app_state` 为 `on` 时，用户长按 `Btn` 不足 3 秒，`app_state` 保持 `on`。
- `on_hold_less_than_3s_keeps_wifi_state`: 负向：`app_state` 为 `on` 时，用户长按 `Btn` 不足 3 秒，`wifi_state` 保持不变。
- `wifi_sta_connected_event_does_not_change_app_state`: 负向：WiFi STA 上报连接成功时，应用不会改变 `app_state`。
- `wifi_sta_connected_event_does_not_change_wifi_intent`: 负向：WiFi STA 上报连接成功时，应用不会改变 `wifi_state`。
- `wifi_sta_disconnected_event_does_not_change_app_state`: 负向：WiFi STA 上报断开时，应用不会改变 `app_state`。
- `wifi_sta_disconnected_event_does_not_change_wifi_intent`: 负向：WiFi STA 上报断开时，应用不会改变 `wifi_state`。
- `button_press_only_changes_intent_state`: 负向：用户按 `Btn` 只改变 `app_state` 或 `wifi_state`，不直接伪造底层连接成功或断开成功结果。
- `gizclaw_connecting_event_updates_state`: 正向：收到 `gizclaw.set_state` 自定义事件后，GizClaw 状态进入 `connecting`。
- `gizclaw_connected_event_updates_state`: 正向：收到 `gizclaw.set_state` 自定义事件后，GizClaw 状态进入 `connected`。
- `gizclaw_disconnected_event_updates_state`: 正向：收到 `gizclaw.set_state` 自定义事件后，GizClaw 状态进入 `disconnected`。
