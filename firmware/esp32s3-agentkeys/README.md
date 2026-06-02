# AgentKeys ESP32-S3 demo firmware

Companion firmware for [issue #103](https://github.com/litentry/agentKeys/issues/103) — an ESP32-S3 device that talks to a cloud-hosted `agent-infra/sandbox` running Hermes + AgentKeys-injected memory.

## Hardware

- **Board**: ESP32-S3-DevKitC-1 (or any ESP32-S3-WROOM-1 board with native USB)
- **Connection**: USB-C cable from laptop to the board's USB-OTG port (NOT the UART port if your board has both)

## Build

Requires [PlatformIO](https://platformio.org/) (VSCode extension or CLI).

```bash
# Install PlatformIO CLI (one-time)
pipx install platformio  # or brew install platformio

# Configure WiFi credentials (one-time)
cp main/secrets.h.example main/secrets.h
# Edit main/secrets.h with your WiFi SSID/password

# Build + flash + monitor in one go
pio run -t upload -t monitor
```

First boot sequence (watch USB CDC console at 115200 baud):

```
[agentkeys] booting (version 0.1.0)
[wifi] connecting to <SSID>
[wifi] connected, ip=192.168.1.42
[agentkeys] ready (press BOOT button on GPIO 0 to chat)
```

Press the BOOT button (GPIO 0 on DevKitC-1), type a message + ENTER over USB CDC, watch the agent reply stream back.

## Config

Three sources, priority order (high → low):

1. **NVS** (persistent storage) — set via serial command `agentkeys config set <key> <value>` (TODO: implement CLI in `main/cli.c`)
2. **`main/secrets.h`** — compile-time defines, gitignored, copied from `secrets.h.example`
3. **Hardcoded defaults** in `main/config.h` — last-resort fallback

Config keys:

| Key | Default | Source |
|---|---|---|
| `wifi_ssid` | (must set) | secrets.h |
| `wifi_password` | (must set) | secrets.h |
| `sandbox_url` | `https://demo.aiosandbox.litentry.org/v1/chat` | config.h |
| `actor_token` | `demo_token_O_demo_001_changeme` | config.h |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Board not detected by `pio run -t upload` | Wrong USB port (UART instead of USB-OTG) | Use the USB-C port closest to the EN button; if your board has separate UART + USB ports, use USB |
| `[wifi] timeout` | Bad credentials or WPA3-only network | Verify `secrets.h`; ESP32-S3 supports WPA3-Personal but some routers need WPA2/WPA3-mixed mode |
| `[https] tls handshake failed` | Sandbox cert chain not in mbedTLS bundle | Make sure `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y` in `sdkconfig.defaults`; rebuild |
| `[chat] http 401` | Wrong actor token | Verify token matches sandbox's `AGENTKEYS_DEMO_ACTOR_TOKEN` env var |
| Garbage on serial monitor | Wrong baud rate | `pio device monitor` defaults to 115200 — match your terminal |

## File layout

```
firmware/esp32s3-agentkeys/
├── README.md                  # this file
├── platformio.ini             # board + framework + build flags
├── CMakeLists.txt             # ESP-IDF project root
├── sdkconfig.defaults         # ESP-IDF config overrides (USB CDC, PSRAM, mbedTLS)
├── partitions.csv             # NVS + factory + OTA partition layout
├── .gitignore                 # build/, .pio/, secrets.h
└── main/
    ├── CMakeLists.txt         # ESP-IDF component manifest
    ├── main.c                 # app_main + FreeRTOS task spawn
    ├── config.h               # SANDBOX_URL, ACTOR_TOKEN, GPIO pins, event bits
    ├── secrets.h.example      # WiFi creds template (copy → secrets.h)
    ├── wifi_sta.{h,c}         # WiFi STA + reconnect loop
    ├── https_chat.{h,c}       # POST /v1/chat with Bearer auth + JSON parse
    ├── button.{h,c}           # GPIO interrupt → FreeRTOS queue event
    └── led_status.{h,c}       # RGB LED state machine
```

## What's implemented vs TODO

| Module | v0 status |
|---|---|
| `main.c` | ✅ working — spawns tasks, prints ready |
| `wifi_sta.c` | ✅ working — STA mode + reconnect |
| `button.c` | ✅ working — GPIO interrupt + debounce |
| `led_status.c` | ⚠ stub — blinks on-board LED in a placeholder pattern |
| `https_chat.c` | ⚠ stub — currently echoes back user input; real `esp_http_client` POST is TODO |
| NVS config CLI | TODO — falls back to compile-time defaults from `secrets.h` |

## Related

- **Plan**: [`docs/plan/issue-103-aiosandbox-hermes-esp32-demo.md`](../../docs/plan/issue-103-aiosandbox-hermes-esp32-demo.md)
- **Sandbox-side runbook**: TBD (issue #103 step 12)
- **AgentKeys arch**: [`docs/arch.md`](../../docs/arch.md)
