# AgentKeys on-device firmware — Waveshare ESP32-S3-Touch-LCD-4B

Issue [#348](https://github.com/litentry/agentKeys/issues/348). The real device firmware that
mirrors the `volcano-probe` dev-harness TUI onto a 4" touch screen.
The device is a thin **voice client** to its assigned cloud agent (a
`hermes-sandbox` instance): it talks over WiFi using the PR
[#347](https://github.com/litentry/agentKeys/pull/347) contract (bearer-gated `/v1/chat`, the
`agentkeys-pair://claim` deep-link) and renders the TUI's screens in LVGL.

> This is a **separate project** from [`../esp32s3-agentkeys`](../esp32s3-agentkeys), which targets
> the ESP32-S3-DevKitC-1 (a USB-CDC text demo, issue #103). This one targets the Touch-LCD-4B
> (480×480 display + touch + audio).

## Board

Waveshare **ESP32-S3-Touch-LCD-4B** — a complete voice-device platform:

- **ESP32-S3-WROOM-1-N16R8** — dual-core LX7 @240 MHz, **16 MB flash / 8 MB octal PSRAM**, WiFi + BLE
- **4" 480×480 RGB IPS capacitive touch** — ST7701 (RGB) + GT911 (I2C)
- **ES8311** audio codec + **ES7210** echo-cancellation + onboard mic + 8 Ω speaker
- **TCA9554** I2C IO-expander, QMI8658 IMU, AXP2101 PMIC + battery

**All board pins are owned by the official BSP** —
[`waveshare/esp32_s3_touch_lcd_4b`](https://components.espressif.com/components/waveshare/esp32_s3_touch_lcd_4b)
(in `main/idf_component.yml`). The firmware never hand-codes a GPIO; it calls `bsp_i2c_init()`,
`bsp_display_start()`, `bsp_display_lock/unlock()`, and (P3) `bsp_audio_*`. The BSP transitively
pulls LVGL v9, `esp_lvgl_port`, and `esp_codec_dev`.

## Build

Requires **ESP-IDF ≥ 5.3** (the BSP's floor).

**Fastest path — one idempotent script** (toolchain check → build → flash; auto-detects the port —
any USB serial device, and prompts if several are connected):

```bash
bash setup-esp32.sh             # add --monitor to watch boot, --no-flash to build only
```

Or do it by hand:

```bash
# One-time: install ESP-IDF ≥5.3 (full steps + flashing runbook:
# docs/wiki/esp32s3-touch-lcd-4b-flash-and-test.md). Then source it in EACH shell —
# this sets IDF_PATH + puts idf.py on PATH (a bare $IDF_PATH is empty until you do):
. ~/esp/esp-idf/export.sh    # use the path where you cloned esp-idf
cd firmware/esp32s3-touch-lcd-4b

# Per-device dev config (WiFi creds + the agent endpoint/bearer)
cp main/secrets.h.example main/secrets.h    # then edit

idf.py set-target esp32s3
idf.py build flash monitor
```

The first build downloads the BSP + LVGL from the component registry into `managed_components/`
(gitignored). Production devices get WiFi creds + the agent base URL/bearer from **NVS** at
provisioning instead of `secrets.h` (see `app_config.h` precedence: NVS > secrets.h > defaults).

**Full step-by-step flash + test runbook** (toolchain install, port selection, first-boot
checklist, agent + pairing tests, troubleshooting table):
[Flash & test the ESP32-S3-Touch-LCD-4B](../../docs/wiki/esp32s3-touch-lcd-4b-flash-and-test.md).

## Screens (mirrors the TUI)

| Screen | Mirrors | Status |
|---|---|---|
| **Home / Conversation** — chat bubbles, live streaming reply, big hold-to-**TALK** button, status bar | TUI conversation pane + header | P1 ✅ (text turn; voice in P3) |
| **Pairing** — the real `agentkeys-pair://claim` deep-link as a QR + short code + device-key hash, unbound→bound | TUI `p` | P1 ✅ UI / P2 wiring |
| **Settings** — speak on/off, speech speed, Voice ›, Connection › | TUI `t` / speed / `v` | P1 ✅ |
| **Connection** — WiFi · IP · agent · broker + live state | header | P1 ✅ (provisioning UI P2) |
| **Voice picker** — scrollable voice list | TUI Voices | P1 ✅ (catalog is mock; real catalog P4) |

The status bar (WiFi · agent · paired · 🔊 · battery) is backed by live `app_state` except battery
(AXP2101 SoC is a P4 TODO).

## Phase status

- **P0 bring-up** ✅ — ESP-IDF project + BSP dependency + memory/partition config; `app_main` brings
  up the board (I2C, ST7701 display, LVGL task).
- **P1 UI shell** ✅ — all five screens in LVGL, touch-navigable, with the status bar + the real
  QR widget. Demoable with mock data.
- **agent client** ✅ — `net/agent_client.c` speaks the PR #347 bridge contract exactly:
  `POST /v1/chat` with `Authorization: Bearer`, SSE parse of `token`/`tool_start`/`tool`/`done`/
  `error` streamed into the conversation; `GET /healthz` liveness. The TALK button drives a real
  text turn (P3 swaps the placeholder transcript for ES8311 mic → ASR).
- **P2 connection + pairing** ⏳ — `net/pairing.c` implements the request + poll flow against
  `{agent}/v1/pairing/{request,poll}` and surfaces failures honestly (no fake QR). **Blocked on the
  agent-side endpoint**: the bridge must front the daemon's `--request-pairing` / `--retrieve-pairing`
  (a `hermes-sandbox` + daemon follow-up). On-device WiFi provisioning (SoftAP/BLE) is also P2.
- **P3 voice** ⏳ — ES8311 mic capture → ASR → `/v1/chat` → streamed TTS → speaker + barge-in.
- **P4 streaming + polish** ⏳ — WebSocket-Opus streaming (Xiaozhi-style), real voice catalog,
  battery SoC, per-round metrics.

## File layout

```
firmware/esp32s3-touch-lcd-4b/
├── CMakeLists.txt            # ESP-IDF project root
├── sdkconfig.defaults        # octal PSRAM, 16 MB flash, LVGL qrcode, mbedTLS CA bundle
├── partitions.csv            # single-app 16 MB layout
└── main/
    ├── idf_component.yml      # depends on waveshare/esp32_s3_touch_lcd_4b ^2.0.0
    ├── app_main.c             # boot: NVS → board → ui_init → wifi + health poll
    ├── app_config.h           # config layering (NVS > secrets.h > defaults)
    ├── app_state.{h,c}        # thread-safe shared state (conn, pairing, settings, conversation)
    ├── ui/
    │   ├── ui.{h,c}           # screen manager, status bar, theme, nav, refresh timer
    │   └── screen_*.c         # home / pairing / settings / connection / voices
    └── net/
        ├── agent_client.{h,c} # /v1/chat bearer + SSE (PR #347) + /healthz
        ├── pairing.{h,c}      # §10.2 request + poll → bound
        └── wifi.{h,c}         # WiFi STA + auto-reconnect
```

## Threading

LVGL is single-threaded. Network tasks (WiFi, agent client, pairing) only ever mutate `app_state`
(mutex-guarded) and bump a revision counter; the LVGL refresh timer redraws the active screen when
the revision changes. Screen switches from any task take the BSP's recursive LVGL lock. No task
touches an `lv_obj_t` outside that lock.

## Related

- **Flash & test runbook**: [docs/wiki/esp32s3-touch-lcd-4b-flash-and-test](../../docs/wiki/esp32s3-touch-lcd-4b-flash-and-test.md)
- Device ↔ agent protocol: PR [#347](https://github.com/litentry/agentKeys/pull/347) (bridge bearer + pairing deep-link)
- The dev harness that simulates this device: the `volcano-probe` TUI
- Pairing ceremony (§10.2) + canonical deep-link: [`docs/arch.md`](../../docs/arch.md)
