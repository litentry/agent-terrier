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
- **device identity (K10)** ✅ — `net/device_identity.c` generates (first boot, from `esp_fill_random`)
  or loads the secp256k1 K10 via the shared `agentkeys-device-core` FFI (issue #367), persists it in
  NVS, and logs the address + `device_key_hash` at boot. Phase B wires `device_identity_pop_sig()`
  into §10.2 pairing. See "Shared Rust device-core" below.
- **P2 pairing (device-direct §10.2)** ✅ — `net/pairing.c` does the §10.2 ceremony **directly against
  the broker** with the device's own K10 (`device_identity`): pop_sig-authenticated `POST
  /v1/agent/pairing/request` → shows the `agentkeys-pair://claim` QR → polls `/v1/agent/pairing/poll`
  until the master's claim mints `J1_agent` → bound. No agent-bridge endpoint, no server change (the
  broker §10.2 routes are already deployed) — this retires the old bridge dependency. (On-device WiFi
  provisioning / SoftAP is the remaining P2 item.)
- **P3 voice** ⏳ — ES8311 mic capture → ASR → `/v1/chat` → streamed TTS → speaker + barge-in.
- **P4 streaming + polish** ⏳ — WebSocket-Opus streaming (Xiaozhi-style), real voice catalog,
  battery SoC, per-round metrics.

## File layout

```
firmware/esp32s3-touch-lcd-4b/
├── CMakeLists.txt            # ESP-IDF project root
├── sdkconfig.defaults        # octal PSRAM, 16 MB flash, LVGL qrcode, mbedTLS CA bundle
├── partitions.csv            # single-app 16 MB layout
├── components/
│   └── agentkeys_device/     # builds agentkeys-device-core as an xtensa no_std staticlib
│       ├── CMakeLists.txt    #   + links it (issue #367 anti-drift)
│       └── include/agentkeys_device.h  # GENERATED FFI header (cbindgen, never hand-edited)
└── main/
    ├── idf_component.yml      # depends on waveshare/esp32_s3_touch_lcd_4b ^2.0.0
    ├── app_main.c             # boot: NVS → board → ui_init → wifi + device identity + health poll
    ├── app_config.h           # config layering (NVS > secrets.h > defaults)
    ├── app_state.{h,c}        # thread-safe shared state (conn, pairing, settings, conversation)
    ├── ui/
    │   ├── ui.{h,c}           # screen manager, status bar, theme, nav, refresh timer
    │   └── screen_*.c         # home / pairing / settings / connection / voices
    └── net/
        ├── agent_client.{h,c}    # /v1/chat bearer + SSE (PR #347) + /healthz
        ├── pairing.{h,c}         # §10.2 request + poll → bound
        ├── device_identity.{h,c} # K10 keygen/load via the shared crate's FFI → NVS (#367)
        └── wifi.{h,c}            # WiFi STA + auto-reconnect
```

## Threading

LVGL is single-threaded. Network tasks (WiFi, agent client, pairing) only ever mutate `app_state`
(mutex-guarded) and bump a revision counter; the LVGL refresh timer redraws the active screen when
the revision changes. Screen switches from any task take the BSP's recursive LVGL lock. No task
touches an `lv_obj_t` outside that lock.

## Shared Rust device-core (K10 identity, issue #367)

The device's K10 crypto — secp256k1 keygen, the `device_key_hash`, and the EIP-191 `pop_sig` the
broker `ecrecover`s — is **not** reimplemented in C. The firmware links
[`crates/agentkeys-device-core`](../../crates/agentkeys-device-core), the **same** `#![no_std]` Rust
crate the daemon + broker use, compiled for Xtensa as a staticlib. One implementation, two targets →
the bytes can't drift; the daemon-vs-device parity problem becomes a build concern, not a runtime
mystery. (This extends the same "ONE owner" pattern the wire protocol already uses across native + wasm.)

- `components/agentkeys_device/CMakeLists.txt` builds the crate with
  `cargo +esp rustc --features freestanding --crate-type staticlib --target xtensa-esp32s3-none-elf -Zbuild-std=core,alloc`
  and links the resulting `.a` (panic=abort; the crate brings its own panic handler + a C-malloc-backed
  global allocator under the `freestanding` feature). `-Zbuild-std` compiles core+alloc from `rust-src`
  because the esp toolchain ships no precompiled std for `xtensa-esp32s3-none-elf`.
- `net/device_identity.c` wraps the FFI: generate-on-first-boot from `esp_fill_random` (run **after**
  WiFi so the RNG has RF entropy) → store the 32-byte K10 in NVS → expose `address` / `device_key_hash`
  / `pop_sig` / `delegation_sig`. The key is born on the device and never leaves.
- `include/agentkeys_device.h` is **generated** — `bash crates/agentkeys-device-core/gen-header.sh`
  (cbindgen) — so the C header can't drift from `ffi.rs`. CI (`.github/workflows/firmware-sim.yml`)
  gates the no_std build, the staticlib link, and header freshness.

**Device→sandbox delegation (issue #369).** So a cloud sandbox can reach the user's workers
(memory / creds) without ever holding the K10, the device co-signs a short-lived, scoped
delegation to the sandbox's OWN ephemeral key — `ak_device_delegation_sig` /
`device_identity_delegation_sig(sandbox_key, scope, expires_at)` — signing
`keccak256("agentkeys-delegation:v1:" || device_key_hash || ":" || sandbox_key || ":" || scope_hash
|| ":" || expires_at)`. The worker re-`ecrecover`s it (the native `verify_delegation`) and checks
`keccak(signer) == device_key_hash`, so a sandbox compromise can't forge authority — the exact same
no_std bytes, gated by the `delegation_sig == golden vector` check in the C smoke harness. One K10 use
per sandbox spawn (the bootstrap), never per worker op. The broker relay that carries the sandbox key
to the device + the worker-side `delegation_path` verify are the next slice; the boot **`delegation
self-check (#369)`** log line is the on-device proof the co-sign path links + has crypto-worker stack.

**Toolchain (one-time):** the ESP32-S3 is Xtensa, which needs Espressif's Rust fork:

```bash
cargo install espup && espup install && rustup component add rust-src --toolchain esp
```

Do **not** `source ~/export-esp.sh` for the IDF build — it prepends espup's `xtensa-esp-elf-gcc` and
shadows ESP-IDF's own GCC (`idf.py` then fails `Tool doesn't match supported version`). The build uses
`cargo +esp` (no GCC needed for a pure-Rust archive), so ESP-IDF's GCC stays first on PATH. After that,
`idf.py build` drives the staticlib build automatically through the component.

## Related

- **Flash & test runbook**: [docs/wiki/esp32s3-touch-lcd-4b-flash-and-test](../../docs/wiki/esp32s3-touch-lcd-4b-flash-and-test.md)
- Device ↔ agent protocol: PR [#347](https://github.com/litentry/agentKeys/pull/347) (bridge bearer + pairing deep-link)
- The dev harness that simulates this device: the `volcano-probe` TUI
- Pairing ceremony (§10.2) + canonical deep-link: [`docs/arch.md`](../../docs/arch.md)
