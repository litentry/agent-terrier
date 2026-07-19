# Device UI mirror (LVGL → WASM / SDL)

A browser (and desktop) simulator of the on-device UI. It compiles the **real**
firmware screens (`../main/ui/*.c`) and the **real** shared state (`../main/app_state.c`)
against LVGL's SDL backend, so the mirror **cannot drift** from the device — it *is* the
device's UI code, with only two things swapped:

- **display + touch** → LVGL's SDL window/mouse (browser canvas via Emscripten) instead of ST7701/GT911.
- **`net/`** (agent / pairing / WiFi) → depends on the build, see below.

A React re-implementation was rejected on purpose: it would be a second source of truth that
drifts from the C firmware. This shares one.

### Two modes

| | `net/` | What it proves |
|---|---|---|
| **browser (WASM)** | `mock_net.c` fixtures | pixels / layout / touch-UX. The `firmware-sim` CI gate. |
| **desktop (#517)** | the **real** `main/net/*.c` | the device actually *works*: real K10, real §10.2 pairing, real `/v1/chat` |

Desktop is the **mock device**: it runs the firmware's own `pairing.c`, `agent_client.c` and
`device_identity.c` — nothing about the broker, the daemon, or the pairing ceremony is faked.
Only the hardware is substituted (SDL for the panel; `desktop_wifi.c` for `wifi.c`, because a
laptop is already on a network and no broker contract lives there). The K10 crypto links the
**same** `agentkeys-device-core` staticlib the ESP32 does.

ESP-IDF calls are shimmed in `shims/`: `esp_http_client` → libcurl (keeping the *streaming*
pull semantics, so SSE tokens still arrive incrementally), `nvs` → a 0600 file, `esp_random` →
the OS CSPRNG (it seeds a real key), FreeRTOS tasks/queues/semaphores → pthreads. TLS is
libcurl's normal verification against the system trust store — never disabled.

## Run it (browser)

Needs the [Emscripten SDK](https://emscripten.org/docs/getting_started/downloads.html):

```bash
git clone https://github.com/emscripten-core/emsdk ~/emsdk
cd ~/emsdk && ./emsdk install latest && ./emsdk activate latest
source ~/emsdk/emsdk_env.sh        # in each shell

cd firmware/esp32s3-touch-lcd-4b/sim
bash watch.sh                       # build + serve http://localhost:8131 + rebuild-on-change
```

`watch.sh` rebuilds the WASM on every change to the UI sources and live-reloads the browser
(zero extra deps; `brew install fswatch` upgrades the poll loop to instant). `bash build.sh`
does a one-shot build into `build-web/`.

## Run it (desktop, optional)

The same sources build natively against system SDL2 for a faster inner loop / native debugging:

```bash
brew install sdl2 curl              # or apt-get install libsdl2-dev libcurl4-openssl-dev
cmake -S . -B build-pc && cmake --build build-pc

# Point it at a real broker — this is a REAL device, it pairs for real:
AGENTKEYS_BROKER_URL=https://broker.agentterrier.cn ./build-pc/mirror
```

The pairing code + deep-link are printed to stderr as well as rendered as a QR, so you can
claim the device in parent-control without squinting at the window:

```
I (device_id) K10 generated + stored: 0xe40e04af…
I (mirror)    device_key_hash 0x0414855e…  (identity file: ~/.agentkeys/mock-device/agentkeys.nvs)
I (pairing)   code:      cYb2AOSlWez3UZdQN4xgpzeX
I (pairing)   deep-link: agentkeys-pair://claim?code=…&broker=https://broker.agentterrier.cn
I (pairing) polling for the master's claim...
```

Restart it and the K10 is **loaded**, not regenerated (`K10 loaded from NVS`, same
`device_key_hash`) — it is a device with an identity, not a session. To factory-reset,
delete the identity file. To run several devices at once, give each its own:

```bash
AGENTKEYS_MOCK_DEVICE_DIR=/tmp/dev-a AGENTKEYS_BROKER_URL=… ./build-pc/mirror
```

Env: `AGENTKEYS_BROKER_URL` (pairing), `AGENTKEYS_AGENT_URL` + `AGENTKEYS_AGENT_BEARER`
(the agent bridge `/v1/chat` talks to), `AGENTKEYS_MOCK_DEVICE_DIR` (identity store).
Build the UI-only mirror instead with `-DAGENTKEYS_REAL_NET=OFF`.

### Talking to a spawned delegate

A spawn grants the delegate `channel-pub:opchat-<label>` + `channel-sub:opchat-<label>`. Pair
this device, accept it in parent-control with the mirrored grants, and it converses over the
real channel plane. The headless equivalent (no window, CI-runnable) is
`e2e/channel-e2e-demo.sh --from-step 17 --to-step 19` with `KD_SERVICES` pointed at the same
channel.

## CI

[`.github/workflows/firmware-sim.yml`](../../../.github/workflows/firmware-sim.yml) runs
`bash watch.sh --ci` (one-shot WASM build) on every PR that touches the screens or the sim, so a
UI change that breaks the mirror build is caught, and the built `build-web/` is uploaded as an
artifact (previewable / Pages-deployable).

## Files

| File | Role |
|---|---|
| `sim_main.c` | entry point: LVGL + SDL init, seed mock data, run the loop (`emscripten_set_main_loop` / native) |
| `mock_net.c` | stub `net/` impls (agent/pairing/WiFi) that drive `app_state` |
| `CMakeLists.txt` | Emscripten/SDL build; fetches LVGL **v9.5.0** (pin matches the firmware's `esp_lvgl_port`) and configures it via defines (no `lv_conf.h`) |
| `shell.html` | the browser page (device-framed 480×480 canvas) |
| `shims/` | tiny headers so the firmware code compiles off-device: `esp_log.h` (→ stderr), `bsp/esp-bsp.h` (lock = no-op), `freertos/*` (recursive mutex = no-op; the sim is single-threaded) |
| `build.sh` / `watch.sh` | one-shot build / watch-rebuild-serve (+ `--ci`) |

**Fidelity note:** keep the `CMakeLists.txt` LVGL `GIT_TAG` equal to the firmware's LVGL version
(today **9.5.0**) — a mismatch is the one way the mirror could render differently from the device.
