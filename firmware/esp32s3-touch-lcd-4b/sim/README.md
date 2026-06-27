# Device UI mirror (LVGL → WASM / SDL)

A browser (and desktop) simulator of the on-device UI. It compiles the **real**
firmware screens (`../main/ui/*.c`) and the **real** shared state (`../main/app_state.c`)
against LVGL's SDL backend, so the mirror **cannot drift** from the device — it *is* the
device's UI code, with only two things swapped:

- **display + touch** → LVGL's SDL window/mouse (browser canvas via Emscripten) instead of ST7701/GT911.
- **`net/`** (agent / pairing / WiFi) → `mock_net.c`, which seeds `app_state` with sample data.

This is a *pixels / layout / touch-UX* mirror. Live agent/voice/pairing **behavior** is
exercised by the `volcano-probe` TUI, not here. A React re-implementation was rejected on
purpose: it would be a second source of truth that drifts from the C firmware. This shares one.

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
brew install sdl2                   # or apt-get install libsdl2-dev
cmake -S . -B build-pc && cmake --build build-pc && ./build-pc/mirror
```

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
