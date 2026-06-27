**Scope:** how to build, flash, and test the AgentKeys on-device firmware on the Waveshare
**ESP32-S3-Touch-LCD-4B** (issue [#348](https://github.com/litentry/agentKeys/issues/348)). The
device is a thin voice client to its assigned cloud agent (a `hermes-sandbox` instance); the LVGL
UI mirrors the `volcano-probe` TUI. Source: [`firmware/esp32s3-touch-lcd-4b`](../../firmware/esp32s3-touch-lcd-4b/README.md).

**Status (phased delivery):** P0 board bring-up + P1 LVGL UI + the agent `/v1/chat` client ship
today and are testable below. **Pairing (P2), voice/audio (P3), and WebSocket-Opus streaming (P4)
are not finished** — the runbook calls out exactly what works versus what is a no-op so far.

## Quick start (one script)

Plug the board into USB-C and run the idempotent wrapper — it checks/installs the toolchain, builds,
and flashes, auto-detecting the serial port:

```bash
bash firmware/esp32s3-touch-lcd-4b/setup-esp32.sh             # toolchain → build → flash
bash firmware/esp32s3-touch-lcd-4b/setup-esp32.sh --monitor   # …then open the serial monitor
bash firmware/esp32s3-touch-lcd-4b/setup-esp32.sh --no-flash  # toolchain + build only (no board)
```

Re-runnable: each step pre-checks state and logs `ok` / `skip` / `fail`. **Port detection is
VID-agnostic** — a candidate is *any* USB serial device (it has a USB vendor id; the OS's internal
Bluetooth/debug ports don't), so a brand-new board with an unfamiliar chip is found with no
maintained allowlist. One device → auto; several connected → it lists them and you pick; none → a
clear error (and no zsh glob abort). It also auto-recovers from a truncated component download.
Override with `--port /dev/cu.usbmodemXXX` or `--idf-path <path-to-esp-idf>`.

The numbered sections below are the manual reference for what the script does, and where to look
when a step needs hand-holding.

## 1. What you need

**Hardware**

- Waveshare **ESP32-S3-Touch-LCD-4B** board.
- A **data** USB-C cable (not a charge-only cable) from your computer to the board's USB-C port.
- A 2.4 GHz WiFi network the board can reach.
- (For the agent test) a reachable **agent endpoint** — a running `hermes-sandbox` bridge over
  HTTPS — and its **bearer** (`AGENTKEYS_BRIDGE_TOKEN`, PR [#347](https://github.com/litentry/agentKeys/pull/347)).

**Host toolchain: ESP-IDF ≥ 5.3** (the BSP's floor). Either the
[VS Code ESP-IDF extension](https://github.com/espressif/vscode-esp-idf-extension) (pick a version
≥ 5.3 in the setup wizard), or the CLI:

```bash
mkdir -p ~/esp && cd ~/esp
git clone -b release/v5.4 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh esp32s3
. ./export.sh          # run this in every new shell (puts idf.py on PATH)
```

**Already cloned `esp-idf`?** Skip the clone — `cd` into it, run `./install.sh esp32s3` once (it
installs the toolchain into `~/.espressif`), then `. ./export.sh`. Until you source `export.sh` in
the current shell, `$IDF_PATH` is empty — so `. $IDF_PATH/export.sh` resolves to `/export.sh` and
fails with `no such file or directory`.

## 2. Configure the device

```bash
cd firmware/esp32s3-touch-lcd-4b
cp main/secrets.h.example main/secrets.h
```

Edit `main/secrets.h`:

| Define | Set to |
|---|---|
| `WIFI_SSID` / `WIFI_PASSWORD` | your 2.4 GHz network |
| `AGENT_BASE_URL` | the assigned agent, e.g. `https://<instance>.<vefaas-gateway>` |
| `AGENT_BEARER` | the instance's `AGENTKEYS_BRIDGE_TOKEN` (empty only if the bridge runs unauthenticated dev mode) |
| `BROKER_URL` | the broker, e.g. `https://broker.<zone>` (used by pairing, P2) |

`secrets.h` is gitignored. Production devices receive these from **NVS** at provisioning instead
(precedence: NVS > `secrets.h` > defaults — see [`main/app_config.h`](../../firmware/esp32s3-touch-lcd-4b/main/app_config.h)).
You can build and exercise the UI **without** an agent — the agent calls just report failure.

## 3. Build

```bash
idf.py set-target esp32s3      # once per checkout
idf.py build
```

The first build downloads the board BSP
([`waveshare/esp32_s3_touch_lcd_4b`](https://components.espressif.com/components/waveshare/esp32_s3_touch_lcd_4b))
and LVGL into `managed_components/` — this needs internet access to `components.espressif.com`.

## 4. Flash + monitor

```bash
idf.py -p <PORT> flash monitor
```

Find `<PORT>`:

- **macOS:** run `ls /dev/cu.*` and pick the `usbmodem…` (ESP32-S3 native USB-Serial-JTAG) or `wchusbserial…`/`usbserial…` entry. Do **not** run `ls /dev/cu.usbserial*` on its own — zsh aborts the whole command (`no matches found`) if that glob matches nothing, hiding the `usbmodem` port.
- **Linux:** `/dev/ttyACM0` or `/dev/ttyUSB0`  (add yourself to the `dialout` group if permission-denied)
- **Windows:** `COMx` (Device Manager → Ports)

The board has an onboard auto-download circuit, so flashing normally needs no button presses (as
Waveshare's docs note). If you see `Failed to connect ... No serial data received`, press **RESET**
for >1 s and retry; if it still fails, hold **BOOT**, tap **RESET**, release **BOOT**, and re-run.
Exit the monitor with **Ctrl-]**.

## 5. First-boot checklist

On the **serial monitor** (115200 baud) you should see lines from the `app` and `wifi` log tags:

```
I (...) app:  AgentKeys Touch-LCD-4B firmware v…
I (...) wifi: connecting to <SSID>
I (...) app:  boot complete
I (...) wifi: got ip 192.168.x.y      ← WiFi connects asynchronously; may print after "boot complete"
```

On the **screen**: the Home / Conversation view — the welcome bubble *"Hi! Hold TALK to speak with
me."*, a large **TALK** button, and a top status bar. The WiFi icon turns green once connected;
**AGENT** turns green within ~10 s if the configured agent answers `/healthz` (the health task polls
every 10 s, but only after WiFi is up). Tap **Settings** and **Pair** to confirm the screens are
touch-navigable.

## 6. Test the agent (works today)

1. On Home, **press and hold TALK** → the button shows *Listening...* → **release**. A user bubble
   appears, then the agent's reply **streams in** token by token.
   - In this phase TALK does not yet capture audio (ES8311 mic + ASR is P3): releasing sends a
     **fixed placeholder turn**, so the user bubble reads *"Hello! Tell me something interesting in
     one sentence."* — not your speech. That exercises the real `/v1/chat` streaming path end to end.
   - No agent configured / unreachable → the bubble shows `[agent unreachable]`,
     `[agent error] HTTP <code>`, or `[agent error] <message>` — an honest failure, not a crash (the
     serial log adds `agent: turn failed: …`).
2. Cross-check the same endpoint from your computer (replace `<agent>`; the token is an env var,
   never paste it literally):

   ```bash
   curl -sS https://<agent>/healthz
   curl -sS https://<agent>/v1/chat \
     -H "Authorization: Bearer $AGENTKEYS_BRIDGE_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"text":"hi","stream":false}'
   ```

   A **401** with no/!wrong bearer is expected (PR #347 hardening); `/healthz` is open and returns
   `{"ok":true,...}`.

## 7. Test pairing (P2 — partial)

Open **Pair**, tap **Request**. The device calls `{AGENT_BASE_URL}/v1/pairing/request`, and on
success unhides the QR (hidden until a deep-link exists) rendering the real
`agentkeys-pair://claim?...` deep-link + the short `Code …` and `device-key …` labels, then polls
until the master claims it in the parent-control app (→ *"✓ Paired"*). See
[on-device agent + AgentKeys](./on-device-agent-and-agentkeys.md) for the owner-side flow.

> **Not wired yet:** the agent-side `/v1/pairing/{request,poll}` endpoints do not exist — the bridge
> must front the daemon's `--request-pairing` / `--retrieve-pairing` (a `hermes-sandbox` + daemon
> follow-up). Until then **Request** ends in *"⚠ Pairing failed - tap Request to retry"* on purpose,
> and the QR stays hidden (the firmware never fabricates a fake QR). When the endpoint lands, this
> section becomes a full QR-scan test with no firmware change.

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `. $IDF_PATH/export.sh` → `no such file or directory: /export.sh` | ESP-IDF cloned but `install.sh` not run / not sourced, so `$IDF_PATH` is empty | `cd ~/esp/esp-idf && ./install.sh esp32s3 && . ./export.sh` (install once; source per shell) |
| Board not detected by `flash` | charge-only cable, or wrong port | use a **data** USB-C cable; pick the right `-p` port; force download mode (BOOT+RESET) |
| `idf.py build` fails fetching components | no access to `components.espressif.com` | allow internet; then `idf.py reconfigure` |
| `component.zip is not a zip file` (during `set-target`/`build`) | a managed-component download arrived truncated/corrupt (flaky link) | `rm -rf managed_components dependencies.lock build && idf.py set-target esp32s3` — forces a clean re-download |
| Wrong target / `set-target` skipped | built for the default chip | `idf.py set-target esp32s3 && idf.py fullclean build` |
| White or garbled display | PSRAM not octal / stale config | confirm `idf.py set-target esp32s3`; `idf.py fullclean build` (sdkconfig.defaults sets octal PSRAM) |
| Screen black, serial fine | backlight / board power | the BSP enables backlight in `bsp_display_start`; check board revision + USB power |
| `[wifi] ... disconnected` loop | wrong creds or WPA3-only AP | verify `secrets.h`; use WPA2 or WPA2/WPA3-mixed |
| `esp-tls`/handshake error in a turn | agent cert not in the CA bundle | the full mbedTLS bundle is enabled by default; for a private CA, add it to the bundle |
| `[agent error] HTTP 401` in a bubble | wrong/missing bearer | set `AGENT_BEARER` to the instance's `AGENTKEYS_BRIDGE_TOKEN` |
| `[agent unreachable]` | DNS/route, or agent down | check `AGENT_BASE_URL`; confirm the agent runs; `curl` it from the same network |

## 9. Reflash / reset

```bash
idf.py -p <PORT> erase-flash    # wipe NVS + app (full clean device)
idf.py -p <PORT> flash monitor  # reflash
idf.py fullclean                # host-side: force a clean rebuild
```

## Relation to Waveshare's official docs

This runbook uses the **same ESP-IDF toolchain and the same operations** as the official
[Waveshare wiki](https://www.waveshare.com/wiki/ESP32-S3-Touch-LCD-4B): set target `esp32s3`, build,
flash, and serial-monitor at 115200, with COM-port selection and the download-on-failure reset. The
only difference is **how you invoke them** — Waveshare documents the VS Code Espressif-IDF extension
buttons; this runbook uses the equivalent CLI:

| Waveshare wiki (VS Code Espressif-IDF extension button) | This runbook (CLI) |
|---|---|
| ③ Set device target → `esp32s3` | `idf.py set-target esp32s3` |
| ⑥ Build | `idf.py build` |
| ⑧ Flash (select COM port) | `idf.py -p <PORT> flash` |
| ⑨ Monitor | `idf.py monitor` |
| ⑪ "Build Flash Monitor" one-click (the "little flame") | `idf.py -p <PORT> flash monitor` |

The extension buttons are thin wrappers over those exact `idf.py` commands, so the paths are
equivalent — the CLI is Espressif's own first-class path, the extension is Waveshare's documented
one. You do **not** need `menuconfig` (Waveshare button ④): our
[`sdkconfig.defaults`](../../firmware/esp32s3-touch-lcd-4b/sdkconfig.defaults) pins octal PSRAM, the
16 MB flash size, the mbedTLS CA bundle, and the LVGL options.

**Two deliberate differences from Waveshare's *demo* projects** (cleaner, supported paths — not
toolchain deviations):

- **Drivers** — Waveshare's demo zips vendor the panel/touch/audio drivers inside each demo folder.
  We depend instead on the **official Waveshare BSP component**
  [`waveshare/esp32_s3_touch_lcd_4b`](https://components.espressif.com/components/waveshare/esp32_s3_touch_lcd_4b)
  from the Espressif registry (auto-downloaded on first build), so the pins live in one versioned,
  upstream-maintained place rather than a copied demo.
- **Project** — we build our own app, not a Waveshare demo; the build/flash mechanics are identical.

**Optional board smoke-test (Waveshare §5 "Flash Firmware Flashing and Erasing"):** to verify a
freshly-arrived board before building anything, flash Waveshare's **prebuilt test/factory firmware**
(the `Firmware/` bin in their demo pack — an esp-brookesia + Xiaozhi-AI image) with the **Espressif
Flash Download Tool**. That flashes *their* image, not ours — a hardware check, not part of this
build path.

## Related

- Firmware source + architecture: [`firmware/esp32s3-touch-lcd-4b/README.md`](../../firmware/esp32s3-touch-lcd-4b/README.md)
- Device ↔ agent protocol: PR [#347](https://github.com/litentry/agentKeys/pull/347)
- The dev harness that simulates this device: the `volcano-probe` TUI
- Owner-side pairing + permissions: [on-device agent + AgentKeys](./on-device-agent-and-agentkeys.md), [arch.md](../arch.md)
