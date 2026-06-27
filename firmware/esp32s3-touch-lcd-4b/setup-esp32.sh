#!/usr/bin/env bash
# setup-esp32.sh — idempotent one-shot for the AgentKeys ESP32-S3-Touch-LCD-4B firmware:
#   1) ensure the ESP-IDF toolchain   2) build the image   3) flash the board (auto-detect port)
#
# Re-runnable: every step pre-checks state and logs `ok` / `skip` / `fail`. Auto-detects the serial
# port by USB vendor id (Espressif 0x303a, CH34x 0x1a86, CP210x 0x10c4, FTDI 0x0403), and
# auto-recovers from a truncated managed-component download. Full reference + troubleshooting:
#   docs/wiki/esp32s3-touch-lcd-4b-flash-and-test.md
#
# Usage:
#   bash setup-esp32.sh                 # toolchain -> build -> flash (auto port)
#   bash setup-esp32.sh --monitor       # ...and open the serial monitor after flashing
#   bash setup-esp32.sh --no-flash      # toolchain + build only (no board needed)
#   bash setup-esp32.sh --port /dev/cu.usbmodem101   # force a specific port
#   bash setup-esp32.sh --idf-path ~/esp/esp-idf     # where ESP-IDF is cloned (default: $IDF_PATH or ~/esp/esp-idf)
set -euo pipefail

TARGET="esp32s3"
FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
IDF_DIR="${IDF_PATH:-$HOME/esp/esp-idf}"
PORT="${ESPPORT:-${ESP_PORT:-}}"
DO_FLASH=1
DO_MONITOR=0

while [ $# -gt 0 ]; do
  case "$1" in
    --no-flash|--build-only) DO_FLASH=0 ;;
    -m|--monitor)            DO_MONITOR=1 ;;
    -p|--port)               PORT="${2:?--port needs a value}"; shift ;;
    --idf-path)              IDF_DIR="${2:?--idf-path needs a value}"; shift ;;
    -h|--help)               grep -E '^#( |!)' "$0" | sed -E 's/^#!?[[:space:]]?//'; exit 0 ;;
    *) echo "fail unknown arg: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

log(){ printf '%s %s\n' "$1" "${*:2}"; }

# --- 1. toolchain (idempotent: skip if idf.py already live; install tools only once) ---
ensure_toolchain(){
  if command -v idf.py >/dev/null 2>&1; then
    log skip "toolchain: idf.py already on PATH"
    return
  fi
  [ -f "$IDF_DIR/export.sh" ] || {
    log fail "ESP-IDF not found at $IDF_DIR — clone it first:"
    echo "      git clone -b release/v5.4 --recursive https://github.com/espressif/esp-idf.git \"$IDF_DIR\"" >&2
    exit 1
  }
  if [ -d "$HOME/.espressif" ] || { [ -n "${IDF_TOOLS_PATH:-}" ] && [ -d "${IDF_TOOLS_PATH:-/nonexistent}" ]; }; then
    log skip "toolchain: ESP-IDF tools already installed"
  else
    log ok "toolchain: installing ESP-IDF tools for $TARGET (one-time; ~1-2 GB)"
    ( cd "$IDF_DIR" && ./install.sh "$TARGET" )
  fi
  # shellcheck disable=SC1091
  . "$IDF_DIR/export.sh" >/dev/null 2>&1 || { log fail "toolchain: export.sh failed"; exit 1; }
  command -v idf.py >/dev/null 2>&1 || { log fail "toolchain: idf.py still missing after export"; exit 1; }
  log ok "toolchain: ready"
}

# --- 2. per-device config (idempotent: create secrets.h from the example only if missing) ---
ensure_secrets(){
  if [ -f "$FW_DIR/main/secrets.h" ]; then
    log skip "config: main/secrets.h present"
  else
    cp "$FW_DIR/main/secrets.h.example" "$FW_DIR/main/secrets.h"
    log ok "config: created main/secrets.h from example — EDIT it (WiFi + agent URL/bearer) for a useful run"
  fi
}

# --- 3. build (idempotent: set-target only if the cache target differs; clean-retry on a corrupt download) ---
build_fw(){
  cd "$FW_DIR"
  if [ -f build/CMakeCache.txt ] && grep -q "IDF_TARGET:STRING=$TARGET" build/CMakeCache.txt; then
    log skip "set-target: already $TARGET"
  else
    log ok "set-target $TARGET"
    idf.py set-target "$TARGET" || { log fail "set-target failed — clean re-resolve + retry"; rm -rf managed_components dependencies.lock build; idf.py set-target "$TARGET"; }
  fi
  log ok "build"
  if ! idf.py build; then
    log fail "build failed — clean component re-resolve + retry (truncated download?)"
    rm -rf managed_components dependencies.lock build
    idf.py set-target "$TARGET"
    idf.py build
  fi
  log ok "build complete: $(ls -1 build/*.bin 2>/dev/null | head -1)"
}

# --- port detection: VID-AGNOSTIC, no maintained allowlist. A candidate is ANY USB serial device
#     (it has a USB vendor id); the macOS internal ports (Bluetooth/debug-console/wlan-debug) have
#     no VID and are skipped. Known VIDs are only LABELED + ranked first — never used to exclude —
#     so a brand-new board with an unfamiliar chip still appears automatically. 1 match -> auto;
#     several -> you pick interactively; 0 -> clear error. Override anytime with --port / ESPPORT. ---
_list_usb_serial(){
  python - <<'PY' 2>/dev/null || true
try:
    from serial.tools import list_ports
except Exception:
    raise SystemExit(0)
KNOWN = {0x303a:"Espressif", 0x1a86:"CH34x", 0x10c4:"CP210x", 0x0403:"FTDI", 0x2341:"Arduino", 0x239a:"Adafruit"}
rows = []
for i in list_ports.comports():
    if i.vid is None:        # internal (Bluetooth/debug/wlan) ports have no VID -> not a real device
        continue
    rank = 0 if i.vid in KNOWN else 1
    rows.append((rank, i.device, f"{KNOWN.get(i.vid,'USB-serial')} {i.vid:#06x} {i.product or ''}".strip()))
rows.sort()
for _, dev, label in rows:
    print(f"{dev}\t{label}")
PY
}

CHOSEN_PORT=""
choose_port(){
  if [ -n "$PORT" ]; then CHOSEN_PORT="$PORT"; log ok "port: $CHOSEN_PORT (override)"; return; fi
  local devs=() labels=() dev label
  while IFS=$'\t' read -r dev label; do
    [ -n "$dev" ] && { devs+=("$dev"); labels+=("$label"); }
  done < <(_list_usb_serial)
  if [ "${#devs[@]}" -eq 0 ]; then                 # pyserial unavailable/empty -> /dev fallback
    shopt -s nullglob
    local g=(/dev/cu.usbmodem* /dev/cu.wchusbserial* /dev/cu.usbserial* /dev/ttyUSB* /dev/ttyACM*)
    shopt -u nullglob
    for dev in "${g[@]}"; do devs+=("$dev"); labels+=("(no VID info)"); done
  fi
  if [ "${#devs[@]}" -eq 0 ]; then
    log fail "port: no USB serial device found — plug the board into USB-C (use a DATA cable) or pass --port"; exit 1
  elif [ "${#devs[@]}" -eq 1 ]; then
    CHOSEN_PORT="${devs[0]}"; log ok "port: auto-detected ${CHOSEN_PORT}  (${labels[0]})"
  elif [ -t 0 ]; then
    echo "Multiple USB serial devices connected — pick the board:" >&2
    local i=0
    while [ "$i" -lt "${#devs[@]}" ]; do printf "  %d) %-26s %s\n" "$((i+1))" "${devs[$i]}" "${labels[$i]}" >&2; i=$((i+1)); done
    local sel; printf "port [1-%d]: " "${#devs[@]}" >&2; read -r sel </dev/tty
    case "$sel" in ''|*[!0-9]*) log fail "port: invalid selection"; exit 1 ;; esac
    { [ "$sel" -ge 1 ] && [ "$sel" -le "${#devs[@]}" ]; } || { log fail "port: out of range"; exit 1; }
    CHOSEN_PORT="${devs[$((sel-1))]}"; log ok "port: selected ${CHOSEN_PORT}"
  else
    log fail "port: ${#devs[@]} devices found and no TTY to prompt — pass --port. Candidates:"; printf '  %s\n' "${devs[@]}" >&2; exit 1
  fi
}

# --- 4. flash (auto / interactive port; optional monitor) ---
flash_fw(){
  cd "$FW_DIR"
  choose_port
  log ok "flash: writing to $CHOSEN_PORT"
  idf.py -p "$CHOSEN_PORT" flash
  log ok "flash: done"
  if [ "$DO_MONITOR" = 1 ]; then
    log ok "monitor: opening (Ctrl-] to exit)"
    idf.py -p "$CHOSEN_PORT" monitor
  else
    log ok "to watch it boot:  idf.py -p $CHOSEN_PORT monitor"
  fi
}

ensure_toolchain
ensure_secrets
build_fw
if [ "$DO_FLASH" = 1 ]; then flash_fw; else log skip "flash: skipped (--no-flash)"; fi
log ok "setup-esp32 complete"
