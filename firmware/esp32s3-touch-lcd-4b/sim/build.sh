#!/usr/bin/env bash
# Build the device UI mirror to WASM (browser) via Emscripten. Needs the emsdk.
#   bash build.sh            # -> build-web/index.{html,js,wasm}
#   OUT=dist bash build.sh   # custom output dir
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]:-$0}")"
OUT="${OUT:-build-web}"

# Self-sufficient like setup-esp32.sh: if emcmake isn't already on PATH (e.g. a fleet
# job's bare shell, or any shell that didn't `source emsdk_env.sh`), auto-source a
# locally-installed emsdk before giving up.
if ! command -v emcmake >/dev/null 2>&1; then
  for envsh in "${EMSDK:+$EMSDK/emsdk_env.sh}" "$HOME/emsdk/emsdk_env.sh" /opt/emsdk/emsdk_env.sh; do
    # shellcheck disable=SC1090  # emsdk path is intentionally dynamic
    [ -n "$envsh" ] && [ -f "$envsh" ] && { . "$envsh" >/dev/null 2>&1; break; }
  done
fi
if ! command -v emcmake >/dev/null 2>&1; then
  echo "fail emsdk not found (emcmake/emcc not on PATH, and no emsdk_env.sh at \$EMSDK / ~/emsdk / /opt/emsdk)." >&2
  echo "     install once:  git clone https://github.com/emscripten-core/emsdk ~/emsdk \\" >&2
  echo "                    && cd ~/emsdk && ./emsdk install latest && ./emsdk activate latest" >&2
  echo "     after that this script auto-sources it; or add 'source ~/emsdk/emsdk_env.sh' to your shell profile." >&2
  exit 1
fi

emcmake cmake -S . -B "$OUT" -DCMAKE_BUILD_TYPE=Release
cmake --build "$OUT" -j
echo "ok built -> $OUT/index.html  (serve $OUT/ or open it)"
