#!/usr/bin/env bash
# Watch the firmware UI sources + the sim glue, rebuild the WASM mirror on every
# change, and serve it with live-reload. This is the local dev loop; the SAME build
# runs in CI via `--ci` (build once, no server/watch) so the mirror is gated on every
# PR that touches the screens.
#
#   bash watch.sh            # build + serve http://localhost:8131 + rebuild-on-change
#   PORT=9000 bash watch.sh  # custom port
#   bash watch.sh --ci       # build once and exit (CI gate; also --once)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]:-$0}")"
OUT="${OUT:-build-web}"
PORT="${PORT:-8131}"

build() { OUT="$OUT" bash build.sh; }

# CI / one-shot: just compile (gates drift). No browser, server, or watch loop.
if [ "${1:-}" = "--ci" ] || [ "${1:-}" = "--once" ]; then
  build
  exit 0
fi

# The real firmware UI + shared state, plus the sim glue — a change to any rebuilds.
WATCH=(../main/ui ../main/app_state.c ../main/app_state.h sim_main.c mock_net.c CMakeLists.txt shell.html)

# Live-reload with no extra dependency: bump a stamp file after each build and inject
# a 1s poller into the served index.html (re-injected each build, since the build
# overwrites it). The poller is a watch-only artifact — build.sh's output stays clean.
stamp() { date +%s > "$OUT/reload-stamp"; }
inject() {
  grep -q 'reload-stamp' "$OUT/index.html" 2>/dev/null && return 0
  local poll='<script>let s="";setInterval(async()=>{try{const r=await fetch("reload-stamp",{cache:"no-store"});const t=await r.text();if(s&&s!==t)location.reload();s=t}catch(e){}},1000);</script>'
  awk -v ins="$poll" '/<\/body>/{print ins} {print}' "$OUT/index.html" > "$OUT/index.html.tmp" \
    && mv "$OUT/index.html.tmp" "$OUT/index.html"
}

build; inject; stamp

( cd "$OUT" && python3 -m http.server "$PORT" >/dev/null 2>&1 ) &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT INT TERM
echo "ok serving  http://localhost:$PORT   (live-reload on)"
echo "ok watching ${WATCH[*]}"

rebuild() { echo "[watch] change → rebuild"; build && inject && stamp && echo "[watch] reloaded"; }

if command -v fswatch >/dev/null 2>&1; then
  fswatch -o "${WATCH[@]}" | while read -r _; do rebuild; done
else
  echo "[watch] fswatch not found — polling every 1.5s (brew install fswatch for instant rebuilds)"
  HASH=md5; command -v md5 >/dev/null 2>&1 || HASH=md5sum
  sig() { find "${WATCH[@]}" -type f -exec ls -ld {} + 2>/dev/null | "$HASH"; }
  last="$(sig)"
  while sleep 1.5; do
    cur="$(sig)"
    if [ "$cur" != "$last" ]; then last="$cur"; rebuild; fi
  done
fi
