#!/usr/bin/env bash
# scripts/check-web-api-drift.sh — the frontend↔daemon↔harness drift gate for
# the master-memory plant contract (issue #203 / the #206 parity ladder, rung 2).
#
# Phase 6 (web-parity-demo.sh) used to false-green: it `curl`s the daemon's
# `POST /v1/master/memory/plant` with a hand-built body, while the real frontend
# (apps/parent-control/lib/client/daemon.ts) builds its OWN body at the same URL.
# They agreed by manual coincidence — a daemon.ts route/shape change left phase 6
# green on the old path.
#
# This gate ties both consumers to ONE serde schema (the daemon's `ApiMemoryEntry`
# + the `MASTER_MEMORY_PLANT_ROUTE` const), captured in
# harness/fixtures/web-api/master_memory_plant.json. The Rust side is pinned by a
# unit test (ui_bridge.rs `master_memory_plant_contract_matches_fixture`); this
# script pins the two NON-Rust consumers:
#   - the route literal must appear verbatim in daemon.ts AND web-parity-demo.sh
#   - the `# @web-fixture: master_memory_plant` / `// @web-fixture: …`-annotated
#     entry object literal in each must have exactly the fixture's `entry_keys`.
#
# A drifted route or entry shape (rename/add/drop) on either side is now CI-red
# instead of a stale green. Exit 0 = clean; 1 = drift; 2 = setup error.
#
#   bash scripts/check-web-api-drift.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$REPO_ROOT/harness/fixtures/web-api/master_memory_plant.json"
HARNESS="$REPO_ROOT/harness/web-parity-demo.sh"
FRONTEND="$REPO_ROOT/apps/parent-control/lib/client/daemon.ts"

c() { [ -t 1 ] && printf '\033[%sm%s\033[0m' "$1" "$2" || printf '%s' "$2"; }
ok()   { printf '  %s %s\n' "$(c '1;32' ok)"   "$1"; }
bad()  { printf '  %s %s\n' "$(c '1;31' fail)" "$1"; }
info() { printf '%s %s\n'   "$(c '1;36' '▸')"  "$1"; }

command -v jq  >/dev/null 2>&1 || { bad "jq not found";  exit 2; }
command -v awk >/dev/null 2>&1 || { bad "awk not found"; exit 2; }
[ -f "$FIXTURE" ] || { bad "fixture missing: $FIXTURE"; exit 2; }

ROUTE="$(jq -r '.route' "$FIXTURE")"
WANT_KEYS="$(jq -r '.entry_keys | sort | join(",")' "$FIXTURE")"
info "canonical plant contract (from harness/fixtures/web-api/master_memory_plant.json):"
printf '    route      = %s\n    entry_keys = %s\n' "$ROUTE" "$WANT_KEYS"

# Sorted CSV of top-level keys from a (possibly multi-line) bash/TS object literal.
# Strips to the inside of the outermost braces, drops both quote styles + spaces,
# splits on commas, takes the identifier before each key's first colon.
extract_keys() {
  printf '%s' "$1" \
    | sed -E 's/^[^{]*\{//; s/\}[^}]*$//' \
    | tr -d '"' | tr -d "'" | tr -d ' ' \
    | tr ',' '\n' \
    | sed -E 's/:.*$//' \
    | grep -E '^[A-Za-z_][A-Za-z0-9_]*$' \
    | sort -u | paste -sd, -
}

# First brace-balanced object literal following the `@web-fixture:` annotation in
# a file. Same extractor the backend-protocol gate uses; works for `#` (bash) and
# `//` (TS) comment styles.
annotated_literal() {
  awk '
    /@web-fixture:/ { cap=1; depth=0; started=0; rec=""; next }
    cap==1 {
      n=length($0)
      for(i=1;i<=n;i++){
        ch=substr($0,i,1)
        if(ch=="{"){depth++; started=1}
        if(started) rec=rec ch
        if(ch=="}"){depth--; if(depth==0 && started){print rec; cap=0; exit}}
      }
      if(cap==1 && NR>2000){cap=0}
    }
  ' "$1"
}

# True if the canonical route appears AS A CALL ARGUMENT/URL — i.e. immediately
# followed by a closing quote (it terminates a string literal / URL), within a
# few lines of an actual call ($2 = the call-keyword regex: curl/-X POST for
# bash, postJson/fetch for TS). A stale comment or step-label that merely
# *mentions* the route (route followed by a space, arrow, or end-of-line — not a
# quote) does NOT satisfy this, so changing the real call URL while leaving an
# old label behind is caught instead of passing on the stale literal (Codex
# finding: a whole-file `grep` for the route can't tell the call site from a
# comment). `index()` is a literal substring search (the route is a fixed
# string, not a regex); the char-after test rejects a drifted prefix like
# `…/plantX"` because the char after `plant` is `X`, not a quote.
route_at_call_site() {  # $1=file  $2=call-keyword regex
  awk -v ROUTE="$ROUTE" -v KW="$2" -v Q='["'"'"']' '
    { if ($0 ~ KW) win = 4
      if (win > 0) {
        s = $0; p = index(s, ROUTE)
        while (p > 0) {
          after = substr(s, p + length(ROUTE), 1)
          if (after ~ Q) found = 1
          s = substr(s, p + length(ROUTE)); p = index(s, ROUTE)
        }
        win--
      }
    }
    END { exit(found ? 0 : 1) }
  ' "$1"
}

fails=0
check_consumer() {
  local label="$1" file="$2" kw="$3"
  if [ ! -f "$file" ]; then
    info "$label not present ($file) — skipping (no consumer to gate here)"
    return
  fi
  local rel="${file#"$REPO_ROOT"/}"
  # 1. route used AT THE CALL SITE (not merely present somewhere in the file)
  if route_at_call_site "$file" "$kw"; then
    ok "$rel posts to route $ROUTE at the call site"
  else
    bad "$rel does NOT post to the canonical route $ROUTE at its call site — a changed call URL with a left-behind comment/label that still names the old route would otherwise read as a false-green"
    fails=$((fails + 1))
  fi
  # 2. annotated entry object key-set matches
  local lit got
  lit="$(annotated_literal "$file")"
  if [ -z "$lit" ]; then
    bad "$rel has no '@web-fixture: master_memory_plant'-annotated entry object — annotate the plant body so it's gated"
    fails=$((fails + 1)); return
  fi
  got="$(extract_keys "$lit")"
  if [ "$got" = "$WANT_KEYS" ]; then
    ok "$rel entry shape matches"
  else
    bad "$rel entry shape DRIFT"
    printf '       want: %s\n       got:  %s\n' "$WANT_KEYS" "$got"
    fails=$((fails + 1))
  fi
}

echo
info "gating the two non-Rust consumers (the Rust source is pinned by the ui_bridge unit test)..."
check_consumer "harness web-parity-demo" "$HARNESS" 'curl|-X[[:space:]]+POST'
check_consumer "frontend daemon.ts" "$FRONTEND" 'postJson|fetch|getJson'

echo
if [ "$fails" -gt 0 ]; then
  bad "$fails plant-contract drift(s) — align the consumer, or if the contract changed update ApiMemoryEntry + harness/fixtures/web-api/master_memory_plant.json (the ui_bridge test enforces the Rust half)"
  exit 1
fi
ok "no drift — daemon.ts + web-parity-demo.sh agree with the canonical plant contract"
