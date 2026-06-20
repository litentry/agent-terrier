#!/usr/bin/env bash
# Weekly live-test runner for AgentKeys scrapers.
#
# Runs every deterministic scraper under src/scrapers/ end-to-end against
# real services. Prints a pass/fail summary. Exit code is non-zero if any
# scraper fails.
#
# NOT in CI — this creates real accounts and burns real API calls. Meant
# for the project owner / dedicated human contributor to run on a schedule
# (weekly cron, or before cutting a release) so provider-side flow drift
# gets caught before a user does.
#
# Usage (from repo root):
#   source scripts/stage6-demo-env.sh   # loads DAEMON_* + mints 1h STS creds
#   bash provisioner-scripts/scripts/weekly-live-test.sh
#
# Every test run:
#   1. resets Chrome to a fresh throwaway profile
#   2. mints a fresh bot-$(date +%s)@bots.example.invalid signup email
#   3. runs the scraper, captures JSON events to /tmp/
#   4. records pass/fail based on {"type":"success"} presence
#
# Add a new service: drop its scraper under src/scrapers/<slug>-cdp.ts,
# then add a `run_scraper <slug>` line in the body below.

set -u

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PROVISIONER_ROOT="$REPO_ROOT/provisioner-scripts"
RESET_CHROME="$REPO_ROOT/scripts/reset-chrome-for-recording.sh"

if [ ! -x "$RESET_CHROME" ]; then
  echo "error: $RESET_CHROME not found or not executable" >&2
  exit 2
fi
if [ -z "${DAEMON_ACCESS_KEY_ID:-}" ] || [ -z "${DAEMON_SECRET_ACCESS_KEY:-}" ]; then
  echo "error: DAEMON_* creds not loaded — run 'source scripts/stage6-demo-env.sh' first" >&2
  exit 2
fi

PASS=()
FAIL=()

run_scraper() {
  local slug=$1
  local script="$PROVISIONER_ROOT/src/scrapers/${slug}-cdp.ts"
  local log="/tmp/live-test-${slug}-$(date +%Y%m%d-%H%M%S).jsonl"

  if [ ! -f "$script" ]; then
    echo "skip: $script not found"
    return
  fi

  echo ""
  echo "=== $slug ==="
  bash "$RESET_CHROME" 2>&1 | tail -2

  # Fresh signup email per run (SES-S3 backend is configured by stage6-demo-env.sh).
  export AGENTKEYS_SIGNUP_EMAIL="bot-$(date +%s)@${DOMAIN:-bots.example.invalid}"
  # stage6-demo-env.sh exports AGENTKEYS_SIGNUP_PASSWORD; keep it.
  if [ -z "${AGENTKEYS_SIGNUP_PASSWORD:-}" ]; then
    echo "error: AGENTKEYS_SIGNUP_PASSWORD not set (stage6-demo-env.sh not sourced)" >&2
    FAIL+=("$slug (missing-env)")
    return
  fi

  echo "email:    $AGENTKEYS_SIGNUP_EMAIL"
  echo "log:      $log"

  local start=$(date +%s)
  (cd "$PROVISIONER_ROOT" && npx tsx "src/scrapers/${slug}-cdp.ts") > "$log" 2>&1
  local rc=$?
  local elapsed=$(( $(date +%s) - start ))

  if [ $rc -eq 0 ] && grep -q '"type":"success"' "$log"; then
    local masked
    masked=$(grep -o '"api_key":"[^"]*"' "$log" | head -1 | sed 's/.*"api_key":"\(sk-[^"]\{8\}\).*/\1****/')
    PASS+=("$slug ($elapsed"s", $masked)")
    echo "PASS ($elapsed"s", $masked)"
  else
    local err
    err=$(grep -o '"type":"error","code":"[^"]*","details":"[^"]*"' "$log" | head -1)
    FAIL+=("$slug ($elapsed"s", $err, log=$log)")
    echo "FAIL ($elapsed"s") — see $log"
    tail -5 "$log"
  fi
}

# === scrapers to test ===
run_scraper openrouter
run_scraper openai

# === summary ===
echo ""
echo "================================================================"
echo "WEEKLY LIVE TEST SUMMARY  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
echo "================================================================"
if [ ${#PASS[@]} -gt 0 ]; then
  echo "PASS (${#PASS[@]}):"
  for p in "${PASS[@]}"; do echo "  ✓ $p"; done
fi
if [ ${#FAIL[@]} -gt 0 ]; then
  echo "FAIL (${#FAIL[@]}):"
  for f in "${FAIL[@]}"; do echo "  ✗ $f"; done
fi
echo "================================================================"

[ ${#FAIL[@]} -eq 0 ]
