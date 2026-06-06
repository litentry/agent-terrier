#!/usr/bin/env bash
# Verify the 5 co-located service workers are reachable end-to-end:
# DNS resolves → TLS cert valid → /healthz returns 200.
#
# Runs from the OPERATOR WORKSTATION (laptop). Exits 0 only if all 5 are
# green; exits 1 with a diagnostic if any one fails.
#
# Usage:
#   bash scripts/verify-workers.sh
#   bash scripts/verify-workers.sh --no-tls   # skip TLS check (HTTP-only phase)

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK_TLS=true

while (( $# > 0 )); do
  case "$1" in
    --no-tls) CHECK_TLS=false; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m  %s\n' "$*"; }
fail() { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; }

ENV_FILE="${ENV_FILE:-$REPO_ROOT/scripts/operator-workstation.env}"
[[ -f "$ENV_FILE" ]] || { fail "$ENV_FILE not found"; exit 1; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

ERRORS=0

# scheme: worker-slug:hostname:expected-/healthz-body-substring
WORKERS=(
  "audit:${WORKER_AUDIT_HOST}:ok"
  "email:${WORKER_EMAIL_HOST}:ok"
  "cred:${WORKER_CRED_HOST}:\"ok\":true"
  "memory:${WORKER_MEMORY_HOST}:\"ok\":true"
  "config:${WORKER_CONFIG_HOST}:\"ok\":true"
)

for entry in "${WORKERS[@]}"; do
  slug="${entry%%:*}"
  rest="${entry#*:}"
  host="${rest%%:*}"
  expect="${rest#*:}"

  log "[$slug] $host"

  # 1. DNS resolves via Cloudflare DoH (skip local resolver — VPN may rewrite).
  resolved="$(curl -s --max-time 5 "https://cloudflare-dns.com/dns-query?name=${host}&type=A" \
                -H 'accept: application/dns-json' | jq -r '.Answer[0].data // empty')"
  if [[ -z "$resolved" ]]; then
    fail "  DNS: $host has no A record (Cloudflare DoH)"
    ERRORS=$((ERRORS + 1)); continue
  fi
  ok "  DNS: $host → $resolved"

  # 2. TLS cert (skipped on --no-tls or first-pass HTTP-only deploys).
  if $CHECK_TLS; then
    if ! cert_info="$(echo | openssl s_client -connect "${host}:443" -servername "$host" 2>/dev/null \
                       | openssl x509 -noout -subject -issuer -dates 2>/dev/null)"; then
      fail "  TLS: openssl s_client failed against $host:443 — cert not issued yet?"
      ERRORS=$((ERRORS + 1)); continue
    fi
    if echo "$cert_info" | grep -q "Let's Encrypt"; then
      ok "  TLS: Let's Encrypt cert, valid until $(echo "$cert_info" | grep notAfter | cut -d= -f2)"
    else
      fail "  TLS: cert is NOT Let's Encrypt:\n$cert_info"
      ERRORS=$((ERRORS + 1)); continue
    fi
  fi

  # 3. /healthz returns 200 with expected body marker.
  scheme=$($CHECK_TLS && echo https || echo http)
  body="$(curl -sS --max-time 5 -o /dev/stdout -w "\nHTTP_STATUS=%{http_code}" "${scheme}://${host}/healthz" 2>&1 || true)"
  status="$(printf '%s' "$body" | sed -n 's/.*HTTP_STATUS=\([0-9]*\).*/\1/p')"
  payload="$(printf '%s' "$body" | sed '/HTTP_STATUS=/d')"
  if [[ "$status" != "200" ]]; then
    fail "  /healthz: HTTP $status (expected 200)"
    fail "  body: $payload"
    ERRORS=$((ERRORS + 1)); continue
  fi
  if ! printf '%s' "$payload" | grep -q "$expect"; then
    fail "  /healthz: 200 but body did not contain '$expect'"
    fail "  body: $payload"
    ERRORS=$((ERRORS + 1)); continue
  fi
  ok "  /healthz: HTTP 200, payload matches '$expect'"
done

echo
if (( ERRORS == 0 )); then
  ok "All 5 workers green (audit + email + cred + memory + config)"
  exit 0
else
  fail "$ERRORS worker(s) failed — fix and re-run"
  exit 1
fi
