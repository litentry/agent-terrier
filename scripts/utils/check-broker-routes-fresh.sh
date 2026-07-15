#!/usr/bin/env bash
# scripts/utils/check-broker-routes-fresh.sh — fail loud when the shared test broker
# is running OLDER code than the PR under test (issue #314).
#
# The harness CI deploy job is path-conditional: a PR that doesn't touch broker
# paths skips the redeploy, so the shared test-fleet broker keeps running
# whatever the LAST broker-touching PR deployed. Its route set is therefore
# decoupled from the PR under test. When that PR's harness drives a /v1/cap/*
# route the stale broker doesn't yet serve, the route 404s MID-DEMO with a
# cryptic "backend HTTP error (404)" — a false-red on correct code (the #297
# /v1/cap/memory-canonical-get incident: RED on `main` for ~2 days).
#
# This gate converts that mid-demo 404 into an UP-FRONT, named failure:
#   "broker is missing a route — redeploy" with the exact missing route.
#
# SCOPE & LIMITS (read before relying on this as a "freshness" gate):
#   This proves route PRESENCE, not full handler freshness. It catches the
#   route-ABSENT class of staleness — a deployed broker that lacks a /v1/cap/*
#   path the harness will call (exactly the #297 incident). It does NOT prove
#   the deployed handler's SEMANTICS match this checkout: a broker serving the
#   SAME paths with drifted request schema / auth / response behavior passes
#   here and could still fail later in the harness. That gap is narrow in this
#   CI model — any broker-behavior change rides a broker path, so it redeploys
#   the test broker in its OWN PR (path-conditional deploy), and #203's
#   check-backend-fixture-drift.sh catches wire-shape drift at compile/fixture
#   time. Closing it fully is issue #314 OPTION 3 (broker exposes its deployed
#   git SHA in /readyz; the gate diffs it against this checkout's broker paths)
#   — a separate change that needs a broker build-revision marker + a redeploy.
#
# How it stays drift-proof: the route list is DERIVED from the broker source in
# THIS checkout (the PR under test's expected routes) — never a hand-maintained
# list. Adding a /v1/cap/* route + a harness step that drives it in one PR
# automatically extends this gate. For each route we POST `{}`:
#   - 404  => route ABSENT on the live broker => stale build => FAIL LOUD.
#   - any other non-transient status (422 missing-fields / 401 / 403 / 400 /
#     405 / 2xx) => route PRESENT => pass.
#
# Why 404 is an unambiguous "route absent" signal (verified, not assumed):
#   - The broker router has NO custom `.fallback(...)`, so an unmatched path
#     gets axum's default 404 (confirmed: live probe of a bogus path -> 404).
#   - NO /v1/cap/* handler ever returns 404 (grep cap.rs/canonical_sts.rs:
#     zero NOT_FOUND), so a present cap route can only answer non-404.
#   This is why the gate is deliberately scoped to /v1/cap/* — those handlers
#   have no resource-not-found semantics. Do NOT widen to routes whose handlers
#   can legitimately 404 (e.g. a "pairing code not found" lookup) without first
#   proving they can't 404 on an empty body, or this gate gains a false-stale.
#
# Read-only (verify-* class; zero chain/state mutation — empty bodies fail
# validation before any handler side effect). Safe to run anywhere, any time.
#
# Env (defaults per the no-hardcoded-values rule):
#   ENV_FILE          env file with BROKER_HOST (default operator-workstation.env)
#   BROKER_SRC        broker router source to derive routes from
#                     (default crates/agentkeys-broker-server/src/lib.rs)
#   CAP_ROUTE_PREFIX  route-path prefix to gate on (default /v1/cap/)
#   CURL_MAX_TIME     per-probe timeout seconds (default 10)
#   PROBE_RETRIES     retries on a transient 000/5xx per route (default 2)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/scripts/operator-workstation.env}"
BROKER_SRC="${BROKER_SRC:-$REPO_ROOT/crates/agentkeys-broker-server/src/lib.rs}"
CAP_ROUTE_PREFIX="${CAP_ROUTE_PREFIX:-/v1/cap/}"
: "${CURL_MAX_TIME:=10}"
: "${PROBE_RETRIES:=2}"

[ -f "$ENV_FILE" ]   || { echo "xx  env file not found: $ENV_FILE" >&2; exit 2; }
[ -f "$BROKER_SRC" ] || { echo "xx  broker source not found: $BROKER_SRC" >&2; exit 2; }

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
: "${BROKER_HOST:=}"
[ -n "$BROKER_HOST" ] || { echo "xx  BROKER_HOST not set in $ENV_FILE" >&2; exit 2; }
BROKER_HOST="${BROKER_HOST%/}"   # tolerate a stray trailing slash in the env file

# Derive the cap-route set from the router source under test. The path appears
# as a quoted literal in `.route("<prefix><name>", post(...))` — inline or, for
# the multi-line form, on its own line — so a path-literal grep captures every
# route either way (no need to anchor on `.route(`, which may be a line above).
#
# COMMENTS are stripped BEFORE extraction so a commented-out / documented route
# path can't be probed as a (false-)stale route:
#   - `perl -0777 … s{/\*.*?\*/}{}gs` removes `/* … */` block comments, INCLUDING
#     the multi-line form (slurp mode + non-greedy + /s dotall).
#   - `grep -vE '^[[:space:]]*//'` then drops `//` full-line comments.
# (A quoted cap path in a block comment used to be extracted → probed → 404 →
# reported stale: a LOUD false-FAIL. Now stripped, so neither comment form trips
# the gate.) The path charset is `[a-z0-9_-]` so a future versioned (memory-v2-get)
# or underscore-named (cred_store_v2) route is GATED, not silently skipped — a
# skipped route is the exact false-PASS this gate exists to prevent.
prefix_re="$(printf '%s' "$CAP_ROUTE_PREFIX" | sed 's/[][\.*^$/]/\\&/g')"
routes=()
while IFS= read -r r; do
  [ -n "$r" ] && routes+=("$r")
done < <(perl -0777 -pe 's{/\*.*?\*/}{}gs' "$BROKER_SRC" \
           | grep -vE '^[[:space:]]*//' \
           | grep -oE "\"${prefix_re}[a-z0-9_-]+\"" | tr -d '"' | sort -u)

[ "${#routes[@]}" -gt 0 ] || { echo "xx  no ${CAP_ROUTE_PREFIX}* routes derivable from $BROKER_SRC — pattern drift?" >&2; exit 2; }

# Probe one route. Returns the HTTP status. 404 (absent) and any 2xx/4xx
# (present) are DEFINITIVE — returned immediately. A transient 000 (curl
# failed/timed out) or 5xx (nginx/upstream warm-up) is retried, since the
# /healthz gate that ran before us already proved the broker is up — a blip
# here should not masquerade as a stale build.
probe_route() {
  local url="$1" attempt code=""
  for attempt in $(seq 0 "$PROBE_RETRIES"); do
    # The `|| code="000"` REPLACES (not appends) — curl already emits "000" via
    # -w on a failed/timed-out request, so `$(curl ... || echo 000)` would yield
    # "000000" and slip past the 000/5xx transient case as a (false) "present".
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$CURL_MAX_TIME" \
      -X POST -H 'content-type: application/json' -d '{}' "$url" 2>/dev/null) || code="000"
    case "$code" in
      000|5??) ;;                               # transient — retry if attempts remain
      *) printf '%s' "$code"; return 0 ;;       # definitive (404 absent | 2xx/4xx present)
    esac
    # if/then (not `[ ] && sleep`) so the loop body's last status is unambiguous
    # under `set -e` on the final attempt (a false `[ ]` returns 1).
    if [ "$attempt" -lt "$PROBE_RETRIES" ]; then sleep 2; fi
  done
  printf '%s' "$code"                           # still transient after retries
}

echo "==> probing ${#routes[@]} ${CAP_ROUTE_PREFIX}* route(s) on https://$BROKER_HOST for route PRESENCE vs $(basename "$BROKER_SRC") (route-absent staleness — issue #314)"
missing=0
unreachable=0
report=""
for route in ${routes[@]+"${routes[@]}"}; do
  code="$(probe_route "https://$BROKER_HOST$route")"
  case "$code" in
    404)
      missing=$((missing + 1))
      report="${report}    ${route} -> 404 (not registered on the live broker — route absent)"$'\n'
      echo "    MISSING     ${route} -> 404" ;;
    000|5??)
      unreachable=$((unreachable + 1))
      report="${report}    ${route} -> ${code} (unreachable after retries — broker down/erroring?)"$'\n'
      echo "    UNREACHABLE ${route} -> ${code}" ;;
    *)
      echo "    ok          ${route} -> ${code} (present)" ;;
  esac
done

if [ "$missing" -gt 0 ] || [ "$unreachable" -gt 0 ]; then
  echo "xx  broker cap-route PRESENCE gate FAILED — ${missing} missing, ${unreachable} unreachable:" >&2
  printf '%s' "$report" >&2
  if [ "$missing" -gt 0 ]; then
    echo "xx  the shared test broker LACKS a route this PR's harness will call — it is running" >&2
    echo "xx  OLDER code than this PR (the deploy job is path-conditional and skipped for" >&2
    echo "xx  non-broker PRs — issue #314). Redeploy it:" >&2
    echo "xx    bash scripts/operator/setup-broker-host.sh --ci --ref <this-branch-or-main>   (on the test broker host)" >&2
  fi
  if [ "$unreachable" -gt 0 ]; then
    echo "xx  unreachable routes are a live-broker fault (down / 5xx after retries), not staleness" >&2
    echo "xx  — check the /healthz gate output above and the broker host's systemd/nginx state." >&2
  fi
  echo "xx  Failing the gate UP FRONT instead of letting the harness 404 mid-demo." >&2
  exit 1
fi

echo "==> all ${#routes[@]} ${CAP_ROUTE_PREFIX}* route(s) PRESENT on the live broker (route-presence gate passed; semantic freshness not asserted — see header)"
