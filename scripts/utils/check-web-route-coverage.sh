#!/usr/bin/env bash
# check-web-route-coverage.sh — the parent-control ↔ e2e PARITY RATCHET.
#
# The daemon's ui_bridge is the web app's entire API surface (~50 routes). The
# recurring failure mode: a new route/feature lands with only compile-level
# gates (ts-rs bindings + typecheck) and NO runtime test — the parity gap grows
# silently. This gate makes the gap EXPLICIT and one-directional:
#
#   1. Extract every route the ui_bridge serves (string literals AND the
#      const-mounted ones from agentkeys-protocol, e.g. MASTER_MEMORY_PLANT_ROUTE).
#   2. A route counts RUNTIME-COVERED when its path appears in e2e/*.sh,
#      e2e/scripts/*.sh, or the frontend tests (apps/parent-control/lib/__tests__).
#      Param routes (/v1/actors/:id/…) match on the static prefix.
#   3. Every uncovered route MUST have a WAIVER entry below with a reason
#      (browser-ceremony-only, SSE, dev-only, planned-in-<doc>…). An uncovered,
#      unwaived route fails CI — so landing a new web feature forces either a
#      headless test or a deliberate, reviewable waiver, never a silent gap.
#
# Shrink the waiver table over time; never grow it without a reason that names
# what unblocks removal. Pure file checks — no network, no creds, CI-safe.
#
#   bash scripts/utils/check-web-route-coverage.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UI="$REPO_ROOT/crates/agentkeys-daemon/src/ui_bridge.rs"
PROTO_DIR="$REPO_ROOT/crates/agentkeys-protocol/src"

c() { [ -t 1 ] && printf '\033[%sm%s\033[0m' "$1" "$2" || printf '%s' "$2"; }
ok()   { printf '  %s %s\n' "$(c '1;32' ok)"   "$1"; }
bad()  { printf '  %s %s\n' "$(c '1;31' fail)" "$1"; }
wv()   { printf '  %s %s\n' "$(c '1;33' waiv)" "$1"; }
info() { printf '%s %s\n'   "$(c '1;36' '▸')"  "$1"; }

[ -f "$UI" ] || { bad "missing $UI"; exit 2; }

# ── WAIVERS: route<TAB>reason. Every entry is DEBT — name what removes it. ──
read -r -d '' WAIVERS <<'EOF' || true
/v1/k11/enroll/begin	browser WebAuthn ceremony (navigator.credentials) — headless needs the CDP virtual-authenticator plan (docs/plan/web-flow/web-wire-test-runbook.md); CLI twin covered by suite-1 K11 enroll
/v1/k11/enroll/finish	same WebAuthn ceremony pair as enroll/begin
/v1/master/register/submit	browser-passkey-signed register submit (#278) — build half is proxied via /v1/accept/*; CLI twin covered by erc4337-register-master.sh in suite-1; CDP virtual-authenticator planned
/v1/master/reset	destructive (fleet revoke + wipe, #260/#269) — needs a dedicated throwaway-identity test; do NOT smoke against the suite master
/v1/auth/email/start	needs a live SES inbox round-trip; broker-level email init covered by suite-1 step 6
/v1/auth/email/status	poll half of the email round-trip above
/v1/auth/logout	session-mutating (downgrades the seeded J1) — would break later suite-6 steps; needs an isolated-daemon test
/v1/auth/relogin/start	#242 passkey re-login — browser WebAuthn assert; broker halves live-verified in #242; CDP virtual-authenticator planned
/v1/auth/relogin/finish	same re-login ceremony pair
/v1/actors/:id/scope	legacy scope update (panel uses /v1/scope/build+submit, covered) — remove route or test when panel migration completes
/v1/actors/:id/scope/grant	same legacy scope surface
/v1/actors/:id/payment-cap	payment caps UI not wired to chain yet (#97 payments pending)
/v1/actors/:id/revoke	master-gated revoke (gas) — covered at CLI level by heima-device-revoke.sh; web submit needs signed UserOp e2e
/v1/actors/:id/caps/revoke	cap revoke — MCP-level covered (agentkeys_cap_revoke); web path needs a live cap fixture
/v1/audit/stream	SSE — curl smoke would hang a step; needs a timeout-bounded SSE reader helper
/v1/audit/:id/decode	needs a decodable on-chain audit row id fixture from a prior append
/v1/anchor/status	tier-A anchor status (#109) — worker-dependent; add to suite-6 once audit worker guaranteed in test env
/v1/master/memory/entry	single-entry read — list route covered; add ?ns=demo fixture read after suite-4 plant
/v1/master/inbox	#297/#339 inbox — needs a planted inbox fixture (agent append) in the test env
/v1/master/inbox/entry	same inbox fixture dependency
/v1/master/inbox/accept	inbox mutation — same fixture dependency
/v1/master/inbox/reject	inbox mutation — same fixture dependency
/v1/master/config/presets	#201/#207 config — test env has config worker only when provisioned; suite-3 steps 19-21 cover worker-level
/v1/master/config/init	config write — same provisioning dependency
/v1/master/classify/tag	#207 classify worker — suite-3 step 22 covers the worker gate; daemon proxy needs the worker deployed in test env
/v1/master/classify/propose	same classify worker dependency
/v1/agent/pairing/ack	same live-pairing-request dependency
/v1/agent/pairing/register	same live-pairing-request dependency
/v1/accept/build	#278 sponsored-accept build proxy — errors for an already-registered master (the suite's); needs a fresh-omni fixture
/v1/accept/submit	needs a browser/software-signed UserOp for a FRESH omni (gas) — pair with the accept/build fixture
/v1/scope/submit	needs a signed UserOp (gas); build half covered (suite-6 step 7); headless submit = sign userOpHash with the software passkey — planned
/v1/revoke/build	revoke build proxy — needs a revocable throwaway device fixture
/v1/revoke/submit	same throwaway-device fixture + signed UserOp
/v1/presets	#428 broker preset-catalog GET proxy (static compiled-in content) — broker-side unit tests pin the catalog; retire with a suite-6 step reading the catalog through the daemon
/v1/presets/:id	#428 preset bundle GET proxy — same broker-side unit coverage; the vitest client test pins the URL shape
/v1/agent/spawn/build	#427 spawn build proxy — allowance pre-check + broker K10 gen; needs the 0.5 registry live in the test env; ceremony proven headlessly by `agentkeys agent spawn` (CLI twin) + suite-1 step-12 allowance positive/negative
/v1/agent/spawn/submit	same 0.5-registry dependency + signed UserOp (gas) — the broker relay/finalize path is unit-tested; retire with a suite-6 headless-spawn step post-redeploy
/v1/agent/archive/build	#427 archive build proxy — needs a spawned throwaway delegate fixture (pair with the spawn waiver)
/v1/agent/archive/submit	same throwaway-delegate fixture + signed UserOp; manifest archive-mark covered by the daemon unit layer
/v1/agent/inheritable-namespaces	#429 O2 bookkeeping read (manifest-derived) — daemon unit layer covers the filter; retire with a suite-6 archive→inherit step
/v1/master/agent/chat/send	#430 operator chat publish (master-self channel cap → worker) — needs the redeployed D8 channel worker + a spawned delegate in the test env; retire with a suite-6 duplex step
/v1/master/agent/chat/poll	#430 transcript read/long-poll — same redeployed-worker + delegate fixture; the channel-e2e step-3 harness is the pattern
/v1/master/gateway/status	#418 thin bearer-injecting forward to the weixin gateway admin surface; gateway behavior proven headlessly by the crate's ilink_admin_e2e (channel demo step 15); live daemon-side coverage needs a deployed gateway + AGENTKEYS_WEIXIN_ADMIN_TOKEN in the test env
/v1/master/gateway/login/start	same gateway-admin forward — removed by a suite-6 step once the test env deploys the gateway with an admin token
/v1/master/gateway/login/status	same gateway-admin forward (35 s server-held poll)
/v1/master/gateway/login/verify	same gateway-admin forward
/v1/master/gateway/login/disconnect	same gateway-admin forward — disconnect ceremony pair to login/verify; surfaced by the 2026-07-14 build_router()-scoped extraction fix, was previously invisible to this ratchet
/v1/master/gateway/bind/invite	same gateway-admin forward — bind ceremony proven in ilink_admin_e2e
/v1/master/gateway/bind/pending	same gateway-admin forward
/v1/master/gateway/bind/approve	same gateway-admin forward
/v1/master/gateway/contacts	same gateway-admin forward (worker route /v1/gateway/contacts also asserted by channel demo step 14)
/v1/master/gateway/contacts/update	same gateway-admin forward — contact display-name/label edit; surfaced by the 2026-07-14 extraction fix
/v1/master/gateway/contacts/revoke	same gateway-admin forward — contact revoke (D13-safe, no openid in response); surfaced by the 2026-07-14 extraction fix
/v1/master/gateway/bind/reject	same gateway-admin forward — withdraw-invite ceremony proven headlessly by gateway_flow::bind_reject
/v1/master/gateway/monitor	same gateway-admin forward — live message monitor; behavior proven by the crate's gateway_flow tests; live daemon-side coverage needs a deployed gateway + admin token (same as gateway/status)
/v1/master/gateway/history	same gateway-admin forward — durable message history; append/read proven by gateway_flow::durable_history; same deployed-gateway limitation
/v1/master/gateway/activity	same gateway-admin forward — durable contact-audit trail; append/read proven by gateway_flow::durable_activity; same deployed-gateway limitation
/v1/channels	#404 channel registry list — CRUD + in-use guard proven by ui_bridge unit tests (channel_registry_candidates_and_holders, channel_id_validation); a suite-6 GET needs the config worker provisioned in the test env (same dependency as /v1/master/config/*)
/v1/channels/:id	#404 registry display-field update (id immutable) — same unit-test coverage + config-worker dependency
/v1/channels/:id/delete	#404 registry delete (409 while grants hold the id) — same unit-test coverage + config-worker dependency
EOF

# ── 1. extract served routes ────────────────────────────────────────────────
# Scoped to the `build_router()` fn body ONLY — the file also carries unit
# tests that stand up their OWN `Router::new()...route(...)` to mock the
# BROKER side of a proxy call (e.g. `/v1/auth/passkey/verify` mocking the
# broker in relogin_finish_restores_the_session_from_a_verified_assertion);
# scanning the whole file misattributes those as ui_bridge-served routes.
# Within that scope, `.route(\n    "/path",\n    handler)` (rustfmt-wrapped,
# long paths) is joined onto one line before matching — a plain single-line
# grep silently dropped every multi-line registration (found 2026-07-14: 11
# real routes, incl. the whole gateway login/bind ceremony, were invisible).
ROUTER_FN="$(awk '/^pub fn build_router/,/^}/' "$UI")"
[ -n "$ROUTER_FN" ] || { bad "cannot locate build_router() in $UI"; exit 2; }
ROUTER_FN_JOINED="$(printf '%s' "$ROUTER_FN" | perl -0777 -pe 's/\.route\(\s*\n\s*/.route(/g')"
lit_routes="$(printf '%s' "$ROUTER_FN_JOINED" | grep -oE '\.route\("(/[^"]+)"' | sed -E 's/^\.route\("//; s/"$//')"
const_names="$(printf '%s' "$ROUTER_FN_JOINED" | grep -oE '\.route\(([A-Z][A-Z0-9_]*)' | sed -E 's/^\.route\(//' | sort -u)"
const_routes=""
for cn in $const_names; do
  v="$(grep -rhoE "pub const $cn: &str = \"[^\"]+\"" "$PROTO_DIR" "$UI" 2>/dev/null | head -1 | sed -E 's/.*= "//; s/"$//')"
  if [ -n "$v" ]; then const_routes="$const_routes $v"; else bad "cannot resolve const route $cn"; exit 2; fi
done
routes="$(printf '%s\n%s\n' "$lit_routes" "$(printf '%s' "$const_routes" | tr ' ' '\n')" | grep -v '^$' | sort -u)"

# ── 2. coverage corpus ──────────────────────────────────────────────────────
corpus_files="$(ls "$REPO_ROOT"/e2e/*.sh "$REPO_ROOT"/e2e/scripts/*.sh "$REPO_ROOT"/apps/parent-control/lib/__tests__/* 2>/dev/null)"

covered() { # $1 = route. Param routes match each :seg as one path segment
  # with an END BOUNDARY, so /v1/audit/:id/decode can NOT ride on
  # /v1/audit/recent (the prefix-match false-positive this replaced).
  local sq rx cls bnd
  sq="'"
  case "$1" in
    *:*)
      cls="[^/\"$sq ]+"
      bnd="(\"|$sq| |/|$)"
      rx="$(printf '%s' "$1" | sed -E 's/[]\[().+*?^${}|]/\\&/g' | sed -E "s#:[A-Za-z_]+#$cls#g")"
      # shellcheck disable=SC2086
      grep -lE "${rx}${bnd}" $corpus_files >/dev/null 2>&1 ;;
    *)
      # shellcheck disable=SC2086
      grep -lF "$1" $corpus_files >/dev/null 2>&1 ;;
  esac
}
waived() { printf '%s\n' "$WAIVERS" | grep -qE "^$1	"; }
waiver_reason() { printf '%s\n' "$WAIVERS" | grep -E "^$1	" | head -1 | cut -f2; }

info "ui_bridge serves $(printf '%s\n' "$routes" | wc -l | tr -d ' ') routes; checking runtime coverage (e2e/ + frontend tests)…"
fails=0; ncov=0; nwaiv=0
stale_waivers=""
for r in $routes; do
  # infra/dev-only routes are out of ratchet scope
  case "$r" in
    /healthz|/v1/dev/*) continue ;;
  esac
  if covered "$r"; then
    ncov=$((ncov+1)); ok "$r"
    waived "$r" && stale_waivers="$stale_waivers $r"
  elif waived "$r"; then
    nwaiv=$((nwaiv+1)); wv "$r — $(waiver_reason "$r")"
  else
    fails=$((fails+1)); bad "$r — NO runtime test and NO waiver (add a suite-6/e2e step, a frontend test, or a reasoned waiver entry)"
  fi
done

echo
[ -n "$stale_waivers" ] && { bad "stale waiver(s) — now covered, DELETE from the table:$stale_waivers"; fails=$((fails+1)); }
if [ "$fails" -gt 0 ]; then
  bad "$fails violation(s) — the web↔e2e parity gap may only shrink (covered=$ncov waived=$nwaiv)"
  exit 1
fi
ok "parity ratchet holds — covered=$ncov, waived=$nwaiv (waivers are visible debt; shrink them)"
