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
/v1/sandbox/self/audit	#612 runtime-audit tee sink — a SANDBOX-INTERNAL route (delegate daemon, sandbox-self bearer), never reachable from the web app; covered by the dsh suite's audit tests + the daemon's op_kind allowlist unit test. Retire this waiver when a suite-6 step drives a live delegate's tee.
/v1/sandbox/self/credential	#612 vault-backed credential resolution — sandbox-internal (delegate daemon, sandbox-self bearer), not a web surface; the resolve path is unit-tested in the suite and the cap-mint half is covered by suite-3. Retire with a live in-sandbox credential fetch step.
/v1/sandbox/self/grants	#611 grant-projection read the in-loop guard compiles its allowlist from — sandbox-internal (delegate daemon), not a web surface; chain-read half is unit-tested (classify_scope_hashes) and the guard's compile is covered in the dsh suite. Retire with a live delegate guard step.
/v1/actors/:id/scope	legacy scope update (panel uses /v1/scope/build+submit, covered) — remove route or test when panel migration completes
/v1/actors/:id/scope/grant	same legacy scope surface
/v1/actors/:id/payment-cap	payment caps UI not wired to chain yet (#97 payments pending)
/v1/sandbox/self/audit	serves the in-sandbox dsh suite (#611-613); client half pinned by packages/agentkeys-dsh/tests/audit.spec.ts against the wire shape — daemon-handler runtime test lands with the #620 spawn-valve e2e (needs a spawned dsh sandbox on the test stack)
/v1/sandbox/self/credential	same dsh-suite surface — client half pinned by packages/agentkeys-dsh/tests/credentials.spec.ts; daemon handler needs the #620 spawned-sandbox e2e
/v1/sandbox/self/grants	same dsh-suite surface — client half pinned by packages/agentkeys-dsh/tests/guard.spec.ts; daemon handler needs the #620 spawned-sandbox e2e
/v1/actors/:id/revoke	master-gated revoke (gas) — covered at CLI level by heima-device-revoke.sh; web submit needs signed UserOp e2e
/v1/actors/:id/caps/revoke	cap revoke — broker cap.rs unit-tests the revoked-deny; web path needs a live cap fixture (former MCP-tool coverage retired, #560)
/v1/audit/stream	SSE — curl smoke would hang a step; needs a timeout-bounded SSE reader helper
/v1/audit/:id/decode	needs a decodable on-chain audit row id fixture from a prior append
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
/v1/agent/spawn/build	#427 spawn build proxy — allowance pre-check + broker K10 gen; needs the 0.5 registry live in the test env; ceremony proven headlessly by `agentkeys agent spawn` (CLI twin) + suite-1 step-12 allowance positive/negative
/v1/agent/spawn/submit	same 0.5-registry dependency + signed UserOp (gas) — the broker relay/finalize path is unit-tested; retire with a suite-6 headless-spawn step post-redeploy
/v1/agent/archive/build	#427 archive build proxy — needs a spawned throwaway delegate fixture (pair with the spawn waiver)
/v1/agent/archive/submit	same throwaway-delegate fixture + signed UserOp; manifest archive-mark covered by the daemon unit layer
/v1/agent/update	#577 in-place image update — needs a live sandbox backend (veFaaS) + a spawned delegate on the VE test stack; broker halves unit-tested (chain-probe/ownership, staleness, mgmt-token derivation, jobs-guard parse) + the bridge export/import round-trip is python-tested; retire with a suite-6 spawn→update step once the test env spawns delegates
/v1/agent/image-status	#577 staleness read — same live-backend dependency; the frozen-vs-current registration verdict is pinned by ve_faas::image_stale unit tests; retire together with the /v1/agent/update step
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
/v1/master/gateway/contacts/welcome	same gateway-admin forward — (re)send a contact's bound acknowledgement, or arm it for their next message; both halves proven headlessly by ilink_admin_e2e (member scan test); same deployed-gateway limitation
/v1/master/gateway/bind/reject	same gateway-admin forward — withdraw-invite ceremony proven headlessly by gateway_flow::bind_reject
/v1/master/gateway/monitor	same gateway-admin forward — live message monitor; behavior proven by the crate's gateway_flow tests; live daemon-side coverage needs a deployed gateway + admin token (same as gateway/status)
/v1/master/gateway/history	same gateway-admin forward — durable message history; append/read proven by gateway_flow::durable_history; same deployed-gateway limitation
/v1/master/gateway/activity	same gateway-admin forward — durable contact-audit trail; append/read proven by gateway_flow::durable_activity; same deployed-gateway limitation
/v1/master/apps/install/submit	#664 the install ceremony's SUBMIT half (ONE Touch ID → registerDelegate + setScope batch) — phase 8 runs it only with a software passkey (`--allow-skip=app-install-needs-passkey` in CI); the build half + registries are live gates in suite-8 steps 4-6
/v1/master/apps/:label/uninstall/build	#664 uninstall build — needs an INSTALLED app (the ceremony above); phase 8 runs the whole install→inspect→uninstall cycle under the same passkey gate
/v1/master/apps/:label/uninstall/submit	#664 uninstall submit — same passkey gate as the install submit
/v1/master/apps/:label/command	#670 a card-action tap publishes a `command` event from the console's device actor — needs an installed app with a display slot + a granted console actor; the card contract is pinned by the protocol + CardView golden tests, the publish path by the channel demo; retire with the passkey-gated phase-8 cycle running in CI
/v1/master/console/device/enroll/build	#541 the console's own device-actor enrollment (pairing request → claim → accept build) — ONE Touch ID; the shared master halves are exercised by the gateway enrollment's unit tests + the §10.2 pairing e2e (suite-1); retire with a software-passkey phase-8 step
/v1/master/console/device/enroll/submit	#541 console enrollment submit — same gate
/v1/master/gateway/device/enroll/build	#667 the gateway's device-actor enrollment — needs a DEPLOYED gateway with AGENTKEYS_BROKER_URL + a K10 file (setup-broker-host.sh converge) in the test env, then ONE Touch ID; the gateway-side halves are unit-tested (device.rs), the daemon halves shared with the console's
/v1/master/gateway/device/enroll/submit	#667 gateway enrollment submit — same deployed-gateway + passkey gate
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
# The waiver lookups read the table WITHOUT a pipe: `printf … | grep -q` raced
# itself (grep exits at the first match, printf's write of the long table then
# fails EPIPE, and under pipefail the lookup reads "not waived" — a waived route
# became a violation in CI, 2026-09-16). awk over a here-string, one pass.
waived() { awk -F'\t' -v r="$1" '$1 == r { found = 1; exit } END { exit !found }' <<<"$WAIVERS"; }
waiver_reason() { awk -F'\t' -v r="$1" '$1 == r { print $2; exit }' <<<"$WAIVERS"; }

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
