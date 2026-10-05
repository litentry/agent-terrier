#!/usr/bin/env bash
# check-unit-inline-secrets.sh — no secret rides a systemd unit's Environment=.
#
# THE BUG (measured 2026-10-04, read-only, names only): the broker and gate
# units on VE prod + VE test carried AGENTKEYS_GATE_ADMIN_TOKEN, and the broker
# units on VE prod/test + AWS prod/test carried AGENTKEYS_CHANNEL_STS_TOKEN, as
# Environment= lines. A unit file is 0644, and systemd hands Environment= to ANY
# local user over D-Bus: as user `nobody`, `systemctl show -p Environment
# agentkeys-gate` returned the gate admin bearer. A 0600 unit would not fix it —
# systemd.exec(5), Environment=: "Environment variables set for a unit are
# exposed to unprivileged clients via D-Bus IPC".
#
# THE FIX — a secret lives in a 0600 file every consumer unit loads as
# EnvironmentFile= (host_ensure_bearer_file in scripts/operator/lib/host-common.sh).
#
# TWO GATES, ONE PREDICATE (HOST_UNIT_SECRET_KEY_RE + _EXEMPT_RE in host-common.sh):
#   1. runtime — host_apply_unit refuses to write a unit carrying a secret-shaped
#      Environment= key. It sees the RENDERED unit (env blocks included), and
#      every VE converge runs it — CI's ve-e2e job on every PR among them.
#   2. static (this script) — every `Environment=KEY=` spelled out in a tracked
#      *.sh: the AWS entry's unit heredocs never pass through host_apply_unit.
#      Full-line comments are skipped. Plus a self-test of the predicate against
#      the key names the fleet deploys (it must keep passing them) and the
#      secrets the fleet holds (it must keep flagging them).
#
#   bash scripts/utils/check-unit-inline-secrets.sh            # repo default set
#   bash scripts/utils/check-unit-inline-secrets.sh path.sh …  # explicit files
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)"
cd "$REPO_ROOT"

LIB=scripts/operator/lib/host-common.sh
if [ ! -f "$LIB" ]; then
  echo "unit inline secrets: $LIB absent (the public mirror ships no operator scripts) — nothing to check"
  exit 0
fi
# shellcheck source=../operator/lib/host-common.sh
. "$LIB"

fails=0
flag() { printf 'FAIL %s\n' "$1" >&2; fails=$((fails + 1)); }

# ── 1. self-test: the predicate against the fleet's real key names ──────────
# Deployed Environment= keys measured on VE prod/test + AWS prod/test
# (2026-10-04), plus pointer/label names that merely mention a secret.
for key in HOME ACCOUNT_ID REGION AGENTKEYS_CHAIN AGENTKEYS_CHAIN_RPC_HTTP \
  SIDECAR_REGISTRY_ADDRESS_HEIMA CREDENTIAL_AUDIT_ADDRESS_HEIMA PAYMASTER_ADDRESS_HEIMA \
  AGENTKEYS_STS_PROVIDER AGENTKEYS_CLIENT_ID VOLCENGINE_REGION AGENTKEYS_VE_TOS_BUCKETS \
  BROKER_DATA_ROLE_ARN BROKER_OIDC_KEYPAIR_PATH BROKER_SESSION_KEYPAIR_PATH BROKER_STS_AUDIENCE \
  CHANNEL_ROLE_ARN MEMORY_ROLE_ARN SPEECH_ROLE_ARN AGENTKEYS_WORKER_CHANNEL_URL AGENTKEYS_DELEGATE_KEYS \
  AGENTKEYS_SIGNER_URL AGENTKEYS_GATE_ADMIN_URL AGENTKEYS_GATE_TURN_URL \
  AGENTKEYS_GATE_DELEGATE_BUDGET_TOKENS AGENTKEYS_GATE_KEYS_FILE AGENTKEYS_INFERENCE_CREDS_DIR \
  SANDBOX_FUNCTION_ID SANDBOX_GATEWAY_URL SANDBOX_GATEWAY_SECRET_TOKEN_HEADER CR_IMAGE \
  BROKER_AUTH_METHODS BROKER_EMAIL_FROM_ADDRESS AGENTKEYS_BUNDLER_URL AGENTKEYS_BUNDLER_BIND \
  AGENTKEYS_ACCEPT_ALLOW_ADDR_OVERRIDE AGENTKEYS_SIGNER_STS_PROVIDER AGENTKEYS_STS_ROLE_TRN_VAULT \
  AGENTKEYS_SIGNER_REQUIRE_CHAIN_GRANT AGENTKEYS_REGISTRY_ADDRESS AGENTKEYS_SANDBOX_ECS_CLUSTER \
  AGENTKEYS_ALLOW_DIRECT_ARK AGENTKEYS_GATE_SEARCH_ENGINES TYPESAFE_BASE_URL KEV_BASE_URL AWS_PROFILE \
  AWS_ACCESS_KEY_ID AGENTKEYS_WEIXIN_SECRETS_FILE PORT HOST RUST_LOG; do
  got="$(host_unit_secret_key_names "Environment=${key}=x")"
  [ -z "$got" ] || flag "predicate flags the non-secret deployed key $key (narrow HOST_UNIT_SECRET_KEY_RE)"
done
for key in AGENTKEYS_GATE_ADMIN_TOKEN AGENTKEYS_CHANNEL_STS_TOKEN SANDBOX_GATEWAY_SECRET_TOKEN \
  VOLCENGINE_ACCESS_KEY VOLCENGINE_SECRET_KEY AWS_SECRET_ACCESS_KEY DEV_KEY_SERVICE_MASTER_SECRET \
  BROKER_SPONSOR_SIGNER_KEY AGENTKEYS_BUNDLER_SIGNER_KEY AGENTKEYS_WORKER_KEK_HEX \
  AGENTKEYS_CHANNEL_KEK_HEX ARK_API_KEY TYPESAFE_API_KEY KEV_API_KEY AGENTKEYS_WEIXIN_ADMIN_TOKEN \
  AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN AGENTKEYS_WEIXIN_APP_SECRET AGENTKEYS_DEVICE_KEY_HEX \
  AGENTKEYS_BRIDGE_TOKEN ASR_ACCESS_TOKEN; do
  got="$(host_unit_secret_key_names "Environment=${key}=x")"
  [ "$got" = "$key" ] || flag "predicate misses the secret $key (widen HOST_UNIT_SECRET_KEY_RE)"
done
# The quoted form and a multi-assignment line are units too (the quote comes
# from $q so this test line does not trip the static scan below).
q='"'
[ "$(host_unit_secret_key_names "Environment=${q}AGENTKEYS_GATE_ADMIN_TOKEN=x${q}")" = AGENTKEYS_GATE_ADMIN_TOKEN ] \
  || flag "predicate misses a quoted Environment=\"KEY=…\" line"
[ "$(host_unit_secret_key_names 'Environment=HOME=/x AGENTKEYS_CHANNEL_STS_TOKEN=y')" = AGENTKEYS_CHANNEL_STS_TOKEN ] \
  || flag "predicate misses the second assignment of an Environment= line"
# Through the real renderer: an env block → host_broker_unit_content → predicate.
rendered="$(host_broker_unit_content 'self-test' "$(printf 'HOME=/x\nAGENTKEYS_GATE_ADMIN_TOKEN=deadbeef')" /etc/agentkeys/x.env)"
[ "$(host_unit_secret_key_names "$rendered")" = AGENTKEYS_GATE_ADMIN_TOKEN ] \
  || flag "a secret in a rendered broker unit's env block is not caught"
rendered="$(host_broker_unit_content 'self-test' 'AGENTKEYS_GATE_ADMIN_URL=http://127.0.0.1:8077' /etc/agentkeys/gate-admin.env)"
[ -z "$(host_unit_secret_key_names "$rendered")" ] \
  || flag "a clean rendered broker unit (secret via EnvironmentFile=) is flagged"

# ── 2. static: every Environment=KEY= spelled out in a tracked *.sh ─────────
if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=()
  while IFS= read -r f; do
    case "$f" in docs/archived/*) continue ;; esac
    files+=("$f")
  done < <(git ls-files '*.sh')
fi
for f in ${files[@]+"${files[@]}"}; do
  [ -f "$f" ] || continue
  while IFS= read -r hit; do
    lineno="${hit%%:*}"; text="${hit#*:}"
    case "$(printf '%s' "$text" | sed -E 's/^[[:space:]]+//')" in \#*) continue ;; esac
    keys="$(printf '%s\n' "$text" | grep -oE 'Environment="?[A-Za-z_][A-Za-z0-9_]*=' | sed -E 's/^Environment="?//; s/=$//' || true)"
    for key in $keys; do
      if [ -n "$(host_unit_secret_key_names "Environment=${key}=x")" ]; then
        flag "$f:$lineno — $key is set by an Environment= line (move it to a 0600 EnvironmentFile=)"
      fi
    done
  done < <(grep -nE 'Environment="?[A-Za-z_][A-Za-z0-9_]*=' "$f" || true)
done

if [ "$fails" -gt 0 ]; then
  {
    echo ""
    echo "$fails problem(s). A unit file is 0644 and its Environment= values reach any local user"
    echo "over D-Bus (systemctl show). A secret lives in a 0600 file each consumer unit loads as"
    echo "EnvironmentFile= — host_ensure_bearer_file (scripts/operator/lib/host-common.sh)."
  } >&2
  exit 1
fi
echo "unit inline secrets: none (${#files[@]} script(s) scanned; predicate self-test passed)"
