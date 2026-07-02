#!/usr/bin/env bash
# check-storage-policy-parity.sh — #372 storage-plane parity + no-broad-grant gate.
#
# The provisioning identities on BOTH clouds (AWS agentkeys-admin group,
# VE agentterrier-admin user + agentterrier-broker-setup signing identity)
# carry SCOPED custom policies whose single source of truth is
# scripts/operator/policies/*.json. This gate keeps the pair honest without cloud
# credentials (pure file checks, CI-safe):
#
#   1. The canonical documents parse and carry Sids.
#   2. Sid-level parity: every Sid in the AWS document has a VE twin (and
#      vice versa) unless listed in the documented exception table below.
#   3. No broad grants: no bare `s3:*` / `tos:*` action, no action-wildcard
#      statement, anywhere in the canonical documents.
#   4. Data-bucket object isolation: NO statement grants object read/write/
#      delete on the vault/memory/config data buckets on either cloud.
#   5. The setup scripts render from the canonical documents (no inline
#      re-typed policy JSON — the #200/#203 drift-bug class) and never
#      ATTACH the broad system policies they replaced.
#
# Exit 0 = parity holds; exit 1 = drift (message names the violation).
# CI: .github/workflows/storage-policy-parity.yml. Run locally any time:
#   bash scripts/utils/check-storage-policy-parity.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$SCRIPT_DIR/../operator/policies"
AWS_DOC="$POLICY_DIR/aws-provisioning-storage.json"
VE_ADMIN_DOC="$POLICY_DIR/ve-admin-tos.json"
VE_BROKER_DOC="$POLICY_DIR/ve-broker-setup.json"

fail=0
err() { echo "FAIL  $*" >&2; fail=1; }
ok()  { echo "ok    $*"; }

# Sid-parity exception table — every entry is a DELIBERATE asymmetry with the
# reason recorded here (the "documented side by side" half of the #372
# acceptance). Adding a one-sided Sid without an entry fails the gate.
#   MailObjectRW  (AWS-only): email is hybrid-AWS — SES + the mail bucket have
#                 no VE counterpart by decision (operator-workstation.ve.env).
#   OidcObjectRW  (VE-only): the VE OIDC issuer is a public TOS bucket the
#                 admin publishes discovery/JWKS into; the AWS issuer is
#                 broker-hosted (no bucket, no object grant needed).
#   ProbeObjectRW (VE-only): tests/tos_live.rs addressing probe bucket —
#                 a TOS-specific seam probe with no AWS counterpart.
AWS_ONLY_SIDS=("MailObjectRW")
VE_ONLY_SIDS=("OidcObjectRW" "ProbeObjectRW")

# ── 1. Documents parse ────────────────────────────────────────────────────────
for doc in "$AWS_DOC" "$VE_ADMIN_DOC" "$VE_BROKER_DOC"; do
  [ -f "$doc" ] || { err "missing canonical policy document: $doc"; continue; }
  jq -e '.Statement | length > 0' "$doc" >/dev/null 2>&1 \
    || err "$(basename "$doc") is not a policy document (no Statement array)"
  jq -e '[.Statement[] | has("Sid")] | all' "$doc" >/dev/null 2>&1 \
    || err "$(basename "$doc") has a statement without a Sid (parity is keyed on Sids)"
done
[ "$fail" = 0 ] && ok "canonical documents parse, every statement carries a Sid"

# ── 2. Sid-level parity (AWS admin ⟷ VE admin) ───────────────────────────────
aws_sids=$(jq -r '.Statement[].Sid' "$AWS_DOC" | sort)
ve_sids=$(jq -r '.Statement[].Sid' "$VE_ADMIN_DOC" | sort)
for sid in $aws_sids; do
  case " ${AWS_ONLY_SIDS[*]} " in *" $sid "*) continue ;; esac
  grep -qx "$sid" <<<"$ve_sids" \
    || err "Sid '$sid' exists in $(basename "$AWS_DOC") but has no VE twin (add it to ve-admin-tos.json or to the exception table with a reason)"
done
for sid in $ve_sids; do
  case " ${VE_ONLY_SIDS[*]} " in *" $sid "*) continue ;; esac
  grep -qx "$sid" <<<"$aws_sids" \
    || err "Sid '$sid' exists in $(basename "$VE_ADMIN_DOC") but has no AWS twin (add it to aws-provisioning-storage.json or to the exception table with a reason)"
done
[ "$fail" = 0 ] && ok "Sid parity holds (exceptions: AWS-only ${AWS_ONLY_SIDS[*]}; VE-only ${VE_ONLY_SIDS[*]})"

# ── 3. No broad grants in the canonical documents ────────────────────────────
for doc in "$AWS_DOC" "$VE_ADMIN_DOC" "$VE_BROKER_DOC"; do
  if jq -e '.Statement[] | select((.Action | if type=="array" then . else [.] end)
        | any(. == "s3:*" or . == "tos:*" or . == "*"))' "$doc" >/dev/null 2>&1; then
    err "$(basename "$doc") grants a bare service wildcard (s3:*/tos:*/*) — the exact broad grant #372 removed"
  fi
done
[ "$fail" = 0 ] && ok "no bare service-wildcard actions"

# ── 4. Data-bucket object isolation (both clouds) ────────────────────────────
# No statement may grant object-level access (GetObject/PutObject/DeleteObject,
# either prefix) on a resource that matches a vault/memory/config data bucket.
for doc in "$AWS_DOC" "$VE_ADMIN_DOC" "$VE_BROKER_DOC"; do
  if jq -e '.Statement[]
      | select((.Action | if type=="array" then . else [.] end)
               | any(test("(s3|tos):(Get|Put|Delete)Object")))
      | select((.Resource | if type=="array" then . else [.] end)
               | any(test("(agentkeys|agentterrier)-(vault|memory|config)")))' \
      "$doc" >/dev/null 2>&1; then
    err "$(basename "$doc") grants object-level access on a vault/memory/config data bucket — the provisioning identity must never reach data-class objects"
  fi
done
[ "$fail" = 0 ] && ok "no object grants on vault/memory/config data buckets"

# The broker signing identity gets ZERO storage actions of any kind.
if jq -e '.Statement[] | select((.Action | if type=="array" then . else [.] end)
      | any(startswith("tos:") or startswith("s3:")))' "$VE_BROKER_DOC" >/dev/null 2>&1; then
  err "$(basename "$VE_BROKER_DOC") grants storage actions — the broker signing identity mints STS sessions only (ve-broker-runtime-port.md mitigation 4)"
else
  ok "broker signing identity carries zero storage actions"
fi

# ── 5. Setup scripts render from the canonical documents ─────────────────────
# Post-#376 the VE flow is split across the entry + lib/cloud-ve.sh (the driver
# seams), so search both. AWS stays inline in setup-cloud.sh.
VE_RENDER_FILES="$SCRIPT_DIR/../operator/setup-cloud-ve.sh $SCRIPT_DIR/../operator/lib/cloud-ve.sh"
grep -q 'policies/aws-provisioning-storage.json' "$SCRIPT_DIR/../operator/setup-cloud.sh" \
  || err "setup-cloud.sh does not render scripts/operator/policies/aws-provisioning-storage.json"
# shellcheck disable=SC2086  # word-split VE_RENDER_FILES into grep's file list on purpose
grep -qh 've-broker-setup.json' $VE_RENDER_FILES \
  || err "the VE setup flow (setup-cloud-ve.sh / lib/cloud-ve.sh) does not render scripts/operator/policies/ve-broker-setup.json"
# shellcheck disable=SC2086
grep -qh 've-admin-tos.json' $VE_RENDER_FILES \
  || err "the VE setup flow (setup-cloud-ve.sh / lib/cloud-ve.sh) does not render scripts/operator/policies/ve-admin-tos.json"

# The broad system grants may appear only on DETACH paths, never ATTACH.
if grep -nE 'attach-group-policy.*AmazonS3FullAccess|AmazonS3FullAccess.*attach-group-policy' \
    "$SCRIPT_DIR/../operator/setup-cloud.sh" | grep -v detach; then
  err "setup-cloud.sh attaches AmazonS3FullAccess (broad grant re-introduced)"
fi
if grep -nE 'AttachUserPolicy.*TOSFullAccess|TOSFullAccess.*AttachUserPolicy' \
    "$SCRIPT_DIR/../operator/setup-cloud-ve.sh" | grep -viE 'detach|re-attach|warn'; then
  err "setup-cloud-ve.sh attaches TOSFullAccess (broad grant re-introduced)"
fi
[ "$fail" = 0 ] && ok "setup scripts render from canonical documents; broad grants appear only on detach paths"

if [ "$fail" != 0 ]; then
  echo "" >&2
  echo "storage-policy parity BROKEN — fix scripts/operator/policies/*.json (the source of truth) and keep both clouds mirrored (#372)." >&2
  exit 1
fi
echo "storage-policy parity: ALL GREEN"
