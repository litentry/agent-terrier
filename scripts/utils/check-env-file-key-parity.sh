#!/usr/bin/env bash
# Gate: operator env files (scripts/operator-workstation*.env) stay at
# KEY-SET parity across the AWS-cloud stacks (prod / test / test-2 / base).
#
# WHY: the env files are NOT auto-derived from one another — each is edited
# by hand. When a new data class / worker / EIP-keyed resource lands (a new
# WORKER_*_HOST + AGENTKEYS_WORKER_*_URL + *_ROLE_ARN + *_BUCKET), the keys
# must be added to EVERY AWS stack's env file. Miss one and a bare
# `setup-cloud.sh --ci --slot N` (or `--base`) dies at RUNTIME under `set -u`
# with `<KEY>: unbound variable` on the box that file targets — long after
# review, in front of an operator.
#
# Real incidents this gate closes:
#   * #201 — a new Config data-class key landed in prod but not the test env
#     file, killing `setup-cloud.sh --ci`.
#   * #406 (channels epic) — WORKER_CHANNEL_HOST + AGENTKEYS_WORKER_CHANNEL_URL
#     + CHANNEL_ROLE_ARN + CHANNEL_BUCKET landed in operator-workstation.env +
#     operator-workstation.test.env but NOT operator-workstation.test-2.env, so
#     `setup-cloud.sh --ci --slot 2` died at dns-upsert-workers.sh under set -u
#     while `--ci` (slot 1) passed.
#
# The discipline is documented in AGENTS.ops.md ("Env-file discipline for ANY
# new data class / worker / EIP-keyed resource"), but a doc rule alone was
# violated twice — this is the enforcement half.
#
# TWO checks:
#   1. Data-plane key parity — the recurring-bug category (WORKER_*_HOST,
#      AGENTKEYS_WORKER_*_URL, *_ROLE_ARN, *_BUCKET) must be the SAME set in
#      every AWS-cloud env file. These are AWS S3 / IAM concepts shared by
#      every AWS stack regardless of chain, so the set is identical.
#   2. Test-slot full parity — every operator-workstation.test-N.env slot file
#      must carry the IDENTICAL full key set as slot 1 (operator-workstation.
#      test.env). Test slots are the same environment (Heima test fleet)
#      differing only in the -test-N suffix VALUE, so their key sets must match
#      exactly (catches non-data-plane test drift too).
#
# NON_AWS_ENV_FILES: operator-workstation.ve.env is the #376 Volcano Engine
# mirror — a DIFFERENT cloud with a different storage + addressing seam (VE
# TOS, not S3; VE STS, not IAM ARNs), so its data-plane keys are legitimately
# named differently. Excluded from check 1 with this reason, NOT silently.
#
# ALLOWLIST_KEYS: data-plane keys that legitimately live in only some AWS
# stacks. Empty today; add with a reason + removal condition if ever needed.
#
# Output convention: `ok proceeding` / `fail <reason>` per the repo's
# idempotent-script rule.

set -euo pipefail
cd "$(dirname "$0")/../.."

PROD="scripts/operator-workstation.env"
SLOT1="scripts/operator-workstation.test.env"

# AWS-cloud env files that are NOT subject to data-plane parity (different
# cloud). Every entry needs the reason + the condition for its removal.
NON_AWS_ENV_FILES=(
  # #376 Volcano Engine mirror — VE TOS/STS addressing, not AWS S3/IAM; its
  # data-plane keys are a different set by design. Remove only if VE is
  # migrated onto AWS-style *_BUCKET / *_ROLE_ARN naming.
  "scripts/operator-workstation.ve.env"
  # The VE TEST stack (CI broker on Volcano Engine — the ve.env twin with
  # -test names). Same different-cloud seam, same removal condition.
  "scripts/operator-workstation.ve-test.env"
)

# Data-plane keys legitimately absent from some AWS stack. Empty — every AWS
# stack needs every worker / data class today. Add with a reason if that
# ever stops being true.
ALLOWLIST_KEYS=()

is_excluded() {
  local f="$1" x
  for x in ${NON_AWS_ENV_FILES[@]+"${NON_AWS_ENV_FILES[@]}"}; do
    [ "$f" = "$x" ] && return 0
  done
  return 1
}

# All variable names (LHS of `KEY=`) in an env file, sorted-unique. Missing
# file → empty (the OSS mirror strips operator-workstation.env; see the
# fork guard in the workflow).
all_keys() { grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$1" 2>/dev/null | sed 's/=$//' | sort -u; }

# The data-plane subset: workers, per-data-class roles, buckets, worker URLs.
data_keys() {
  all_keys "$1" | grep -E '^(WORKER_[A-Z0-9]+_HOST|AGENTKEYS_WORKER_[A-Z0-9]+_URL|[A-Z0-9]+_ROLE_ARN|[A-Z0-9]+_BUCKET)$' || true
}

# Drop ALLOWLIST_KEYS from stdin (no-op when the list is empty).
filter_allowlist() {
  if [ "${#ALLOWLIST_KEYS[@]}" -eq 0 ]; then
    cat
  else
    grep -vxF -f <(printf '%s\n' "${ALLOWLIST_KEYS[@]}") || true
  fi
}

fail=0

# Emit MISSING / EXTRA sets for one file vs a reference; returns non-zero on drift.
diff_keys() {
  local label="$1" reffile="$2" ref="$3" cur="$4"
  local missing extra
  missing=$(comm -23 <(printf '%s\n' "$ref") <(printf '%s\n' "$cur") || true)
  extra=$(comm -13 <(printf '%s\n' "$ref") <(printf '%s\n' "$cur") || true)
  if [ -n "$missing" ] || [ -n "$extra" ]; then
    fail=1
    echo "fail  $label drift vs $reffile:" >&2
    [ -n "$missing" ] && { echo "  MISSING (present in reference, absent here):" >&2; printf '%s\n' "$missing" | sed 's/^/    - /' >&2; }
    [ -n "$extra" ] && { echo "  EXTRA (present here, absent in reference):" >&2; printf '%s\n' "$extra" | sed 's/^/    + /' >&2; }
    return 1
  fi
  return 0
}

echo "==> Check 1: data-plane key parity across AWS-cloud env files (reference: $PROD)"
ref_data=$(data_keys "$PROD" | filter_allowlist)
for f in scripts/operator-workstation*.env; do
  [ -e "$f" ] || continue
  [ "$f" = "$PROD" ] && continue
  if is_excluded "$f"; then
    echo "    skip  $f (non-AWS cloud — different storage/addressing seam)"
    continue
  fi
  cur_data=$(data_keys "$f" | filter_allowlist)
  if diff_keys "data-plane $f" "$PROD" "$ref_data" "$cur_data"; then
    echo "    ok    $f — data-plane keys match prod"
  fi
done

echo "==> Check 2: test-slot full key-set parity (reference slot 1: $SLOT1)"
if [ -f "$SLOT1" ]; then
  ref_all=$(all_keys "$SLOT1")
  slot_seen=0
  for f in scripts/operator-workstation.test-*.env; do
    [ -e "$f" ] || continue
    slot_seen=1
    cur_all=$(all_keys "$f")
    if diff_keys "test-slot $f" "$SLOT1" "$ref_all" "$cur_all"; then
      echo "    ok    $f — full key set matches slot 1"
    fi
  done
  [ "$slot_seen" = "0" ] && echo "    skip  no operator-workstation.test-N.env slot files present"
else
  echo "    skip  $SLOT1 not present (OSS mirror strips operator env files)"
fi

if [ "$fail" -ne 0 ]; then
  cat >&2 <<'EOF'

A new data class / worker / EIP-keyed resource must land in THREE places
(AGENTS.ops.md "Env-file discipline for ANY new data class / worker / …"):
  1. EVERY operator-workstation*.env AWS stack (prod + test + test-N + base) —
     the missing key(s) above. Match the stack's suffix convention
     (-test / -test-N / -base) and host style (${ZONE} for test-N).
  2. the setup-cloud.sh -> cloud-aws.sh ENV_FILE passthrough (so a --ci /
     --slot N / --base run provisions the -test-N / -base resource, not prod).
  3. the e2e-ci.yml "Materialize the production env file with TEST values" step
     (CI writes its own env file from secrets + derived -test values; a key
     missing there aborts the stage under set -u).
EOF
  echo "fail  operator env files are not at key parity — see above" >&2
  exit 1
fi

echo "ok proceeding — operator env files are at key parity (data plane + test slots)"
