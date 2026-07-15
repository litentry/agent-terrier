#!/usr/bin/env bash
# check-env-zone-inference.sh — #463 drift guard: one zone per stack, hosts inferred.
#
# The invariant: each operator-workstation*.env file carries exactly ONE
# host-coordinate literal — the AWS files' BROKER_HOST, the VE file's
# VE_CN_ZONE — and every other host var is DERIVED from it
# (`signer.${BROKER_HOST#*.}` / `signer.${VE_CN_ZONE}`). A re-hardcoded
# subdomain is how the stacks forked before (#463: 10 literal .cn hosts + two
# duplicate zone vars, and a stale shell export silently outranked --cloud ve),
# so this is a CI gate, not a convention.
#
# Sibling of check-env-file-key-parity.sh (key parity); this one checks VALUE
# derivation. Pure grep — never sources the env files.
set -euo pipefail

cd "$(dirname "$0")/../.."

fail=0
say() { printf '%s\n' "$*" >&2; }

check_file() {
  local f="$1" allowed_literal="$2" pattern="$3" label="$4"
  [[ -f "$f" ]] || { say "skip $f (absent)"; return 0; }
  local bad
  # a host line is BAD when its value is a bare FQDN literal (contains a dot
  # but no ${...} derivation reference)
  bad=$(grep -E "$pattern" "$f" | grep -vE '=\S*\$\{' | grep -vE "^${allowed_literal}=" || true)
  if [[ -n "$bad" ]]; then
    say "FAIL $f — $label must derive from \$${allowed_literal}, not re-hardcode a literal:"
    say "$bad"
    fail=1
  else
    say "ok   $f — $label derived from \$${allowed_literal}"
  fi
}

# VE stack: VE_CN_ZONE is the one literal; every VE_*_HOST derives from it.
# (VE_ORPHANED_HOSTS — plural, a .ai guard list — is deliberately not matched.)
check_file scripts/operator-workstation.ve.env \
  VE_CN_ZONE '^VE_[A-Z_]*_HOST=' 'VE_*_HOST'

# AWS stacks: BROKER_HOST is the one literal; signer/mcp/worker hosts derive.
for env_file in scripts/operator-workstation.env \
                scripts/operator-workstation.test.env \
                scripts/operator-workstation.test-2.env \
                scripts/operator-workstation.base.env; do
  check_file "$env_file" \
    BROKER_HOST '^(SIGNER_HOST|MCP_HOST|WORKER_[A-Z]+_HOST)=' 'derived hosts'
done

if [[ "$fail" -ne 0 ]]; then
  say ""
  say "One zone per stack (#463): add the subdomain as <name>.\${VE_CN_ZONE} /"
  say "<name>.\${BROKER_HOST#*.} — the zone literal lives in ONE line per file."
  exit 1
fi
say "env zone-inference: all stacks derive hosts from their single zone literal"
