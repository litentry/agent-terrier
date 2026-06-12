#!/usr/bin/env bash
# scripts/check-deployed-contracts-sync.sh — two cheap deterministic checks
# (local + CI via .github/workflows/contracts-sync.yml, issue #251):
#
# 1. SYNC: the chain profile crates/agentkeys-core/chain-profiles/<chain>.json
#    (the machine-readable SOURCE OF TRUTH for deployed addresses + the
#    contract-set version) must agree with scripts/operator-workstation.env
#    (the shell-consumption mirror). heima-bring-up.sh step 6b writes the
#    profile on deploy; step 6 writes the env — this verifies they match.
#
# 2. DOC-LITERAL GATE (#251): no tracked markdown doc may re-write a literal
#    contract address that a chain profile currently owns — docs must ANCHOR
#    (link to the profile + a jq/grep resolve command), never copy. Copies
#    drift: deployed-contracts.md once claimed a stale AgentKeysScope address
#    a full redeploy after heima.json had the live one. Historical/orphaned
#    addresses pass naturally — once a redeploy moves an address out of the
#    profile, its literal is no longer banned. docs/archived/** is exempt
#    (frozen history). Per-file escape hatch: DOC_ALLOWLIST below.
#
#   bash scripts/check-deployed-contracts-sync.sh            # default chain: heima
#   CHAIN=heima bash scripts/check-deployed-contracts-sync.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/scripts/operator-workstation.env}"
CHAIN="${CHAIN:-heima}"
PROFILE="${CHAIN_PROFILE_FILE:-$REPO_ROOT/crates/agentkeys-core/chain-profiles/$CHAIN.json}"
PROFILE_UC="$(printf '%s' "$CHAIN" | tr 'a-z-' 'A-Z_')"

command -v jq >/dev/null 2>&1 || { echo "fail: jq required" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "fail: env file not found: $ENV_FILE" >&2; exit 1; }
[ -f "$PROFILE" ]  || { echo "fail: chain profile not found: $PROFILE" >&2; exit 1; }

set -a; . "$ENV_FILE"; set +a

echo "chain profile $CHAIN contract_set_version = $(jq -r '.contract_set_version // "?"' "$PROFILE")"

# Map each profile contract name → its env key suffix. (Only the keys the env carries.)
mapping="
AgentKeysScope:SCOPE_CONTRACT_ADDRESS
SidecarRegistry:SIDECAR_REGISTRY_ADDRESS
K3EpochCounter:K3_EPOCH_COUNTER_ADDRESS
CredentialAudit:CREDENTIAL_AUDIT_ADDRESS
P256Verifier:P256_VERIFIER_ADDRESS
P256Router:P256_ROUTER_ADDRESS
K11Verifier:K11_VERIFIER_ADDRESS
EntryPoint:ENTRYPOINT_ADDRESS
P256AccountFactory:P256_ACCOUNT_FACTORY_ADDRESS
VerifyingPaymaster:PAYMASTER_ADDRESS
"

lc() { printf '%s' "$1" | tr 'A-F' 'a-f'; }
mismatch=0
for row in $mapping; do
  name="${row%%:*}"; base="${row##*:}"
  prof_addr="$(jq -r --arg n "$name" '.contracts[]? | select(.name == $n) | .address' "$PROFILE")"
  env_addr="$(eval echo "\${${base}_${PROFILE_UC}:-}")"
  [ -z "$prof_addr" ] && { echo "  skip $name (not in profile)"; continue; }
  if [ "$(lc "$prof_addr")" = "$(lc "$env_addr")" ]; then
    echo "  ok   $name = $prof_addr"
  else
    echo "  MISMATCH $name: profile=$prof_addr  env(${base}_${PROFILE_UC})=$env_addr" >&2
    mismatch=1
  fi
done

if [ "$mismatch" = "1" ]; then
  echo "" >&2
  echo "chain profile is OUT OF SYNC with operator-workstation.env." >&2
  echo "A deploy updated one but not the other — reconcile them (the chain profile is the" >&2
  echo "source of truth; heima-bring-up.sh should have written both). Also refresh the human" >&2
  echo "doc: docs/spec/deployed-contracts.md (prose only — it carries no address table)." >&2
  exit 1
fi
echo "chain profile ⟷ operator-workstation.env in sync ✓"

# ---- Doc-literal gate (issue #251) -----------------------------------------
# Docs anchor to the chain profile; they never copy a live address. Files that
# may legitimately carry a CURRENT profile address go here (one repo-relative
# path per line) with a justification — expected to stay empty.
DOC_ALLOWLIST=""

profiles_dir="$REPO_ROOT/crates/agentkeys-core/chain-profiles"
addr_patterns="$(jq -r '.contracts[]?.address | ascii_downcase' "$profiles_dir"/*.json | sort -u)"

if [ -z "$addr_patterns" ]; then
  echo "fail: no contract addresses found in $profiles_dir/*.json" >&2
  exit 1
fi

if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  doc_files="$(git -C "$REPO_ROOT" ls-files -- '*.md' ':(exclude)docs/archived/**')"
else
  # Fallback for a checkout without git metadata (e.g. a deploy tarball).
  doc_files="$(cd "$REPO_ROOT" && find . -name '*.md' \
    -not -path './docs/archived/*' -not -path './target/*' \
    -not -path './node_modules/*' -not -path './.git/*' | sed 's|^\./||')"
fi

pattern_file="$(mktemp)"; trap 'rm -f "$pattern_file"' EXIT
printf '%s\n' "$addr_patterns" > "$pattern_file"

hits="$(cd "$REPO_ROOT" && printf '%s\n' "$doc_files" \
  | xargs grep -niF -f "$pattern_file" -- 2>/dev/null || true)"

for allowed in $DOC_ALLOWLIST; do
  hits="$(printf '%s\n' "$hits" | grep -v "^$allowed:" || true)"
done
hits="$(printf '%s\n' "$hits" | grep -v '^$' || true)"

if [ -n "$hits" ]; then
  echo "" >&2
  echo "DOC-LITERAL GATE FAILED (#251): tracked markdown re-writes a live contract address." >&2
  echo "The chain profile (crates/agentkeys-core/chain-profiles/*.json .contracts[]) is the" >&2
  echo "single source of truth — docs must ANCHOR to it (link + a jq/grep resolve command)," >&2
  echo "never copy the literal. Offending lines:" >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi
echo "doc-literal gate: no tracked .md re-writes a live contract address ✓"
