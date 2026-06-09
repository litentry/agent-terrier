#!/usr/bin/env bash
# scripts/check-deployed-contracts-sync.sh — LOCAL check (no CI): the chain
# profile crates/agentkeys-core/chain-profiles/<chain>.json (the machine-readable
# SOURCE OF TRUTH for deployed addresses + the contract-set version) must agree
# with scripts/operator-workstation.env (the shell-consumption copy).
#
# heima-bring-up.sh step 6b writes the chain profile on deploy; step 6 writes the
# env. This verifies they match — run it after a deploy / before committing.
# Deliberately NOT a per-PR CI workflow (CI is expensive); the profile + the
# deploy script keep things honest, this is the cheap local confirmation.
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
  echo "doc: docs/spec/deployed-contracts.md (its address table points at the profile)." >&2
  exit 1
fi
echo "chain profile ⟷ operator-workstation.env in sync ✓"
