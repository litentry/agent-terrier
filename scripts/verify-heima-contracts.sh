#!/usr/bin/env bash
# scripts/verify-heima-contracts.sh — read-only health-check for the
# four v2 stage-1 contracts deployed to Heima.
#
# What it checks (all read-only RPC, never spends gas):
#   1. eth_getCode for each contract — confirms bytecode is present
#   2. Each contract's known view function — confirms the deployed code
#      matches the expected ABI (catches "wrong contract at this slot")
#   3. AgentKeysScope.registry() points at the deployed SidecarRegistry
#      (catches the constructor wiring drift)
#   4. K3EpochCounter.currentEpoch() ≥ 1, signerGovernance != address(0)
#
# Usage:
#   bash scripts/verify-heima-contracts.sh
#   AGENTKEYS_CHAIN=heima       bash scripts/verify-heima-contracts.sh
#   AGENTKEYS_CHAIN=heima-paseo bash scripts/verify-heima-contracts.sh
#
# Reads addresses from operator-workstation.env (the canonical
# per-operator record). Exits 0 if all checks pass, 1 if any fail.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$REPO_ROOT/scripts/operator-workstation.env"

if [ -t 2 ]; then
  C_HEAD='\033[1;36m'; C_OK='\033[1;32m'; C_ERR='\033[1;31m'; C_RESET='\033[0m'
else
  C_HEAD=''; C_OK=''; C_ERR=''; C_RESET=''
fi
log()  { printf "${C_HEAD}==>${C_RESET} %s\n" "$*" >&2; }
ok()   { printf "    ${C_OK}ok${C_RESET}   %s\n" "$*" >&2; }
fail() { printf "    ${C_ERR}fail${C_RESET} %s\n" "$*" >&2; FAILED=$((FAILED+1)); }

[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE" >&2; exit 1; }
set -a; . "$ENV_FILE"; set +a

AGENTKEYS_CHAIN="${AGENTKEYS_CHAIN:-heima}"
PROFILE_NAME_UC=$(printf '%s' "$AGENTKEYS_CHAIN" | tr 'a-z-' 'A-Z_')
PROFILE_JSON=$(agentkeys chain show "$AGENTKEYS_CHAIN")
RPC_HTTP=$(echo "$PROFILE_JSON" | jq -r .rpc.http)
log "Verifying contracts on $AGENTKEYS_CHAIN ($RPC_HTTP)"

# Resolve per-chain addresses
SCOPE=$(eval echo \$SCOPE_CONTRACT_ADDRESS_${PROFILE_NAME_UC})
REGISTRY=$(eval echo \$SIDECAR_REGISTRY_ADDRESS_${PROFILE_NAME_UC})
EPOCH=$(eval echo \$K3_EPOCH_COUNTER_ADDRESS_${PROFILE_NAME_UC})
AUDIT=$(eval echo \$CREDENTIAL_AUDIT_ADDRESS_${PROFILE_NAME_UC})

FAILED=0
echo "    chain:           $AGENTKEYS_CHAIN" >&2
echo "    rpc:             $RPC_HTTP" >&2
echo "    AgentKeysScope:  $SCOPE" >&2
echo "    SidecarRegistry: $REGISTRY" >&2
echo "    K3EpochCounter:  $EPOCH" >&2
echo "    CredentialAudit: $AUDIT" >&2
echo >&2

# 1. Bytecode presence
log "1/4 bytecode presence (eth_getCode)"
for pair in "AgentKeysScope:$SCOPE" "SidecarRegistry:$REGISTRY" "K3EpochCounter:$EPOCH" "CredentialAudit:$AUDIT"; do
  name="${pair%%:*}"; addr="${pair##*:}"
  code=$(curl -sS -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getCode\",\"params\":[\"$addr\",\"latest\"],\"id\":1}" \
    "$RPC_HTTP" | jq -r .result)
  if [ -z "$code" ] || [ "$code" = "0x" ]; then
    fail "$name @ $addr: NO bytecode (stub or chain reset)"
  else
    ok "$name @ $addr: $((${#code} / 2 - 1)) bytes"
  fi
done

# 2. View functions respond with expected values
log "2/4 view functions return expected constants"
v=$(cast call "$REGISTRY" "ROLE_CAP_MINT()(uint8)" --rpc-url "$RPC_HTTP" 2>&1 || echo ERR)
[ "$v" = "1" ] && ok "SidecarRegistry.ROLE_CAP_MINT = 1" || fail "SidecarRegistry.ROLE_CAP_MINT: expected 1, got '$v'"
v=$(cast call "$REGISTRY" "ROLE_RECOVERY()(uint8)" --rpc-url "$RPC_HTTP" 2>&1 || echo ERR)
[ "$v" = "2" ] && ok "SidecarRegistry.ROLE_RECOVERY = 2" || fail "SidecarRegistry.ROLE_RECOVERY: expected 2, got '$v'"
v=$(cast call "$REGISTRY" "ROLE_SCOPE_MGMT()(uint8)" --rpc-url "$RPC_HTTP" 2>&1 || echo ERR)
[ "$v" = "4" ] && ok "SidecarRegistry.ROLE_SCOPE_MGMT = 4" || fail "SidecarRegistry.ROLE_SCOPE_MGMT: expected 4, got '$v'"
v=$(cast call "$AUDIT" "OP_STORE()(uint8)" --rpc-url "$RPC_HTTP" 2>&1 || echo ERR)
[ "$v" = "0" ] && ok "CredentialAudit.OP_STORE = 0" || fail "CredentialAudit.OP_STORE: expected 0, got '$v'"

# 3. AgentKeysScope.registry() points at the deployed SidecarRegistry
log "3/4 AgentKeysScope.registry() is wired to the deployed SidecarRegistry"
linked=$(cast call "$SCOPE" "registry()(address)" --rpc-url "$RPC_HTTP" 2>&1 || echo ERR)
# Normalize case for comparison
linked_lc=$(printf '%s' "$linked" | tr '[:upper:]' '[:lower:]')
registry_lc=$(printf '%s' "$REGISTRY" | tr '[:upper:]' '[:lower:]')
if [ "$linked_lc" = "$registry_lc" ]; then
  ok "AgentKeysScope.registry() = $linked (matches deployed SidecarRegistry)"
else
  fail "AgentKeysScope.registry() = $linked but SIDECAR_REGISTRY_ADDRESS_${PROFILE_NAME_UC} = $REGISTRY (constructor wired to wrong address?)"
fi

# 4. K3EpochCounter initialized
log "4/4 K3EpochCounter initialized"
epoch_val=$(cast call "$EPOCH" "currentEpoch()(uint256)" --rpc-url "$RPC_HTTP" 2>&1 || echo ERR)
gov=$(cast call "$EPOCH" "signerGovernance()(address)" --rpc-url "$RPC_HTTP" 2>&1 || echo ERR)
[ "$epoch_val" -ge 1 ] 2>/dev/null && ok "K3EpochCounter.currentEpoch = $epoch_val" || fail "K3EpochCounter.currentEpoch unset: '$epoch_val'"
case "$gov" in
  0x0000000000000000000000000000000000000000) fail "K3EpochCounter.signerGovernance = address(0) — not initialized" ;;
  ERR) fail "K3EpochCounter.signerGovernance: cast failed" ;;
  *)   ok "K3EpochCounter.signerGovernance = $gov" ;;
esac

echo >&2
if [ "$FAILED" = "0" ]; then
  printf "${C_OK}═══ all checks passed ═══${C_RESET}\n" >&2
  exit 0
else
  printf "${C_ERR}═══ $FAILED check(s) failed ═══${C_RESET}\n" >&2
  exit 1
fi
