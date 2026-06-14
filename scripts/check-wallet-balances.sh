#!/usr/bin/env bash
# scripts/check-wallet-balances.sh — read-only HEI balance snapshot for the
# AgentKeys on-chain wallets + the paymaster's EntryPoint deposit. Zero gas,
# zero mutation (eth_getBalance / eth_call only). Run it any time to answer
# "which wallet is running dry?".
#
# Address provenance (the #251 source-of-truth hierarchy — NEVER hardcoded):
#   • VERSIONED CONTRACTS (EntryPoint, VerifyingPaymaster) ← the chain profile
#     crates/agentkeys-core/chain-profiles/<chain>.json `.contracts[]` — the
#     single machine source of truth, compiled into the broker via include_str!.
#   • WALLET EOAs (deployer, sponsor/bundler) ← scripts/operator-workstation.env
#     (EOAs are operator identifiers, not part of the versioned contract set).
#   • Test/CI deployer EOA ← scripts/operator-workstation.test.env.
#
# The funding map that explains what each wallet does is
# docs/chain-setup.md §Wallets, contracts & funding map.
#
# Usage:
#   bash scripts/check-wallet-balances.sh                 # prod profile
#   CHAIN_PROFILE=crates/agentkeys-core/chain-profiles/heima-paseo.json bash scripts/check-wallet-balances.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/operator-workstation.env}"
TEST_ENV_FILE="${TEST_ENV_FILE:-$SCRIPT_DIR/operator-workstation.test.env}"
CHAIN_PROFILE="${CHAIN_PROFILE:-$REPO_ROOT/crates/agentkeys-core/chain-profiles/heima.json}"

[ -f "$ENV_FILE" ]       || { echo "missing env file: $ENV_FILE" >&2; exit 1; }
[ -f "$CHAIN_PROFILE" ]  || { echo "missing chain profile: $CHAIN_PROFILE" >&2; exit 1; }
set -a; . "$ENV_FILE"; set +a
RPC="${AGENTKEYS_CHAIN_RPC_HTTP:-https://rpc.heima-parachain.heima.network}"

# Versioned contract addresses — read from the chain profile, the SOT (#251).
prof_addr() { jq -r --arg n "$1" '(.contracts[] | select(.name==$n) | .address) // ""' "$CHAIN_PROFILE"; }
ENTRYPOINT="$(prof_addr EntryPoint)"
PAYMASTER="$(prof_addr VerifyingPaymaster)"
SET_VERSION="$(jq -r '.contract_set_version // "?"' "$CHAIN_PROFILE")"

# Test-stack values — read WITHOUT sourcing the test env (sourcing would
# clobber the prod vars we just loaded). The test stack runs its OWN ERC-4337
# EntryPoint/factory (+ optional paymaster) since #250 — separate instances
# from prod, recorded only in the test env file + the TEST_* GH secrets.
test_env_val() { grep -E "^$1=" "$TEST_ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2 || true; }
TEST_DEPLOYER="$(test_env_val DEPLOYER_ADDR_HEIMA)"
TEST_ENTRYPOINT="$(test_env_val ENTRYPOINT_ADDRESS_HEIMA)"
TEST_PAYMASTER="$(test_env_val PAYMASTER_ADDRESS_HEIMA)"

# Retry up to 3x so a transient RPC blip degrades to one `n/a` cell, not a crash.
rpc() {
  local out i
  for i in 1 2 3; do
    out=$(curl -s --max-time 8 -X POST -H 'content-type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$RPC")
    [ -n "$out" ] && { printf '%s' "$out"; return 0; }
    sleep 1
  done
}
hexresult() { jq -r '.result // empty' 2>/dev/null; }
native_wei() { rpc eth_getBalance "[\"$1\",\"latest\"]" | hexresult; }
# Paymaster deposit = EntryPoint.balanceOf(paymaster) — the funds live INSIDE
# the EntryPoint keyed by the paymaster address, NOT as the paymaster's own
# balance (a plain transfer to the paymaster does NOT fund sponsorship).
deposit_wei() { rpc eth_call "[{\"to\":\"$1\",\"data\":\"0x70a08231000000000000000000000000${2:2}\"},\"latest\"]" | hexresult; }
hei() { python3 -c "import sys; v=sys.argv[1] if len(sys.argv)>1 else ''; print('     n/a' if not v.startswith('0x') else f'{int(v,16)/1e18:.6f}')" "${1:-}"; }

printf '\n  Heima mainnet — RPC %s\n' "$RPC"
printf '  contracts from %s (set v%s)\n\n' "${CHAIN_PROFILE#"$REPO_ROOT"/}" "$SET_VERSION"
printf '  %-26s %-44s %14s\n' "wallet / contract" "address" "HEI"
printf '  %s\n' "$(printf '%.0s-' {1..86})"
row() { printf '  %-26s %-44s %14s\n' "$1" "$2" "$(hei "$(native_wei "$2")")"; }

row "prod deployer  [env]"      "$DEPLOYER_ADDR_HEIMA"
[ -n "$TEST_DEPLOYER" ] && row "test/CI deployer  [env]"  "$TEST_DEPLOYER"
row "sponsor/bundler  [env]"    "$BROKER_SPONSOR_SIGNER_ADDRESS_HEIMA"
row "paymaster raw  [profile]"  "$PAYMASTER"
row "EntryPoint  [profile]"     "$ENTRYPOINT"
printf '  %s\n' "$(printf '%.0s-' {1..86})"
printf '  %-26s %-44s %14s\n' "paymaster DEPOSIT" \
  "in EntryPoint, key ${PAYMASTER:0:12}…" \
  "$(hei "$(deposit_wei "$ENTRYPOINT" "$PAYMASTER")")"
# Test-stack ERC-4337 (#250 — separate instances; rows appear once deployed).
if [ -n "$TEST_ENTRYPOINT" ]; then
  printf '  %s\n' "$(printf '%.0s-' {1..86})"
  row "TEST EntryPoint  [test-env]" "$TEST_ENTRYPOINT"
  if [ -n "$TEST_PAYMASTER" ]; then
    row "TEST paymaster raw  [test-env]" "$TEST_PAYMASTER"
    printf '  %-26s %-44s %14s\n' "TEST paymaster DEPOSIT" \
      "in TEST EntryPoint, key ${TEST_PAYMASTER:0:12}…" \
      "$(hei "$(deposit_wei "$TEST_ENTRYPOINT" "$TEST_PAYMASTER")")"
  fi
fi
printf '\n  The DEPOSIT row is the sponsored-gas pool (drawn down per accept).\n'
printf '  The sponsor/bundler EOA fronts handleOps gas and is refunded from it.\n'
printf '  [profile] = versioned, from the chain profile; [env] = operator EOA;\n'
printf '  [test-env] = the test stack'"'"'s own instance (operator-workstation.test.env).\n\n'
