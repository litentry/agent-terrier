# Deployed contracts — v2 stage 1

**Canonical record** of the four v2 stage-1 Solidity contracts deployed to each chain. Source-of-truth for "what's the live address of `SidecarRegistry` on Heima mainnet right now?"

Same addresses are mirrored into [`scripts/operator-workstation.env`](../../scripts/operator-workstation.env) (the shell-script-consumable form, written by `scripts/heima-bring-up.sh` step 6 via `env_set`). When the two diverge, **this doc is authoritative for human reads, the env file for tooling**. The bring-up script keeps both in sync.

## Heima mainnet (chain_id = 212013)

**v2 (current live)** — wider AgentKeysScope + SidecarRegistry surface:

| Contract | Address | Bytecode |
|---|---|---|
| `AgentKeysScope` | `0xd44b375daefc65768f417d0f0125b68d5ba7df3b` | 4572 bytes |
| `SidecarRegistry` | `0x1Ac62f1C2D828476a5D784e850a700dC1f17e0bE` | 4572 bytes |
| `K3EpochCounter` | `0x6c9e675c699a06acefbc156afdee6bfbfe32ccb3` | 591 bytes |
| `CredentialAudit` | `0x63c4545ac01c77cc74044f25b8edea3880224577` | 3043 bytes |
| `P256Verifier` | `0xda5b772f9d6c09abe80414eea908612df9b54749` | (pre-deployed verifier) |
| `K11Verifier` | `0x5a441431f08e0f5f5ed10659620cb4e0e814e627` | (pre-deployed verifier) |

**Historical v1 deploy** (superseded by v2 above; preserved for cross-reference of old txs):

| Contract | Address | Bytecode |
|---|---|---|
| `AgentKeysScope` | `0x14C23B5D1cE20c094af643a20e6b0972dAD12aa8` | 3146 bytes |
| `SidecarRegistry` | `0x76D574a107727bE87fc1422661A030FEFda70786` | 3301 bytes |
| `K3EpochCounter` | `0x8396dEc50ff755d6DE7728DABB00Be2eFBCdf4dF` | 687 bytes |
| `CredentialAudit` | `0x1801ded1a4FBD8c9224Ab18B9EcbB293B8674c06` | 1421 bytes |

**Explorer note**: [`heima.statescan.io`](https://heima.statescan.io/) is a Substrate-side explorer — it indexes pallet extrinsics + events but does NOT decode EVM contract calls or bytecode. Verifying EVM contracts on Heima today goes via direct RPC, not the explorer. The recipes (pointing at the live v2 deploy):

```bash
# Bytecode presence (eth_getCode) — v2 AgentKeysScope:
curl -sS -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_getCode","params":["0xd44b375daefc65768f417d0f0125b68d5ba7df3b","latest"],"id":1}' \
  https://rpc.heima-parachain.heima.network | jq -r '.result' | head -c 40
# → non-"0x" output = contract bytecode present

# View function (cast call, zero gas) — v2 SidecarRegistry:
cast call 0x1Ac62f1C2D828476a5D784e850a700dC1f17e0bE "ROLE_CAP_MINT()(uint8)" \
  --rpc-url https://rpc.heima-parachain.heima.network
# → 1
```

Or run the one-shot health check:

```bash
AGENTKEYS_CHAIN=heima bash scripts/verify-heima-contracts.sh
# → 13 checks across all 4 contracts; exits 0 on all-pass
```

Future stage-2/3 work: agentkeys-specific indexing on top of Litentry's fork of `subscan-essentials` ([backend](https://github.com/litentry/subscan-essentials) + [UI](https://github.com/litentry/subscan-essentials-ui-react)) per arch.md §22a.6 — this will surface contract calls/events at the explorer level. Until that ships, RPC is the source of truth.

**Deploy metadata**:
- Deployer wallet (EVM): `0xdE644936D5B7d5d42032fd08bbA42Fbbfd6663Bc`
- Deployer wallet (Substrate SS58 prefix 31): `47NGSq6JE5ZSnymGNa4nFVjWbsuhTfoSKN2jtpk28mUyC1M3` *(see [funding the EVM side via the Substrate twin](../../scripts/evm-to-substrate-address.mjs))*
- Deploy date: 2026-05-19
- Compiler: Solc 0.8.20, `evm_version = "london"` (a `forge script` header-validation workaround, NOT Heima's EVM level — Heima's execution level is actually Cancun; see CLAUDE.md "Heima EVM compatibility level")
- Forge: 1.6.0
- Deploy script: [`crates/agentkeys-chain/script/DeployAgentKeysV1.s.sol`](../../crates/agentkeys-chain/script/DeployAgentKeysV1.s.sol)

**Constructor wiring** (verified post-deploy against v2):
- `AgentKeysScope.registry()` = `0x1Ac62f1C2D828476a5D784e850a700dC1f17e0bE` (= the deployed v2 SidecarRegistry above) ✓
- `K3EpochCounter.currentEpoch()` = `1` (initialized) ✓
- `K3EpochCounter.signerGovernance()` = `0xdE644936D5B7d5d42032fd08bbA42Fbbfd6663Bc` (deployer; expected to be transferred to the operational signer wallet OR an M-of-N multisig in stage 2 via `setSignerGovernance(newGov)`)
- `SidecarRegistry.ROLE_CAP_MINT()` = `1`, `ROLE_RECOVERY()` = `2`, `ROLE_SCOPE_MGMT()` = `4` ✓

## Heima Paseo testnet (chain_id = 2013)

Currently halted (block 2,905,430 frozen since 2026-01-15; 4+ months). No stage-1 contracts deployed yet. When collators come back online, run:

```bash
AGENTKEYS_CHAIN=heima-paseo bash harness/v2-stage1-demo.sh --only-step 9
```

…to deploy + auto-fund via Alice sudo. This doc will be updated with the live testnet addresses once that lands.

## Verifying the contracts are live + functional

Read-only RPC check (zero gas):

```bash
AGENTKEYS_CHAIN=heima bash scripts/verify-heima-contracts.sh
```

Checks performed (all four pass right now per the deploy verification):

1. **Bytecode presence** — `eth_getCode` for each contract returns non-empty bytecode
2. **View functions** — each contract responds to a known constant view function with the expected value (catches "wrong contract code at this slot" drift)
3. **Constructor wiring** — `AgentKeysScope.registry()` points at the deployed `SidecarRegistry` (catches wrong-address-in-constructor)
4. **Initialization** — `K3EpochCounter.currentEpoch ≥ 1`, `signerGovernance != address(0)`

The script reads addresses from `operator-workstation.env`, so changing `AGENTKEYS_CHAIN` picks up the chain-specific deployment.

## Re-deploy / replace

Re-running `bash harness/v2-stage1-demo.sh --only-step 9` is **idempotent**: step 5 calls `cast code` on each stored address and skips the deploy if all four already have on-chain bytecode. Re-deploys only fire when:

- Stored address in `operator-workstation.env` is the `0x0` sentinel or absent
- OR the stored address has no bytecode on-chain (chain reset, address corrupted)

To **force** a fresh deploy at new addresses (e.g. after a contract patch), manually clear the address entries from `operator-workstation.env` (or set them to `0x0`) and re-run.

After any re-deploy, **update this doc** with the new addresses + bytecode sizes + deploy date. The deploy operator is responsible for the doc bump; the bring-up script handles `operator-workstation.env` automatically but doesn't touch markdown.

## ABI summary

Full ABIs in [`crates/agentkeys-chain/src/*.sol`](../../crates/agentkeys-chain/src/). The functions broker + workers + CLI read on hot paths:

### `SidecarRegistry`
- `registerMasterDevice(bytes32 deviceKeyHash, bytes32 operatorOmni, bytes32 actorOmni, bytes32 k11CredId, bytes attestation, uint8 roles, bytes k11Assertion)` — first call bootstraps `operatorMasterWallet[operatorOmni] = msg.sender`; subsequent require existing master + K11
- `registerAgentDevice(bytes32 deviceKeyHash, bytes32 operatorOmni, bytes32 actorOmni, bytes linkCodeRedemption, bytes agentPopSig)` — master-only; agents get `ROLE_CAP_MINT` only
- `revokeDevice(bytes32 deviceKeyHash, bytes k11Assertion)` — master-only; K11 required for master tier
- `getDevice(bytes32 deviceKeyHash) → DeviceEntry` — view
- `isActive(bytes32 deviceKeyHash) → bool` — hot-path view for workers
- `operatorMasterWallet(bytes32 operatorOmni) → address` — auto-generated getter

### `AgentKeysScope`
- `setScopeWithWebauthn(bytes32 operatorOmni, bytes32 agentOmni, bytes32[] services, bool readOnly, uint128 maxPerCall, uint128 maxPerPeriod, uint128 maxTotal, uint32 periodSeconds, bytes k11Assertion)` — master-only, K11-gated
- `revokeScope(bytes32 operatorOmni, bytes32 agentOmni, bytes k11Assertion)` — master-only, K11-gated
- `getScope(bytes32 operatorOmni, bytes32 agentOmni) → Scope` — view
- `isServiceInScope(bytes32 operatorOmni, bytes32 agentOmni, bytes32 serviceHash) → bool` — hot-path view

### `K3EpochCounter`
- `advanceEpoch()` — signerGovernance-only
- `setSignerGovernance(address newGov)` — signerGovernance-only (handoff or rotation)
- `currentEpoch() → uint256` — auto-generated getter
- `signerGovernance() → address` — auto-generated getter

### `CredentialAudit`
- `append(bytes32 operatorOmni, bytes32 actorOmni, bytes32 serviceHash, uint8 opType, bytes32 payloadHash)` — open append (any caller; gas is the spam-resistance)
- `getEntries(bytes32 operatorOmni, uint256 offset, uint256 limit) → AuditEntry[]` — paginated view
- `entryCount(bytes32 operatorOmni) → uint256` — view

## When this doc needs to change

1. **New deploy on any chain** — update the table for that chain (addresses + bytecode sizes + date + deployer + tx hash if known)
2. **Constructor re-wiring** — any change to the deploy script's constructor args; re-record the "Constructor wiring" section
3. **K3 epoch advance** — currentEpoch monotonically increases; update the "Constructor wiring" line for the latest value
4. **`signerGovernance` transfer** — when handoff from deployer → operational signer (or → multisig in stage 2) happens, record the new address + tx hash
5. **Re-deploy** at fresh addresses — replace the table row entirely; old addresses move to a "Historical deploys" appendix at the bottom of this doc for audit-trail
