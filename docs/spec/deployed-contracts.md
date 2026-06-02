# Deployed contracts — canonical registry

**Single source of truth** for every on-chain contract address AgentKeys has deployed, per chain, plus the EVM deployer wallets (prod vs test/CI). Answers "what's the live address of `SidecarRegistry` / the ERC-4337 `EntryPoint` on Heima mainnet right now?" and "which EVM account deployed it?"

Mirrored into [`scripts/operator-workstation.env`](../../scripts/operator-workstation.env) (the shell-consumable form, written by `scripts/heima-bring-up.sh` step 6 via `env_set`). When the two diverge, **this doc is authoritative for human reads, the env file for tooling**; the bring-up script keeps both in sync. Indexed from [`arch.md`](../arch.md) §5. (`docs/contracts.md` is a redirect to this file.)

---

## EVM deployer wallets (prod vs test/CI)

Two distinct EVM accounts deploy AgentKeys contracts. They are **different keys**, so each lands the contract set at **different addresses** via `(deployer, nonce)` CREATE derivation — the prod set and the test set never collide.

| Role | Deployer EVM address | Key location | Source of truth |
|---|---|---|---|
| **Local / prod deploy** | `0xdE644936D5B7d5d42032fd08bbA42Fbbfd6663Bc` | `$HEIMA_DEPLOYER_KEY_FILE` (default `~/.agentkeys/heima-deployer.key`, never committed) | [`scripts/operator-workstation.env`](../../scripts/operator-workstation.env) `HEIMA_DEPLOYER_ADDR_HEIMA` |
| **Test / CI deploy** | `0x9FE9e6c208e9e75D2A19a5c2683127c33896F259` | `~/.agentkeys/heima-deployer-test.key` (operator-provided; wired into GitHub Actions secrets via [`scripts/ci-set-github-secrets.sh`](../../scripts/ci-set-github-secrets.sh)) | [`scripts/operator-workstation.test.env`](../../scripts/operator-workstation.test.env) `HEIMA_DEPLOYER_ADDR_HEIMA` |

- The prod deployer's Substrate twin (SS58 prefix 31) is `47NGSq6JE5ZSnymGNa4nFVjWbsuhTfoSKN2jtpk28mUyC1M3` — fund the EVM side via the twin, see [`scripts/evm-to-substrate-address.mjs`](../../scripts/evm-to-substrate-address.mjs).
- Heima Paseo testnet uses its own deployer `0xeBdE9E5F8c0495e87a871BF4f17Fb85e1bFE827F` (`HEIMA_PASEO_DEPLOYER_ADDR`) — currently unused (chain halted, see below).

---

## Heima mainnet (chain_id = 212013)

### v2 stage-1 set (current live — prod deployer)

| Contract | Address | Bytecode |
|---|---|---|
| `AgentKeysScope` | `0xd44b375daefc65768f417d0f0125b68d5ba7df3b` | 4572 bytes |
| `SidecarRegistry` | `0x1Ac62f1C2D828476a5D784e850a700dC1f17e0bE` | 7200 bytes |
| `K3EpochCounter` | `0x6c9e675c699a06acefbc156afdee6bfbfe32ccb3` | 591 bytes |
| `CredentialAudit` | `0x63c4545ac01c77cc74044f25b8edea3880224577` | 2584 bytes |
| `P256Verifier` | `0xda5b772f9d6c09abe80414eea908612df9b54749` | 3428 bytes (pre-deployed verifier) |
| `K11Verifier` | `0x5a441431f08e0f5f5ed10659620cb4e0e814e627` | 2033 bytes (pre-deployed verifier) |

### ERC-4337 master infra (#164, deployed 2026-06-02 — prod deployer)

Foundation plumbing for the P-256 smart-account master ([plan](../plan/chain/erc4337-master-account.md)). **NOT yet the live master-auth:** the registry/scope cutover to account-authorization (#164 E3/E7) is a later coordinated redeploy; these are inert until masters are registered as accounts.

| Contract | Address | Notes |
|---|---|---|
| `EntryPoint` (ERC-4337 v0.7) | `0x6672E1b315332167aBA12E0B1d3532a7e9B1ADE9` | 11810 bytes; canonical eth-infinitism v0.7 bytecode; landed a UserOp end-to-end in the spike |
| `P256AccountFactory` | `0x1ccCe65b22De81aDA4F378FeAf7503d93f5d27a3` | 4591 bytes; CREATE2 factory; `constructor(entryPoint, k11Verifier)`; wired to the live `K11Verifier`; mainnet CREATE2 determinism smoke-verified |

> **`VerifyingPaymaster` is intentionally NOT deployed.** The spike and current flow submit UserOps via direct `EntryPoint.handleOps` from a pre-funded account — no paymaster needed. [`crates/agentkeys-chain/src/VerifyingPaymaster.sol`](../../crates/agentkeys-chain/src/VerifyingPaymaster.sol) is kept in source for the optional gas-sponsorship path; deploy it only when sponsored UserOps are required, then add its address here and in `operator-workstation.env`.

### Test / CI deploy (Heima mainnet — test deployer)

The test stack deploys the **same four contracts** with the test deployer key (`0x9FE9…F259`), landing them at **different addresses** (distinct `(deployer, nonce)` derivation). It shares the prod AWS account but uses distinct IAM roles, S3 buckets, OIDC issuer, and `-test` DNS — a leaked test cred cannot reach prod data.

- **Tier-1 CI** (the no-LLM gate from #66/#98) runs against an **ephemeral anvil** chain — fresh contracts per run, no persistent mainnet addresses.
- **Tier-2 / persistent test deploy** addresses are pinned in [`scripts/operator-workstation.test.env`](../../scripts/operator-workstation.test.env) (`*_ADDRESS_HEIMA`). **The values there today are placeholders** — that file's own header says "replace with real test addresses post-deploy." Pin the real ones after a one-shot test deploy:

  ```bash
  AGENTKEYS_CHAIN=heima HEIMA_DEPLOYER_KEY_FILE=~/.agentkeys/heima-deployer-test.key \
    MAINNET_CONFIRM=1 bash scripts/setup-heima.sh --from-step 4 --to-step 8
  ```

- The `P256Verifier` + `K11Verifier` are **shared pre-deployed** contracts — same address on prod and test (mirror the prod values above).

### Historical v1 deploy (superseded by v2; preserved for old-tx cross-reference)

| Contract | Address | Bytecode |
|---|---|---|
| `AgentKeysScope` | `0x14C23B5D1cE20c094af643a20e6b0972dAD12aa8` | 3146 bytes |
| `SidecarRegistry` | `0x76D574a107727bE87fc1422661A030FEFda70786` | 3301 bytes |
| `K3EpochCounter` | `0x8396dEc50ff755d6DE7728DABB00Be2eFBCdf4dF` | 687 bytes |
| `CredentialAudit` | `0x1801ded1a4FBD8c9224Ab18B9EcbB293B8674c06` | 1421 bytes |

## Heima Paseo testnet (chain_id = 2013)

Halted (block 2,905,430 frozen since 2026-01-15). **No contracts deployed** — the `*_ADDRESS_HEIMA_PASEO` entries in `operator-workstation.env` are placeholders (`0x..01`–`0x..04`). When collators return: `AGENTKEYS_CHAIN=heima-paseo bash harness/v2-stage1-demo.sh --only-step 9` deploys + auto-funds via Alice sudo; update this doc with the live testnet addresses then.

---

## Deploy metadata (Heima mainnet v2)

- Deployer wallet (EVM): `0xdE644936D5B7d5d42032fd08bbA42Fbbfd6663Bc` (prod) — see the deployer table above for prod vs test.
- v2 deploy date: 2026-05-19 · #164 E1 deploy date: 2026-06-02
- Compiler: Solc 0.8.20, `evm_version = "london"` (a `forge script` header-validation workaround, NOT Heima's EVM level — Heima executes **Cancun**; see CLAUDE.md "Heima EVM compatibility level"). The EntryPoint v0.7 is the canonical eth-infinitism bytecode, deployed via `forge create`.
- Deploy script: [`crates/agentkeys-chain/script/DeployAgentKeysV1.s.sol`](../../crates/agentkeys-chain/script/DeployAgentKeysV1.s.sol)

**Constructor wiring** (verified post-deploy):
- `AgentKeysScope.registry()` = the v2 `SidecarRegistry` ✓
- `P256AccountFactory.entryPoint()` = the v0.7 `EntryPoint` ✓, `.k11Verifier()` = the live `K11Verifier` ✓
- `K3EpochCounter.currentEpoch()` = `1`; `.signerGovernance()` = deployer (to be transferred to an M-of-N multisig)
- `SidecarRegistry.ROLE_CAP_MINT()` = `1`, `ROLE_RECOVERY()` = `2`, `ROLE_SCOPE_MGMT()` = `4` ✓

## Verifying contracts are live (read-only RPC, zero gas)

```bash
# One-shot health check across the v2 set:
AGENTKEYS_CHAIN=heima bash scripts/verify-heima-contracts.sh   # exits 0 on all-pass

# Bytecode presence (eth_getCode), e.g. the ERC-4337 EntryPoint:
cast code 0x6672E1b315332167aBA12E0B1d3532a7e9B1ADE9 --rpc-url https://rpc.heima-parachain.heima.network | head -c 12
# View call, e.g. factory wiring:
cast call 0x1ccCe65b22De81aDA4F378FeAf7503d93f5d27a3 "entryPoint()(address)" --rpc-url https://rpc.heima-parachain.heima.network
```

The verify script checks, per contract: (1) **bytecode presence** (`eth_getCode` non-empty); (2) **view functions** return the expected constant (catches wrong-code-at-this-slot drift); (3) **constructor wiring** (`AgentKeysScope.registry()` → the deployed `SidecarRegistry`); (4) **initialization** (`K3EpochCounter.currentEpoch ≥ 1`, `signerGovernance != address(0)`). It reads addresses from `operator-workstation.env`, so changing `AGENTKEYS_CHAIN` picks up the chain-specific deployment.

**Explorer note:** [`heima.statescan.io`](https://heima.statescan.io/) is Substrate-side — it indexes pallet extrinsics/events but does NOT decode EVM calls/bytecode. EVM contract verification on Heima goes via direct RPC until agentkeys-specific indexing on Litentry's `subscan-essentials` fork ships (arch.md §22a.6).

## Re-deploy / replace

Re-running `bash harness/v2-stage1-demo.sh --only-step 9` is **idempotent**: it calls `cast code` on each stored address and skips the deploy if all four already have on-chain bytecode. Re-deploys only fire when the stored address is the `0x0` sentinel / absent, or has no bytecode on-chain (chain reset, address corrupted). To **force** a fresh deploy at new addresses (e.g. after a contract patch), clear the address entries from `operator-workstation.env` (or set them to `0x0`) and re-run. After any re-deploy, **update this doc** with the new addresses + bytecode sizes + deploy date — the deploy operator owns the doc bump; the bring-up script handles `operator-workstation.env` automatically but doesn't touch markdown.

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
3. **K3 epoch advance** — `currentEpoch` monotonically increases; update the "Constructor wiring" line for the latest value
4. **`signerGovernance` transfer** — when handoff from deployer → operational signer (or → multisig in stage 2) happens, record the new address + tx hash
5. **Re-deploy** at fresh addresses — replace the table row entirely; old addresses move to the "Historical deploys" section for audit-trail
6. **Test deploy pinned** — when the test stack's persistent (non-anvil) addresses are deployed, replace the placeholders in `operator-workstation.test.env` and record them in the "Test / CI deploy" section above
