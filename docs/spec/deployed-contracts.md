# Deployed contracts — canonical registry

**Single source of truth** for every on-chain contract address AgentKeys has deployed, per chain, plus the EVM deployer wallets (prod vs test/CI). Answers "what's the live address of `SidecarRegistry` / the ERC-4337 `EntryPoint` on Heima mainnet right now?" and "which EVM account deployed it?"

Mirrored into [`scripts/operator-workstation.env`](../../scripts/operator-workstation.env) (the shell-consumable form, written by `scripts/heima-bring-up.sh` step 6 via `env_set`). When the two diverge, **this doc is authoritative for human reads, the env file for tooling**; the bring-up script keeps both in sync. Indexed from [`arch.md`](../arch.md) §5. (`docs/contracts.md` is a redirect to this file.) The operator-facing **wallet/funding map** — key custody tiers, prod-vs-test sets side by side, the funding-flow diagram, "which wallet do I fund" — is [`chain-setup.md` §Wallets](../chain-setup.md#wallets-contracts--funding-map-prod--test); update it in the same commit as any redeploy/rotation recorded here.

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

### v2 stage-1 set — **contract_set_version 0.3** (current live — prod deployer; account-auth #164 E3 + #225 E7 account-model master register + owner-gated `resetMaster`)

> **0.3 deployed 2026-06-09** (FORCE_DEPLOY full-set redeploy — fresh `SidecarRegistry` `0xC63E6f64…` + `AgentKeysScope` / `K3EpochCounter` / `CredentialAudit`, replacing the orphaned 0.2 `0xF50ef960…` set). Adds the owner-gated `SidecarRegistry.resetMaster(bytes32 operatorOmni)` recovery escape hatch (+ the `owner` immutable, captured at construction = the deployer). `registerFirstMasterDevice` is first-master-ONLY, so without `resetMaster` an operator who loses/deletes the master passkey could only recover by redeploying the whole set; `resetMaster` lets the deployer unbind one operator in place. `crates/agentkeys-chain/VERSION` == the profile's `contract_set_version` == `0.3` (in sync). **After ANY such redeploy the broker MUST be rebuilt from the SAME committed profile** — `setup-broker-host.sh --ref main` — or the broker reads `operatorMasterWallet` from the orphaned old registry while the daemon onboards into the new one (the #225 split-registry accept failure: handleOps reverts `SIG_VALIDATION_FAILED` because the broker built the UserOp for the old master account). Commit `heima.json` + `operator-workstation.env` in the SAME change as the deploy so the broker host can never lag.

> **Source of truth = the chain profile [`crates/agentkeys-core/chain-profiles/heima.json`](../../crates/agentkeys-core/chain-profiles/heima.json).** Its `contracts[]` array holds the live addresses; `contract_set_version` holds the deployed SET version. `scripts/heima-bring-up.sh` rewrites it programmatically on every fresh deploy (step 6b), and the typed `ChainProfile` struct + `chain_profile::tests::heima_carries_full_contract_registry_and_version` enforce its shape — that is the strict-typed JSON registry. The *expected* source version lives in [`../../crates/agentkeys-chain/VERSION`](../../crates/agentkeys-chain/VERSION); a deploy redeploys + bumps the profile only when the two differ (no bytecode comparison — see "Re-deploy / replace"). **This `.md` is human PROSE only — it no longer carries an address table** (that duplication was the drift source).

**Read the live addresses from the profile** (don't hand-maintain them here):

```bash
jq -r '"contract_set_version \(.contract_set_version)", (.contracts[] | "  \(.name): \(.address)")' \
  crates/agentkeys-core/chain-profiles/heima.json
# Verify the profile ⟷ operator-workstation.env mirror:
bash scripts/check-deployed-contracts-sync.sh
```

The set: the 4 stage-1 cores `AgentKeysScope` / `SidecarRegistry` / `K3EpochCounter` / `CredentialAudit` (account-auth #164 E3 — redeployed 2026-06-08, replacing the pre-#164 `0xd44b375…` / `0x1Ac62f1C…` / `0x6c9e675c…` / `0x63c4545a…` set, now orphaned), the pre-deployed `P256Verifier` / `K11Verifier`, the #164 ERC-4337 infra `EntryPoint` / `P256AccountFactory`, and the `VerifyingPaymaster` (`0xca36550d30e2E4dF927c53C3a5272A319D427602`, #225 — broker-co-signed gas sponsorship for the K11-gated accept UserOp; one shared EntryPoint deposit, the J1 Sybil gate). The parent-control web UI reads the same profile via `GET /v1/chain/info` (#153).

> ✅ **`AgentKeysScope` + `SidecarRegistry` are the #164 account-auth design — cutover landed 2026-06-08.** The live `AgentKeysScope` at `0x5E94f76E…` is the [`src/AgentKeysScope.sol`](../../crates/agentkeys-chain/src/AgentKeysScope.sol) ERC-4337 rewrite: `setScope(...)` (sel `0xd8e9e3c6`, no inline K11 tuple) / `revokeScope(bytes32,bytes32)` (sel `0xdcff8c5b`), with master writes gated by `msg.sender == operatorMasterWallet` (the operator's `P256Account`) — biometric authorization moved upstream to the 4337 account's `validateUserOp`. **Source now matches the deployed bytecode** (the earlier intentional `src/` ≠ deployed divergence is resolved). The pre-cutover stage-1 design (`setScopeWithWebauthn(...,K11Assertion)`, sel `0x864ae93c`; `revokeScope(...,K11Assertion)`, sel `0x6f37dd80`) is now **orphaned at the old address `0xd44b375…`** (no production state — dev-only); its source is retained at [`crates/agentkeys-chain/archived/AgentKeysScope.deployed-stage1.sol`](../../crates/agentkeys-chain/archived/AgentKeysScope.deployed-stage1.sol) (kept per the repo's "move stale to archived, don't delete" policy) so the orphaned bytecode still has findable source. The audit decoder's **live** `scope.grant` mapping ([`audit_decode.rs::onchain_fn`](../../crates/agentkeys-daemon/src/audit_decode.rs)) is now `setScope`; `calldata::REGISTRY` keeps the `setScopeWithWebauthn` FnDef only so the decoder can still resolve orphaned pre-cutover calldata.

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

`bash scripts/heima-bring-up.sh` is **idempotent**, by VERSION not bytecode:

1. **Skip** when all four cores have on-chain code AND `crates/agentkeys-chain/VERSION` == the chain profile's `contract_set_version` (the recorded deployed version).
2. **Redeploy** when the stored address is the `0x0` sentinel / absent or has no on-chain bytecode (chain reset). A bumped `VERSION` ≠ the recorded version is a hard stop that prints the mismatch and asks for an explicit opt-in (it orphans state + costs mainnet gas — see below) rather than auto-redeploying.
3. **Force** a fresh deploy at new addresses (contract patch): bump `crates/agentkeys-chain/VERSION`, then re-run with `FORCE_DEPLOY=1` (blind) — or, for the #164 account-auth cutover, use [`../../scripts/heima-cutover-account-auth.sh`](../../scripts/heima-cutover-account-auth.sh) (probes the live `setScope` selector + skips when already live).

On a fresh deploy the bring-up script **auto-writes the chain profile** (`contracts[]` + `contract_set_version`, step 6b — the source of truth) **and `operator-workstation.env`** (step 6). It does NOT touch this markdown — so update **only the human prose here** (the version line + any ABI/cutover/historical note) when the design or version changes; the addresses live in the profile, not a table here. Confirm the two mirrors agree: `bash scripts/check-deployed-contracts-sync.sh`. No bytecode comparison anywhere — Solidity metadata + immutables make it unreliable, so the human-asserted `VERSION` is the comparison key.

## ABI summary

Full ABIs in [`crates/agentkeys-chain/src/*.sol`](../../crates/agentkeys-chain/src/). The functions broker + workers + CLI read on hot paths:

### `SidecarRegistry` (account-auth design, #164 E3 — live since the 2026-06-08 cutover; #225 E7 account-model + resetMaster)
- `registerFirstMasterDevice(bytes32 deviceKeyHash, bytes32 operatorOmni, bytes32 actorOmni, bytes32 k11CredId, bytes32 k11RpIdHash, uint256 k11PubX, uint256 k11PubY, uint8 roles)` — sel `0x93b14d7c`; bootstraps `operatorMasterWallet[operatorOmni] = msg.sender`. **#225 E7 account model:** the embedded `K11Assertion selfAttestation` was DROPPED — the passkey proof is the account's `validateUserOp` over the `userOpHash` (which commits this calldata). **Rejects an EOA `msg.sender`** (`MasterMustBeAccount`) — the master must be the operator's `P256Account`. **First-master-ONLY** (reverts `DeviceAlreadyRegistered` once `operatorMasterWallet[omni] != 0`).
- `registerAdditionalMasterDevice(bytes32 newDeviceKeyHash, bytes32 operatorOmni, bytes32 newActorOmni, bytes32 newK11CredId, bytes32 newK11RpIdHash, uint256 newK11PubX, uint256 newK11PubY, bytes attestation, uint8 newRoles, K11Assertion existingMasterAssertion)` — requires existing master; `msg.sender == operatorMasterWallet`
- `registerAgentDevice(bytes32 deviceKeyHash, bytes32 operatorOmni, bytes32 actorOmni, bytes linkCodeRedemption, bytes agentPopSig)` — master-only (`msg.sender == operatorMasterWallet`); agents get `ROLE_CAP_MINT` only
- `revokeAgentDevice(bytes32 deviceKeyHash)` — master-only (`msg.sender == operatorMasterWallet[entry.operatorOmni]`)
- `revokeMasterDevice(bytes32 targetDeviceKeyHash, K11Assertion[] recoveryAssertions)` — M-of-N recovery quorum (`recoveryThreshold[operator]`); refuses to strand the operator
- `resetMaster(bytes32 operatorOmni)` — **#225 E7, owner-ONLY** (the deployer captured at construction). Dev/recovery escape hatch: wipes the operator's whole device list + clears `operatorMasterWallet`/`recoveryThreshold`/`operatorNonce`, so a FRESH `registerFirstMasterDevice` can re-bind WITHOUT redeploying the set (needed because first-master-only makes the binding otherwise immutable). The daemon's `POST /v1/master/reset` calls this via `scripts/heima-reset-master.sh`. Emits `MasterReset(operatorOmni, clearedMaster, deviceCount)`.
- `getDevice(bytes32 deviceKeyHash) → DeviceEntry` — view
- `isActive(bytes32 deviceKeyHash) → bool` — hot-path view for workers
- `operatorMasterWallet(bytes32 operatorOmni) → address` — auto-generated getter
- `owner() → address` — auto-generated getter (the deployer; the only `resetMaster` caller). **Probing `owner()` is how `heima-reset-master.sh` detects a pre-0.3 registry** (the call reverts / returns empty there).

### `AgentKeysScope` (account-auth design, #164 E3 — live since the 2026-06-08 cutover)
- `setScope(bytes32 operatorOmni, bytes32 agentOmni, bytes32[] services, bool readOnly, uint128 maxPerCall, uint128 maxPerPeriod, uint128 maxTotal, uint32 periodSeconds)` — sel `0xd8e9e3c6`; gated by `msg.sender == operatorMasterWallet[operatorOmni]` (the operator's `P256Account`). No inline K11 tuple — biometric authorization is the 4337 account's `validateUserOp`.
- `revokeScope(bytes32 operatorOmni, bytes32 agentOmni)` — sel `0xdcff8c5b`; same `msg.sender == operatorMasterWallet` gate.
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

1. **New deploy on any chain** — addresses are written **automatically** by `heima-bring-up.sh` to the chain profile (`contracts[]` + `contract_set_version`) + `operator-workstation.env`; this doc only needs a PROSE touch (the version line + a one-line note) if the design changed. No address table to edit.
2. **Constructor re-wiring** — any change to the deploy script's constructor args; re-record the "Constructor wiring" section
3. **K3 epoch advance** — `currentEpoch` monotonically increases; update the "Constructor wiring" line for the latest value
4. **`signerGovernance` transfer** — when handoff from deployer → operational signer (or → multisig in stage 2) happens, record the new address + tx hash
5. **Re-deploy** at fresh addresses — the chain profile is rewritten automatically; mention the old → orphaned addresses in the prose / "Historical deploys" section for the audit-trail (no table row to replace)
6. **Test deploy pinned** — when the test stack's persistent (non-anvil) addresses are deployed, replace the placeholders in `operator-workstation.test.env` and record them in the "Test / CI deploy" section above
