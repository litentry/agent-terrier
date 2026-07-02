# Deployed contracts — human registry (prose)

The **human registry** for AgentKeys' on-chain contracts: design/version notes, ABI summaries, cutover history, deployer-wallet custody. It deliberately carries **no address table** — addresses have a single machine source of truth, and re-listing them here is how they drift (this doc once claimed a stale `AgentKeysScope` address a full redeploy after `heima.json` had the live one).

## Source-of-truth hierarchy (#251 — anchor, never copy)

| Record | Single source of truth | Notes |
|---|---|---|
| **Prod contract addresses** + deployed set version | chain profile [`crates/agentkeys-core/chain-profiles/heima.json`](../../crates/agentkeys-core/chain-profiles/heima.json) — `.contracts[]` + `contract_set_version` | versioned + compiled in (`include_str!`) — broker/daemon/UI serve it; rewritten by the chain bring-up entry point (operator-internal) on every deploy. Mirrored to `scripts/operator-workstation.env` (the operator-internal shell mirror); `bash scripts/utils/check-deployed-contracts-sync.sh` verifies the mirror. |
| **Test contract addresses** (parallel set) | `scripts/operator-workstation.test.env` (`*_ADDRESS_HEIMA`, operator-internal) — **authoritative** | the `TEST_*` GitHub secrets are a CI-consumable **copy**, synced one-way env→secrets by the CI-secrets sync helper (operator-internal; re-run it after any test redeploy). Never in the chain profile — it records the prod set only. |
| **Wallet (EOA) addresses** | the env files (`*_DEPLOYER_ADDR_HEIMA`, `BROKER_SPONSOR_SIGNER_ADDRESS_HEIMA`) | key custody tiers + funding map: the chain-setup operator runbook §Wallets (operator-internal) |
| **Human prose** | this doc | ABI/cutover/version notes ONLY — no addresses |

**No doc may re-write a literal address that one of those sources owns** — link to the source and give a resolve command instead. CI-enforced: the doc-literal gate in [`scripts/utils/check-deployed-contracts-sync.sh`](../../scripts/utils/check-deployed-contracts-sync.sh) (workflow [`contracts-sync.yml`](../../.github/workflows/contracts-sync.yml)) fails any tracked `.md` containing an address currently in a chain profile. Historical/orphaned addresses pass naturally — once a redeploy moves an address out of the profile, its literal is no longer banned.

Indexed from [`arch.md`](../arch.md) §5. (`docs/contracts.md` is a redirect to this file.) The operator-facing **wallet/funding map** — key custody tiers, prod-vs-test sets side by side, the funding-flow diagram, "which wallet do I fund" — is the chain-setup operator runbook §Wallets (operator-internal); update it in the same commit as any redeploy/rotation recorded here.

---

## EVM deployer wallets (prod vs test/CI)

Two distinct EVM accounts deploy AgentKeys contracts. They are **different keys**, so each lands the contract set at **different addresses** via `(deployer, nonce)` CREATE derivation — the prod set and the test set never collide.

| Role | Deployer EVM address (resolve — the env file is the SoT) | Key location |
|---|---|---|
| **Local / prod deploy** | `grep ^DEPLOYER_ADDR_HEIMA scripts/operator-workstation.env` | `$HEIMA_DEPLOYER_KEY_FILE` (default `~/.agentkeys/heima-deployer.key`, never committed) |
| **Test / CI deploy** | `grep ^DEPLOYER_ADDR_HEIMA scripts/operator-workstation.test.env` | `~/.agentkeys/heima-deployer-test.key` (operator-provided; wired into the `TEST_HEIMA_DEPLOYER_KEY` GitHub secret via the CI-secrets sync helper (operator-internal)) |

- The prod deployer's Substrate twin (SS58 prefix 31) is how the EVM side gets funded — derive it from the EVM address via the EVM-to-Substrate address helper (operator-internal).
- Heima Paseo testnet uses its own deployer (`HEIMA_PASEO_DEPLOYER_ADDR` in `operator-workstation.env`) — currently unused (chain halted, see below).

---

## Heima mainnet (chain_id = 212013)

### v2 set — **contract_set_version 0.4** (current live — prod deployer; router-wired K11 #170 + account-auth #164/#225 + owner-gated `resetMaster`)

> **0.4 deployed 2026-06-12** (FORCE full-set redeploy, operator-approved with NO backward compatibility): the K11 chain is now **router-wired** — `K11Verifier → P256Router → RIP-7212 precompile at `0x100` (runtime 9261), pure-Solidity `P256Verifier` as fallback`. New core-4 + verifier trio + `P256AccountFactory` (re-minted against the new K11); **EntryPoint + VerifyingPaymaster PRESERVED** (K11-independent — deposits intact). On-chain verify cost: **706,696 → 28,372 gas** (live-proven same day). The 0.3 set + ALL its on-chain state (master registrations, scopes, epochs, audit rows) is **ORPHANED** — every operator re-runs the binding ceremonies, and the broker must rebuild from the committed profile (`setup-broker-host.sh --ref main`).

> **0.3 deployed 2026-06-09** (FORCE_DEPLOY full-set redeploy — fresh `SidecarRegistry` `0xC63E6f64…` + `AgentKeysScope` / `K3EpochCounter` / `CredentialAudit`, replacing the orphaned 0.2 `0xF50ef960…` set). Adds the owner-gated `SidecarRegistry.resetMaster(bytes32 operatorOmni)` recovery escape hatch (+ the `owner` immutable, captured at construction = the deployer). `registerFirstMasterDevice` is first-master-ONLY, so without `resetMaster` an operator who loses/deletes the master passkey could only recover by redeploying the whole set; `resetMaster` lets the deployer unbind one operator in place. `crates/agentkeys-chain/VERSION` == the profile's `contract_set_version` == `0.3` (in sync). **After ANY such redeploy the broker MUST be rebuilt from the SAME committed profile** — `setup-broker-host.sh --ref main` — or the broker reads `operatorMasterWallet` from the orphaned old registry while the daemon onboards into the new one (the #225 split-registry accept failure: handleOps reverts `SIG_VALIDATION_FAILED` because the broker built the UserOp for the old master account). Commit `heima.json` + `operator-workstation.env` in the SAME change as the deploy so the broker host can never lag.

> **RIP-7212 note (2026-06-12):** Heima runtime **9261** activated the P-256 precompile at `0x100` (litentry/heima#4030, spec-vector-verified on mainnet) and the same-day **0.4 redeploy consumed it** (router-wired K11, see above). #170 is resolved on both chains.

> **Source of truth = the chain profile [`crates/agentkeys-core/chain-profiles/heima.json`](../../crates/agentkeys-core/chain-profiles/heima.json).** Its `contracts[]` array holds the live addresses; `contract_set_version` holds the deployed SET version. `scripts/operator/chain/heima-bring-up.sh` rewrites it programmatically on every fresh deploy (step 6b), and the typed `ChainProfile` struct + `chain_profile::tests::heima_carries_full_contract_registry_and_version` enforce its shape — that is the strict-typed JSON registry. The *expected* source version lives in [`../../crates/agentkeys-chain/VERSION`](../../crates/agentkeys-chain/VERSION); a deploy redeploys + bumps the profile only when the two differ (no bytecode comparison — see "Re-deploy / replace"). **This `.md` is human PROSE only — it no longer carries an address table** (that duplication was the drift source).

**Read the live addresses from the profile** (don't hand-maintain them here):

```bash
jq -r '"contract_set_version \(.contract_set_version)", (.contracts[] | "  \(.name): \(.address)")' \
  crates/agentkeys-core/chain-profiles/heima.json
# Verify the profile ⟷ operator-workstation.env mirror:
bash scripts/utils/check-deployed-contracts-sync.sh
```

The set: the 4 stage-1 cores `AgentKeysScope` / `SidecarRegistry` / `K3EpochCounter` / `CredentialAudit` (account-auth #164 E3 — redeployed 2026-06-08, replacing the pre-#164 `0xd44b375…` / `0x1Ac62f1C…` / `0x6c9e675c…` / `0x63c4545a…` set, now orphaned), the pre-deployed `P256Verifier` / `K11Verifier`, the #164 ERC-4337 infra `EntryPoint` / `P256AccountFactory`, and the `VerifyingPaymaster` (#225 — broker-co-signed gas sponsorship for the K11-gated accept UserOp; one shared EntryPoint deposit, the J1 Sybil gate). The parent-control web UI reads the same profile via `GET /v1/chain/info` (#153).

> ✅ **`AgentKeysScope` + `SidecarRegistry` are the #164 account-auth design — cutover landed 2026-06-08.** The live `AgentKeysScope` (address in the chain profile — the earlier revision of this line carried a stale literal, the exact drift #251 bans) is the [`src/AgentKeysScope.sol`](../../crates/agentkeys-chain/src/AgentKeysScope.sol) ERC-4337 rewrite: `setScope(...)` (sel `0xd8e9e3c6`, no inline K11 tuple) / `revokeScope(bytes32,bytes32)` (sel `0xdcff8c5b`), with master writes gated by `msg.sender == operatorMasterWallet` (the operator's `P256Account`) — biometric authorization moved upstream to the 4337 account's `validateUserOp`. **Source now matches the deployed bytecode** (the earlier intentional `src/` ≠ deployed divergence is resolved). The pre-cutover stage-1 design (`setScopeWithWebauthn(...,K11Assertion)`, sel `0x864ae93c`; `revokeScope(...,K11Assertion)`, sel `0x6f37dd80`) is now **orphaned at the old address `0xd44b375…`** (no production state — dev-only); its source is retained at [`crates/agentkeys-chain/archived/AgentKeysScope.deployed-stage1.sol`](../../crates/agentkeys-chain/archived/AgentKeysScope.deployed-stage1.sol) (kept per the repo's "move stale to archived, don't delete" policy) so the orphaned bytecode still has findable source. The audit decoder's **live** `scope.grant` mapping ([`audit_decode.rs::onchain_fn`](../../crates/agentkeys-daemon/src/audit_decode.rs)) is now `setScope`; `calldata::REGISTRY` keeps the `setScopeWithWebauthn` FnDef only so the decoder can still resolve orphaned pre-cutover calldata.

### ERC-4337 master infra (#164/#225, prod deployer — LIVE master-auth since the 2026-06-08 cutover)

The P-256 smart-account master plumbing (plan (operator-internal)), all in the chain profile's `.contracts[]`:

- `EntryPoint` (ERC-4337 v0.7, deployed 2026-06-02) — canonical eth-infinitism v0.7 bytecode; landed a UserOp end-to-end in the spike.
- `P256AccountFactory` — CREATE2 factory; `constructor(entryPoint, k11Verifier)`, wired to the live `K11Verifier`; mainnet CREATE2 determinism smoke-verified.
- `VerifyingPaymaster` (#225) — broker-co-signed gas sponsorship for the K11-gated accept UserOp; one shared EntryPoint deposit (the J1 Sybil gate). Deployed + funded via the paymaster deploy helper (operator-internal), which rewrites the chain profile + env mirror. **Fund the deposit via `deposit()`, never a plain transfer** — see the chain-setup operator runbook (operator-internal).

Master mutations are UserOps from the operator's `P256Account`, relayed by the broker to the in-house [`agentkeys-bundler`](../../crates/agentkeys-bundler/) (#230) — the pre-cutover "inert until masters are registered as accounts" status and the pre-#225 "paymaster intentionally not deployed" note are both superseded.

### Test / CI deploy (Heima mainnet — test deployer)

The test stack deploys the **same four contracts** with the test deployer key (`0x051e…475e`), landing them at **different addresses** (distinct `(deployer, nonce)` derivation), **plus its own ERC-4337 set since #250 — a separate EntryPoint v0.7 + P256AccountFactory** (deployed by the ERC-4337 deploy helper (operator-internal), invoked from the chain bring-up entry point's `--ci` step 6; the test EC2 also runs its own `agentkeys-bundler`). Full per-env isolation: a test-stack compromise or mis-pointed bundler can never touch prod's EntryPoint deposits/nonces. It shares the prod AWS account but uses distinct IAM roles, S3 buckets, OIDC issuer, and `-test` DNS — a leaked test cred cannot reach prod data. The test addresses are recorded ONLY in `scripts/operator-workstation.test.env` (operator-internal; **authoritative**) and mirrored into the `TEST_*` GitHub secrets (the CI-consumable **copy** — synced one-way env→secrets by the CI-secrets sync helper (operator-internal); re-run it after any test redeploy or the workflow runs on stale addresses) — **never in the chain profile** (it records the prod set; the chain bring-up enforces this).

- **Tier-1 CI** (the no-LLM gate from #66/#98) runs against an **ephemeral anvil** chain — fresh contracts per run, no persistent mainnet addresses.
- **Tier-2 / persistent test deploy** addresses are pinned in `scripts/operator-workstation.test.env` (`*_ADDRESS_HEIMA`, operator-internal) — real since the #250 test-set deploy (core set + the test stack's own EntryPoint/factory). Re-pin after a test redeploy, then re-run the CI-secrets sync helper:

  ```bash
  # --ci selects operator-workstation.test.env AND auto-defaults the deployer
  # key to ~/.agentkeys/heima-deployer-test.key. Add FORCE_DEPLOY=1 when
  # refreshing over a live-but-outdated test set.
  AGENTKEYS_CHAIN=heima MAINNET_CONFIRM=1 \
    bash scripts/operator/setup-heima.sh --ci --from-step 4 --to-step 8
  ```

- The `P256Verifier` + `K11Verifier` are **shared pre-deployed** contracts — same address on prod and test (`.test.env` mirrors the chain-profile values).

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

## Base mainnet (chain_id = 8453) — the permissioned partner tier (#282 dual-stack)

### v2 set — **contract_set_version 0.4** (`P256Router` #170) — deployed 2026-06-12

> **Source of truth = the chain profile [`crates/agentkeys-core/chain-profiles/base.json`](../../crates/agentkeys-core/chain-profiles/base.json)** (`.contracts[]` + `contract_set_version`), mirrored to `scripts/operator-workstation.base.env` (`*_BASE` keys, operator-internal). Resolve addresses the same way as heima — `jq -r '.contracts[] | "\(.name): \(.address)"' crates/agentkeys-core/chain-profiles/base.json` — never paste literals (#251 gate).

Design notes (what differs from the heima 0.3 set):

- **`P256Router` — the #170 deliverable.** A precompile-first P-256 verifier (RIP-7212 `P256VERIFY` at `0x…0100`, live on Base since Fjord; flat 3,450 gas) with the pure-Solidity `P256Verifier` embedded as fallback, wired as `K11Verifier`'s `p256Addr` by `DeployAgentKeysV1.s.sol`. Every WebAuthn verify (registry mutations, `P256Account` UserOp validation) routes through it. The heima 0.3 set predates the router (its K11Verifier points at the bare `P256Verifier`). **Heima's runtime-9261 precompile ACTIVATED 2026-06-12** (litentry/heima#4030; spec-vector-verified on mainnet) — so heima now needs only the 0.4 full-set redeploy to wire the router and inherit the cheap path; the router itself needs no chain-specific variant.
- **`EntryPoint` = the canonical eth-infinitism v0.7 deployment, ADOPTED not self-deployed** (D2 in `base-migration.md` (operator-internal)): audited bytes + public-bundler interop; `heima-deploy-erc4337.sh` code-verifies it before pinning. Per-env isolation holds because prod-heima / prod-base are different chains.
- **No ED buffer** — Base has no Substrate ExistentialDeposit; the AA91 reaping class can't occur (the erc4337 helper skips the buffer on non-substrate chains).
- **Version note:** this set was deployed under the `0.3` label (router as an aux addition) and relabeled **`0.4`** the same day when heima's 0.4 router-wired redeploy landed — the deployed bytes on base ARE the 0.4 definition, so both chains + `crates/agentkeys-chain/VERSION` now agree on `0.4` (no base redeploy was needed, label only).

Deployer: the Base prod deployer — `grep ^DEPLOYER_ADDR_BASE scripts/operator-workstation.base.env` (key `~/.agentkeys/deployer-base.key`, 0600). Gas is ETH. Heima stays live as the consumer free tier (D5 dual-stack) — nothing on this chain replaces it.

**Live-proven #170 numbers (2026-06-12):** `P256Router.verify` with a valid P-256 signature = **31,776 gas** total (precompile path) vs **683,901 gas** through the pure-Solidity verifier on the same chain; invalid signatures correctly return false via the fallback.

> First-run artifacts: one orphaned factory + one orphaned paymaster exist on Base from a mis-keyed first run (signed by the *heima* prod deployer before `resolve_master_key` became chain-aware) — functional but never referenced by any registry, env, or profile; ignore them on the explorer.

---

## Deploy metadata (Heima mainnet v2)

- Deployer wallet (EVM): the prod deployer — `grep ^DEPLOYER_ADDR_HEIMA scripts/operator-workstation.env`; see the deployer table above for prod vs test.
- v2 deploy date: 2026-05-19 · #164 E1 deploy date: 2026-06-02
- Compiler: Solc 0.8.20, `evm_version = "london"` (a `forge script` header-validation workaround, NOT Heima's EVM level — Heima executes **Cancun**; see AGENTS.md "Heima EVM compatibility level"). The EntryPoint v0.7 is the canonical eth-infinitism bytecode, deployed via `forge create`.
- Deploy script: [`crates/agentkeys-chain/script/DeployAgentKeysV1.s.sol`](../../crates/agentkeys-chain/script/DeployAgentKeysV1.s.sol)

**Constructor wiring** (verified post-deploy):
- `AgentKeysScope.registry()` = the v2 `SidecarRegistry` ✓
- `P256AccountFactory.entryPoint()` = the v0.7 `EntryPoint` ✓, `.k11Verifier()` = the live `K11Verifier` ✓
- `K3EpochCounter.currentEpoch()` = `1`; `.signerGovernance()` = deployer (to be transferred to an M-of-N multisig)
- `SidecarRegistry.ROLE_CAP_MINT()` = `1`, `ROLE_RECOVERY()` = `2`, `ROLE_SCOPE_MGMT()` = `4` ✓

## Verifying contracts are live (read-only RPC, zero gas)

```bash
# One-shot health check across the v2 set:
AGENTKEYS_CHAIN=heima bash scripts/utils/verify-heima-contracts.sh   # exits 0 on all-pass

# Resolve addresses + RPC from the chain profile (#251 — never paste literals):
PROFILE=crates/agentkeys-core/chain-profiles/heima.json
EP=$(jq -r '.contracts[] | select(.name=="EntryPoint").address' "$PROFILE")
FACTORY=$(jq -r '.contracts[] | select(.name=="P256AccountFactory").address' "$PROFILE")
RPC=$(jq -r '.rpc.http' "$PROFILE")
# Bytecode presence (eth_getCode), e.g. the ERC-4337 EntryPoint:
cast code "$EP" --rpc-url "$RPC" | head -c 12
# View call, e.g. factory wiring:
cast call "$FACTORY" "entryPoint()(address)" --rpc-url "$RPC"
```

The verify script checks, per contract: (1) **bytecode presence** (`eth_getCode` non-empty); (2) **view functions** return the expected constant (catches wrong-code-at-this-slot drift); (3) **constructor wiring** (`AgentKeysScope.registry()` → the deployed `SidecarRegistry`); (4) **initialization** (`K3EpochCounter.currentEpoch ≥ 1`, `signerGovernance != address(0)`). It reads addresses from `operator-workstation.env`, so changing `AGENTKEYS_CHAIN` picks up the chain-specific deployment.

**Explorer note:** [`heima.statescan.io`](https://heima.statescan.io/) is Substrate-side — it indexes pallet extrinsics/events but does NOT decode EVM calls/bytecode. EVM contract verification on Heima goes via direct RPC until agentkeys-specific indexing on Litentry's `subscan-essentials` fork ships (arch.md §22a.6).

## Re-deploy / replace

`bash scripts/operator/chain/heima-bring-up.sh` is **idempotent**, by VERSION not bytecode:

1. **Skip** when all four cores have on-chain code AND `crates/agentkeys-chain/VERSION` == the chain profile's `contract_set_version` (the recorded deployed version).
2. **Redeploy** when the stored address is the `0x0` sentinel / absent or has no on-chain bytecode (chain reset). A bumped `VERSION` ≠ the recorded version is a hard stop that prints the mismatch and asks for an explicit opt-in (it orphans state + costs mainnet gas — see below) rather than auto-redeploying.
3. **Force** a fresh deploy at new addresses (contract patch): bump `crates/agentkeys-chain/VERSION`, then re-run with `FORCE_DEPLOY=1` (blind) — or, for the #164 account-auth cutover, use the account-auth cutover helper (operator-internal; probes the live `setScope` selector + skips when already live).

On a fresh deploy the bring-up script **auto-writes the chain profile** (`contracts[]` + `contract_set_version`, step 6b — the source of truth) **and `operator-workstation.env`** (step 6). It does NOT touch this markdown — so update **only the human prose here** (the version line + any ABI/cutover/historical note) when the design or version changes; the addresses live in the profile, not a table here. Confirm the two mirrors agree: `bash scripts/utils/check-deployed-contracts-sync.sh`. No bytecode comparison anywhere — Solidity metadata + immutables make it unreliable, so the human-asserted `VERSION` is the comparison key.

## ABI summary

Full ABIs in [`crates/agentkeys-chain/src/*.sol`](../../crates/agentkeys-chain/src/). The functions broker + workers + CLI read on hot paths:

### `SidecarRegistry` (account-auth design, #164 E3 — live since the 2026-06-08 cutover; #225 E7 account-model + resetMaster)
- `registerFirstMasterDevice(bytes32 deviceKeyHash, bytes32 operatorOmni, bytes32 actorOmni, bytes32 k11CredId, bytes32 k11RpIdHash, uint256 k11PubX, uint256 k11PubY, uint8 roles)` — sel `0x93b14d7c`; bootstraps `operatorMasterWallet[operatorOmni] = msg.sender`. **#225 E7 account model:** the embedded `K11Assertion selfAttestation` was DROPPED — the passkey proof is the account's `validateUserOp` over the `userOpHash` (which commits this calldata). **Rejects an EOA `msg.sender`** (`MasterMustBeAccount`) — the master must be the operator's `P256Account`. **First-master-ONLY** (reverts `DeviceAlreadyRegistered` once `operatorMasterWallet[omni] != 0`).
- `registerAdditionalMasterDevice(bytes32 newDeviceKeyHash, bytes32 operatorOmni, bytes32 newActorOmni, bytes32 newK11CredId, bytes32 newK11RpIdHash, uint256 newK11PubX, uint256 newK11PubY, bytes attestation, uint8 newRoles, K11Assertion existingMasterAssertion)` — requires existing master; `msg.sender == operatorMasterWallet`
- `registerAgentDevice(bytes32 deviceKeyHash, bytes32 operatorOmni, bytes32 actorOmni, bytes linkCodeRedemption, bytes agentPopSig)` — master-only (`msg.sender == operatorMasterWallet`); agents get `ROLE_CAP_MINT` only
- `revokeAgentDevice(bytes32 deviceKeyHash)` — master-only (`msg.sender == operatorMasterWallet[entry.operatorOmni]`)
- `revokeMasterDevice(bytes32 targetDeviceKeyHash, K11Assertion[] recoveryAssertions)` — M-of-N recovery quorum (`recoveryThreshold[operator]`); refuses to strand the operator
- `resetMaster(bytes32 operatorOmni)` — **#225 E7, owner-ONLY** (the deployer captured at construction). Dev/recovery escape hatch: wipes the operator's whole device list + clears `operatorMasterWallet`/`recoveryThreshold`/`operatorNonce`, so a FRESH `registerFirstMasterDevice` can re-bind WITHOUT redeploying the set (needed because first-master-only makes the binding otherwise immutable). The daemon's `POST /v1/master/reset` calls this via `scripts/operator/chain/heima-reset-master.sh`. Emits `MasterReset(operatorOmni, clearedMaster, deviceCount)`.
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
6. **Test redeploy** — re-pin the addresses in `operator-workstation.test.env` (the authoritative test record), then re-run `scripts/operator/secrets/ci-set-github-secrets.sh` so the `TEST_*` secret copies follow; this doc's "Test / CI deploy" section needs only a prose note
