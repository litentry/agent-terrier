# Heima ⟷ Ethereum EVM gaps (the eth-migration index)

Heima is a **Substrate parachain with a Frontier `pallet_evm`** (EVM compatibility), not a
go-ethereum L1. Its EVM *execution* is **Cancun-level**, but its block/consensus layer + a few
JSON-RPC behaviours diverge from standard Ethereum, and the repo carries a handful of
workarounds for them. This doc is the single inventory of those divergences — **gap → symptom →
workaround → code site → what changes on eth** — so a future migration to a standard Ethereum
chain (or an EVM L2) can find and lift each workaround mechanically.

**Scope:** only divergences that forced a workaround. The *capability* claims (what opcodes run)
are proven by on-chain probes in [AGENTS.md "Heima EVM compatibility level"](../../AGENTS.md);
this doc is the migration-facing view and defers there for the proofs. Tooling quirks that are
*not* Heima-specific (e.g. the `cast send --create` clap arg-ordering trap, a foundry-version
issue) are out of scope — they apply to eth too.

> **One-line takeaway:** every Heima workaround here is a **block/RPC/tooling** accommodation, not
> a contract-design change. The ERC-4337 stack (EntryPoint v0.7, `P256AccountFactory`,
> `P256Account`, `VerifyingPaymaster`) + the account-auth contracts are **chain-agnostic standard
> Solidity** — migrating the chain needs **no contract changes**, only the items below.

## The gaps

### 1. `eth_estimateGas` reverts on complex calls (ERC-4337 `handleOps`)

- **Symptom:** `Failed to estimate gas: … VM Exception while processing transaction: revert,
  data: "0x"` — a **bare `0x` revert with no reason**, i.e. NOT an ERC-4337 `FailedOp` / `AAxx`
  string. That signature (empty data) means Heima's `eth_estimateGas` itself can't simulate the
  EntryPoint call, *not* that the UserOp is invalid (a real validation failure carries a
  structured `FailedOp` reason).
- **Workaround:** pin an explicit `--gas-limit` and **skip estimation**. The account / paymaster
  only pays `actualGasUsed`; the limit is a cap the submitter fronts and is refunded for unused.
- **Code:** [`agentkeys-bundler`](../../crates/agentkeys-bundler/src/server.rs)
  (`AGENTKEYS_HANDLEOPS_GAS_LIMIT`, default `4_000_000` — the broker's `accept_submit` now relays
  to the bundler per #230, which owns the pinned-gas legacy tx);
  [`erc4337-register-master.sh`](../../harness/scripts/erc4337-register-master.sh)
  (`--gas-limit 3000000`); [`heima-deploy-paymaster.sh`](../../scripts/heima-deploy-paymaster.sh)
  (`--gas-limit 2000000`).
- **On eth:** `eth_estimateGas` works — drop the pin (or keep a generous cap; harmless).

### 2. mixHash-less receipts break cast / forge / alloy receipt parsing

- **Cause:** Heima's Frontier block header has **no `mixHash` / `prevrandao` /
  `withdrawalsRoot` / `blobGasUsed`** (Ethereum-PoS *consensus* fields). alloy's strict receipt
  deserialisation fails on the missing fields → **cast / forge EXIT NON-ZERO even though the tx
  LANDED on chain.**
- **Workaround:** **never trust cast/forge's exit code** for a Heima tx — `|| true` it and verify
  the *outcome* on chain: `cast code <addr>` (deploy landed), `isActive(deviceKeyHash)` /
  `operatorMasterWallet(omni)` (register landed), or a **direct `eth_getTransactionReceipt`** read
  (parse `.status` yourself, not via alloy's strict deser).
- **Code:** [`agentkeys-bundler`](../../crates/agentkeys-bundler/src/server.rs) (#230 — ALL chain
  reads are raw `serde_json::Value`, no alloy/ethers; it signs + RLP-encodes the legacy `handleOps`
  tx itself and reads `eth_getTransactionReceipt.status` directly, which is also WHY a stock
  bundler/cast is not in the submit path anymore); [`erc4337-register-master.sh`](../../harness/scripts/erc4337-register-master.sh)
  (`|| true` + `isActive`); [`heima-deploy-paymaster.sh`](../../scripts/heima-deploy-paymaster.sh)
  (`|| true` + `cast code`); [`heima-bring-up.sh`](../../scripts/heima-bring-up.sh) (`cast code`
  per deployed address).
- **On eth:** receipts parse — trust the parsed receipt + exit code; the on-chain re-checks become
  belt-and-braces rather than load-bearing. `cast send --json` becomes usable again.

### 3. `forge create` pre-broadcast estimation errors (forge 1.x on Heima)

- **Symptom:** `forge create … --broadcast` errors on Heima **before broadcasting** (the deployer
  nonce is unchanged — no tx sent). forge 1.x runs an `eth_estimateGas`-style pre-flight that
  trips on Heima (related to #1).
- **Workaround:** deploy via **`cast send --create <init‖ctor-args>`** at the **deterministic
  CREATE address** (`cast compute-address <deployer> --nonce <n>`), `|| true` + `cast code` verify
  (so the mixHash quirk #2 doesn't matter either).
- **Code:** [`heima-deploy-paymaster.sh`](../../scripts/heima-deploy-paymaster.sh). (The 4-core
  deploy uses `forge script`, which is gated separately by #4.)
- **On eth:** `forge create` works; `cast send --create` is portable and keeps the
  no-estimation posture, so it's fine to leave it.

### 4. `forge script --broadcast` header validation (`prevrandao not set`)

- **Symptom:** `EVM error; header validation error: prevrandao not set` when `evm_version >=
  paris`.
- **Cause:** forge script's **local simulator** validates the fetched block header against the
  target EVM revision *before* broadcasting; `paris`+ requires `prevrandao`, absent on Heima.
  This is a *simulator header* check, NOT an opcode-capability gate.
- **Workaround:** pin **`evm_version = "london"`** in
  [`crates/agentkeys-chain/foundry.toml`](../../crates/agentkeys-chain/foundry.toml).
- **Code:** `foundry.toml` (`evm_version = "london"`);
  [`DeployAgentKeysV1.s.sol`](../../crates/agentkeys-chain/script/DeployAgentKeysV1.s.sol) (run via
  `forge script`).
- **On eth:** the header carries `prevrandao` — bump `evm_version` to `paris` / `shanghai` /
  `cancun`.

### 5. EVM execution IS Cancun — the header format is not a capability signal

- Heima's Frontier `stable2412` `pallet_evm` returns `&CANCUN_CONFIG`. **PUSH0** (Shanghai) and
  **TSTORE/TLOAD** (EIP-1153, Cancun-only) execute — verified on chain (#168). The
  pre-London-*looking* header (no `prevrandao`/`blobGasUsed`) reflects the **consensus/block
  layer**, not the opcode level. So the `evm_version=london` pin (#4) is a **simulator-header
  workaround, not an opcode ceiling** — contracts MAY use ≤Cancun features (PUSH0, transient
  storage) at runtime today. The P-256 verification is **pure Solidity** (no RIP-7212 precompile,
  no chain change).
- **On eth:** same opcode level; once the header matches (#4 lifts), no behavioural change.

### 6. `chain_id` is deployment-year-prefixed (migration note, not a gap)

- Heima mainnet `212013`, Heima Paseo `2013` (= `HEIMA_PARA_ID`; mainnet prefixes the year).
  Recorded in [`crates/agentkeys-core/chain-profiles/heima.json`](../../crates/agentkeys-core/chain-profiles/heima.json)
  / `heima-paseo.json`.
- **On eth:** a different `chain_id` + RPC + explorer — a new chain profile, nothing more.

### 7. The pure-Solidity P-256 verify is gas-heavy → `verificationGasLimit` must be ≥ 1.5M

- **Why:** no RIP-7212 P-256 precompile (gap #5), so a passkey UserOp's account `validateUserOp`
  runs the WebAuthn/P-256 verify in **pure Solidity** — ~1M+ gas on Heima. The ERC-4337
  `verificationGasLimit` (the account-validation gas cap the EntryPoint enforces) MUST cover it.
- **Symptom (real #225 incident):** a UserOp with `verificationGasLimit = 600_000` reverts
  `handleOps` with **`AA24 signature error`** — looking exactly like a wrong-passkey bug. It is NOT:
  the `P256Account` wraps the verify in `try checkUserOpSignature() catch { SIG_FAIL }`, so an
  out-of-gas inside the capped call is **caught and mapped to `SIG_VALIDATION_FAILED`** (AA24, not
  the AA23 a bare OOG would give). Diagnosing this needs an on-chain replay: `validateUserOp`
  returns SIG_OK under unlimited (eth_call) gas but SIG_FAIL under the 600k cap. (Since #247 the
  replay-and-decode is automatic: on a reverted `handleOps` the in-house bundler replays the
  calldata via `eth_call`, decodes `FailedOp`, and the `/v1/accept/submit` error carries the
  verbatim `AAxx` reason plus per-code operator guidance — no more manual `cast call` dance.)
- **Workaround:** pin `verificationGasLimit` ≥ **1_500_000** (the value the working passkey
  REGISTER UserOp uses). Keep `maxFeePerGas` ≥ Heima base fee (~25 gwei) so the op can pay — but
  low enough that `Σ(gasLimits) × maxFee` stays under the paymaster's EntryPoint deposit.
  Code site: [`handlers/accept.rs`](../../crates/agentkeys-broker-server/src/handlers/accept.rs)
  `DEF_VERIFICATION_GAS_LIMIT` / `DEF_MAX_FEE`.
- **On eth:** with a RIP-7212 precompile the verify is ~3.5k gas → `verificationGasLimit` can drop
  back to ~100–200k and `maxFee` tracks the target chain's base fee.

### 8. Existential Deposit bricks low-balance EntryPoints → `AA91 failed send to beneficiary`

- **Why:** Substrate's `pallet_balances` enforces an **ExistentialDeposit** (~0.1 HEI): an account
  whose free balance drops below it is **reaped to 0**, and value sends out of (or leaving the
  account below) the ED fail. The ERC-4337 EntryPoint holds every actor's deposit as its OWN native
  balance and pays each op's gas compensation out of it — so a fresh EntryPoint whose total deposits
  drain near the ED has its beneficiary payout fail **inside `handleOps`**, reverting the whole tx.
- **Symptom (real 2026-06-10 incident, the fresh TEST EntryPoint):** every UserOp reverts with
  outer `status 0` at ~820k gas (validation completes, payout fails); `eth_call` decodes
  **`AA91 failed send to beneficiary`** (surfaced automatically in the `/v1/accept/submit`
  error since #247, with the ED guidance inline); the account nonce does not advance. Worse: once below the
  ED the EntryPoint's native account is REAPED — `cast balance` shows **0** while the internal
  `deposits` mapping still shows the escrowed amounts. Prod never hit this only because its
  EntryPoint balance is ~13 HEI across many deposits.
- **Workaround:** keep a standing **native ED buffer** in every EntryPoint —
  [`scripts/heima-deploy-erc4337.sh`](../../scripts/heima-deploy-erc4337.sh) ensures balance ≥
  `ERC4337_EP_BUFFER_WEI` (default 1 HEI) on every run, sent via the EntryPoint's `receive()` (which
  credits the **deployer's own withdrawable deposit** — nothing is burned). Note the recreation
  quirk: topping up a reaped account can land ~the ED short of the sent value, so the top-up is
  deficit-based with headroom.
- **On eth:** no ED exists — drop the buffer (it stays harmless if kept; it is a withdrawable
  deposit).

## Migration checklist (Heima → standard Ethereum / EVM L2)

Lift each workaround in lock-step with the chain swap:

- [ ] **#1 estimateGas** — drop (or relax) the pinned `--gas-limit` / `AGENTKEYS_HANDLEOPS_GAS_LIMIT`;
  let the tooling estimate.
- [ ] **#2 receipts** — trust cast/forge exit codes + parsed receipts; `eth_receipt_status` / the
  on-chain re-checks become belt-and-braces; `cast send --json` is usable again.
- [ ] **#3 deploys** — `forge create` works; the `cast send --create` deterministic-address path is
  still fine to keep.
- [ ] **#8 ED buffer** — optional to remove (`ERC4337_EP_BUFFER_WEI=0`); the buffer is a
  withdrawable deposit, not a cost.
- [ ] **#4/#5 foundry.toml** — bump `evm_version` past `london` (header now valid; opcode level
  unchanged).
- [ ] **#6 chain profile** — new `chain_id` / RPC / explorer; redeploy contracts; re-record the
  registry (the chain profile is the source of truth — see
  [`deployed-contracts.md`](deployed-contracts.md)).
- [ ] **#7 verificationGasLimit** — if the target chain has a RIP-7212 P-256 precompile, drop
  `DEF_VERIFICATION_GAS_LIMIT` back to ~100–200k and let `DEF_MAX_FEE` track the chain's base fee.
- [ ] **Contracts** — none. EntryPoint v0.7 / `P256AccountFactory` / `P256Account` /
  `VerifyingPaymaster` / `SidecarRegistry` / `AgentKeysScope` are standard Solidity; redeploy
  as-is. A standard ERC-4337 **bundler + RIP-7212 P-256 precompile** (if the target chain has it)
  could replace the broker's direct `handleOps` submit + the pure-Solidity verifier, but neither
  is required.

## See also

- [AGENTS.md "Heima EVM compatibility level"](../../AGENTS.md) — the on-chain capability proofs.
- [`deployed-contracts.md`](deployed-contracts.md) — the live contract set + the chain profile.
- [`../plan/chain/erc4337-master-account.md`](../plan/chain/erc4337-master-account.md) — the
  ERC-4337 master design (chain-agnostic).
