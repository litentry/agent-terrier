How an operator recovers control of their AgentKeys account after losing a master
device — without a seed phrase, an anchor wallet, or any third party. Recovery is
**M-of-N guardian social recovery**, and the part most people get wrong about it
here: the recovery is **executed on-chain by a smart contract**, deterministically,
not merely *audited* on-chain. The chain is the executor, not the bookkeeper.

> **Scope:** the operator-facing recovery model + its on-chain enforcement, what it
> does and does NOT restore (control vs. secrets), the dev escape hatch, and why a
> related hot-path control — spend caps — is deliberately enforced OFF-chain. Deep
> spec: [`arch.md` §11](../arch.md) and the ERC-4337 master plan
> `docs/plan/chain/erc4337-master-account.md` (operator-internal).

## What recovery is (and is not)

Your master is an ERC-4337 smart-contract account ([`P256Account`](../../crates/agentkeys-chain/src/P256Account.sol)) controlled by one or more **passkeys** (P-256, Secure-Enclave / StrongBox-sealed). Recovery replaces a lost passkey with a fresh one, authorized by a quorum of **guardians** — passkeys you registered on surviving devices (your phone, a tablet, a partner's device, an offline recovery-only key).

- **No seed phrase, no anchor wallet.** The devices themselves are the quorum. There is nothing to write down or lose.
- **No third-party recovery.** No friends-as-custodians service, no email reset, no recovery code. The only thing that proves "I am this operator" is **biometric presence (K11) on a surviving guardian** that is still registered on chain.
- **K11 is the gate.** A stolen device key (K10) alone cannot trigger recovery — that would let a single compromised machine lock you out (DoS). Recovery requires a real WebAuthn user-presence assertion from each guardian.

## The chain executes recovery — it does not just record it

`P256Account.recover(newCredIdHash, newPubX, newPubY, newRpIdHash, assertions[])` ([P256Account.sol](../../crates/agentkeys-chain/src/P256Account.sol)) is the whole authority. It runs **in the contract**, with no broker, relayer, or off-chain party deciding anything:

- **Each guardian's WebAuthn assertion is P-256 verified in-contract** (`IK11Verifier.verifyAssertion`, the pure-Solidity [`P256Verifier`](../../crates/agentkeys-chain/src/P256Verifier.sol) — no precompile, no trusted oracle).
- **The contract enforces every rule:** `recoveryThreshold` (0 = recovery disabled, the safe default); a replay-bound challenge `keccak(OP_RECOVER, newSigner, recoveryNonce, chainId, address(this))`; guardian de-duplication (the same credId **or** the same physical pubkey is rejected, so one guardian can't satisfy an M≥2 quorum); and `validSignatures ≥ threshold`.
- **It is atomic and final:** `signerGeneration += 1` invalidates *every* prior signer instantly (the lost passkey is dead the moment recovery lands), then installs the new passkey as the sole active signer.
- **It is permissionless to submit.** A relayer can land the transaction for a locked-out operator; authority comes purely from the guardian signatures, never from who pays the gas.

This is the distinction that matters: scope grants, agent binding, master registration, K3 epoch advance, and recovery are all **enforced by contracts** here, not decided off-chain and mirrored. A compromised broker cannot grant scope, mint a master, or recover an account. The only purely-audit contract is [`CredentialAudit`](../../crates/agentkeys-chain/src/CredentialAudit.sol) (a Merkle-root anchor) — which is correctly audit-only, since you do not "execute" an audit.

## Setting it up (operator)

1. **Register guardians** — add a passkey from each surviving device as a guardian (`addGuardian`, gated to the account itself / EntryPoint, so only you can add one).
2. **Set the threshold** — `recoveryThreshold` is per-operator (default 1; the onboarding flow prompts you to bump to 2 when you add a third device). Threshold M with N guardians = an **M-of-N** quorum.

Operator ceremonies (K11-gated):
`heima-set-recovery-threshold.sh` (operator-internal) sets the quorum;
`heima-recovery.sh` (operator-internal) drives the M-of-N master-device revoke + rotate;
`heima-register-spare-master.sh` (operator-internal) registers a third device to exercise the quorum end-to-end.

## The recovery timeline (you lose your laptop)

1. **t=0** — you notice the laptop (master device A) is lost/stolen, and pick up a surviving device B (phone) that holds its own K10 + a guardian passkey K11.
2. **t≈60s** — in the app you choose *"Lost device — revoke & rotate"*; it builds the revoke + new-signer payload and asks for the K11 biometric on device B.
3. **t≈90s** — if the threshold is ≥ 2, the app collects the additional guardian assertion(s) (a desktop at home, a tablet, a co-approver) until signatures ≥ threshold.
4. **t≈2m** — the quorum-signed `recover` / `revoke_device` lands on chain; the contract verifies the assertions, swaps the signer, and bumps the generation. The chain emits the event.
5. **t≈2m+1s** — the broker receives the chain event over SSE, drops every cap tied to the revoked key, and rejects new cap-mints from it; daemons under your `operator_omni` zero their credential cache. Within ~60s more (the 5-minute `cred_cache_ttl` ceiling, but typically immediate), an attacker holding the old device can no longer perform **any** authorized operation.

## Control vs. secrets — what recovery does and does NOT restore

This is the one boundary to internalize:

- **Recovery restores CONTROL — on-chain, instantly.** After `recover()`, your new passkey can sign UserOps, mint caps, set scope, bind agents — everything the master can do.
- **Recovery does NOT, by itself, decrypt your EXISTING vaulted secrets.** Vaulted credentials are AES-256-GCM under a per-operator KEK (K3) **derived inside the signer / TEE** — a decryption key can never live on chain (it would be public). So reading secrets that were vaulted *before* recovery requires the TEE to re-derive and re-wrap the KEK under the new master: a **K3-epoch rotation**, *coordinated* on chain ([`K3EpochCounter`](../../crates/agentkeys-chain/src/K3EpochCounter.sol)'s M-of-N) but *executed* in the enclave. Control is on-chain and immediate; the secret re-wrap is a separate TEE ceremony. (See [`./key-security.md`](./key-security.md) and [`./blockchain-tee-architecture.md`](./blockchain-tee-architecture.md).)

**If you lose ALL devices/guardians at once** (whole-household theft, fire) you have lost your actor tree — the deliberate trade-off for having no third-party recovery surface to attack. Mitigate by diversifying: a phone in your pocket, a laptop at home, and a biometric-locked **offline recovery-only guardian** kept in a safe. High-stakes operators can additionally pre-position a TEE-attested emergency override that publishes on chain (designed, not enabled by default).

## The dev escape hatch (NOT recovery): reset master

The reset-master helper (operator-internal) (`SidecarRegistry.resetMaster`, behind the daemon's *reset master* button) is a **deployer-gated dev escape** — not Touch ID, not a guardian quorum. It exists because first-master registration makes `operatorMasterWallet` immutable, so a lost passkey with **no guardians configured** is otherwise unrecoverable. It also tears down the whole fleet (declines pending pairings, revokes every agent device, clears local state). In production this would be gated on guardian recovery (`P256Account.recover`) instead of a deployer key. See the *reset master* note in [`../user-manual.md`](../user-manual.md).

## Why spend caps are enforced OFF-chain (the design contrast)

Recovery is the textbook case for **on-chain execution**: it is **rare** and **high-stakes**, so paying a transaction's gas + latency to make it deterministic and trustless is obviously worth it. **Spend caps are the opposite shape, and the architecture treats them differently on purpose.**

- The **limits** are on-chain, in the scope itself ([`AgentKeysScope`](../../crates/agentkeys-chain/src/AgentKeysScope.sol): `maxPerCall`, `maxPerPeriod`, `maxTotal`, `periodSeconds`). The policy — *what an agent is allowed to spend* — is tamper-proof and master-set, exactly like its service scope.
- The **accounting** — *how much has it spent this period* — is enforced **off-chain** (broker / worker), reading the on-chain limit. The scope contract intentionally has **no `recordSpend` / usage accumulator**.

The reason is **frequency**. Spend enforcement sits on the **hot path**: it is consulted on effectively every cap-mint / operation, potentially many times per second across a fleet. An on-chain per-spend accumulator would charge a transaction's gas and add block-time latency to **every** agent action — prohibitive for a high-frequency meter. So the system follows a clean principle:

> **Put EXECUTION on-chain for the RARE, high-stakes events (recovery, scope grant, master register, agent binding, K3 epoch). Keep the HOT-PATH meter (spend accounting) off-chain, reading the on-chain policy.** The chain is the authority on *what is allowed*; the fast off-chain layer is the authority on *how much has been used*, and it can only ever be **more** restrictive than the on-chain cap, never less.

A future enhancement could add an on-chain spend ledger (a `recordSpend` + rolling-window accumulator that reverts over-cap) to make spend deterministic the way recovery already is — but only where the per-operation gas + latency is acceptable: high-value, low-frequency settlements, or a periodic batch reconciliation, rather than the per-call hot path. The default stays off-chain precisely because spending is high-frequency. (Related: [`./policy-scope-namespace.md`](./policy-scope-namespace.md) for how scope + limits are authored and verified.)

## See also

- [`arch.md` §11 — Recovery: M-of-N device quorum](../arch.md) (the canonical spec) and §4 (the K-key inventory: K10 device key, K11 passkey, K3 KEK).
- [`./key-security.md`](./key-security.md) — the two-tier secret-storage model and why the KEK is TEE-held.
- [`./blockchain-tee-architecture.md`](./blockchain-tee-architecture.md) — how the chain and the TEE divide responsibility.
- [`./policy-scope-namespace.md`](./policy-scope-namespace.md) — scope, services, and spend limits.
- Plan: `docs/plan/chain/erc4337-master-account.md` (operator-internal) (the P256Account + guardian-recovery design, #164 E5).
