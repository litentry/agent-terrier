# Heima Open Questions — The Kai Meeting Agenda

**Purpose:** this file is the walk-in agenda for the conversation with Kai about what the Heima TEE worker currently supports, what it doesn't, and what gap work is needed before AgentKeys v0 can ship. It is designed to be fillable during the meeting — each question has space for Kai's answer, and the Reuse–Build–Block matrix at the bottom is the summary artifact to walk out with.

> **Context shift (Round 13, 2026-04-09):** The purpose of this meeting has shifted from "can we build v0?" to "will this API contract survive contact with Heima reality?" v0 ships on the mock backend regardless. This meeting validates the v0.1 migration path.

**Context:** the AgentKeys auth-layer sub-analysis ([`1-step-analysis.md`](./1-step-analysis.md)) reached ~17% ambiguity across 8 interview rounds. The remaining blockers are all "verify against Heima reality" items. Kai holds the TEE worker code that is not in the public `litentry/heima` repo, so this meeting is the **reality check** that determines whether the architecture as designed is buildable, needs re-scoping, or is blocked.

**Companion docs:**
- [`1-step-analysis.md`](./1-step-analysis.md) — the AgentKeys auth-layer sub-analysis this meeting is checking against
- [`../../../lifeKnowledge/heima.md`](../../../lifeKnowledge/heima.md) — Heima parachain primitives (public repo only)
- [`../../../lifeKnowledge/heima-auth.md`](../../../lifeKnowledge/heima-auth.md) — existing auth methods in dexs-backend (Wildmeta account service)

---

## The three goals of the meeting

1. **Reuse check.** For each AgentKeys requirement, determine whether the TEE worker already supports it (✅ reuse), almost supports it (🛠 delta), or doesn't (🚫 build or workaround).
2. **Scope estimate.** For every 🛠 or 🚫, get a size in days-of-Kai's-time or weeks-of-AgentKeys-team-time.
3. **Ownership decision.** For every non-reuse item, decide who does the work: Kai, the AgentKeys team (if they can fork/PR), the Heima core team, or "blocked."

**Walk-out deliverable:** a filled-in Reuse–Build–Block matrix (§4 below) plus a scope/ownership column for every non-reuse item.

---

## 1. P0 — critical-path questions (answers can force re-architecture)

### Q9. Session key revocation latency (**TOP PRIORITY — the ONLY defense on stock sandbox**)

> **Why this is #1 now:** Round 13 runtime probe confirmed that stock `agent-infra/sandbox` has no Landlock, no LSM, no UID isolation. Revocation latency is the ONLY remaining defense against a compromised agent — if revocation is slow, a stolen session key has a long exploitation window with no other barrier. This makes revocation latency the single most important variable in the v0 threat model.
>
> **Wanted:** when the master calls `agentkeys revoke`, propagation to the TEE reaches ≤ 1 Heima block (~6 s), and the next credential read with the revoked session fails synchronously.
>
> **Feared:** revocation is polling-based with a lag of tens of seconds, or the TEE worker caches session validity for N minutes.
>
> **If feared:** the demo's "instant kill" moment gets slower. Adjust the talk's claim from "instant" to "within one block / ~6 seconds." More critically, the v0 threat model's honest "blast radius" window grows from seconds to minutes.

**Kai's answer:**
```
Revocation mechanism: [ ] chain event subscription / [ ] polling / [ ] other
Typical latency: _______
```

---

### Q1. Scoped child-session key minting — does it exist today?

> **Wanted:** the TEE worker can, given a master session key, mint a new session key that is (a) bound to a specific agent's x402 wallet address, (b) restricted to a specific capability subset (e.g., "read credentials for services S₁, S₂"), (c) has its own TTL, (d) can be revoked independently of the master.
>
> **Feared:** every session key is currently full-master-scope; adding scoped derivation is weeks of TEE worker work.
>
> **If feared:** v0 falls back to "one session key per agent, no master-child distinction at the key level." The daemon per sandbox holds what's effectively a restricted account's master key; revocation means killing that account's access entirely rather than just that session. Weaker but still shippable. The master "controlling" children becomes a client-side convention, not a TEE-enforced one.

**Kai's answer:**
```
[ ] Already supported — where in the code?
[ ] Partially — gap is: _______
[ ] Not supported — scope to build: _______ days
[ ] Blocked — because: _______
```

---

### Q2. Per-agent credential blob storage — reusable or net-new?

> **Wanted:** a generic encrypted-blob-in-TEE store keyed by `(owner_omni, agent_wallet, service_name)`, with TEE-side access control on read. `pallet-evm-assertions.secrets` is the closest precedent (from `heima.md`), but it's tied to VC assertion contracts, not general credentials.
>
> **Feared:** there is no general credential vault; adding one is a new pallet (~weeks) or a new module in the `omni-executor` (~days–weeks).
>
> **If feared:** AgentKeys either (a) writes a new `pallet-secrets-vault` and PRs it upstream, (b) hacks the existing `evm-assertions.secrets` surface to store our blobs there (fast but ugly, conflates with VC assertions), or (c) authors a simpler AgentKeys-owned pallet.

**Kai's answer:**
```
[ ] Already supported — pallet/module name: _______
[ ] Partially supported via: _______
[ ] Not supported — preferred build path: _______
[ ] Blocked — because: _______
```

---

### Q3. TEE-side policy enforcement for credential reads

> **Wanted:** the TEE enforces "agent 0x9c3e… may read `openrouter` but not `brave`" **at the moment of decryption**, not just at session-creation time. A stolen session key should be unable to cross-agent-read even if the AgentKeys daemon is buggy or compromised.
>
> **Feared:** policy is enforced client-side only; a session key is a bearer to whatever its scope was at creation, and no fresh check happens on each read. The TEE just decrypts whatever it's asked to decrypt.
>
> **If feared:** defense-in-depth collapses onto daemon correctness + revocation latency. The writeup's security story takes a hit. v0 ships anyway, but §3.3a's "what this does NOT protect against" list grows — and the claim "TEE-gated access control" becomes "daemon-gated access control with Heima as the audit witness."

**Kai's answer:**
```
[ ] Enforced TEE-side at each read
[ ] Enforced TEE-side at session creation only (snapshot)
[ ] Client-side enforcement only
[ ] Other: _______
```

---

### Q4. First-login policy for recoverable identity types

> **Wanted:** the TEE worker can enforce "if `identity_type not in {google, synced_passkey, email}`, reject first-login OmniAccount creation." From §3.1 of the sub-analysis. One-line policy.
>
> **Feared:** no hook for first-login-specific policy; would require modifying the identity-worker state machine.
>
> **If feared:** AgentKeys enforces client-side in its own CLI and documents that any other client can bypass it. Risk: someone's sandbox creates a stranded master account by accident. Mitigation: AgentKeys refuses to create a session on a device type that can't recover. Acceptable if not ideal.

**Kai's answer:**
```
[ ] Hookable — exact location: _______
[ ] Requires code change — scope: _______
[ ] Not worth doing TEE-side — client-side only
```

---

## 2. P1 — scope and schedule (changes what's v0 vs v0.1)

### Q5. x402 EVM wallet generation on account creation — is it the existing HeimaLogin flow?

> **Wanted:** confirm that `heima-auth.md`'s claim is accurate — `RegisterUserByOmniAccount` auto-provisions Solana + EVM wallets, the private keys live inside the TEE (bitacross-style), and the pubkey/address is returned to the caller and registered on-chain. AgentKeys wants to reuse this exact flow for generating the master and child wallet addresses that serve as canonical account names (§3.1a of the sub-analysis).
>
> **Feared:** the flow exists but EVM keys are held differently (e.g., derived client-side from the master password, or stored in plain RocksDB without enclave protection), or the addresses aren't the ones AgentKeys wants to expose publicly.
>
> **If feared:** AgentKeys adds x402-wallet generation as a TEE worker extension — still moderate work, but not architecturally re-blocking.

**Kai's answer:**
```
Current flow for wallet generation: _______
Where the private key lives: _______
Is it reusable for AgentKeys: [ ] yes / [ ] with changes / [ ] no
```

---

### Q6. Multi-tenant client isolation — can AgentKeys register its own `client_id`?

> **Wanted:** Wildmeta's users and AgentKeys' users are in separate namespaces — separate identity graphs, separate credential stores, no cross-tenant access. `heima-auth.md` noted there's a `client_id` concept in `pkg/omni/identity_tool.go`, used to derive OmniAccount fingerprints. AgentKeys wants its own `client_id` so its users are on a separate OmniAccount namespace from Wildmeta's.
>
> **Feared:** the TEE worker is single-tenant, or `client_id` is hard-coded, or there are implicit assumptions that only the Wildmeta client_id is valid.
>
> **If feared:** AgentKeys deploys its own TEE worker instance (much more operational work — we need to run a second tee-worker process), or forks the TEE worker entirely. Either choice changes the talk from "built on Heima" to "built on a forked/second instance of Heima."

**Kai's answer:**
```
client_id registry location: _______
Process to register a new client_id: _______
Cross-tenant isolation guarantees: _______
```

---

### Q7. Device-code interpretation B — does it exist?

> **Wanted:** Heima-native device-code flow (Round 5 interpretation B) where the master mints a per-device unique code, the code is consumed on exchange for a session, code-derived sessions are revocable by the master.
>
> **Feared:** no such flow exists; the only headless auth path today is `HeimaLogin` with an upstream-issued JWT.
>
> **If feared:** v0 uses the rendezvous relay through the mock backend for pairing (the daemon generates a pair code, the master CLI approves via the backend's authorization-request primitive). Heima-native device-code is deferred to v0.1.

**Kai's answer:**
```
[ ] Exists as: _______
[ ] Doesn't exist — scope to add: _______
[ ] Can work around via rendezvous relay for v0
```

---

### Q8. Audit event schema — what fires when, and what's in it?

> **Wanted:** for every credential read, an on-chain extrinsic fires with shape approximately `(owner_omni, agent_wallet, service_name, action, result, block_height, timestamp)` — queryable via a Subsquid or Subquery indexer for the `agentkeys usage` command and the demo block-explorer walkthrough.
>
> **Feared:** existing events are coarse (e.g., just `DispatchedAsOmniAccount`) and don't identify the (agent, service) tuple.
>
> **If feared:** small TEE worker change to add a purpose-built AgentKeys event, OR AgentKeys runs its own indexer that tails the TEE worker's off-chain activity via a side channel (worse).

**Kai's answer:**
```
Existing events for credential-like ops: _______
Event schema extensibility: _______
Cost per event (extrinsic fee): _______
```

---

## 3. P2 — operational and roadmap

### Q10. TEE worker stability and rewrite plans

> **Wanted:** the TEE worker is actively maintained, API is stable, no imminent rewrite that would break AgentKeys' integration in the next 3–6 months.
>
> **Feared:** rewrite in progress, AgentKeys should wait or pin to a deprecated version.
>
> **If feared:** delay v0 or target the new version.

**Kai's answer:**
```
Current state: _______
Planned rewrites/changes: _______
Recommendation for AgentKeys: _______
```

---

### Q11. Open-source posture of the TEE worker and the AgentKeys-facing API

> **Wanted:** the AgentKeys-facing API surface can be fully documented and published in the writeup / GitHub, even if the TEE worker internals remain closed-source.
>
> **Feared:** anything AgentKeys calls is under NDA or Wildmeta-confidential; the writeup can't be fully reproducible; third parties can't self-audit the integration.
>
> **If feared:** the writeup describes the interface abstractly and acknowledges the opaque dependency. Reproducibility of the demo weakens; "self-sovereign" claim has to be explicit that one dependency is not self-auditable.

**Kai's answer:**
```
TEE worker source availability: _______
API docs publication: [ ] OK / [ ] with conditions / [ ] NDA
Conditions: _______
```

---

### Q12. Rate limits, call cost, mainnet vs testnet

> **Wanted:** AgentKeys can run 10s of credential fetches per second during bursts without hitting rate limits. Per-extrinsic fees on Heima are < $0.001, so per-credential cost is negligible. Paseo testnet is available for the demo and mainnet for eventual production.
>
> **Feared:** low rate limits, high per-call fees, or testnet instability.
>
> **If feared:** v0 runs on Paseo; the writeup is about testnet; mainnet is a v0.1 consideration with explicit cost analysis.

**Kai's answer:**
```
Rate limits: _______
Extrinsic cost: _______
Testnet (Paseo) availability: _______
Mainnet readiness: _______
```

---

## 3a. Chain backbone — EVM, Paseo, sudo (added 2026-05-18 after Heima dev info handoff)

**Context for this section:** Stage 1 of v2 deploys four Solidity contracts (`AgentKeysScope`, `SidecarRegistry`, `K3EpochCounter`, `CredentialAudit`) on Heima's Frontier-EVM. Production target: **Heima mainnet** (`heima` profile, chain ID 212013, live RPC verified 2026-05-18). Development target: **Heima Paseo testnet** (`heima-paseo` profile). The Heima developer team confirmed that Paseo's runtime ships `pallet_sudo` with the sudoer set to **account Alice** — a Substrate dev convention that bears explaining.

### Educational background — "what is Alice?" and "what is sudo?"

**Alice is one of six well-known Substrate dev accounts.** When you run `subkey inspect //Alice` (or any Substrate node with the `--alice` flag), you get a deterministic keypair derived from this seed phrase:

```
bottom drive obey lake curtain smoke basket hold race lonely fit walk//Alice
```

The other five — Bob, Charlie, Dave, Eve, Ferdie — derive the same way with `//Bob`, `//Charlie`, etc. These keys are **intentionally public** (printed in `subkey`'s docs, baked into every Substrate dev-chain genesis) so that anyone can run a dev/test chain and immediately have funded accounts with known keys. They are **never** secure — anyone with access to a chain that recognizes Alice can sign as Alice. This is the point.

Canonical Alice details (sr25519, the Substrate default):

| Property | Value |
|---|---|
| Secret seed | `0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a` |
| Public key (hex) | `0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d` |
| SS58 address (generic prefix 42) | `5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY` |
| SS58 address on Heima (prefix 31, verified live via `system_properties` 2026-05-18) | (re-encode of the same public key under prefix 31 — need to confirm with Kai) |

**`pallet_sudo` is the Substrate root-authority pallet.** Runtimes that include it expose one extrinsic: `sudo.sudo(call)`. The pallet stores ONE address as the "sudo key" and lets only that address execute `sudo.sudo(...)`, which runs the wrapped call with `RawOrigin::Root` — bypassing every other origin check in every other pallet. The sudoer can:

- Force-transfer balances (e.g., pre-fund any account for testing)
- Force-set chain state (`system.setStorage`)
- Force-run a runtime upgrade (`system.setCode`)
- Whitelist EVM contracts for privileged paths (if the runtime exposes such hooks)
- Reset the K3 epoch counter (in our case) without waiting for the signer-governance multisig

Sudo is **standard practice on testnets** — it gives the chain operator (or anyone with the sudo key) a god-mode lever for unblocking dev workflows. It is **never** on a production chain. Either the pallet is excluded from the runtime entirely, or the sudo key is rotated to a multisig held by governance and eventually destroyed via `sudo.killSudo()`.

**Why Heima Paseo's sudoer is Alice:** the public, anyone-knows-it Alice key + sudo pallet means **any developer can call sudo on Heima Paseo for free** — pre-fund a deployer wallet, force-bump the K3 epoch counter for testing, force-set an actor's scope without going through the K11/K10 ceremony. This is exactly the dev convenience the testnet exists to provide. It does NOT mean Alice owns the chain or that there's a security flaw — Paseo is a deliberately permissionless dev environment.

**How AgentKeys uses (or doesn't use) sudo on Heima Paseo:**

| Use case | Sudo needed? | Notes |
|---|---|---|
| Deploy four Solidity contracts via Foundry | No | Anyone with HEI gas can deploy. Sudo not involved. |
| Pre-fund a hot-key deployer wallet from Alice | Yes | `sudo.sudo(balances.forceTransfer(Alice → deployer, X HEI))` saves operators from chasing faucets. |
| Bootstrap `K3EpochCounter` to a non-1 starting epoch for testing rotation flows | Yes | `sudo.sudo(system.setStorage(K3EpochCounter::current_epoch → N))` — testnet-only. |
| Force-register a fake `SidecarRegistry` entry for testing worker re-verification | Maybe | Could `sudo.sudo(ethereum.transact(...))` to call the contract as if msg.sender were anyone. |
| Production `K3EpochCounter.bump_epoch` (mainnet) | **NEVER** | Production uses the signer-governance multisig directly; sudo is not in the runtime. |

**Tooling note:** `sudo.sudo(...)` is a Substrate-side extrinsic, NOT an EVM transaction. Calling it requires Substrate-side signing — either via Polkadot.js Apps (Developer → Sudo tab), `subxt` (Rust), `@polkadot/api` (JS), or `subkey`. Foundry / `cast` / web3.js cannot construct sudo extrinsics because they only know Ethereum-style RLP-encoded transactions. The crossover gotcha for our use case: when we want sudo to "do something to the EVM side" (e.g., call a Solidity function as if msg.sender were the contract owner), the sudo extrinsic wraps `pallet_ethereum.transact(...)` — which is the Substrate-side primitive that submits an EVM transaction. That's the bridge.

### Q13. What's the canonical Heima Paseo RPC URL? ✅ RESOLVED 2026-05-18

> **Wanted:** a single HTTP + WSS endpoint that responds to both EVM JSON-RPC (`eth_chainId`, `eth_blockNumber`) and Substrate-RPC (`system_chain`, `system_properties`, `sudo_*` extrinsics via Polkadot.js Apps).

**Heima dev team answer (2026-05-18 handoff):**

```
Paseo HTTP RPC URL:        https://rpc.paseo-parachain.heima.network
Paseo WSS RPC URL:         wss://rpc.paseo-parachain.heima.network   (same host)
Paseo Substrate WSS URL:   wss://rpc.paseo-parachain.heima.network   (same host)
Paseo EVM chain ID:        2013  (= HEIMA_PARA_ID — mainnet's 212013
                                  prefixes the deployment year; paseo
                                  skips the prefix)
Paseo SS58 prefix:         131   (NOT the 31 used by mainnet, NOT the
                                  generic 42 — re-encode any pasted
                                  pubkey under prefix 131 for paseo,
                                  or use //Alice as a SURI directly)
Paseo faucet URL:          (still pending; sudo via Alice covers most
                            cases — see Q14 and §4.0 of the demo doc)
Paseo block explorer URL:  https://heima-paseo.statescan.io  (per the
                            existing profile pattern — verify once a
                            tx is on chain)
```

**Live verification (run 2026-05-18 from operator workstation):**

```
$ curl -sS -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
    https://rpc.paseo-parachain.heima.network
{"jsonrpc":"2.0","id":1,"result":"0x7dd"}        # 0x7dd = 2013 decimal

$ curl ... method:system_chain         → "Heima-paseo"
$ curl ... method:system_properties    → {"ss58Format":131,"tokenDecimals":18,"tokenSymbol":"HEI"}
$ curl ... method:eth_blockNumber      → 0x2c5556  (~2.9M blocks; live chain)
```

These values landed in `crates/agentkeys-core/chain-profiles/heima-paseo.json` in the 2026-05-18 commit. The `chain_id: 0` auto-detect sentinel was retired — now hard-pinned to `2013`.

### Q14. Heima Paseo sudo — confirm the sudoer + how to invoke

> **Wanted:** confirmation that `pallet_sudo` is in the Heima Paseo runtime, the sudo key is the well-known Substrate dev Alice (`0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d`), and a documented recipe for calling `sudo.sudo(...)` from a typical operator workstation.
>
> **Why we need to know:** the v2 stage-1 demo doc covers dev bring-up against Heima Paseo. We want to document a one-line "use Alice to pre-fund your deployer" recipe so operators don't have to chase faucet tokens for every dev iteration. We also want to know whether sudo can force-bump `K3EpochCounter` for K3-rotation testing.

**Kai / Heima dev answer:**
```
sudo pallet in paseo runtime:       [ ] yes / [ ] no
sudoer:                              [ ] well-known Alice (sr25519) / [ ] other: _______
sudoer's SS58 on Heima (prefix 31): _______
Sudo via Polkadot.js Apps works:    [ ] yes / [ ] no / [ ] yes but UI path: _______
Sudo via subkey/subxt CLI recipe:   _______
sudo wrapping pallet_ethereum.transact:  [ ] works / [ ] doesn't / [ ] untested
Will the sudo key rotate during the v2 dev cycle?  [ ] stable / [ ] may rotate at: _______
```

### Q15. Heima mainnet — confirm sudo is NOT in the runtime

> **Wanted:** explicit confirmation that Heima mainnet (chain ID 212013) has either (a) removed `pallet_sudo` from the runtime entirely, or (b) the sudo key has been transferred to a governance multisig + the multisig threshold is high enough to be operationally meaningful. Anything less is a single-key takeover risk against the chain that hosts our contracts.

**Kai / Heima dev answer:**
```
Heima mainnet sudo state:
  [ ] pallet_sudo removed from runtime (best)
  [ ] pallet_sudo retained, key is held by governance multisig
       — Multisig address: _______
       — Threshold / participants: _______
  [ ] pallet_sudo retained, key is held by a single account
       — Account: _______
       — Plan to remove / threshold: _______
Date sudo will be removed (if planned):  _______
```

---

## 4. The Reuse-Build-Block matrix (fill in during meeting)

| # | Requirement | Status | Scope (if build) | Owner | Notes |
|---|---|---|---|---|---|
| Q9 | **Revocation latency ≤ 1 block** | ✅🛠🚫 | | | **TOP PRIORITY** — only defense on stock sandbox |
| Q1 | Scoped child-session key minting | ✅🛠🚫 | | | |
| Q2 | Per-agent credential blob storage | ✅🛠🚫 | | | |
| Q3 | TEE-side policy enforcement on read | ✅🛠🚫 | | | |
| Q4 | First-login recoverable-identity policy | ✅🛠🚫 | | | |
| Q5 | x402 EVM wallet on account creation | ✅🛠🚫 | | | |
| Q6 | Multi-tenant `client_id` isolation | ✅🛠🚫 | | | |
| Q7 | Heima-native device-code (interp B) | ✅🛠🚫 | | | |
| Q8 | Audit event schema for AgentKeys | ✅🛠🚫 | | | |
| Q10 | TEE worker stability / rewrite status | ✅🛠🚫 | | | |
| Q11 | Open-source posture of AgentKeys API | ✅🛠🚫 | | | |
| Q12 | Rate limits, fees, testnet, mainnet | ✅🛠🚫 | | | |
| Q13 | Canonical Heima Paseo RPC URL (HTTP + WSS) | ✅ resolved | | Heima dev | 2026-05-18: `rpc.paseo-parachain.heima.network`, chain_id 2013, ss58 prefix 131, token HEI 18 decimals. Profile updated. |
| Q14 | Heima Paseo sudo — Alice as sudoer + invocation recipe | ✅🛠🚫 | | | added 2026-05-18; unblocks dev-bring-up pre-funding flow |
| Q15 | Heima mainnet — sudo removed OR governance-multisig-held | ✅🛠🚫 | | | added 2026-05-18; security gate on production chain |

Legend: **✅** = reuse as-is, **🛠** = build (small to medium delta), **🚫** = blocked or requires workaround.

---

## 5. Decisions that hinge on the answers

1. **Can the v0.1 migration ship as architected, or does the storage design collapse?**
   - Depends on: **Q1 + Q2 + Q3**
   - If all three are ✅ or 🛠 small build → ship as designed in `1-step-analysis.md`
   - If Q1 or Q2 is 🚫 or 🛠 large build → fall back to "one session key per agent, no master-child distinction at key level"; §3.2 becomes two-row instead of master+child
   - v0 storage design: daemon runs as `gem` UID, session at `/home/gem/.agentkeys/session` (mode 0600), no UID split (stock sandbox cannot support it)

2. **Is the demo's "instant revoke" moment live or recorded?**
   - Depends on: **Q9**
   - < 1 block → live on stage
   - Otherwise → screen-recorded with an "observed latency: ~Xs" label

3. **Is Demo 3 (provisioning-in-action with OpenRouter) buildable in time?**
   - Depends on: **Q5** (wallet creation flow exists) and **Q12** (fees low enough that a live USDC transfer during the demo is affordable)
   - Demo syntax: `agentkeys setup agent-A --services openrouter` (CLI) or agent calls `agentkeys.provision(service: "openrouter")` via MCP

4. **Does the meetup talk say "built on Heima" or "built on a fork of Heima" or "built on our own Heima instance"?**
   - Depends on: **Q6 + Q10**
   - Clean `client_id` registration on the main Heima instance → "built on Heima"
   - Fork required → "built on a forked Heima (here's why)"
   - Own instance → "built on Heima, running our own tee-worker (here's why)"

5. **Is the writeup claim "TEE-gated access control" or "daemon-gated access control"?**
   - Depends on: **Q3**
   - ✅ TEE-side enforcement → strong claim
   - ❌ client-side only → weaker but still honest claim

6. **Which testnet/mainnet does v0 run on?**
   - Depends on: **Q12**
   - Default: Paseo testnet for the demo

---

## 6. Minimum set of answers needed to unblock `2-step-analysis.md`

If we have to pick just three answers to walk out with, they're **Q9, Q1, Q2** — revocation latency (the only defense on stock sandbox) plus the two storage-architecture P0 questions. With those three locked, the rest is scope negotiation that can happen async.

**Second priority after the top three:** Q3 (TEE-side enforcement), Q5 (wallet flow), Q6 (multi-tenancy).

---

## 7. Post-meeting summary template

Fill this in immediately after the meeting while the context is fresh:

### 7.1 Can AgentKeys v0 ship as architected?
```
[ ] Yes, exactly as `1-step-analysis.md` describes
[ ] Yes, with these specific reductions: _______
[ ] No, fundamental rework needed in area: _______
[ ] Blocked until: _______
```

### 7.2 Critical-path work items (sorted by who does them)
- **Kai:**
- **AgentKeys team:**
- **Heima core team:**
- **Blocked on third party:**

### 7.3 Scope estimate for v0
- Total person-days of Heima-side work: _______
- Total person-days of AgentKeys-side work: _______
- Calendar weeks to v0 demo-ready: _______

### 7.4 What I learned that was NOT in the question list
- _______
- _______
- _______

### 7.5 Decisions recorded in the meeting (pin these)
- _______
- _______
- _______

### 7.6 Follow-up items
- [ ] _______
- [ ] _______
- [ ] _______

### 7.7 What gets updated in `1-step-analysis.md` and `2-step-analysis.md`
- _______
- _______

---

*Walk into the meeting with this file open. Walk out with §4 filled in and §7 drafted. Update `1-step-analysis.md` with any architecture changes that fall out of the answers.*
