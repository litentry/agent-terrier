How AgentKeys answers two questions that every credential manager has to answer:

1. **Serve:** when an agent asks for a credential, how does the system return the plaintext bytes?
2. **Audit:** how does the system record that the read happened, in a way that survives operator compromise?

The answers look simple in v0 (mock backend) and get much more interesting in v0.1 (Heima TEE). This page captures the design space, the patterns considered, and why the v0.1 target is **Pattern 4 (TEE-as-paymaster per-read sponsored audit)**.

> **Status:** v0 ships today with a synchronous SQLite audit insert (Pattern 0 equivalent). Pattern 4 is the **v0.1 target** — tracked in [#5](https://github.com/litentry/agentKeys/issues/5). Sections below that describe the ~50ms serve + ~6s audit-lag numbers are v0.1 numbers; the ~6s figure is the *audit-lag* (time from serve → on-chain confirmation), not the serve latency.

Companion doc: `[wiki/key-security.md](./key-security.md)` for the broader security architecture, two-tier storage model, and hardening plan.

---

## 1. The two flows, at a glance

### v0 (mock backend) — what runs today

```
agent calls MCP get_credential(service)
   ↓
daemon loads session from keychain (bearer token)
   ↓
daemon POSTs /credential/read to mock backend
   Authorization: Bearer <session-token>
   ↓
mock backend validates session, scope-checks agent_id
   ↓
mock backend writes audit_log row (SQLite INSERT)
   ↓
mock backend decrypts blob (in-process, no TEE)
   ↓
returns plaintext over HTTP
   ↓
daemon forwards to agent
```

**Serve:** HTTP + bearer token. ~50ms round trip on localhost.
**Audit:** SQLite `audit_log` table. Centralized, trust-the-operator, not tamper-evident.

This is a **deliberate v0 scope cut**. The mock backend is a placeholder that matches the shape of the v0.1 API but skips the cryptographic and tamper-evidence properties that would otherwise double Stage 1 scope.

### v0.1 (Heima TEE) — the target

```
agent calls MCP get_credential(service)
   ↓
daemon loads session private key from ~/.agentkeys/session (0600)
   ↓
daemon builds Heima extrinsic:
   call: read_credential(agent_id, service)
   nonce: <monotonic per session>
   ↓
daemon signs extrinsic with session private key (SR25519/Ed25519)
   ↓
daemon submits via wss to Heima TEE worker
   ↓
TEE verifies session signature against session pubkey
TEE checks scope, revocation list, rate limit
TEE decrypts blob (using TEE-held shielding key)
   ↓
TEE returns plaintext to daemon over the wss response
   ↓
   ──── at some point, an audit event is recorded on-chain ────
   ↓
daemon forwards plaintext to agent
```

**Serve:** session-key-signed extrinsic over wss. Target ~50ms end-to-end (same ballpark as v0).
**Audit:** on-chain event, signed, tamper-evident, queryable via block explorer + Subsquid indexer. Timing is the interesting part — see §3 below.

The "at some point" is where all the design work is. That's §3.

---

## 2. Why audit is load-bearing (and why v0.1 is fundamentally different from v0)

Per `[docs/spec/heima-cli-exploration.md:85](../spec/heima-cli-exploration.md)`:

> Every `read_secret` is an extrinsic signed by the agent's ephemeral session key. The block explorer shows: `agent_pubkey 0xabc… (MRENCLAVE 0xdef…, owner OmniAccount 0x123…) read secret S at block N`. **This is cryptographic, not log-shaped. Forging it requires breaking SR25519.**

And from the comparison table at `[docs/spec/heima-cli-exploration.md:105](../spec/heima-cli-exploration.md)`:


|               | 1Password CLI                           | Heima CLI                                                                              |
| ------------- | --------------------------------------- | -------------------------------------------------------------------------------------- |
| **Audit log** | Centralized DB (Events API), admin-only | Public chain extrinsics, cryptographically signed, queryable by anyone with capability |


This is AgentKeys's core differentiator. 1Password's audit log is a centralized database that 1Password itself maintains. If 1Password wants to hide a read, they can. If their DB is compromised, audit history can be silently rewritten. AgentKeys's design says: *every credential access is a public, signed, block-included event that the Heima validator set has agreed on, and no one — not even AgentKeys operators — can erase it.*

So the audit log isn't a side effect of the read flow. **It IS the security story.** Any design that weakens it needs a very good reason.

This is also why v0 and v0.1 look fundamentally different: v0's SQLite audit is a placeholder for API-shape testing. The real security property doesn't exist until v0.1 moves audit to on-chain events.

---

## 3. The latency problem

Heima block time is ~6 seconds. If the serve path waits for the audit extrinsic to get into a block before returning the credential, every first read gets a ~6s tax:

```
agent calls get_credential
  ↓ ~50ms    TEE decrypts
  ↓ ~6000ms  wait for audit extrinsic to confirm on-chain
  ↓ ~10ms    return plaintext
total: ~6 seconds
```

Compared to 1Password's sub-100ms Connect cache, this is terrible. `docs/spec/heima-cli-exploration.md:116` acknowledges it directly:

> **Latency:** every read is at minimum a chain RTT (~6s block time on Heima) unless we add an off-chain fast-path. 1Password is sub-100ms via Connect.

**~6s is fine for a one-off interactive command. It is a product killer for unattended agents.** Concrete failure modes:

- An agent task that fetches 30 credentials over 2 hours spends **3 full minutes** of wall-clock time just waiting for audit extrinsics to confirm
- A cron job that fetches one credential per minute spends **10% of every minute** waiting on chain
- A CI runner with a 10-second timeout on credential fetch simply fails
- Any MCP tool call that touches a credential becomes noticeably sluggish — it takes longer than the average LLM inference step, which is a UX tell that "something's wrong"

So the design work is all about: **how do you decouple serve latency from audit latency without giving up the audit property?**

---

## 4. Five patterns considered

### Pattern 0: Cold-first-read (the naive baseline)

```
read_credential
  ↓
CLI signs extrinsic with session key
  ↓
CLI submits via wss RPC
  ↓
──── ~6s ────  wait for block inclusion (THIS IS THE PROBLEM)
  ↓
TEE decrypts credential
  ↓
Extrinsic confirms, credential returned
```

**How it works:** the CLI submits the `read_credential` extrinsic and waits for it to be included in a block before the TEE releases the credential. Serve and audit are coupled on the critical path.

**Pros:** simplest possible design. Strongest audit guarantee — the credential is not visible to the caller until the audit event is final.

**Cons:** ~6s first-read latency. This is the thing every other pattern tries to fix.

**Verdict:** unworkable for the target workload. Included only as the baseline against which the other patterns are measured.

### Pattern 1: TEE-batched async audit

```
CLI signs read_credential extrinsic
  ↓ ~50ms
TEE verifies, decrypts, returns credential immediately
  ↓
   ──── decoupled hereafter ────
  ↓
TEE appends audit event to internal memfd_secret log
  ↓
every 10s OR every 32 events:
  TEE batches recent events into one extrinsic,
  submits via its own substrate account (funded from
  a top-up pool the master wallet deposits)
  ↓
Batched extrinsic confirms in the next block (~6s after submission)
```

**How it works:** TEE serves the credential direct (~50ms), records the audit event in an internal append-only log, and flushes batches of events to chain periodically.

**Pros:** first read is warm. Chain fees amortized 32x across batched events. Per-read events still visible on block explorer (as entries in the batched extrinsic).

**Cons:** up to ~10s audit staleness window — if the TEE is compromised between batch flushes, recent events could be lost or fabricated. Requires a new top-up pool primitive that the master wallet funds. TEE needs its own substrate account with fee-management code.

**Verdict:** good, but more complex than Pattern 4. Preserved here for reference.

### Pattern 2: Merkle-committed TEE log

```
CLI signs read_credential extrinsic
  ↓
TEE verifies, decrypts, returns credential immediately
  ↓
TEE appends event to internal Merkle log
  ↓
every N operations or N seconds:
  TEE commits the Merkle root of the log to chain (single 32-byte hash)
  ↓
To prove a read happened:
  ask the TEE for a Merkle inclusion proof against a committed root
```

**How it works:** TEE maintains a Merkle-structured append-only log. Only the root hash is committed to chain, periodically.

**Pros:** same fast serve as Pattern 1. Much cheaper on-chain footprint (one hash per batch instead of N events per batch). Cryptographically strong audit — the TEE can't retroactively drop reads without changing the root.

**Cons:** block explorer UX is significantly worse. You can't scroll and see `agent 0xabc… read op://openrouter` — you have to query the TEE for inclusion proofs and verify them locally. Subsquid indexing becomes harder because there are no per-read events to tail.

**Verdict:** preserved for consideration if on-chain fee costs become dominant at scale. Not the default because the block-explorer UX matters for "does this credential manager feel auditable to a non-technical operator."

### Pattern 3: CLI fire-and-forget async submission

```
CLI signs read_credential extrinsic
  ↓
TEE verifies, decrypts, returns credential + a signed "audit envelope"
  ↓
CLI uses the credential immediately
CLI asynchronously submits the audit envelope as its own extrinsic
  ↓
If CLI crashes before submission — audit event LOST
```

**How it works:** TEE hands back the credential plus a signed audit envelope. The CLI is responsible for submitting the envelope on-chain.

**Pros:** simplest TEE-side implementation. No batching, no Merkle log, no TEE-side substrate account.

**Cons:** **no guaranteed audit.** If the CLI crashes mid-read, the audit event never reaches the chain. Attackers could deliberately force CLI crashes after successful reads to suppress audit. This undermines the "trust the chain, not the client" design that was supposed to make the audit log tamper-evident in the first place.

**Verdict:** rejected. Moves the trust boundary back to the client, which is exactly the thing the whole architecture was trying to avoid.

### Pattern 4: TEE-as-paymaster per-read sponsored audit (CHOSEN)

```
CLI signs read_credential extrinsic with session key
  ↓
Submits to TEE over wss RPC
  ↓
TEE verifies session signature + scope (~10ms)
  ↓
TEE decrypts credential (~5ms)
  ↓
TEE returns credential to CLI               ← user sees this (~50ms total)
  ↓
   ──── decoupled hereafter ────
  ↓
TEE builds audit extrinsic, signs as        ← uses the user's REAL wallet key
the user's wallet (TEE-held per             ← no separate TEE operational account
pallet-bitacross pattern)                   ← on-chain event correctly attributed
  ↓
TEE submits via paymaster (Option A)        ← fees covered by AgentKeys operator pool
  ↓
──── ~6s ──── audit extrinsic confirms on-chain
  ↓
Audit event visible on block explorer
```

**How it works:** the meta-transaction pattern (EIP-2771 on Ethereum; custom signed extension on Substrate), applied specifically to audit submission.

The critical architectural move: **signer and payer are decoupled**. The audit extrinsic is *signed* by the user's wallet key (which Heima already holds in the TEE per `pallet-bitacross` pattern — see `[docs/spec/1-step-analysis.md:88](../spec/1-step-analysis.md)`) so the on-chain event correctly attributes the read to the user's wallet address. But the *fees* come from a paymaster — no user-side top-up pool, no new fee primitive at the user level, no error path when "the wallet ran out of chain gas."

**Pros:**

- First read is warm (~50ms)
- Every read is warm (~50ms) — no cold/warm distinction at all
- Audit events on chain within ~6s (one block, no batching staleness)
- Per-read events visible on block explorer, one-to-one with reads
- No user-facing fee management — paymaster handles it
- No new primitive required (works with standard Substrate fee handling via a custom signed extension)
- Simpler TEE-side code than Pattern 1 (no batcher, no flush timer, no pool account)
- Smaller audit loss window than Pattern 1 on TEE compromise (only in-flight extrinsics, not a 10s batch window)

**Cons:**

- 1 extrinsic per read instead of 1 per 32 reads — 32x more on-chain load
- Paymaster treasury is a shared resource that can be drained by abusive usage if not rate-limited
- Paymaster is an operational dependency — requires monitoring, alerting, top-up procedures
- Cost scales linearly with usage × reads/user, sustainable only via per-user fees

**Verdict:** **CHOSEN as the v0.1 default** for AgentKeys. The cons are manageable (the rate limit in §6 closes the DoS vector, and chain load at 1 extrinsic per read is fine for the expected workload of dozens-to-hundreds of reads per hour per agent). The pros cleanly solve the latency problem while preserving the tamper-evident public audit property.

---

## 5. Side-by-side comparison


| Property                                                | **0. Cold-first-read**       | **1. TEE-batched async**                | **2. Merkle-committed**                 | **3. CLI fire-and-forget**        | **4. TEE-as-paymaster (chosen)**                                   |
| ------------------------------------------------------- | ---------------------------- | --------------------------------------- | --------------------------------------- | --------------------------------- | ------------------------------------------------------------------ |
| **First read latency**                                  | ~6s                          | ~50ms                                   | ~50ms                                   | ~50ms                             | ~50ms                                                              |
| **Warm read latency**                                   | ~50ms                        | ~50ms                                   | ~50ms                                   | ~50ms                             | ~50ms                                                              |
| **Audit on-chain latency**                              | Synchronous (0s)             | Up to ~10s (batch interval)             | Up to ~10s (commit interval)            | Best-effort (client-dependent)    | ~6s (next block)                                                   |
| **Audit loss window on TEE compromise**                 | 0s                           | ~10s                                    | ~10s (but cryptographically detectable) | Unbounded (client-dependent)      | Seconds (only in-flight extrinsics)                                |
| **Per-read events on block explorer**                   | Yes (one extrinsic per read) | Yes (batched into fewer extrinsics)     | No (only root hashes)                   | Yes (one per read)                | Yes (one extrinsic per read)                                       |
| **Chain fees per read**                                 | 1 extrinsic                  | 1/32 extrinsic                          | ~0 (one hash per batch)                 | 1 extrinsic                       | 1 extrinsic                                                        |
| **User-facing fee model**                               | Chain fees charged to user   | Top-up pool primitive required          | Top-up pool primitive required          | Chain fees charged to user        | Paymaster (no user-side fee)                                       |
| **Requires new Heima primitives**                       | None                         | Top-up pool pallet call                 | Merkle log pallet                       | None (but weak audit)             | Custom signed extension OR Option B free-call primitive            |
| **TEE code complexity**                                 | Simplest                     | Medium (batcher + timer + pool account) | Medium (Merkle log + inclusion proofs)  | Simplest                          | Medium (paymaster integration)                                     |
| **Client code complexity**                              | Simplest                     | Simplest                                | Simplest                                | Medium (async submission + retry) | Simplest                                                           |
| **Scales to high read volume**                          | Yes (but latency unusable)   | Yes (batching amortizes)                | Yes (commits amortize)                  | Yes                               | Yes if rate-limited                                                |
| **Preserves "compromise is detectable" audit property** | Yes                          | Yes (bounded 10s gap)                   | Yes (cryptographically)                 | No (client trust hole)            | Yes (bounded 6s gap)                                               |
| **Works with existing Heima runtime**                   | Yes                          | Yes (but requires new pallet call)      | Requires new pallet                     | Yes                               | Yes via custom signed extension; better with new runtime primitive |


---

## 6. Why Pattern 4 wins (the full argument)

For AgentKeys's specific constraints:

### Constraint 1: First read must be fast

Non-negotiable. Cold-first-read is out. The four remaining patterns all achieve this.

### Constraint 2: Audit must be tamper-evident and publicly verifiable

- Pattern 3 (CLI fire-and-forget) fails this. The audit property depends on client diligence, which is the opposite of what "tamper-evident" means.
- Patterns 1, 2, 4 all preserve tamper-evidence with bounded staleness windows.

### Constraint 3: Per-read events must be visible on block explorer

- Pattern 2 (Merkle-committed) fails this. Operators want to scroll a block explorer and see `agent 0xabc… read op://openrouter at block N` — they don't want to file Merkle inclusion proofs. This is a UX requirement, not a cryptography requirement.
- Patterns 1, 4 preserve per-read visibility.

### Constraint 4: No user-side fee management

- Pattern 1 (TEE-batched async) requires users to fund a top-up pool for the TEE's audit account. That's a new user-facing primitive to explain, monitor, and support.
- Pattern 4 uses a paymaster and moves fee management to the operator. Users never see "your audit pool is low — please top up."

### Constraint 5: Minimal new Heima primitives

- Pattern 1 requires a new `deposit_audit_pool` / `withdraw_audit_pool` pallet call.
- Pattern 2 requires a new Merkle log pallet.
- Pattern 4 can ship with a custom signed extension on top of standard Substrate fee handling — no new pallet code required. (An even cleaner implementation using a free-call primitive is filed as Option B for future reconsideration.)

### Scoring


| Constraint                   | 1   | 2   | 3   | 4   |
| ---------------------------- | --- | --- | --- | --- |
| Fast first read              | ✅   | ✅   | ✅   | ✅   |
| Tamper-evident audit         | ✅   | ✅   | ❌   | ✅   |
| Per-read explorer visibility | ✅   | ❌   | ✅   | ✅   |
| No user-side fee management  | ❌   | ❌   | ✅   | ✅   |
| Minimal new primitives       | ❌   | ❌   | ✅   | ✅   |


**Pattern 4 is the only pattern that satisfies all five constraints.**

---

## 7. Who pays the paymaster?

Pattern 4 requires a fee-paying entity that isn't the user. Three options were considered for the v0.1 default:

### Option A — AgentKeys operators subsidize (CHOSEN)

AgentKeys deploys a Substrate account funded from operator treasury. The paymaster pays all audit fees from this account.

- **Pros:** ships today with no Heima runtime changes. Matches the hosted-service pricing model. Easy to operate, audit, and bill for.
- **Cons:** cost grows linearly with usage × reads/user. Sustainable only via per-user fees at deployment time. The operator account is a shared resource that must be rate-limited to prevent abuse.
- **Risk mitigation:** the TEE-side rate limit (see §8 and [issue #4](https://github.com/litentry/agentKeys/issues/4)) caps per-session reads at 100/minute by default, bounding the worst-case fee burn per user.

### Option B — Heima protocol subsidizes via "free calls" (FILED)

Runtime adds a new primitive: TEE-originated audit extrinsics consume no fees. Cost is borne by validators as part of base chain operation.

- **Pros:** most architecturally elegant. Zero per-read cost to anyone. No treasury to fund, no fee-management code.
- **Cons:** blocked on Heima runtime changes. Requires a new pallet primitive for free TEE-originated calls. Cannot ship in v0.1 without coordination with Kai on the runtime side.
- **Status:** filed for reconsideration once Kai confirms feasibility. Tracked in `[docs/spec/heima-open-questions.md](../spec/heima-open-questions.md)`.

### Option C — User wallet pays from its existing USDC balance (FILED)

The TEE signs the audit extrinsic with the user's wallet key, and fees are debited from the wallet's existing USDC balance (the same balance that holds x402 funds).

- **Pros:** self-scaling, fair, no new treasury. No operator subsidy needed.
- **Cons:** mixes "wallet pays gas" with "wallet is user's identity" roles. Creates confusing error UX when the wallet balance runs low ("audit submission failed — please top up your wallet" is a bad error message in the middle of a read).
- **Status:** filed as a potential opt-in for self-hosted deployments where users prefer to pay their own audit fees directly. Not the default because of the UX problem.

### Why Option A for v0.1

The chosen option (A) minimizes Heima-side work and matches the hosted-AgentKeys business model. Options B and C remain open for future reconsideration as the product matures. See `[docs/archived/development-stages-v2-2026-04.md](../archived/development-stages-v2-2026-04.md)` Stage 9 for the full decision record.

---

## 8. Abuse defense: TEE-side per-session rate limit

Pattern 4's paymaster-funded model is vulnerable to DoS without upstream rate limiting. An abusive session could call `read_credential` thousands of times per second, each call generating one subsidized audit extrinsic, draining the treasury in minutes.

The rate limit lives at the **credential-read layer**, not the audit-submission layer, so it defends everything downstream simultaneously:

```
read_credential request arrives
  ↓
TEE checks rate limit BEFORE doing any work
  ↓ rejected   ↓ accepted
  return       serve credential + submit audit
  error
```

If you can't do 10,000 reads/second, you can't cause 10,000 audit submissions/second, and you can't drain the paymaster 10,000 fees/second, and you can't exfiltrate credentials 10,000 times/second. Three threats collapse to one rate check.

**Policy:**

- **Default:** 100 reads per minute per session
- **Algorithm:** token bucket, linearly refilled at `rate_limit / 60` tokens/second, starts full
- **Configurable:** each session can be created with a custom `read_rate_limit` up to a hard cap (e.g., 10,000/min)
- **Structured error on excess:** `{ "code": "rate_limit_exceeded", "retry_after_secs": <integer> }` so agents can back off and retry
- **Audited:** every rate-limit rejection emits its own audit event so abusive patterns are visible in `agentkeys usage`

**Rate limit is a prerequisite for Pattern 4 to safely deploy.** Do not merge Pattern 4 without it.

Full design: [issue #4](https://github.com/litentry/agentKeys/issues/4).

---

## 9. Deferred decisions

From the Stage 9 notes in `[docs/archived/development-stages-v2-2026-04.md](../archived/development-stages-v2-2026-04.md)`, three things need explicit design work before Pattern 4 implementation starts:

### 9.1 Cross-pattern mixing: `--sync-audit` opt-out

Some users (regulated industries, compliance-sensitive deployments) may want the strong synchronous-audit guarantee of cold-first-read for specific critical operations, accepting the ~6s latency. Should the CLI offer a `--sync-audit` flag that forces cold-first-read semantics?

- **Leaning yes.** The implementation is trivial (just don't return the credential until the extrinsic confirms), and it lets the user explicitly trade latency for guarantee on a per-call basis.
- **Decision deferred** until v0.1 implementation begins. Not a blocker.

### 9.2 Paymaster DoS protection beyond rate limiting

The per-session rate limit (100 reads/minute default) bounds the per-session fee burn. Should there also be a per-user audit-fee budget cap — "wallet 0x123 has burned $5 of paymaster gas today, further reads are blocked until tomorrow"?

- **Leaning yes for hosted AgentKeys.** Operators need an upper bound on per-user cost to make pricing predictable.
- **Leaning no for self-hosted.** Self-hosted operators set their own policies; they don't need AgentKeys to impose one.
- **Decision deferred** until ops tooling lands.

### 9.3 Audit submission failure handling

What happens when the paymaster fails to submit an audit extrinsic? (Chain halted, paymaster out of funds, network issue, TEE crash before submission, etc.)

Four options:

1. **TEE holds a pending-audit queue with retry + backoff.** Audit events wait in TEE memory until they can be submitted. Survives transient network issues. Vulnerable to TEE crash (queue lost).
2. **TEE circuit-breaks further reads** from affected sessions until the queue drains. Strongest durability — no read happens unless its audit is guaranteed deliverable. But creates availability coupling between audit submission health and read serving.
3. **TEE logs failures locally and flushes later.** Audit events stored in TEE-internal append-only log, flushed when the path recovers. Survives transient issues. Vulnerable to permanent TEE compromise.
4. **TEE submits a failure marker extrinsic** (cheap, only one field) instead of the full audit event. The failure marker says "audit for read X failed, investigate." Recovers the audit property as "we can at least see that something was attempted."

Each has different durability-availability tradeoffs. **Decision deferred** until Pattern 4 implementation begins. Needs its own design doc.

---

## 10. Implementation status

### v0 (mock backend) — shipping

- ✅ Stage 1: mock backend with `POST /session/create`, `POST /credential/read`, bearer-token auth
- ✅ Stage 1: SQLite `audit_log` table, `audit_log` rows written by `read_credential` handler
- ✅ Stage 1: `query_audit` endpoint serving `agentkeys usage`
- ✅ Stage 2: CLI `cmd_read`, `cmd_run`, `cmd_usage` using `CredentialBackend::read_credential` and `query_audit`
- ✅ Stage 3: daemon MCP tool `agentkeys.get_credential` proxies to backend

### v0 → v0.1 migration — planned

- ⏳ **Rate limit ([issue #4](https://github.com/litentry/agentKeys/issues/4))** — must land in v0 mock backend as well as v0.1 TEE, prerequisite for Pattern 4
- ⏳ **Pattern 4 ([issue #5](https://github.com/litentry/agentKeys/issues/5))** — TEE-side paymaster integration, decoupled serve/audit code path, failure handling strategy (deferred decisions above)
- ⏳ **Stage 9 design decisions** captured in `[docs/archived/development-stages-v2-2026-04.md](../archived/development-stages-v2-2026-04.md)` as a holding pen until v0.1 migration work begins

### v0.2+ (future)

- ⏳ **Option B (Heima free calls)** — requires runtime coordination with Kai, filed for reconsideration once that conversation happens
- ⏳ **Option C (user wallet pays)** — opt-in mode for self-hosted deployments
- ⏳ `**--sync-audit` opt-out flag** — per-call latency/guarantee tradeoff

---

## 11. Quick-reference: latency budget

Expected wall-clock latency for a single credential read, under each pattern:


| Pattern                          | 50th percentile | 99th percentile | Dominant cost          |
| -------------------------------- | --------------- | --------------- | ---------------------- |
| **0. Cold-first-read**           | ~6s             | ~12s            | Block inclusion time   |
| **1. TEE-batched async**         | ~50ms           | ~100ms          | TEE decrypt + response |
| **2. Merkle-committed**          | ~50ms           | ~100ms          | TEE decrypt + response |
| **3. CLI fire-and-forget**       | ~50ms           | ~100ms          | TEE decrypt + response |
| **4. TEE-as-paymaster (chosen)** | ~50ms           | ~100ms          | TEE decrypt + response |


The ~50ms target assumes Heima TEE is co-located with the daemon's network reach (same region / same wss endpoint). Remote-region latency adds 20-100ms of network RTT on top, which is irreducible at the architecture level.

**Pattern 4's audit lag** (the time between serving the credential and the audit event appearing on chain) is ~6s at the 50th percentile, bounded by Heima block time. The user doesn't perceive this lag directly — it's only visible when querying `agentkeys usage` within the first ~10s after a read.

---

## 12. References

### Spec documents

- `[docs/spec/tech-brief.md](../spec/tech-brief.md)` — v0 / v0.1 split, TEE shielding key model
- `[docs/spec/1-step-analysis.md](../spec/1-step-analysis.md)` — auth layer design, `pallet-bitacross` pattern for TEE-held wallet keys
- `[docs/spec/heima-cli-exploration.md](../spec/heima-cli-exploration.md)` — audit-as-extrinsic design (line 85), latency acknowledgement (line 116)
- `[docs/spec/heima-open-questions.md](../spec/heima-open-questions.md)` — open questions for Kai including paymaster feasibility
- `[docs/archived/development-stages-v2-2026-04.md](../archived/development-stages-v2-2026-04.md)` — Stage 9 design decisions for Pattern 4, Option A fee funding, rate limit rationale
- `[wiki/key-security.md](./key-security.md)` — companion doc on the broader security architecture

### Source

- `crates/agentkeys-cli/src/lib.rs` — `cmd_read`, `cmd_run`, `cmd_usage`
- `crates/agentkeys-core/src/backend.rs` — `CredentialBackend` trait (abstracts over v0 and v0.1 backends)
- `crates/agentkeys-core/src/mock_client.rs` — v0 mock HTTP client implementation
- `crates/agentkeys-mock-server/src/handlers/credential.rs` — v0 mock audit log write sites
- `crates/agentkeys-mock-server/src/handlers/session.rs` — v0 mock session creation

### Issues

- [#3](https://github.com/litentry/agentKeys/issues/3) — Stage 8: Production hardening (daemon memory hygiene + CLI defensive features)
- [#4](https://github.com/litentry/agentKeys/issues/4) — Stage 8 / v0.1: TEE-side per-session read rate limit (abuse defense)
- [#5](https://github.com/litentry/agentKeys/issues/5) — v0.1: Pattern 4 audit submission (TEE-as-paymaster per-read sponsored audit)

