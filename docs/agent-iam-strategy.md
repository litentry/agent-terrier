# AgentKeys strategic direction — Agent IAM for the AI device era

**Status**: Strategic anchor (revised 2026-05-24). Captures the strategic framing that emerged from a multi-round discussion: original Agent IAM proposal → independent analysis → ChatGPT critique with four architecture corrections → this synthesis.

**Purpose**: be the source of truth for "what AgentKeys is, what it isn't, and what we ship next." Future planning, positioning, and scope decisions reference this doc.

**Companion docs**:
- [`ai-hardware-companion-office-hours.md`](./research/ai-hardware-companion-office-hours.md) — original wedge brainstorm (positioning is updated by this doc)
- [`xiaozhi-hermes-architecture.md`](./research/xiaozhi-hermes-architecture.md), [`volcano-ark-mcp-integration.md`](./research/volcano-ark-mcp-integration.md), [`tuya-vs-xiaozhi.md`](./research/tuya-vs-xiaozhi.md) — tactical adapter architectures (unchanged by this doc)
- [issue #103 plan](./plan/issue-103-aiosandbox-hermes-esp32-demo.md) — Phase 1 execution (scope is updated by this doc)

---

## 1. TL;DR

> AgentKeys is the **Agent IAM and memory control plane** for a future where users have many AI devices, many agents, and many LLMs, but still need one trusted way to manage what those systems can know, access, and do.

We stay infrastructure. We do not become a task-execution agent. We integrate with Hermes, OpenClaw, Claude Code, Doubao agents, vendor-specific runtimes — we provide them with identity, memory, permissions, capabilities, and audit. They do the work; we control the authority to do the work.

Three-layer positioning, told to three audiences:

| Layer | Audience | Pitch |
|---|---|---|
| **AI Device Account** | Consumer / vendor BD | "Your AI memory follows you safely across devices. Parents control what devices can know and do." |
| **Agent IAM** | Investor / CTO / CISO / partner | "Identity, permissions, capabilities, audit for AI agents — the IAM layer for the AI device era." |
| **Trust Substrate** | Compliance / regulator / Web3 partner | "Tamper-evident permission history + cryptographic device/agent identity attestation + on-chain anchoring." |

Cap-token machinery, signer, memory/cred/audit workers, per-actor isolation, and HDKD identity are already shipped via Stage 7+. What's net-new is the MCP server wrapper, the parent-control web UI, vendor onboarding, and the three-act demo storyboard.

---

## 2. What we accept from the Agent IAM proposal

These ideas survived independent analysis and ChatGPT critique. They are committed strategic direction.

### 2.1 Task Host vs Authority Host distinction

Hermes, OpenClaw, Claude Code, Codex, Doubao agents, vendor-specific runtimes = **Task Execution Hosts**. They reason, plan, retry, execute, and complete tasks.

AgentKeys = **Authority Host**. We manage identity, device registry, agent registry, memory namespaces, credential broker, capability token issuance, policy engine, delegation chains, approval workflows, audit logs, revocation, budget controls.

The distinction has the same shape as "OS vs application" or "AWS IAM vs the EC2 instance running your workload." Both are valuable, both are needed, they don't compete because they sit at different layers. **Authority must be neutral by construction** — no specialized runtime can credibly play this role without giving up their own walled garden. That neutrality is our structural moat.

### 2.2 Agent IAM as the technical category

"Key management for agents" is too narrow (1Password + Vault eat it). "Memory MCP server" is too narrow (Mem0 / Zep / Letta eat it). "Agent IAM" is the right size:

- *Who is this agent?*
- *Which device is it running on?*
- *Acting for which user?*
- *Can it access which memory?*
- *Can it use which credential?*
- *Can it delegate?*
- *Can it spend?*
- *Can it be revoked?*
- *Can it be audited?*

This is a $20B+ comparable market with deep mental models (Okta, Auth0, AWS IAM, Ping). Extending into the AI agent substrate is a category-creation move with the same buyer logic.

### 2.3 MCP is an integration surface, not the product identity

MCP is the protocol vendor LLMs use to call our tools. Important. But also: SDKs, OAuth-style flows, device APIs, runtime adapters, policy APIs are all eventually-needed surfaces. **We sequence**: MCP first (open standard, broad reach), Python + TypeScript SDKs second, OAuth-style flows third, the rest later.

The product identity is "Agent IAM" — not "an MCP server."

**Addendum (2026-05-28)**: the MCP server delivers IAM *tools*. Turning a tool into an IAM *guarantee* (a check the LLM cannot skip) requires a non-LLM enforcement layer — either lifecycle **hooks** in the Task Host runtime (primary, [#133](https://github.com/litentry/agentKeys/issues/133)) or an OpenAI-compatible **proxy** for hosts without hooks (fallback, Phase 3b). See §3.6 for the IAM-tool-vs-IAM-guarantee distinction and the hooks-first / proxy-fallback decision.

### 2.4 Zero orchestration in v1 — hard line

The proposal said *"AgentKeys can optionally provide lightweight orchestration."* That's a slippery slope. Once we ship even lightweight orchestration, vendors will ask for more. Each ask is reasonable; the sum is mission creep that turns us into "another agent runtime" — exactly the position the Task Host vs Authority Host distinction exists to prevent.

**Policy**: zero orchestration in v1, documented explicitly. If a vendor needs orchestration, they pick a runtime (Hermes, OpenClaw, their own). We provide the authority layer around it.

### 2.5 Deploy → grow → standardize sequencing

Standards work (MCP extensions for IAM-grade auth headers, OAuth-for-Agents, W3C/IETF engagement) is the right long-term direction. But standards adoption requires deployed reference implementations, vendor partners, and credibility we don't yet have.

Sequence: ship working code → grow vendor adoption → THEN propose specs. Not the reverse.

### 2.6 Three-act demo direction over memory-only demo

Single-act memory injection reads as "smart toy." Three acts read as "Agent IAM." See §4 for the revised Phase 1 demo.

### 2.7 The mobile-OS permission model is the product's spine (added 2026-05-31)

The clearest mental model for AgentKeys — for the parent buying a toy, for the vendor integrating it, for the engineer building it — is the **mobile-OS app-permission system**. Everyone already understands it: you install an app, it asks for the permissions it needs at first launch, you grant or deny each one, the OS enforces those grants at the syscall boundary (the app physically cannot reach your camera if you said no), and you can revoke any permission later in Settings.

AgentKeys is the same model, one layer up — for AI agents instead of mobile apps:

| Mobile OS (iOS / Android) | AgentKeys | Mechanism in our stack |
|---|---|---|
| Install an app | Onboard a new agent | `agentkeys agent create` → `agentkeys wire <runtime>` (§3.7) |
| First-launch permission prompt | Master's grant ceremony | K11 WebAuthn assertion on the master device (arch §10.7) |
| Permission categories (Camera, Location, Contacts, Mic) | Capability categories | Memory namespaces (§3.5) × services × bounds |
| Grant / deny per permission | Per-category grant | `AgentKeysScope.Scope` written on chain (arch §16.1) |
| "Allow once" / "While using" / precise-vs-approximate | Bounded grants | read-only memory; payment ≤ ¥50; specific IoT devices |
| OS enforces at the syscall boundary (app can't bypass) | **Hook enforces at the tool-call boundary** | PreToolUse hook → `permission.check` (§3.6, arch §22d) — the IAM *guarantee*, not the *tool* |
| Runtime re-prompt for a sensitive action | `permission.check` → `ask_parent` verdict | deterministic policy engine escalates |
| Revoke a permission in Settings | Parent revokes in the web UI | `cap.revoke` / `revoke_scope_with_webauthn` — the Act-3 demo |
| Per-app sandbox | Per-actor isolation | four-layer per-actor invariants (CLAUDE.md) |
| App Store review before distribution | Vendor onboarding / device pairing | arch §22c.4 |

**Why this is the spine, not just an analogy:**

1. **It tells the consumer what they're buying without saying "IAM."** Per §3.4's dual-narrative rule, a parent buying an AI toy doesn't want "Agent IAM." They want "the toy asks me before it can spend money or read the family calendar — the same way apps ask before using my camera." The mobile-OS model is the consumer pitch, already pre-installed in everyone's head.

2. **It explains why hooks (not just MCP tools) are non-negotiable.** §3.6's IAM-tool-vs-IAM-guarantee distinction *is* the mobile-OS distinction between (a) an app *politely calling* a "may I use the camera?" function it could choose to skip, and (b) the *OS intercepting* the camera syscall so the app cannot proceed without the grant. The `PreToolUse` hook is the syscall-interception layer. Without it, AgentKeys is a courtesy API; with it, AgentKeys is the OS.

3. **It makes the onboarding ceremony the product moment.** Mobile OS made "the permission prompt at first launch" the defining trust interaction of the smartphone era. AgentKeys' equivalent — the master being prompted, on their own device with biometric presence, to grant a freshly-onboarded agent its capabilities — is the moment the user feels in control. The grant ceremony (arch §10.7) is where Phase-1's demo "surprise" (§3.7) actually lands.

**Permission categories — the consumer-facing vocabulary (v0):**

| Consumer label | Maps to | Typical grant for a kids' AI toy |
|---|---|---|
| 出行记忆 Travel memory | `namespace=travel`, read | ✅ read |
| 健康记忆 Health memory | `namespace=personal` (health subset), read | ❌ none |
| 关系记忆 Relationship memory | `namespace=family`, read | ⚠️ read, parent-toggled |
| 工作记忆 Work memory | `namespace=work` | ❌ none |
| 支付能力 Payment | `service=payment`, `max_per_call` | ✅ ≤ ¥50/call, ≤ ¥200/day |
| 家居控制 IoT control | `service=iot`, device allow-list | ⚠️ specific devices only |
| 凭证访问 Credential access | `service=cred-store`, per-service | ❌ none |

Each category is a `(service, namespace, operation, bound)` tuple. The existing primitives already carry every field — services in `Scope.services`, namespaces in the cap-token's `namespaces_allowed`, bounds in `Scope.max_per_call`. What v0 lacks — and what the mobile-OS model demands — is presenting them as **per-category toggles in one onboarding screen**, with each toggle bound to its own structured grant. That extension is recorded conservatively (additive, no v0 contract change) in arch §10.7.

**You confirm; you don't configure — the AI recommends the scopes.** A parent shouldn't face a blank toggle grid. At onboarding the AI proposes a *recommended* scope set — derived from the agent's role (the classifier, #207), the master's saved policy (global config, #201), and a safe default preset — and the master just reviews, edits, and approves it with one biometric tap. It's the app-manifest, inverted: instead of the agent declaring the permissions it wants, AgentKeys *infers* the manifest and asks you to confirm. The AI recommends; **only the master's K11 assertion grants** — the recommendation authorizes nothing on its own.

**The recommendation sharpens with use; it never loosens on its own.** An optional 2–3 question setup ("who is this for?") and, over time, the master's own grant/deny history make each next agent's recommendation smarter — held in the master's audited config, advisory-only. It ratchets toward caution: sensitive categories (health, payment, credentials) keep asking every time even after past grants, and high-impact learned defaults are periodically re-confirmed. No learned preference ever widens a live scope without a fresh K11 grant. (Mechanism in arch §10.7.)

---

## 3. Four corrections that reshape architecture commitments

These are the ChatGPT-surfaced corrections to the original proposal. They sharpen what we promise vs what we deliver.

### 3.1 Revocation: immediate online, bounded offline

**Wrong commitment**: *"real-time revocation, no propagation delay."*

That's accurate only when every action passes through an online AgentKeys permission check. Real AI device scenarios include local caches, short-lived capability tokens, offline mode, weak network, device sleep/wake, edge gateways.

**Correct commitment**:

> **Online revocation is immediate. Cached/offline capabilities are bounded by short TTL and revocation-list refresh on next online interaction.**

The honest security model:

| Action class | Enforcement | Latency to revoke |
|---|---|---|
| High-risk (payment, credential write, send-email) | Always online permission check + fresh cap-token mint per call | Immediate on revocation |
| Low-risk (memory read of a non-sensitive namespace) | Short-lived cached cap (1-5 min TTL) | At most cap-TTL |
| Offline mode | Deny sensitive actions by default; allow safe reads from cached memory | Sensitive actions blocked entirely |

This is also better engineering: forcing every memory read through online check kills voice UX latency. Layered enforcement = right answer.

For the demo: show the high-risk path with immediate revocation (the dramatic moment), explain the layered model in the runbook.

### 3.2 Audit: real-time off-chain feed + batched on-chain anchor

**Wrong commitment**: *"audit row appears on-chain in real-time"* (would contradict batched anchoring + cost real gas + tie us to one chain).

**Correct commitment**:

> **Off-chain audit feed is real-time, shown in the parent-control web UI. On-chain audit anchor is a batched 2-minute Merkle root posted to the audit chain (chain-agnostic — modern fast-finality chains with cheap gas make sub-block batching viable), shown on the chain's block explorer as tamper-evidence proof.**

Two-tier audit:

| Tier | What | Where shown | Latency | Purpose |
|---|---|---|---|---|
| Off-chain feed | Every authority event (cap mint, permission check, memory read, credential fetch, revocation) | Parent-control web UI + AgentKeys API | Real-time (~100ms) | UX, monitoring, dispute resolution |
| On-chain anchor | Merkle root of off-chain events for a 2-min window | Configured chain's block explorer | 2 min | Tamper-evidence, cryptographic proof, regulatory export |

Demo language: *"The parent sees the audit event instantly in the app. The cryptographic audit batch is anchored on-chain for tamper-evidence within ~2 minutes — verifiable on the block explorer."*

The block explorer is **trust proof, not real-time UX**. Parent-control web UI is the experience surface. Chain choice is a deployment config (per arch.md the current backend is the operator-chosen substrate; the strategy doc stays chain-agnostic on positioning).

### 3.3 Delegation: schema/preview in v1, not active

Delegation is genuinely complex: parent agent, child agent, scope narrowing, TTL, revocation inheritance, audit chain, approval gates, liability.

**Correct scope for v1**:

| Status | Tools |
|---|---|
| **Implemented + active in v1** | `agentkeys.identity.whoami`, `agentkeys.memory.get`, `agentkeys.memory.put`, `agentkeys.permission.check`, `agentkeys.cap.mint`, `agentkeys.cap.revoke`, `agentkeys.audit.append` |
| **Documented but NOT active in v1** | `agentkeys.delegation.grant`, `agentkeys.delegation.revoke`, `agentkeys.approval.request` (schema only, returns `not_implemented_in_v1`) |

The reason to document-but-not-ship: delegation is a future capability the architecture must accommodate, but shipping a half-baked version risks vendors building on assumptions we'll have to break. Schema-only signals "this is coming" without locking in details we'll change.

### 3.4 Dual narrative — separate consumer pitch from B2B pitch

**Wrong commitment**: leading with "Agent IAM" in consumer contexts.

Agent IAM is correct for B2B / investor / partner / CTO audiences. It's sharp, well-categorized, defensible. But "Agent IAM" to a parent buying an AI toy on Tmall reads as enterprise jargon. They don't care about IAM; they care about whether the toy is safe for their kid.

**Two faces, one product**:

- **Consumer-facing brand and copy**: *"Control what your AI devices can remember, access, and do."* or *"Your AI memory follows you safely across devices."* — practical, benefit-led, parent-friendly. Brand candidates from earlier discussion: `scoped.ai`, `leash.ai`, `bonded.ai`. Don't say "IAM" in any consumer surface.
- **B2B / investor / technical**: *"AgentKeys is the Agent IAM and memory control plane for the AI device economy."* — category-defining, moat-articulating, comparable-anchoring.
- **Regulator / compliance**: *"Tamper-evident audit + cryptographic device identity + scoped capability tokens for AI device interactions."* — Trust Substrate framing.

Three audiences, three pitches, one product. Don't conflate.

### 3.5 Memory namespace model (early-phase, composes with the 4-type taxonomy)

The existing AgentKeys memory design ([`docs/plan/agentkeys-memory-design.md`](./plan/agentkeys-memory-design.md), committed on `main` as `53ccc9f`) defines four STRUCTURAL types — `profile` (single CAS-mutable file), `procedural` (append + occasional rewrite), `semantic` (one S3 object per ULID), `episodic` (date-prefixed per ULID). These are how memory is STORED on the per-actor S3 prefix.

For Agent IAM, we add an ORTHOGONAL semantic dimension: **namespaces**. These are how memory is SCOPED for permission and discovery. Namespaces compose with structural types — a memory item belongs to one namespace AND one structural type.

**Composition example** (Kevin owns a MagicLick + FoloToy):
```
Memory item: { type: "semantic", namespace: "travel", line: "Kevin asked about Chengdu customs clearance" }
Memory item: { type: "profile",  namespace: "personal", line: "Lives in Shanghai, allergic to peanuts" }
Memory item: { type: "episodic", namespace: "family", line: "Anniversary dinner reservation 2026-06-15" }
```

The MagicLick's cap-token grants `namespaces_allowed: ["travel"]`. It can read the first item, NOT the second or third. The toy's reply to *"where am I going this weekend?"* references Chengdu (travel) but never reveals the peanut allergy (personal) or the anniversary (family).

**Why this composes cleanly with the existing memory design**:

- The 4-type S3 key derivation in [memory-design §3.2a](./plan/agentkeys-memory-design.md) is unchanged. No new path components in v0. (S3 layout: `bots/<actor>/memory/{profile.json.enc, procedural.jsonl.enc, semantic/<ulid>.enc, episodic/<date>/<ulid>.enc}` — exactly as designed.)
- Namespaces live in the wire-format metadata + line envelope, NOT in the S3 key derivation. The memory worker filters at retrieval time.
- Cap-tokens add a `namespaces_allowed: ["personal", "travel"]` claim. The worker enforces the filter deterministically (no LLM, no fuzzy matching — string-set membership check).
- Future evolution: if scale / perf demands a path-prefixed namespace layout for cheap S3 LIST per namespace, migration is well-defined (rewrite per-actor under `bots/<actor>/memory/<namespace>/{...}` paths); cap-tokens already speak the namespace language at that point.

**v0 default namespaces** (keep the list small — 4):

| Namespace | Purpose | Typical writer | Typical reader |
|---|---|---|---|
| `personal` | User's own profile, preferences, health, history | Any device the user owns | Trusted personal devices |
| `family` | Family-context memory (spouse, kids, shared events, household) | Vetted family-aware devices | Family-context apps |
| `work` | Work projects, contacts, deadlines, work travel | Work-context apps + devices | Work-context apps + devices |
| `travel` | Trip planning, location context, near-term itinerary | Travel-context apps + devices | Travel-context apps + toys/wearables |

A device's cap-token scopes which namespaces it can read AND write. The MagicLick demo Act 1 (Permissioned Memory) shows the toy with `cap = {namespaces_allowed: ["travel"]}` — reads ONLY `travel`, sees nothing in `personal` / `family` / `work` even though they exist for the same actor.

**What we explicitly defer** (not in v0):

- Path-prefixed namespace layout (no S3 layout changes; namespaces stay metadata-only)
- Per-namespace embedding indexes (v0 uses the existing global index per memory-design §5)
- Cross-namespace memory sharing rules beyond cap-token consent toggles
- Dynamic / user-defined namespaces (v0 uses the 4 defaults; user-defined lands Phase 4 with the ACL-maturity work)
- `kids`, `device`, `temp` namespaces from the original Agent IAM proposal — `kids` folds into `family` for v0 (split when per-namespace ACL granularity matures in Phase 4); `device` and `temp` are out of scope as user-visible concepts

**Future namespace evolution** (Phase 3-4):
- Phase 3: add `device` namespace for device-local memory that doesn't sync cross-vendor
- Phase 4: split `kids` out of `family` once per-namespace ACL granularity is mature
- Phase 4: add `temp` namespace with TTL semantics for auto-expiring task memory
- Phase 4: user-defined custom namespaces via parent-control UI

**arch.md compatibility check** (no contradictions found, verified 2026-05-24):

- ✅ Memory data_class binding ([arch.md §17.5](./arch.md)) unchanged — namespaces are inside the data_class, not parallel to it
- ✅ Per-actor isolation via PrincipalTag ([arch.md §17](./arch.md)) unchanged — namespaces are inside the actor's prefix
- ✅ Cap-token format extensible — adding `namespaces_allowed` is additive (existing cap verifier ignores unknown fields gracefully per its design)
- ✅ Memory worker never calls an LLM (memory-design §1 invariant 1) — namespace filter is deterministic string-set membership, no inference
- ✅ K3 epoch rotation ([arch.md §16](./arch.md), memory-design §8.3) unchanged — namespaces are envelope metadata, not part of the keying material
- ✅ Architecture-as-source-of-truth (AGENTS.md policy) — once v0 namespaces ship, arch.md §17 gets an additive paragraph + memory-design §3 adds the namespace field to the wire format. No conflicting canonical names introduced.

### 3.6 IAM tool vs IAM guarantee — and how AgentKeys delivers each

Added 2026-05-28 to crystallize the distinction that drives the Phase 3 architecture choice.

**Terminology** (full reference: [`docs/wiki/agent-iam-guarantee-glossary.md`](./wiki/agent-iam-guarantee-glossary.md)):

| | Definition | Whether the check runs is decided by... | Failure mode |
|---|---|---|---|
| **IAM tool** | Function in the LLM's tool registry | The LLM (prompt + context + sampling) | LLM skips / is jailbroken → unauthorized action proceeds |
| **IAM guarantee** | Non-LLM gate in the execution path | The runtime (deterministically) | Gate fails closed; action cannot proceed without allow verdict |

The seven Phase-1 MCP tools in §4.2 are *tools* by themselves. They become *guarantees* only when a non-LLM enforcement layer wraps them.

**Decision (2026-05-28)**: AgentKeys delivers guarantees via two tracks, with explicit priority:

1. **Primary — Hooks** ([issue #133](https://github.com/litentry/agentKeys/issues/133)). Task Host runtimes (Claude Code, Codex, Hermes, OpenClaw) fire lifecycle hooks (`PreToolUse`, `PostToolUse`, `Stop`, `SessionEnd`) that synchronously invoke AgentKeys MCP tool calls. Verified 2026-05-28: Hermes's hook JSON shape is explicitly Claude-Code-compatible; Codex shape is similar but needs a thin shim; OpenClaw shares Hermes lineage. One reference script bundle ports across Tier-1 with low per-host adapter cost.
2. **Fallback — OpenAI-compatible proxy** (lower priority). For hosts without a hook surface (xiaozhi-server, vendor mobile chatbots, plain `openai.ChatCompletion` scripts), the LLM client's `base_url` points at an AgentKeys-hosted proxy that intercepts prompts + `tool_calls` + responses and enforces policy before forwarding upstream. Lower priority because: (a) §2.4 mission-creep risk — proxy lives in the path of every byte; (b) competitively crowded space (Vercel AI Gateway, Helicone, Portkey, OpenRouter, Cloudflare AI Gateway); (c) hooks cover the strategically-important Tier-1 hosts.

This decision sharpens §3.1's bounded-revocation commitment: *high-risk = always-online permission check + fresh cap-token mint per call* is only deliverable when there's a non-LLM gate. Hooks are the primary gate; proxy is the fallback gate for hooks-less hosts.

Phasing per §5: hooks land in Phase 3 (issue #133); proxy lands as Phase 3b (after #133 ships + at least one vendor pilot is on hooks).

### 3.7 Authority-provisioned config — `agentkeys wire <runtime>` (added 2026-05-28)

A corollary of §3.6: if hooks are the IAM-guarantee delivery mechanism, *who writes the hook configs into the user's runtime?* Two extremes:

- **Manual** — user runs both `agentkeys …` and the runtime's own setup wizard, then hand-edits `~/.<runtime>/config.<ext>` to register AgentKeys hooks. Two-wizard friction. Demo "surprise" effect diluted because the user already configured the runtime.
- **Automatic** — AgentKeys CLI writes the hook scripts + the `hooks:` block + the runtime's LLM-provider config in one idempotent command. One wizard. Strong demo surprise. Higher maintenance burden (track each runtime's config schema; nightly drift check needed).

**Decision (2026-05-28): hybrid.** Detailed in [`docs/plan/phase-1-fresh-user-wire-onboarding.md`](./plan/phase-1-fresh-user-wire-onboarding.md):

| AgentKeys owns | Runtime owns |
|---|---|
| IAM-gate config — the `hooks:` block, the AgentKeys hook scripts, first-use consent pre-approval | OAuth flows (Claude Code login, Codex login, Hermes Portal OAuth) — cannot be scripted remotely |
| LLM-provider config when the user provisioned the key via AgentKeys creds — `model.provider`, `model.base_url`, `model.api_key` come from the credential broker | Non-AgentKeys-managed config — model selection, region, custom prompts, runtime-specific knobs |
| Idempotent re-runs — `agentkeys wire <runtime>` is safe to invoke repeatedly; diffs current vs intended, writes only on drift | The runtime's own state — sessions, history, checkpoints, plugins |

The user-facing entry point is `agentkeys wire <runtime>` (one CLI command). The CLI dispatches to per-runtime adapters. Output follows the AGENTS.md idempotent-remote-setup convention (`ok proceeding / skip <reason> / fail <reason>` per step).

This pattern stays cleanly on §2.1 Authority Host side — AgentKeys is configuring an integration, not running the runtime. It also operationalizes §2.5 "deploy → grow → standardize": ship the hybrid for Hermes first (open-source, scriptable), expand to additional Task Hosts once a vendor pilot validates the approach.

---

## 4. Revised Phase 1 (ship in ~2 weeks)

### 4.1 Phase 1 goal

Prove in <5 minutes to a vendor that AgentKeys is Agent IAM, not chatbot infrastructure. Three behavioral properties visible end-to-end:

1. A device can read **permissioned** memory (not just memory)
2. Unauthorized actions are **deterministically denied** by policy, no LLM in the decision
3. A parent can **revoke** capabilities and the device complies immediately on the next online check

### 4.2 Phase 1 MCP server scope

Already-shipped backend (per AGENTS.md Stage 7+) provides the heavy lifting:

| Capability | Status in backend |
|---|---|
| Broker (cap-token issuance + verification) | ✅ exists (`agentkeys-broker-server`) |
| Signer (K3 / K10 HDKD per arch.md §17) | ✅ exists |
| Memory worker (per-actor S3 isolation) | ✅ exists (`agentkeys-worker-memory`, issue #92) |
| Credential worker (per-actor + per-data-class isolation) | ✅ exists (`agentkeys-worker-creds`, issue #90) |
| Audit worker (off-chain + on-chain anchoring) | ✅ exists (`agentkeys-worker-audit`) |
| OIDC issuer (federation) | ✅ exists |
| Per-actor + per-data-class isolation invariants | ✅ exists (issue #90) |

What we wrap with MCP for Phase 1 (~1 week of new code, thin layer over backend RPCs):

| MCP tool | Status in v1 |
|---|---|
| `agentkeys.identity.whoami(actor)` | **Active** |
| `agentkeys.memory.get(actor, namespace)` | **Active** |
| `agentkeys.memory.put(actor, namespace, content)` | **Active** |
| `agentkeys.permission.check(actor, scope)` | **Active** — deterministic policy engine, no LLM |
| `agentkeys.cap.mint(actor, op, params, ttl)` | **Active** — bounded TTL per §3.1 |
| `agentkeys.cap.revoke(cap_id)` | **Active** — immediate online; bounded offline |
| `agentkeys.audit.append(actor, event)` | **Active** — real-time off-chain feed; batched on-chain anchor per §3.2 |
| `agentkeys.delegation.grant(...)` | Documented schema only; returns `not_implemented_in_v1` per §3.3 |
| `agentkeys.delegation.revoke(...)` | Documented schema only |
| `agentkeys.approval.request(...)` | Documented schema only |

### 4.3 Phase 1 three-act demo storyboard

The demo runs on MagicLick 2.5 (xiaozhi-esp32 v1.9.4, unchanged) + stock xinnan-tech/xiaozhi-esp32-server with our MCP server registered in `mcp_server_settings.json` (per [`xiaozhi-hermes-architecture.md`](./research/xiaozhi-hermes-architecture.md) MCP-direct pivot).

**Act 1 — Permissioned Memory** (not "smart memory")

- User says: *"Where am I going this weekend?"*
- Doubao/Qwen LLM in xiaozhi-server decides it needs memory context
- LLM calls `agentkeys.memory.get(actor=O_kevin_001, namespace="travel")`
- AgentKeys MCP server verifies cap-token, scopes the read to the `travel` namespace only (NOT `profile`, NOT `family`, NOT `work`)
- Returns Chengdu trip context
- LLM synthesizes response via TTS
- **Headline**: the device reads ONLY the memory namespace it's allowed to read — not "it knows you"; "it knows what it's allowed to know about you"

**Act 2 — Deterministic Denial** (no LLM in the policy decision)

- User says: *"Order me hotpot for ¥600"*
- LLM decides this requires payment authority; calls `agentkeys.permission.check(actor=O_kevin_001, scope="payment.spend", amount_rmb=600)`
- AgentKeys deterministic policy engine returns `denied: daily_spend_cap_exceeded (cap=500, requested=600, period=daily)`
- LLM (because we trained the prompt this way) refuses politely and explains
- Audit row appears in parent-control web UI **instantly**; chain explorer anchor visible in next 2-min batch
- **Headline**: policy decides, not the LLM. Cap-bounded blast radius. Cryptographically auditable later.

**Act 3 — Online Revocation** (parent UI → device denies, bounded)

- Parent opens AgentKeys web UI (mobile-responsive, not native app)
- Taps "Revoke FoloToy payment access"
- AgentKeys revokes all cap-tokens scoped to `actor=O_kevin_folotoy_001, scope=payment.*`
- Demo: user attempts another spend → online permission check fails immediately → device refuses
- Audit row appears in real-time
- **Headline**: parent revokes; device complies on next online check. For high-risk actions = immediate. The runbook explains the layered TTL/cache model for offline scenarios (Act 3 doesn't need to demo this; just acknowledge it exists).

### 4.4 Phase 1 deliverables (non-implementation view)

| Deliverable | What it is | Why it matters |
|---|---|---|
| AgentKeys MCP server | 7 active tools wrapping existing backend RPCs | The integration surface vendors plug into |
| **`agentkeys wire <runtime>` CLI** (per §3.7) | Hybrid auto-provisioning — writes IAM-gate config + LLM-provider config into a Task Host's config files; idempotent; tracked in [`docs/plan/phase-1-fresh-user-wire-onboarding.md`](./plan/phase-1-fresh-user-wire-onboarding.md) | The user-facing entry point that turns "AgentKeys is wired into the runtime" into one command. The fresh-user "surprise" moment depends on this. |
| Hermes adapter (Phase 1.a) | First runtime adapter for `wire`; lives in `crates/agentkeys-cli/src/wire/adapters/hermes.rs` | Validates the hybrid auto-provisioning shape against a real Task Host inside aiosandbox |
| `agentkeys hook check / audit / memory-inject` CLI helpers | The thin wrappers the dropped hook scripts call — translate host stdin/stdout JSON to AgentKeys MCP tool calls | Makes the hook scripts trivial (single `exec` line); bug fixes ship in the AgentKeys binary, not in the user's filesystem |
| Parent-control web UI (mobile-responsive) | One page: actor list, scope toggles, revoke buttons, audit feed | The face of "Agent IAM" — without this, Act 3 isn't a demo |
| Two-tier audit | Real-time off-chain feed + 2-min batched on-chain anchor | §3.2 corrected architecture |
| Bounded revocation model | Immediate online; documented TTL/cache for offline | §3.1 corrected architecture |
| Three mock memory namespaces | `profile`, `travel`, `family` (only `travel` readable by demo actor) | Shows scoped access in Act 1 |
| Demo runbook + 15-min vendor pitch script | Operator can re-run; vendor sees value in 5 min via the 7-step fresh-user journey (install → curl-bootstrap → master approve → install Task Host → `agentkeys wire` → open runtime → memory-aware first turn) | Distribution-ready; the 7 steps are the runbook scaffold |

### 4.5 What Phase 1 does NOT include

Explicitly out of scope. Each is the right move later, premature now.

- **Orchestration of any kind** (§2.4 hard line)
- **Active delegation** (§3.3 — schema only)
- **Approval workflows** (deferred to Phase 2 — needs more design)
- **Native mobile app** (§5.3 — web UI sufficient for v0, native after pilot)
- **Real-time on-chain audit** (§3.2 corrected — batched only)
- **Volcano Ark MCP server registration** (Phase 2)
- **Tuya Cloud connector** (Phase 2)
- **Hermes / OpenClaw as MCP tools** (Phase 3)
- **OAuth-for-Agents** or any standards body engagement (Phase 4-5)
- **Vendor-specific MCP tools or vendor onboarding portal** (Phase 2)

---

## 5. Revised 12-month roadmap

Sequenced to test the Agent IAM thesis with minimum viable surface, then deepen the moat with each phase.

### Phase 0 — Done (Stage 7+)

Broker, signer, memory/cred/audit workers, OIDC issuer, per-actor + per-data-class isolation (issue #90), on-chain anchoring backend (currently Heima per arch.md, swappable per the chain-agnostic design), HDKD identity tree. All cap-token machinery shipped.

### Phase 1 — Agent IAM v0 demo (0-2 weeks)

Per §4. Goal: vendor understands AgentKeys ≠ chatbot in <5 minutes. MagicLick 2.5 + xiaozhi-server stock + AgentKeys MCP + parent web UI + three-act demo. Two-tier audit. Bounded revocation. Zero orchestration. Delegation as schema preview.

### Phase 2 — First vendor wedge + multi-rail reach (1-2 months)

Not "build many protocol surfaces." Land a real vendor pilot.

- Vendor configuration tools (vendor onboarding portal: tenant tokens, per-vendor billing, attributed devices)
- Device identity provisioning (vendor brings devices into AgentKeys, gets actor omnis back)
- Memory namespace template (for the "AI companion" product class: profile, work, family, child, travel, temp)
- Permission policy template (default-deny for sensitive scopes, sensible defaults for memory reads)
- Audit dashboard for parents (better UI than v0 web page; family-friendly)
- **Volcano Ark MCP marketplace registration** (open international signup per `tuya-vs-xiaozhi.md` Phase 3a)
- **Tuya Cloud Development connector** (Phase 2 from `tuya-vs-xiaozhi.md` original roadmap)

Goal: 1 paid vendor pilot signed at the $2-3/active-device/mo Basic tier from the office-hours pricing doc.

### Phase 3 — Runtime neutrality via hook reference configs (3-4 months) — primary IAM-guarantee track

Prove "the same authority layer works across different agent runtimes" by shipping the **hook reference configs** that turn AgentKeys MCP tools into IAM guarantees inside each Task Host. Per §3.6, this is the primary enforcement seam: hooks live in the Task Host runtime, fire deterministically around tool calls, and don't depend on LLM discretion.

Tracked under [issue #133](https://github.com/litentry/agentKeys/issues/133). Tier-1 hosts (verified 2026-05-28 — see [`docs/wiki/agent-iam-guarantee-glossary.md`](./wiki/agent-iam-guarantee-glossary.md) §3 for the full availability table):

- **Hermes** — `~/.hermes/config.yaml` `hooks:` block; explicitly Claude-Code-compatible JSON shape. The reference implementation.
- **Claude Code** — `~/.claude/settings.json`; richest hook surface (~24 events). Same shell scripts as Hermes (compatible JSON).
- **Codex (OpenAI)** — `~/.codex/hooks.json` / `~/.codex/config.toml`; same event names but needs a thin `decision ↔ continue` shim.
- **OpenClaw** — likely Hermes-compatible (Hermes ships `hermes claw` as the migration tool); verify with live install.
- **Hermes-MCP / OpenClaw-MCP / Doubao via Volcano Ark** — also exposed as MCP tools so other Task Hosts can call them; not the same as IAM enforcement.

Phase 3 deliverables ([#133](https://github.com/litentry/agentKeys/issues/133)):

- Reference hook configs for all Tier-1 hosts (one script bundle ports across with thin shims thanks to Hermes-Claude-Code shape parity)
- `agentkeys hook check` CLI helper (wraps host stdin/stdout JSON convention so operators just write `command: 'agentkeys hook check --scope payment.spend'`)
- Cap-mint pre-warming for sub-50ms p99 hook latency (mint a short-TTL cap on session start; per-call check is in-process)
- One end-to-end demo per runtime — same three-act storyboard (Permissioned Memory / Deterministic Denial / Online Revocation per §4.3) running on each Tier-1 host via hooks instead of LLM-invoked tools
- Reverse-direction stub — JSON shape AgentKeys fires when our server initiates a denial/revocation (impl deferred to M4)
- Python SDK + TypeScript SDK (for non-MCP integration paths)

Goal: 3+ runtimes integrated, demonstrably interoperable through the same AgentKeys backend with the same IAM-guarantee semantics.

### Phase 3b — OpenAI-compatible proxy fallback (post-Phase-3, lower priority)

For Tier-2 hosts without a hook surface — xiaozhi-server (verified 2026-05-28: only plugin/MCP tool registration), vendor mobile chatbots, plain `openai.ChatCompletion` scripts — ship an OpenAI-compatible proxy that the host's LLM client points at via `OPENAI_BASE_URL`. The proxy intercepts prompts + `tool_calls` + completions, enforces policy, logs audit, then forwards upstream.

**Sequenced lower than Phase 3** because:

1. §2.4 mission-creep risk — proxy lives in the path of every byte; vendors will ask for retry/fallback/caching that edges toward Task Host territory.
2. Competitive crowding — Vercel AI Gateway, Helicone, LangSmith, Portkey, OpenRouter, Cloudflare AI Gateway. We want this only when our authority position is established and we own the IAM-shaped differentiation.
3. Tier-1 hosts already cover the strategically-important runtimes; Phase 3 is broader-reach for less per-host cost.

**Gate to start Phase 3b**: #133 reference configs ship + at least one vendor pilot is live on the hooks path.

### Phase 4 — Capability + revocation depth (6 months)

Take the half-spec'd v1 schemas and ship the deep versions.

- **Delegation chains in production** (parent agent → child agent with scope narrowing, TTL inheritance, revocation cascade, audit chain)
- **Approval workflows** (high-risk actions push to parent app for one-tap approval before execution)
- **Policy versioning** (vendors deploy new policies; existing devices upgrade with audit trail)
- **Audit replay** (regulator-grade reconstruction of any agent's authority history)
- **Memory namespace ACL maturity** (cross-vendor consent ceremony in production, not demo)
- **Family / work / kids memory separation** (the consumer narrative made operational)

Goal: first enterprise customer (could be a regulated B2B brand-owner — toy maker selling to schools, health-data-adjacent device maker, etc.).

### Phase 5 — Standards + ecosystem (post-12-months)

Only if Phases 1-4 land with deployed reference implementations and 10+ vendor partners.

- Propose MCP extensions for IAM-grade auth headers (session keys, cap-token forwarding, audit-chain headers)
- OAuth-for-Agents specification engagement (likely IETF or W3C working group)
- Reference implementations for non-MCP runtimes (raw HTTP / gRPC clients for vendors that don't use MCP)
- Brand-owner partnerships: Tuya, Xiaomi (per `tuya-vs-xiaozhi.md` Phase 3c "deferred"), Alibaba Smart Home

Goal: become the reference implementation that every new agent runtime + IoT cloud integrates with by default.

---

## 6. Strategic risks worth tracking explicitly

### Risk 1 — Hyperscaler absorption

Anthropic, OpenAI, Tencent, ByteDance could each build their own "Agent IAM" natively. Likely path: limited to their own walled garden (Claude permissions in Claude's ecosystem only, etc.).

**Mitigation**: be the cross-platform layer they CANNOT credibly build (since each would only do their own walled garden). Race to neutral adoption across vendors before any one hyperscaler ships a closed equivalent that everyone defaults to.

### Risk 2 — Over-extension into orchestration

Vendor asks: "can you also handle X workflow?" → mission creep → we become "another agent runtime" → we lose Authority Host neutrality.

**Mitigation**: §2.4 hard line, documented in this doc, referenced in every product conversation. If a vendor needs orchestration, they pick a runtime; we provide the authority around it.

### Risk 3 — Weak consumer face

If AgentKeys is invisible to end-users (no app, no consumer brand), vendors can't justify the upgrade tier. The B2B sale alone doesn't sustain the model — vendor base fee ($2-3/device/mo) is thin; the $10/$20 consumer upgrade is where margin is. Without a consumer face, no consumer upgrades.

**Mitigation**: parent-control web UI is Phase 1. Mobile-responsive. Native mobile app is Phase 2 (only after the v0 web UI proves we know what the UX should be). Brand naming + consumer-facing landing page is Phase 1.5.

### Risk 4 — Pure neutrality = no adoption

Switzerland-grade neutrality without product-market traction = LDAP-grade obscurity. Standards bodies listen to deployed code, not pitches.

**Mitigation**: be the reference implementation everyone defaults to, not just a spec. Open-source the SDK + MCP server (already MIT-aligned with the broader ecosystem). Charge for hosting + premium features (consumer upgrade tier, vendor enterprise tier). Standards engagement only after 10+ vendor deployments.

### Risk 5 — Premature standards work

Engaging IETF / W3C / OpenAPI / MCP spec working groups before we have deployed reference implementations = looking like a vendor lobbying for spec changes that benefit our positioning. Bad optics, weak influence.

**Mitigation**: deploy → grow → propose. Standards work is post-12-months.

### Risk 6 — Memory eclipses authority in the narrative

If we lead every pitch with "memory portability," we get categorized as "Mem0 / Zep / Letta competitor" — and lose the IAM moat. Memory is one of many authority surfaces, not the headline.

**Mitigation**: every Phase 1 demo, deck, and one-pager leads with the three behaviors together (permissioned memory + deterministic denial + revocation). Memory alone is the smallest of the three. Authority is the category.

### Risk 7 — Privacy positioning trap

Privacy is a benefit, not a category. "Privacy product" is crowded (Brave, DuckDuckGo, Signal, etc.) and easy to commoditize. Authority is the category that produces privacy as one of its outputs.

**Mitigation**: never lead with "privacy." Lead with "control" (consumer narrative) or "authority" (B2B narrative). Privacy follows naturally and is a strong supporting benefit.

---

## 7. What this strategic anchor changes about existing docs

| Doc | Update needed |
|---|---|
| [`ai-hardware-companion-office-hours.md`](./research/ai-hardware-companion-office-hours.md) | Update positioning note at top to point at this strategy doc + add Agent IAM framing + three-narrative reality. Substance below the banner stays. |
| [`ai-hardware-companion-wedge.md`](./research/ai-hardware-companion-wedge.md) | Update positioning sections — sharper "Agent IAM" framing; keep market sizing + competitive analysis as-is. |
| [issue #103 plan](./plan/issue-103-aiosandbox-hermes-esp32-demo.md) | Pivot demo storyboard to the three-act IAM demo per §4.3. Add parent-control web UI deliverable. Note the four corrections (bounded revocation, two-tier audit, delegation-as-preview, zero orchestration). Implementation detail unchanged (cap-token machinery already exists). |
| [`xiaozhi-hermes-architecture.md`](./research/xiaozhi-hermes-architecture.md) | No change — MCP-direct pivot still correct. |
| [`volcano-ark-mcp-integration.md`](./research/volcano-ark-mcp-integration.md) | Minor: clarify Phase 2 timing per §5 above; tool inventory unchanged. |
| [`tuya-vs-xiaozhi.md`](./research/tuya-vs-xiaozhi.md) | No change — complement-not-compete framing still correct. |
| [`xiaozhi-hermes-risks.md`](./research/xiaozhi-hermes-risks.md) | No change — risk analysis still applies; many risks evaporate under MCP-direct. |

---

## 8. The one-sentence summary

> AgentKeys is the **user-owned authority layer for the AI device era** — Agent IAM to technical buyers, "your AI memory follows you safely" to consumers, tamper-evident trust substrate to regulators. We stay infrastructure; we never become an agent runtime; we work with Hermes / OpenClaw / Claude Code / Doubao / xiaozhi / any agent that needs identity, memory, permissions, capabilities, and audit. They do the work; we control the authority to do the work.

---

## 9. Sources + lineage

- **Original proposal**: pasted in chat 2026-05-24 — "AgentKeys Strategic Direction: Agent IAM for the AI Device Era." Captured §1-14 of the strategic framing.
- **Independent analysis (this AI)**: pushed back on consumer/B2B positioning tension, sequencing of multiple integration surfaces, standards timing, demo storyboard.
- **ChatGPT critique**: four architectural corrections (bounded revocation, two-tier audit, delegation-as-preview, dual-narrative) + the three-layer positioning framework (AI Device Account / Agent IAM / Trust Substrate).
- **This doc**: synthesis of all three. Source of truth for Agent IAM positioning + Phase 1 scope + roadmap. Future planning references this anchor.

Companion architectural research:
- [`ai-hardware-companion-wedge.md`](./research/ai-hardware-companion-wedge.md) — market + competitive landscape
- [`ai-hardware-companion-office-hours.md`](./research/ai-hardware-companion-office-hours.md) — wedge brainstorm + Approach D selection
- [`xiaozhi-esp32-magiclink.md`](./research/xiaozhi-esp32-magiclink.md) — hardware identification + Option 1 decision
- [`xiaozhi-hermes-architecture.md`](./research/xiaozhi-hermes-architecture.md) — MCP-direct architecture
- [`xiaozhi-hermes-risks.md`](./research/xiaozhi-hermes-risks.md) — risk verification
- [`volcano-ark-mcp-integration.md`](./research/volcano-ark-mcp-integration.md) — Volcano Ark MCP-server adapter
- [`tuya-vs-xiaozhi.md`](./research/tuya-vs-xiaozhi.md) — Tuya vs xiaozhi role comparison + Phase 3 feasibility
