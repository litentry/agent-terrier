# AgentKeys strategic direction — Agent IAM for the AI device era

**Status**: Strategic anchor (revised 2026-05-24; certified-stack and business-model update 2026-06-19). Captures the strategic framing that emerged from a multi-round discussion: original Agent IAM proposal → independent analysis → ChatGPT critique with four architecture corrections → the Volcano/ESP32 device platform review → this synthesis.

**Purpose**: be the source of truth for "what AgentKeys is, what it isn't, and what we ship next." Future planning, positioning, and scope decisions reference this doc.

**Companion docs**:
- [`arch.md`](./arch.md) — source of truth for shipped trust boundaries, key inventory, daemon role, backend wiring, and IAM-guarantee seams
- `plan/ai-device-platform.md` (operator-internal) — gate-first AI-device platform, de-phased around one platform with Volcano as default engine/substrate
- `plan/esp32-touch-agent-console.md` (operator-internal) — first certified-stack device plan and the AgentKeys-vs-Volcano component split
- `volcano/service.md` (operator-internal) — Volcano service inventory and open integration questions
- `research/on-device-memory-daemon-esp32.md` (operator-internal) — why the ESP32 stays a terminal and memory stays server-side/warm-cached for v0
- `ai-hardware-companion-office-hours.md` (operator-internal) — original wedge brainstorm (positioning is updated by this doc)
- `volcano-ark-mcp-integration.md` (operator-internal), `tuya-vs-xiaozhi.md` (operator-internal) — tactical adapter architectures (unchanged by this doc)
- [issue #103 plan](./archived/issue-103-aiosandbox-hermes-esp32-demo.md) — historical MCP/Hermes demo context (**archived**); superseded for Phase 1 by the certified Volcano device pilot. The xiaozhi/MagicLick device-chatbot research it relied on ([`xiaozhi-esp32-magiclink.md`](./archived/xiaozhi-esp32-magiclink.md), [`xiaozhi-hermes-architecture.md`](./archived/xiaozhi-hermes-architecture.md), [`xiaozhi-hermes-risks.md`](./archived/xiaozhi-hermes-risks.md)) is archived alongside it.

---

## 1. TL;DR

> AgentKeys is the **Agent IAM and memory control plane** for a future where users have many AI devices, many agents, and many LLMs, but still need one trusted way to manage what those systems can know, access, and do.

We stay infrastructure. We do not become a task-planning/execution agent. We integrate with Hermes, OpenClaw, Claude Code, Codex, Doubao, Volcano Ark, vendor-specific runtimes, and certified device stacks — we provide them with identity, memory, permissions, capabilities, and audit. They do the work; we control the authority to do the work.

The business model follows the same boundary: **bundle a certified underlying stack + AgentKeys premium**, without becoming a low-margin compute reseller. ASR/TTS/LLM/sandbox are COGS with quotas, overage pass-through/cost-plus, or BYO-cloud enterprise options. Margin and moat come from the control plane: identity, consent, memory ownership, deterministic policy, audit, revocation, portability, and the policy-intent classifier that turns natural-language requests into structured gates.

Three-layer positioning, told to three audiences:

| Layer | Audience | Pitch |
|---|---|---|
| **AI Device Account** | Consumer / vendor BD | "Your AI memory follows you safely across devices. Parents control what devices can know and do." |
| **Agent IAM** | Investor / CTO / CISO / partner | "Identity, permissions, capabilities, audit, and spend/memory control for AI agents — the IAM layer for the AI device era." |
| **Trust Substrate** | Compliance / regulator / Web3 partner | "Tamper-evident permission history + cryptographic device/agent identity attestation + on-chain anchoring." |

Cap-token machinery, signer, memory/cred/audit workers, per-actor isolation, HDKD identity, and the app/daemon trust core are already shipped or specified in `arch.md`. What's net-new strategically is the certified-stack adapter shape (Volcano first, others later), the in-path gate endpoint for device UX, billing/quota around bundled COGS, and the small policy-intent model tracked in [issue #322](https://github.com/litentry/agentKeys/issues/322).

---

## 2. What we accept from the Agent IAM proposal

These ideas survived independent analysis and ChatGPT critique. They are committed strategic direction.

### 2.1 Task Host vs Authority Host distinction

Hermes, OpenClaw, Claude Code, Codex, Doubao agents, vendor-specific runtimes = **Task Execution Hosts**. They reason, plan, retry, execute, and complete tasks.

Volcano, Ark/Doubao, AIO Sandbox, RTC, OpenViking, Alibaba, Baidu, Bedrock, and future local bridges = **Engine / execution substrate providers**. They provide voice transport, ASR/TTS, LLM calls, sandbox hosting, tool surfaces, or ranking. They are swappable behind adapters.

AgentKeys = **Authority Host**. We manage identity, device registry, agent registry, memory namespaces, credential broker, capability token issuance, policy engine, delegation chains, approval workflows, audit logs, revocation, budget controls.

The distinction has the same shape as "OS vs application" or "AWS IAM vs the EC2 instance running your workload." Both are valuable, both are needed, they don't compete because they sit at different layers. **Authority must be neutral by construction** — no specialized runtime can credibly play this role without giving up its own walled garden. That neutrality is our structural moat.

Certified-stack packaging does not collapse the boundary. When AgentKeys ships an Agent Task Host image, a CustomLLM endpoint, or hooks, those components exist only to put the gate in the execution path. They must not own task planning, retry policy, generic tool orchestration, or user-data custody beyond the authority primitives above. This matches `arch.md` §22c.5: the daemon stays a trust core; it does not become the agent runtime.

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

MCP is one protocol vendor LLMs use to call our tools. Important. But MCP is **reach**, not the consistency boundary. If an LLM may choose whether to call an MCP tool, the user does not have an IAM guarantee; they have a courtesy API.

The consistency boundary is a non-LLM gate in the execution path: hooks for hook-capable Task Hosts, a certified-stack in-path endpoint for device stacks, and worker-side re-verification before data access. This is exactly the `arch.md` §22d distinction between IAM tool and IAM guarantee.

We still use MCP where it is the best adapter: hosted MCP for broad reach, SDKs for embedded/vendor flows, OAuth-style flows for account linking, and certified-stack adapters for productized device stacks. The product identity is "Agent IAM" — not "an MCP server."

**Addendum (2026-05-28; refined 2026-06-19)**: the MCP server delivers IAM *tools*. Turning a tool into an IAM *guarantee* (a check the LLM cannot skip) requires a non-LLM enforcement layer — lifecycle **hooks** in the Task Host runtime (primary for local/runtime hosts, [#133](https://github.com/litentry/agentKeys/issues/133)) or a certified-stack **in-path endpoint** such as Volcano RTC CustomLLM for the device stack. The generic OpenAI-compatible proxy fallback was dropped 2026-06-19 (agent-first; see §3.6).

### 2.4 Zero task orchestration in v1 — hard line

The proposal said *"AgentKeys can optionally provide lightweight orchestration."* That's a slippery slope. Once we ship even lightweight orchestration, vendors will ask for more. Each ask is reasonable; the sum is mission creep that turns us into "another agent runtime" — exactly the position the Task Host vs Authority Host distinction exists to prevent.

**Policy**: zero task orchestration in v1, documented explicitly. If a vendor needs planning, retries, workflow graphs, tool scheduling, or autonomous execution, they pick a runtime (Hermes, OpenClaw, Volcano/AIO Sandbox, their own). We provide the authority layer around it.

Allowed in v1: narrow adapter code that makes the authority layer enforceable — hooks, `agentkeys wire`, a CustomLLM gate endpoint, broker-driven sandbox binding, cap prewarming, audit capture, and memory injection. These are not orchestration features; they are the consistency boundary.

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
| OS enforces at the syscall boundary (app can't bypass) | **Non-LLM gate enforces at the action boundary** | PreToolUse hook or certified-stack in-path endpoint → `permission.check` (§3.6, arch §22d) — the IAM *guarantee*, not the *tool* |
| Runtime re-prompt for a sensitive action | `permission.check` → `ask_parent` verdict | deterministic policy engine escalates |
| Revoke a permission in Settings | Parent revokes in the web UI | `cap.revoke` / `revoke_scope_with_webauthn` — the Act-3 demo |
| Per-app sandbox | Per-actor isolation | four-layer per-actor invariants (CLAUDE.md) |
| App Store review before distribution | Vendor onboarding / device pairing | arch §22c.4 |

**Why this is the spine, not just an analogy:**

1. **It tells the consumer what they're buying without saying "IAM."** Per §3.4's dual-narrative rule, a parent buying an AI toy doesn't want "Agent IAM." They want "the toy asks me before it can spend money or read the family calendar — the same way apps ask before using my camera." The mobile-OS model is the consumer pitch, already pre-installed in everyone's head.

2. **It explains why a non-LLM gate (not just MCP tools) is non-negotiable.** §3.6's IAM-tool-vs-IAM-guarantee distinction *is* the mobile-OS distinction between (a) an app *politely calling* a "may I use the camera?" function it could choose to skip, and (b) the *OS intercepting* the camera syscall so the app cannot proceed without the grant. `PreToolUse` hooks are the syscall-interception layer for hook-capable runtimes; a CustomLLM/in-path endpoint is the equivalent for certified device stacks. Without that gate, AgentKeys is a courtesy API; with it, AgentKeys is the OS.

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

### 2.8 Certified stacks, not a free-form component matrix

The right product posture is **certified stacks**: a small number of tested combinations where AgentKeys knows the latency, billing, auth, data-residency, and enforcement behavior end-to-end. Volcano/Ark is the first default stack because it can provide voice, LLM, sandbox host, agent tools, and memory ranking while AgentKeys keeps the sovereign gate. Alibaba, Baidu, local bridge, or global-cloud stacks can follow behind the same adapter contract.

We should not promise every user can independently swap ASR, TTS, LLM, sandbox, memory ranker, and hosting provider in arbitrary combinations. That sounds neutral but destroys performance responsibility and support quality. The platform is provider-neutral at the authority layer; the product experience ships as certified bundles.

### 2.9 Commercial model: stack bundle + AgentKeys premium

For consumer/device products, charge for the bundle users understand: device + voice/model/sandbox quota + AgentKeys control plane. Underlying services are COGS:

- **Free tier**: shared sandbox, capped model/voice budget, hibernate-to-zero, enough to prove value.
- **Paid consumer tier**: dedicated or warmer sandbox, higher voice/model quota, cross-device memory/control, premium audit/history.
- **Vendor tier**: per-active-device platform fee + usage pass-through/cost-plus, with revenue share where the vendor owns distribution.
- **Enterprise/BYO cloud**: customer brings Volcano/Alibaba/Baidu/AWS/local stack; AgentKeys sells the control plane, policy model, audit, and portability.

The strategic mistake is to compete on raw ASR/TTS/LLM/sandbox margin. The strategic moat is the authority layer that remains valuable when providers are swapped.

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

The existing AgentKeys memory design (`docs/plan/agentkeys-memory-design.md` (operator-internal), committed on `main` as `53ccc9f`) defines four STRUCTURAL types — `profile` (single CAS-mutable file), `procedural` (append + occasional rewrite), `semantic` (one S3 object per ULID), `episodic` (date-prefixed per ULID). These are how memory is STORED on the per-actor S3 prefix.

For Agent IAM, we add an ORTHOGONAL semantic dimension: **namespaces**. These are how memory is SCOPED for permission and discovery. Namespaces compose with structural types — a memory item belongs to one namespace AND one structural type.

**Composition example** (Kevin owns an ESP32 panel + FoloToy):
```
Memory item: { type: "semantic", namespace: "travel", line: "Kevin asked about Chengdu customs clearance" }
Memory item: { type: "profile",  namespace: "personal", line: "Lives in Shanghai, allergic to peanuts" }
Memory item: { type: "episodic", namespace: "family", line: "Anniversary dinner reservation 2026-06-15" }
```

The device's cap-token grants `namespaces_allowed: ["travel"]`. It can read the first item, NOT the second or third. The reply to *"where am I going this weekend?"* references Chengdu (travel) but never reveals the peanut allergy (personal) or the anniversary (family).

**Why this composes cleanly with the existing memory design**:

- The 4-type S3 key derivation in memory-design §3.2a (operator-internal) is unchanged. No new path components in v0. (S3 layout: `bots/<actor>/memory/{profile.json.enc, procedural.jsonl.enc, semantic/<ulid>.enc, episodic/<date>/<ulid>.enc}` — exactly as designed.)
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

A device's cap-token scopes which namespaces it can read AND write. The Phase-1 Permissioned Memory act shows the device with `cap = {namespaces_allowed: ["travel"]}` — reads ONLY `travel`, sees nothing in `personal` / `family` / `work` even though they exist for the same actor.

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

The tools in §4.2 are *tools* by themselves. They become *guarantees* only when a non-LLM enforcement layer wraps them.

**Decision (2026-05-28; refined 2026-06-19)**: AgentKeys delivers guarantees through **two agent-first non-LLM seams** (`arch.md` §22d), packaged by deployment shape:

1. **Primary for hook-capable Task Hosts — hooks** ([issue #133](https://github.com/litentry/agentKeys/issues/133)). Claude Code, Codex, Hermes, OpenClaw and similar runtimes fire lifecycle hooks (`PreToolUse`, `PostToolUse`, `Stop`, `SessionEnd`) that synchronously invoke AgentKeys checks. Verified 2026-05-28: Hermes's hook JSON shape is explicitly Claude-Code-compatible; Codex shape is similar but needs a thin shim; OpenClaw shares Hermes lineage. One reference script bundle ports across Tier-1 with low per-host adapter cost.
2. **Primary for certified device stacks — in-path endpoint**. Volcano RTC CustomLLM is the concrete first case: Volcano carries realtime voice, ASR/TTS, and the LLM substrate; our endpoint sits where the LLM turn is resolved and runs cap-check + memory-inject + audit before calling Doubao/Ark. The endpoint is in the agent's execution path by construction, so the gate cannot be skipped; it is a certified-stack seam we can validate end-to-end (latency, auth, billing) — **not** a generic gateway.

**Explicitly NOT a track — the generic OpenAI-compatible proxy.** An earlier revision kept a fallback that put an AgentKeys-hosted `base_url` in front of hooks-less hosts (vendor mobile chatbots, plain `openai.ChatCompletion` scripts). **Dropped 2026-06-19 — agent is the development direction.** A host earns an IAM guarantee by being an agent runtime (hooks) or a certified device stack (in-path endpoint); a bare chatbot/script with no agent loop is not a target, and we do not ship a generic LLM gateway. Rationale: (a) §2.4 mission-creep — a proxy in the path of every byte invites retry/fallback/caching asks that drift toward Task-Host territory; (b) crowded, undifferentiated space (Vercel AI Gateway, Helicone, Portkey, OpenRouter, Cloudflare AI Gateway); (c) hooks + certified stacks already cover the strategically-important paths, and reach for non-agent hosts is better served by SDK/MCP/direct adapter than by becoming a gateway business.

This decision sharpens §3.1's bounded-revocation commitment: *high-risk = always-online permission check + fresh cap-token mint per call* is only deliverable when there's a non-LLM gate — and both seams are non-LLM gates. Hooks are primary for runtimes that expose lifecycle hooks; the certified-stack in-path endpoint is primary for the Volcano device pilot.

Phasing per §5: the certified-stack in-path gate lands first for the device pilot; hooks remain the primary runtime-neutral path.

### 3.7 Authority-provisioned config — `agentkeys wire <runtime>` (added 2026-05-28)

A corollary of §3.6: if hooks are the IAM-guarantee delivery mechanism, *who writes the hook configs into the user's runtime?* Two extremes:

- **Manual** — user runs both `agentkeys …` and the runtime's own setup wizard, then hand-edits `~/.<runtime>/config.<ext>` to register AgentKeys hooks. Two-wizard friction. Demo "surprise" effect diluted because the user already configured the runtime.
- **Automatic** — AgentKeys CLI writes the hook scripts + the `hooks:` block + the runtime's LLM-provider config in one idempotent command. One wizard. Strong demo surprise. Higher maintenance burden (track each runtime's config schema; nightly drift check needed).

**Decision (2026-05-28): hybrid.** Detailed in `docs/plan/phase-1-fresh-user-wire-onboarding.md` (operator-internal):

| AgentKeys owns | Runtime owns |
|---|---|
| IAM-gate config — the `hooks:` block, the AgentKeys hook scripts, first-use consent pre-approval | OAuth flows (Claude Code login, Codex login, Hermes Portal OAuth) — cannot be scripted remotely |
| LLM-provider config when the user provisioned the key via AgentKeys creds — `model.provider`, `model.base_url`, `model.api_key` come from the credential broker | Non-AgentKeys-managed config — model selection, region, custom prompts, runtime-specific knobs |
| Idempotent re-runs — `agentkeys wire <runtime>` is safe to invoke repeatedly; diffs current vs intended, writes only on drift | The runtime's own state — sessions, history, checkpoints, plugins |

The user-facing entry point is `agentkeys wire <runtime>` (one CLI command). The CLI dispatches to per-runtime adapters. Output follows the AGENTS.md idempotent-remote-setup convention (`ok proceeding / skip <reason> / fail <reason>` per step).

This pattern stays cleanly on §2.1 Authority Host side — AgentKeys is configuring an integration, not running the runtime. It also operationalizes §2.5 "deploy → grow → standardize": ship the hybrid for Hermes first (open-source, scriptable), expand to additional Task Hosts once a vendor pilot validates the approach.

For certified device stacks, the analogous action is **broker-driven stack binding**, not `agentkeys wire`: LAN/QR pair the device, bind it to an actor, attach or spawn the right sandbox tier, install/activate the Agent Task Host image, and issue a scoped cap-token. This is adapter delivery. The authority model remains the same: master K11 grants, K10 proves the delegated caller, workers re-verify before data access.

### 3.8 Policy-intent classifier — model helps translate, gate decides

Natural-language requests need to be converted into a structured action intent before a deterministic gate can evaluate them. The right shape is a small policy-intent classifier, not an embedding-only solution:

- **Small model**: maps utterances/tool proposals into structured intent such as `{action, data_class, namespace, actor, resource, spend_amount, risk, confidence}`.
- **Embeddings**: support retrieval of relevant policy examples, user preferences, and similar past decisions. They do not replace intent classification.
- **Deterministic gate**: consumes the structured intent plus chain/config state and returns allow/deny/ask. The model never authorizes.
- **Deployment**: run the classifier stack-local — Volcano stack in China, Alibaba/Baidu stacks where used, local bridge when offline, US stack for global users — so latency and data residency do not force every request through our US servers.
- **Training factory**: use the US 8×H100 capacity for synthetic data generation, distillation, eval, red-team, and fine-tuning. Do not put China realtime inference on the US GPU path.

This work is tracked in [issue #322](https://github.com/litentry/agentKeys/issues/322). It is a moat because the classifier encodes the user-permission taxonomy across stacks, but it must remain advisory to the deterministic gate to preserve sovereignty and auditability.

---

## 4. Revised Phase 1 — certified Volcano device pilot

### 4.1 Phase 1 goal

Prove in <5 minutes to a vendor that AgentKeys is the gate/control plane for AI devices, not chatbot infrastructure and not a Volcano wrapper. The first certified stack is ESP32-S3-Touch-LCD-4B + Volcano RTC/Ark/Cloud Sandbox + AgentKeys gate. Three behavioral properties must be visible end-to-end:

1. A device can read **permissioned** memory (not just memory)
2. Unauthorized actions are **deterministically denied** by policy, no LLM in the decision
3. A parent can **revoke** capabilities and the device complies immediately on the next online check

### 4.2 Authority substrate + tool surface

Already-shipped or architecture-owned backend (per `arch.md`) provides the heavy lifting:

| Capability | Status in backend |
|---|---|
| Broker (cap-token issuance + verification) | ✅ exists (`agentkeys-broker-server`) |
| Signer (K3 / K10 HDKD per arch.md §17) | ✅ exists |
| Memory worker (per-actor S3 isolation) | ✅ exists (`agentkeys-worker-memory`, issue #92) |
| Credential worker (per-actor + per-data-class isolation) | ✅ exists (`agentkeys-worker-creds`, issue #90) |
| Audit worker (off-chain + on-chain anchoring) | ✅ exists (`agentkeys-worker-audit`) |
| OIDC issuer (federation) | ✅ exists |
| Per-actor + per-data-class isolation invariants | ✅ exists (issue #90) |

What we expose as tools/APIs for the gate layer:

| Tool/API | Status in v1 |
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

MCP remains one wrapper around this surface. The certified-stack path calls the same authority surface from an in-path endpoint rather than relying on the LLM to voluntarily call MCP.

### 4.3 Phase 1 three-act demo storyboard

The demo runs on ESP32-S3-Touch-LCD-4B + Volcano RTC CustomLLM + Doubao/Ark + AgentKeys in-path endpoint. Volcano carries realtime voice, ASR/TTS, LLM hosting, and sandbox substrate. AgentKeys owns pairing, cap-token scope, memory store, policy enforcement, audit, and the management view.

**Act 1 — Permissioned Memory** (not "smart memory")

- User says: *"Where am I going this weekend?"*
- Volcano RTC sends ASR text to the AgentKeys CustomLLM endpoint
- AgentKeys verifies the device/agent cap, loads only the `travel` namespace for `actor=O_kevin_001`, and optionally lets OpenViking rank **only the gate-authorized lines**
- AgentKeys calls Doubao/Ark with the authorized memory slice
- Volcano synthesizes the reply via TTS
- **Headline**: the device reads ONLY the memory namespace it's allowed to read — not "it knows you"; "it knows what it's allowed to know about you"

**Act 2 — Deterministic Denial** (no LLM in the policy decision)

- User says: *"Order me hotpot for ¥600"*
- Policy-intent classifier maps the request to structured intent: `payment.spend`, `amount_rmb=600`, `actor=O_kevin_001`
- AgentKeys deterministic policy engine returns `denied: daily_spend_cap_exceeded (cap=500, requested=600, period=daily)`
- The endpoint refuses before any payment tool or provider call can execute
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
| Certified Volcano stack adapter | ESP32-S3-Touch-LCD-4B + Volcano RTC CustomLLM + Ark/Doubao + Cloud Sandbox + AgentKeys gate | Proves the first full product stack without making Volcano the authority |
| CustomLLM agent endpoint | In-path turn handler: cap-check + memory-inject + policy-intent classify + audit → Doubao/Ark | Makes the gate deterministic and non-skippable for voice UX |
| Broker-driven device binding | LAN/QR pair → bind actor → attach/spawn sandbox tier → issue scoped cap-token | Turns onboarding into the authority ceremony, not a manual MCP setup |
| AgentKeys tool/API surface | 7 active authority tools over existing backend RPCs, callable via MCP or direct adapter | Keeps reach and consistency decoupled |
| Agent Task Host image + daemon sidecar | Narrow runtime package deployed inside the certified sandbox; daemon holds K10 only for the agent | Places enforcement near the agent without turning AgentKeys into a general runtime |
| Parent-control web UI / management view | Actor list, memory view, scope toggles, revoke buttons, audit feed | The consumer face of "control what your AI devices can remember/access/do" |
| Two-tier audit | Real-time off-chain feed + 2-min batched on-chain anchor | §3.2 corrected architecture |
| Bounded revocation model | Immediate online; documented TTL/cache for offline | §3.1 corrected architecture |
| Policy-intent classifier v0 | Small model or distilled classifier that emits structured intent for the deterministic gate | Shows how natural-language device requests become auditable policy decisions |
| Quota/billing guardrails | Free shared sandbox quota, paid dedicated/warm tier, overage pass-through/cost-plus | Prevents the Volcano integration from becoming low-margin unlimited compute resale |
| Demo runbook + 15-min vendor pitch script | Operator can re-run: pair device → approve scope → voice turn → denial → revoke → audit | Distribution-ready; the vendor sees the gate, not a chatbot |

### 4.5 What Phase 1 does NOT include

Explicitly out of scope. Each is the right move later, premature now.

- **Task orchestration of any kind** (§2.4 hard line)
- **Active delegation** (§3.3 — schema only)
- **Approval workflows** (deferred to Phase 2 — needs more design)
- **Spend execution** before single-use caps + mint-time budgeting ship (`plan/ai-device-platform.md` (operator-internal) §4)
- **Native mobile app** (§5.3 — web UI sufficient for v0, native after pilot)
- **Real-time on-chain audit** (§3.2 corrected — batched only)
- **Generic Volcano Ark marketplace listing** beyond the certified stack
- **Tuya Cloud connector / Alibaba / Baidu / local bridge** (after the first stack proves the adapter seam)
- **Hermes / OpenClaw as productized certified stacks** (runtime-neutral path after the device pilot)
- **OAuth-for-Agents** or any standards body engagement (Phase 4-5)
- **Vendor self-serve onboarding portal** (after one manually-supported pilot)

---

## 5. Revised 12-month roadmap

Sequenced to test the gate-first AI-device thesis with one certified stack, then deepen the moat without locking the authority layer to any provider.

### Phase 0 — Done (Stage 7+)

Broker, signer, memory/cred/audit workers, OIDC issuer, per-actor + per-data-class isolation (issue #90), on-chain anchoring backend (currently Heima per arch.md, swappable per the chain-agnostic design), HDKD identity tree. All cap-token machinery shipped.

### Phase 1 — Certified Volcano device v0 (0-2 weeks)

Per §4 and `plan/esp32-touch-agent-console.md` (operator-internal). Goal: vendor understands AgentKeys ≠ chatbot and ≠ Volcano wrapper in <5 minutes. ESP32-S3-Touch-LCD-4B + Volcano RTC CustomLLM + Ark/Doubao + AgentKeys gate endpoint + parent-control management view + three-act demo. Two-tier audit. Bounded revocation. Zero task orchestration. Delegation as schema preview.

### Phase 2 — Commercial pilot + bundle economics (1-2 months)

Not "build many protocol surfaces." Land a real vendor pilot with the economics visible.

- Vendor configuration tools: tenant tokens, attributed devices, per-vendor quotas, per-stack cost telemetry.
- Device identity provisioning: vendor brings devices into AgentKeys, gets actor omnis back, and binds them through the master K11 ceremony.
- Stack bundle pricing: free shared sandbox quota, paid dedicated/warm sandbox, overage pass-through/cost-plus, BYO-cloud enterprise escape hatch.
- Memory namespace template for AI companions: profile, work, family, child, travel, temp.
- Permission policy template: default-deny for sensitive scopes, sensible defaults for memory reads, spend disabled until prerequisites ship.
- Parent dashboard: family-friendly control, audit, memory view, and revoke.
- Volcano open questions closed: sandbox lifecycle API, OpenViking rank-only mode, CustomLLM auth/streaming/timeout contract.

Goal: 1 paid vendor pilot signed at the $2-3/active-device/mo Basic tier from the office-hours pricing doc.

### Phase 3 — Policy-intent model + runtime guarantees (2-4 months)

Deepen the moat that the first certified stack exposes: the same authority layer should work across runtimes, and natural-language requests should reliably become structured policy intents.

Policy-intent classifier track ([issue #322](https://github.com/litentry/agentKeys/issues/322)):

- Generate and curate request → structured-intent datasets for memory, device control, spend, credential access, audit, and delegation.
- Distill a small model that emits typed intent + risk + confidence; evaluate against adversarial prompt-injection and provenance attacks.
- Deploy stack-local: Volcano China, future Alibaba/Baidu stacks, local bridge, and global cloud stacks. US 8×H100 is the training/eval factory, not the China realtime path.
- Keep authority deterministic: classifier output is input to the gate; it never authorizes.

Runtime-guarantee track ([issue #133](https://github.com/litentry/agentKeys/issues/133)):

- **Hermes** — `~/.hermes/config.yaml` `hooks:` block; explicitly Claude-Code-compatible JSON shape. The reference implementation.
- **Claude Code** — `~/.claude/settings.json`; richest hook surface (~24 events). Same shell scripts as Hermes (compatible JSON).
- **Codex (OpenAI)** — `~/.codex/hooks.json` / `~/.codex/config.toml`; same event names but needs a thin `decision ↔ continue` shim.
- **OpenClaw** — likely Hermes-compatible (Hermes ships `hermes claw` as the migration tool); verify with live install.
- **Hermes-MCP / OpenClaw-MCP / Doubao via Volcano Ark** — also exposed as MCP tools so other Task Hosts can call them; not the same as IAM enforcement.

Guarantee deliverables:

- Reference hook configs for all Tier-1 hosts (one script bundle ports across with thin shims thanks to Hermes-Claude-Code shape parity)
- `agentkeys hook check` CLI helper (wraps host stdin/stdout JSON convention so operators just write `command: 'agentkeys hook check --scope payment.spend'`)
- Cap-mint pre-warming for sub-50ms p99 hook latency (mint a short-TTL cap on session start; per-call check is in-process)
- One end-to-end demo per runtime — same three-act storyboard (Permissioned Memory / Deterministic Denial / Online Revocation per §4.3) running on each Tier-1 host via hooks instead of LLM-invoked tools
- Reverse-direction stub — JSON shape AgentKeys fires when our server initiates a denial/revocation (impl deferred to M4)
- Python SDK + TypeScript SDK (for non-MCP integration paths)

Goal: one certified stack + 3+ runtimes integrated, demonstrably interoperable through the same AgentKeys backend with the same IAM-guarantee semantics and classifier schema.

### Phase 3b — ~~Generic OpenAI-compatible proxy fallback~~ — DROPPED (2026-06-19)

**Removed from the roadmap.** The generic OpenAI-compatible proxy (an AgentKeys-hosted `OPENAI_BASE_URL` in front of hooks-less hosts — xiaozhi-server, vendor mobile chatbots, plain `openai.ChatCompletion` scripts) is no longer a planned track. Agent is the development direction: a host earns an IAM guarantee by being an agent runtime (hooks, Phase 3) or a certified device stack (in-path endpoint, Phase 1) — not by routing a bare chatbot through a gateway. Non-agent hosts are reached via SDK / MCP / direct adapter, never a generic LLM gateway. See §3.6 ("Explicitly NOT a track") for the full rationale (mission-creep, crowded space, weak differentiation).

### Phase 4 — Multi-stack neutrality + capability depth (6-9 months)

Take the half-spec'd v1 schemas and ship the deep versions.

- **Delegation chains in production** (parent agent → child agent with scope narrowing, TTL inheritance, revocation cascade, audit chain)
- **Approval workflows** (high-risk actions push to parent app for one-tap approval before execution)
- **Policy versioning** (vendors deploy new policies; existing devices upgrade with audit trail)
- **Audit replay** (regulator-grade reconstruction of any agent's authority history)
- **Memory namespace ACL maturity** (cross-vendor consent ceremony in production, not demo)
- **Family / work / kids memory separation** (the consumer narrative made operational)
- **Second certified stack** (Alibaba/Baidu/local bridge/global cloud) behind the same adapter contract, proving Volcano is default, not lock-in

Goal: first enterprise customer (could be a regulated B2B brand-owner — toy maker selling to schools, health-data-adjacent device maker, etc.).

### Phase 5 — Standards + ecosystem (post-12-months)

Only if Phases 1-4 land with deployed reference implementations and 10+ vendor partners.

- Propose MCP extensions for IAM-grade auth headers (session keys, cap-token forwarding, audit-chain headers)
- OAuth-for-Agents specification engagement (likely IETF or W3C working group)
- Reference implementations for non-MCP runtimes (raw HTTP / gRPC clients for vendors that don't use MCP)
- Brand-owner partnerships: Tuya, Xiaomi (per `tuya-vs-xiaozhi.md` Phase 3c "deferred"), Alibaba Smart Home, Baidu/Xiaodu-style device ecosystems

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

### Risk 8 — Margin compression from bundled compute

If the product is perceived as "Volcano plus markup," ASR/TTS/LLM/sandbox costs eat the business and customers pressure us into commodity resale pricing.

**Mitigation**: price and message the bundle around the AgentKeys control plane, not raw tokens/minutes. Include explicit quotas, overage pass-through/cost-plus, and BYO-cloud enterprise options. Track COGS per stack from the first pilot.

### Risk 9 — Provider lock-in through the first certified stack

Volcano is the right first stack, but if identity, memory store, policy, or audit leak into Volcano-specific services, the "swappable engine" promise becomes marketing copy.

**Mitigation**: keep the red-line rows from `plan/esp32-touch-agent-console.md` (operator-internal) §3 owned by AgentKeys: identity, caps, canonical memory store, deterministic enforcement, audit, pairing, and control plane. Volcano can rank authorized lines and run the engine/substrate; it cannot become the authority.

### Risk 10 — Component-matrix sprawl

Provider-neutral architecture can tempt us into supporting arbitrary ASR × TTS × LLM × sandbox × ranking combinations before any one stack is excellent. That creates latency bugs, support burden, and weak product taste.

**Mitigation**: certify stacks, not components. Start with Volcano; add one second stack only after the first paid pilot proves the adapter contract. Keep arbitrary component swapping as an internal architecture property, not a user-facing promise.

### Risk 11 — Classifier becomes a hidden authority

The policy-intent classifier is necessary for UX, but if teams treat its output as authorization, the system becomes probabilistic at the trust boundary.

**Mitigation**: classifier output is typed evidence only. The deterministic gate decides from structured intent + chain/config state. Low confidence or high-risk classifications become `ask`, not `allow`. Every decision logs classifier version, input hash, structured intent, and deterministic policy result.

### Risk 12 — Cross-region latency and data residency

If China device requests depend on a classifier or policy service hosted only on our US infrastructure, latency and data-sovereignty constraints will break the product.

**Mitigation**: deploy the small classifier stack-local. Use the US 8×H100 servers for training, distillation, eval, and red-team. Realtime inference runs in the customer's stack/region: Volcano China, Alibaba/Baidu China, local bridge, or global cloud.

---

## 7. What this strategic anchor changes about existing docs

| Doc | Update needed |
|---|---|
| [`arch.md`](./arch.md) | Source-of-truth reference checked against this revision: daemon remains trust core (§22c.5), MCP remains a tool/reach surface (§22c.1-§22c.2), and IAM guarantees require a non-LLM gate — hooks or the certified-stack in-path endpoint — plus worker verify (§22d, §17.5; the generic proxy fallback was dropped 2026-06-19). This change updates cross-references only; the component inventory changes when the certified-stack adapter ships. |
| `plan/ai-device-platform.md` (operator-internal) | Already reflects the de-phased, gate-first platform: one platform, Volcano as default engine/substrate, AgentKeys as sovereign gate. This strategy doc now adopts that framing. |
| `plan/esp32-touch-agent-console.md` (operator-internal) | Becomes the canonical Phase-1 device plan. Keep its red-line component split synchronized with §2.8/§4 here. |
| `volcano/service.md` (operator-internal) | Keep open questions tied to the Phase-2 pilot gate: sandbox lifecycle API, OpenViking rank-only mode, CustomLLM contract. |
| `research/on-device-memory-daemon-esp32.md` (operator-internal) | Strategy adopts its conclusion: ESP32 stays a terminal in v0; server-side warm cache/preload is the latency path; no K10/cap-mint daemon on device. |
| [issue #322](https://github.com/litentry/agentKeys/issues/322) | Becomes the canonical classifier track for request-intent → structured gate input. |
| `ai-hardware-companion-office-hours.md` (operator-internal) | Update positioning note at top to point at this strategy doc + add Agent IAM framing + three-narrative reality. Substance below the banner stays. |
| `ai-hardware-companion-wedge.md` (operator-internal) | Update positioning sections — sharper "Agent IAM" framing; keep market sizing + competitive analysis as-is. |
| [issue #103 plan](./archived/issue-103-aiosandbox-hermes-esp32-demo.md) | **Archived** — superseded for Phase 1 by the certified Volcano device pilot; kept as historical MCP/Hermes demo context. |
| [`xiaozhi-hermes-architecture.md`](./archived/xiaozhi-hermes-architecture.md) | **Archived** — server-side bridge/warm-cache topology, kept as historical reference; the device-chatbot path is not the Phase-1 product (now the certified Volcano stack). |
| [`xiaozhi-esp32-magiclink.md`](./archived/xiaozhi-esp32-magiclink.md) | **Archived** — MagicLick 2.5 / xiaozhi-esp32 hardware research; the Phase-1 device is now ESP32-S3-Touch-LCD-4B per `plan/esp32-touch-agent-console.md` (operator-internal). |
| [`xiaozhi-hermes-risks.md`](./archived/xiaozhi-hermes-risks.md) | **Archived** — risk analysis kept as historical reference; many risks evaporate under the certified-stack in-path model. |
| `volcano-ark-mcp-integration.md` (operator-internal) | Fold into the certified-stack adapter view: Ark is one provider behind the gate, not the product identity. |
| `tuya-vs-xiaozhi.md` (operator-internal) | Keep complement-not-compete framing; Tuya connector moves after the first certified stack proves the adapter seam. |

---

## 8. The one-sentence summary

> AgentKeys is the **user-owned authority layer for the AI device era** — Agent IAM to technical buyers, "control what your AI devices can remember, access, and do" to consumers, tamper-evident trust substrate to regulators. We ship certified stacks where needed for product quality, starting with Volcano, but the red line stays ours: identity, memory ownership, policy, audit, revocation, and portability. Engines do the work; AgentKeys controls the authority to do the work.

---

## 9. Sources + lineage

- **Original proposal**: pasted in chat 2026-05-24 — "AgentKeys Strategic Direction: Agent IAM for the AI Device Era." Captured §1-14 of the strategic framing.
- **Independent analysis (this AI)**: pushed back on consumer/B2B positioning tension, sequencing of multiple integration surfaces, standards timing, demo storyboard.
- **ChatGPT critique**: four architectural corrections (bounded revocation, two-tier audit, delegation-as-preview, dual-narrative) + the three-layer positioning framework (AI Device Account / Agent IAM / Trust Substrate).
- **Volcano/ESP32 platform review (2026-06-18/19)**: de-phased the old Plan A/B framing, selected Volcano as the first certified engine/substrate, kept AgentKeys as the sovereign gate, and identified the policy-intent classifier as a control-plane moat.
- **This doc**: synthesis of all inputs. Source of truth for Agent IAM positioning + certified-stack business model + Phase 1 scope + roadmap. Future planning references this anchor.

Companion architectural research:
- `ai-hardware-companion-wedge.md` (operator-internal) — market + competitive landscape
- `ai-hardware-companion-office-hours.md` (operator-internal) — wedge brainstorm + Approach D selection
- [`xiaozhi-esp32-magiclink.md`](./archived/xiaozhi-esp32-magiclink.md) — hardware identification + Option 1 decision (archived)
- [`xiaozhi-hermes-architecture.md`](./archived/xiaozhi-hermes-architecture.md) — MCP-direct architecture (archived)
- [`xiaozhi-hermes-risks.md`](./archived/xiaozhi-hermes-risks.md) — risk verification (archived)
- `volcano-ark-mcp-integration.md` (operator-internal) — Volcano Ark MCP-server adapter
- `tuya-vs-xiaozhi.md` (operator-internal) — Tuya vs xiaozhi role comparison + Phase 3 feasibility
- `plan/ai-device-platform.md` (operator-internal) — gate-first device platform, Volcano-composed
- `plan/esp32-touch-agent-console.md` (operator-internal) — certified Volcano device stack
- `volcano/service.md` (operator-internal) — Volcano service inventory
- [issue #322](https://github.com/litentry/agentKeys/issues/322) — policy-intent classifier training plan
