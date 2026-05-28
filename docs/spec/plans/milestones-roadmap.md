# AgentKeys — Milestone Roadmap (M1 → M7 + beyond)

**Status**: source of truth for milestone-level work after the v2-stage1/2/3 demo lands.
**Date**: 2026-05-24.
**Companion to**: [`docs/arch.md`](../../arch.md) (architecture invariants), [`docs/agent-iam-strategy.md`](../../agent-iam-strategy.md) (positioning + risks + corrections).

This file replaces the v1/v2 staged development-stages.md plan (now archived at [`docs/archived/development-stages-v2-2026-04.md`](../../archived/development-stages-v2-2026-04.md)). Once v2-stage3 ships green, the v1/v2 naming retires entirely. Future work is tracked under the seven milestones below, plus a "beyond M7" horizon.

---

## 0. Vision in one paragraph

AgentKeys is the **Authority Host** for the AI device era — the cross-vendor identity + memory + permissions + audit layer that lives outside any one agent runtime. We are not a chatbot. We are not an orchestrator. We are the IAM that holds when a hardware vendor's stack changes underneath. The product surface evolves from a three-act demo (M1) → a paid vendor pilot (M2) → cross-runtime neutrality (M3) → production-grade capability + revocation depth (M4) → consumer mobile surface (M5) → TEE-rooted security (M6) → standards adoption (M7). Each milestone earns the right to the next by deploying a working reference implementation before chasing the next ambition.

The category we own is **Agent IAM** — Identity, Memory, Permissions, capability-token Authority, Audit, Delegation, Revocation. Memory is **one of** these surfaces, not the headline. The competition is Auth0/Okta for agents, not Mem0 for chatbots. See [`agent-iam-strategy.md` §2.2](../../agent-iam-strategy.md) for the full positioning.

---

## 1. Phase 0 — Done (Stage 7+ era)

Already shipped, persisted for historical context:

- `agentkeys-broker-server` — OIDC issuer + cap-token mint + audit
- `agentkeys-signer` — TEE-isolatable signer with HDKD per-actor derivation
- `agentkeys-worker-creds` + `agentkeys-worker-memory` + `agentkeys-worker-audit` — per-data-class isolation enforced at four layers (broker cap-mint, worker chain-verify, AWS PrincipalTag, per-data-class bucket separation) per [arch.md §17](../../arch.md)
- HDKD identity tree (K1–K11 key inventory per [arch.md §4](../../arch.md))
- v2-stage1/2/3 demo orchestrators in [`harness/`](../../../harness/) prove the end-to-end Heima EVM backbone + per-actor isolation
- Project board automation (this `pm/` folder; see [`pm/PROJECT-DASHBOARD-GUIDE.md`](../../../pm/PROJECT-DASHBOARD-GUIDE.md))

What this gives us going into M1: a working backend, deployed signer + broker on the broker host, audited isolation, deterministic field schemas on the project board. The v2 staging name retires after v2-stage3 ships green; future work refers to milestones, not stages.

---

## 2. M1 — Agent IAM v0 demo (0–2 weeks)

**Goal**: a hardware vendor watches a 5-minute demo and understands "this is the IAM for AI devices, not another chatbot platform." Anchored to [`agent-iam-strategy.md` §4](../../agent-iam-strategy.md).

### Scope

- **MagicLick 2.5 hardware** (ESP32-S3 + ES8311 + 128×128 LCD + WiFi/4G) running the upstream [xiaozhi-esp32](https://github.com/78/xiaozhi-esp32) firmware with no AgentKeys-side fork. Xiaozhi-server's first-class MCP support means we register one MCP server in its `mcp_server_settings.json` — no Hermes-as-bridge fork needed.
- **AgentKeys MCP server** (issue #107) exposing 7 active tools (`identity.whoami`, `memory.get`, `memory.put`, `permission.check`, `cap.mint`, `cap.revoke`, `audit.append`) + 3 schema-preview tools (`delegation.grant`, `delegation.revoke`, `approval.request` — return `not_implemented_in_v1`).
- **Memory namespace model** (issue #108) — v0 defaults `personal / family / work / travel`. Wire-format `namespace` field on memory put/get + cap-token `namespaces_allowed` claim. Per [`agent-iam-strategy.md` §3.5](../../agent-iam-strategy.md).
- **Two-tier audit** (issue #109) — real-time off-chain feed for the parent UI; 2-minute Merkle-batched on-chain anchor for tamper-evidence. Chain-agnostic. Per [`agent-iam-strategy.md` §3.2](../../agent-iam-strategy.md).
- **Bounded revocation** (issue #110) — immediate online, ≤60-second offline via cap-token TTL. Per [`agent-iam-strategy.md` §3.1](../../agent-iam-strategy.md).
- **Parent-control web UI** (issue #111) — mobile-responsive, three columns: actor list / scope toggles per namespace / real-time audit feed. Native app deferred to M5.
- **Three-act demo storyboard**: (1) permissioned memory recall demonstrating namespace isolation; (2) deterministic denial of an out-of-scope action; (3) parent revokes a scope live and the device's next attempt fails. Per [`agent-iam-strategy.md` §4.3](../../agent-iam-strategy.md).

### Hard exclusions

Per [`agent-iam-strategy.md` §2.4 + §4.5](../../agent-iam-strategy.md): no orchestration, no active delegation (schema only), no approval workflows, no native mobile app, no real-time on-chain audit, no vendor onboarding portal, no second-rail integration (Volcano Ark Phase 2).

### M1 done when

- A reviewer can run `bash scripts/setup-demo-iam.sh` and within 15 minutes execute all three acts live against a MagicLick 2.5 device.
- Demo can be re-run cleanly between vendor pitches (state resets without manual cleanup).
- A 15-minute vendor deck (issue #112) walks: pain point → three-act live → cross-vendor portability moat → pricing → "what blocks a pilot in 30 days?"

### M1 issues (open today)

#103 (ESP32 firmware foundation — superseded by xiaozhi-esp32 use), #107 (AgentKeys MCP server), #108 (memory namespace model), #109 (two-tier audit), #110 (parent-control web UI), #111 (demo runbook + pitch deck), #116 (FoloToy vendor outreach tracking).

---

## 3. M2 — First vendor wedge + multi-rail (1–2 months after M1)

**Goal**: 1 signed paid vendor pilot at the $2-3/active-device/month base tier; demonstrate that the same authority backend serves a second integration rail (Volcano Ark).

### Scope

- **Vendor onboarding portal** (issue #114) — tenant signup, Bearer token issuance, per-vendor device registration API (`/v1/vendor/devices/register`), per-vendor billing dashboard, vendor settings (allowed memory namespaces, default cap policies, branding).
- **Pricing structure** materialized: $2-3/device/month base + 30% lifetime acquirer-of-record revshare on consumer Pro upgrades. Stripe + Alipay rails.
- **Volcano Ark MCP marketplace registration** (issue #112 in the current numbering) — open international developer signup, no PRC entity required. Deploy AgentKeys MCP server at `mcp.agentkeys.io`, register in [`mcp.so/server/mcp-server/volcengine`](https://mcp.so/server/mcp-server/volcengine), prove a Doubao agent can invoke `agentkeys.memory.get` from the marketplace.
- **Tuya Cloud Development connector** (issue #114) — Tuya brand-owner authorizes AgentKeys access; webhook receiver maps Tuya device events → memory.put / audit.append; Tuya MCP-server hook for "Hey Tuya" upgrade.
- **Memory namespace template** for the AI-companion product class (profile / work / family / child / travel / temp).
- **Permission policy template** with default-deny for sensitive scopes.
- **Audit dashboard for parents** (better UI than the v0 web page; family-friendly).

### M2 done when

- 3 vendor discovery conversations completed within 30 days of M1 demo readiness; 1 signed paid pilot within 60 days.
- A Doubao agent on Volcano Ark can call AgentKeys MCP tools through the marketplace listing.
- Cross-rail proof: same `agentkeys_user_wallet` actor's memory read via Doubao MCP returns identical content to xiaozhi-server MCP.

### M2 kill criterion

Per [`agent-iam-strategy.md` §C12](../../agent-iam-strategy.md): 0 paid pilots from 3 priority vendors in 6 months → pivot to MCP credential broker for consumer agent apps.

---

## 4. M3 — Runtime neutrality (3–4 months after M2)

**Goal**: prove "the same authority layer works across different agent runtimes." This is the moat — when a vendor's runtime changes underneath, AgentKeys holds.

### Scope

- **Hermes-MCP wrapper** (issue #117) — NousResearch [hermes-agent](https://github.com/nousresearch/hermes-agent) exposed as an MCP server: `hermes.execute_task(task, context, constraints)` returns `{result, steps_taken, cost_usd, audit_trail_id}`. Hermes calls AgentKeys MCP tools internally (recursive composition).
- **OpenClaw-MCP wrapper** (issue #118) — Tencent OpenClaw same shape as Hermes (commercial ToS verified per [`agent-iam-strategy.md` §9.5](../../agent-iam-strategy.md)).
- **Doubao agent compatibility** — already exercised via M2's Volcano Ark registration; M3 hardens the integration to production.
- **Claude Code / Codex CLI compatibility** — these are coding agents (different use case from the consumer demo) but proving cross-runtime IAM works for developer-tier agents widens the moat.
- **Python SDK + TypeScript SDK** for non-MCP integration paths.

### Architectural decision encoded here

Per the May session's "agent-as-MCP-tool, NOT LLM-caller-replacement" call: agentic runtimes like Hermes and OpenClaw integrate as MCP tools the host LLM can invoke, not as alternative LLMs to swap in for xiaozhi-server's default model. Keeps the fast path cheap; expensive agentic loops are explicit tool calls.

### M3 done when

- 3+ runtimes (Hermes, OpenClaw, Doubao agent) all invoke the same set of AgentKeys MCP tools and produce isolated, audited results.
- A vendor can pick their runtime (xiaozhi default model / Doubao agent / Hermes for complex tasks) without AgentKeys-side changes.

---

## 5. M4 — Capability + revocation depth (6 months after M3)

**Goal**: take the half-spec'd v1 schemas (delegation, approval, policy versioning) and ship the deep versions in production. First enterprise customer.

### Scope

- **Delegation chains in production** — parent agent → child agent with scope narrowing, TTL inheritance, revocation cascade, audit chain. Per [`agent-iam-strategy.md` §3.3](../../agent-iam-strategy.md) corrected design: delegation is implicit in cap-tokens by default; explicit delegation activates only after vendor proves M2-tier traction.
- **Approval workflows** — high-risk actions (payment > threshold, cross-namespace memory grant, scope expansion) push to the parent app for one-tap approval before execution. Replaces deterministic-denial as the path for "I trust this agent but want eyes on this specific request."
- **Policy versioning** — vendors deploy new policies; existing devices upgrade with explicit audit trail showing the diff.
- **Audit replay** — regulator-grade reconstruction of any agent's authority history from the on-chain anchor + off-chain feed. First-class regulator API.
- **Memory namespace ACL maturity** — cross-vendor consent ceremony in production. Family / work / kids memory separation operationalized (not demo).
- **First enterprise customer signed** — likely a regulated B2B brand-owner: toy maker selling to schools, health-data-adjacent device maker, fintech-adjacent agent vendor.

### M4 done when

- A live delegation chain (parent agent issues a narrower cap to a child agent) is exercised end-to-end with audit trail.
- An approval workflow rejects a high-value payment until parent approves; audit shows the approval event.
- First enterprise customer in production on signed-pilot terms.

---

## 6. M5 — Native mobile app + biometric (post-M4)

**Goal**: the consumer surface that justifies the $10-20/month Pro tier from the office-hours pricing doc.

### Scope

- **Native iOS app** (Swift / SwiftUI) — parent-control dashboard, real-time audit feed via push notifications, biometric-gated approvals (FaceID / TouchID).
- **Native Android app** (Kotlin / Compose) — same feature parity.
- **Push notifications** for high-risk events (approval requests, revocation events, anomalous activity).
- **Family-sharing UX** — multiple parents bound to one actor tree, shared revocation rights, audit visibility split by role.
- **Brand + landing site** (issue #126) — `scoped.ai` / `leash.ai` / `bonded.ai` or alternative. Trademark search gates the choice. International + Chinese-language registration.

### Why this is M5 not M1

Per [`agent-iam-strategy.md` §6 Risk 3](../../agent-iam-strategy.md): native mobile is expensive and slow to iterate. The v0 web UI is sufficient to prove the UX premise; native ships only after a paying vendor pilot has signed and consumer demand is demonstrated.

### M5 done when

- iOS + Android apps in production with 5-star App Store / Play Store launches.
- 100+ consumer Pro upgrades attributed to a vendor pilot.

---

## 7. M6 — TEE integration + enhanced security depth (post-M5)

**Goal**: production-grade crypto hardening. TEE moves from "isolatable design" to "actively isolating in prod."

### Scope

- **K3 (MSK) inside TEE** — Master Sealing Key only readable by the TEE-attested signer process. Per [`arch.md` §4 K3 row](../../arch.md).
- **K10 / K11 device-key hardening** — WebAuthn enrollment ceremony at the TEE attestation boundary. Stage-1 K11 enrollment audit-row format finalized.
- **Key rotation depth** — K3 epoch rotation in production (currently shipped as scaffolding); K1 broker key rotation; K2 OIDC key rotation. Each documented as a ceremony in arch.md §10.
- **Sealed key migration** — operator switches the broker host's TEE and migrates K3 with a sealed-blob transfer ceremony (Phase 6 from earlier roadmap; deferred from M5 because pre-M4 we don't yet have enough deployed TEEs to justify the ceremony complexity).
- **Threat model deepening** — adversarial review per [`docs/spec/threat-model-key-custody.md`](../threat-model-key-custody.md). External pentest pass + remediation.

### M6 done when

- K3 in production reads only by TEE-attested signer; non-TEE reads fail loudly with audit row.
- One operator-led TEE migration ceremony successfully completed (e.g., when the broker host EC2 is upgraded).
- External pentest produces no findings above Medium.

---

## 8. M7 — Standards + ecosystem (post-M5/M6, 12+ months out)

**Goal**: become the reference implementation every new agent runtime + IoT cloud integrates with by default. Standards engagement only after deployed reference implementations exist.

### Scope

- **Propose MCP extensions** for IAM-grade auth headers (session keys, cap-token forwarding, audit-chain headers).
- **OAuth-for-Agents specification engagement** — likely IETF or W3C working group. Lead the spec discussion with deployed reference code, not slide decks. Per [`agent-iam-strategy.md` §6 Risk 5](../../agent-iam-strategy.md): premature standards engagement looks like vendor lobbying; standards work is post-12-months.
- **Reference implementations for non-MCP runtimes** — raw HTTP / gRPC clients for vendors that don't use MCP.
- **Brand-owner partnerships at scale** — Tuya (built in M2), Xiaomi (per [`tuya-vs-xiaozhi.md` Phase 3c "deferred"](../../research/tuya-vs-xiaozhi.md)), Alibaba Smart Home (per Phase 3b "partnership-gated"), Samsung SmartThings.
- **Open-source SDK ecosystem** — MIT-licensed SDK + MCP server. Community contributions, third-party integrations, hackathon presence.

### M7 done when

- AgentKeys is referenced in at least one MCP-spec or OAuth-related public discussion as the reference implementation.
- 10+ vendor partners deployed in production (not pilots).
- The SDK has at least 1000 GitHub stars and 50+ external contributors.

---

## 9. Beyond M7 — strategic horizons

Post-M7 horizons we hold in mind but do not commit to today. None of these are scoped beyond intent; each becomes a real milestone only after M1-M7 land.

### 9.1 Default-IAM-for-MCP

If MCP becomes the de-facto AI integration protocol (current trajectory looks likely), AgentKeys positions as the default IAM layer that ships next to it. Goal: a new MCP server author who needs auth doesn't write their own — they import AgentKeys. Analogous to how SSL libraries became infrastructure rather than competitive surface.

### 9.2 Multi-region + multi-chain neutrality

Production deployments across multiple regions (US / EU / APAC) and multiple chain backbones (Heima default; Base / Ethereum / Polygon / chain-X for vendor preference). Per [`arch.md` §22 (chain-pluggable design)](../../arch.md) the architecture supports this today; M-beyond is the actual deployment.

### 9.3 Regulator-grade product line

A separate product tier with audit-chain APIs, SOC2 / ISO27001 attestations, compliance reports tailored to specific regulations (COPPA for kids' devices, HIPAA for health-adjacent agents, EU AI Act for general-purpose agents).

### 9.4 Hyperscaler interop without absorption

Per [`agent-iam-strategy.md` §6 Risk 1](../../agent-iam-strategy.md): Anthropic / OpenAI / ByteDance each build native walled-garden IAM for their own runtime. AgentKeys becomes the cross-walled-garden bridge — a vendor's device can authenticate to Claude *and* Doubao through the same actor tree. Hyperscalers don't credibly build this themselves (each can only do their own garden).

### 9.5 Authority-as-infrastructure pricing

When we have enough adoption that AgentKeys is critical infrastructure, pricing shifts from per-device to a hybrid (usage-based + reserved capacity), similar to how Cloudflare and Stripe price. Reference customer expansion: vendor → device manufacturer → IoT cloud → AI cloud → SaaS-for-agents.

### 9.6 The unboring case

If MCP stalls or shifts, AgentKeys has the actor-tree + cap-token + audit primitives that compose with whatever the next protocol becomes. We bet on the primitives, not the protocol — the primitives are right because they reflect how IAM has always worked, not because of one specific runtime.

---

## 10. Strategic risks to track at every milestone

Full list in [`agent-iam-strategy.md` §6](../../agent-iam-strategy.md). Summary:

| Risk | Mitigation |
|---|---|
| R1 Hyperscaler absorption | Be cross-platform layer they can't credibly build |
| R2 Over-extension into orchestration | §2.4 hard line in every conversation |
| R3 Weak consumer face | Parent UI in M1; native mobile in M5; brand in M1.5 |
| R4 Pure neutrality = no adoption | Reference impl + charge for hosting + standards after 10+ deploys |
| R5 Premature standards work | Deploy → grow → propose. Standards in M7, not earlier. |
| R6 Memory eclipses authority in narrative | Lead with all 3 behaviors; memory is one of many surfaces |
| R7 Privacy positioning trap | Lead with "control" or "authority"; privacy is supporting benefit |

---

## 11. How to use this doc

- **Per-milestone planning**: each M is the scope of work for that phase. Issues in the repo are tagged with their milestone via the GitHub Milestones system; project board grouping by Milestone reveals the current cohort.
- **Per-issue planning**: when a new issue is opened, it inherits its milestone from this doc (the `/agentkeys-issue-create` skill prompts for it). The issue body should link back here for shared context.
- **Per-PR planning**: every PR description that touches feature work should name which milestone it's serving — and if it's expanding scope beyond the milestone's spec, that's a conversation before implementation.
- **Per-quarter retrospective**: walk this doc and the strategy doc together; identify scope drift, mitigation effectiveness, and what the next milestone needs to gain to be honest about its "done when."

When this doc disagrees with [`arch.md`](../../arch.md), arch.md wins — the milestone roadmap is the plan, arch.md is the architecture. When it disagrees with [`agent-iam-strategy.md`](../../agent-iam-strategy.md), the strategy doc wins on positioning + corrections; this doc owns sequencing + scope per milestone.

---

## 12. References

- **Architecture** (single source of truth) — [`docs/arch.md`](../../arch.md)
- **Strategy** (positioning, corrections, risks) — [`docs/agent-iam-strategy.md`](../../agent-iam-strategy.md)
- **xiaozhi-server integration** — [`docs/research/xiaozhi-hermes-architecture.md`](../../research/xiaozhi-hermes-architecture.md), [`docs/research/xiaozhi-hermes-risks.md`](../../research/xiaozhi-hermes-risks.md), [`docs/research/xiaozhi-esp32-magiclink.md`](../../research/xiaozhi-esp32-magiclink.md)
- **Volcano Ark integration** — [`docs/research/volcano-ark-mcp-integration.md`](../../research/volcano-ark-mcp-integration.md)
- **Tuya analysis** — [`docs/research/tuya-vs-xiaozhi.md`](../../research/tuya-vs-xiaozhi.md)
- **AI hardware wedge thesis** — [`docs/research/ai-hardware-companion-wedge.md`](../../research/ai-hardware-companion-wedge.md), [`docs/research/ai-hardware-companion-office-hours.md`](../../research/ai-hardware-companion-office-hours.md)
- **Memory system survey** — [`docs/research/ai-memory-systems-survey.md`](../../research/ai-memory-systems-survey.md), [`docs/plan/agentkeys-memory-design.md`](../../plan/agentkeys-memory-design.md)
- **Project board guide** — [`pm/PROJECT-DASHBOARD-GUIDE.md`](../../../pm/PROJECT-DASHBOARD-GUIDE.md)
- **Archived stage docs** (historical only): [`docs/archived/`](../../archived/) — `development-stages-v2-2026-04.md`, `stage7-demo-and-verification-2026-04.md`, `stage8-wip-2026-04.md`, `operator-runbook-stage7-2026-04.md`
