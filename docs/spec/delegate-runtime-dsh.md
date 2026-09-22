# Delegate runtime: DeepSeek Harness (dsh) + the AgentKeys plugin suite

**Status:** decision record + LIVE architecture. Owner decision 2026-08-23 (Hanwen Cheng); **live since 2026-08-25** — the VE prod default flipped (#620), the first dsh delegate runs in production, and Hermes was fully deleted with #621 (see [`ve-sandbox-image-pipeline.md`](ve-sandbox-image-pipeline.md)); [`arch.md` §5](../arch.md) `AI runtime` row points here. Tracking: epic #609; plan: `docs/plan/dsh-runtime-migration.md` (operator-internal).

**Scope:** what runs inside a delegate's sandbox, how AgentKeys authority is enforced in-loop, the grant vocabulary that makes that enforcement a pure projection of on-chain grants, and what the owner sees. Out of scope: chain contracts, broker/worker data-plane changes (none required), cloud/deploy mechanics (plan).

## 1. Decision

1. **DeepSeek Harness (`dsh`) replaces Hermes as the AI runtime every delegate equips.** MIT, Node ≥22, built on Cordis ("everything is a plugin", including the agent loop). Hermes is **fully deprecated** at the end of the migration: the Hermes rollback valve exists only through rollout, then every Hermes-specific artifact is deleted (plan §deprecation).
2. **AgentKeys mounts inside dsh as the *AgentKeys plugin suite*** (`@agentkeys/*` packages; never "bundle" — that word is dsh's own distribution format): a monotonic tool guard, an approval answerer, a vault/cap-backed credential provider, the gate LLM route, an audit tee, and a **bridge plugin** that serves today's bridge HTTP contract byte-for-byte (§3.2).
3. **OpenViking stays the memory engine**, via its official dsh bundle (`@openviking/dsh-memory-plugin`, volcengine/OpenViking `examples/dsh-memory-plugin`); `openviking-server` keeps running inside the sandbox on `:1933`.
4. **MCP is not an extension surface.** The target profile mounts no MCP servers and exposes no MCP configuration to owners, delegates or operators (the #560 posture stands). The OpenViking plugin's loopback stdio proxy to the co-located server is accepted as in-image plumbing (decision A, §4.5).
5. **The permission model is three planes, one authority** (§4): on-chain grants are the only writable authority; the dsh tool pipeline is a compiled projection of them; kernel-level process confinement is blast-radius containment that never appears in any owner surface.

## 2. Why — the facts that drove it

- **Today there is no in-loop tool gate at all.** The sandbox bridge auto-grants every ACP `session/request_permission`; the runtime overlay configures only `memory` + `model`; toolsets are upstream defaults; the hooks delivery was retired with #560 and re-scoped to #133 as design posture; the L3 per-tool check in the original sandbox plan was never built. Everything that constrains a delegate is data-plane (chain grants → cap-mint with chain re-verify → workers → STS → gate custody). That plane survives a hostile agent process and stays exactly as it is; what it never governed is *what the model executes*.
- **dsh supplies that front line as typed, fail-closed machinery** (all paths in the dsh repo, master 0.1.1-rc.2, checked 2026-08-23): `tools/pre-execute` → **monotonic guards** ("no guard can force-allow a call another guard denied", `docs/subsystems/tools.md`) → `ctx.approval` with closed outcomes `allowed-once | rejected | cancelled | unavailable` and an `approval/asked`/`approval/decided` audit pair in the append-only session log (`packages/interaction/user-approval/src/types.ts:29`, `index.ts:94`). Every tool from every plugin — MCP-bridged and Code-Mode sub-calls included — rides the same pipeline (`docs/tool-execution-pipeline.md`).
- **dsh deliberately ships no durable authority** — policy is per-session `ask | never`, grants are one-shot, the bridge "never persists client policy"; the Claude Code hooks bridge maps hooks.json decisions only, not CC's `permissions.allow`. Policy *content* is the answerer's job; AgentKeys is that answerer. No wheel is reinvented on either side.
- **The seams line up.** Model config is OpenAI-compatible-gateway-as-configuration (`packages/llm/llm-pi-ai`), so gate custody (per-delegate `gk_` key, op_kind 90/93 metering) carries over unchanged; the credentials seam is references-in-config + per-operation resolve (`docs/subsystems/credentials.md`); per-agent presets give persona + per-delegate toolsets a native home; sessions are durable JSONL/sqlite with fork/replay.
- **Measured** (operator Mac, Node v24.14.0, 2026-08-15): warm boot of the full `web` profile to HTTP 200 in **1.8 s**; installed package tree **307 MB**. Pod boot against the veFaaS Ready budget is a pre-flip gate (§8), not assumed.
- **Release churn is accepted, priced in, and symmetric with Hermes** (npm head rc.7 → 0.1.1-rc.2 within a week; the OpenViking plugin 0.1.0 → 0.2.1 with a changed architecture): exact pins for the dsh + plugin pair in the seeded base, bumped together through a review gate (§4.6).

## 3. Target topology

```
veFaaS pod (dsh-sandbox image) — outer boundary unchanged
├─ supervisord (PID 1, AIO base — unchanged)
├─ dsh (Node 24, DSH_HOME=/root/.dsh)            ← replaces hermes venv + hermes_bridge.py
│   ├─ agent loop · session log
│   ├─ ctx.tools pipeline: pre-execute → guards → approval
│   ├─ AgentKeys plugin suite: guard · answerer · credentials · gate LLM route · audit tee
│   ├─ @openviking/dsh-memory-plugin (auto-recall · capture · memory tools)
│   └─ bridge plugin :8090 — byte-compatible /v1/chat SSE · /healthz · /v1/jobs · /v1/context/* · /v1/agent/restart · /v1/sandbox/mgmt/*
├─ openviking-server :1933 (python) — unchanged
└─ agentkeys-daemon :3114 (rust) — chat loop · memory mirror · checkpoint — unchanged
         ↕ cap-mint / STS            ↕ OpenAI-compatible (ARK_* env names unchanged)
      broker → Heima chain (grants)       gate relay (gk_ custody, metering)
```

### 3.1 Components

| Component | Role | Notes |
|---|---|---|
| dsh profile (baked) | one `DSH_HOME` profile whose patch layer mounts the three plugin sets | per-delegate customization (#425/#390) = a patch layer the daemon writes; presets are config rows, not code |
| AgentKeys plugin suite | the in-loop enforcement of AgentKeys authority (§4) | `@agentkeys/*`; consumes grants via the co-located daemon; never holds K10 (#552 signer custody) |
| bridge plugin | the HTTP contract the five existing bridge consumers already speak | daemon chat loop, broker update handler, parent-control persona editor, ESP32 firmware, dev tooling need **zero** changes |
| OpenViking plugin | memory tools + auto-recall | reads the same `OPENVIKING_*` / `~/.openviking/ov.conf` the sandbox renders today; requires server support for the `viking://~` home alias (§7) |
| agentkeys-daemon | unchanged | `chat_loop`, `memory_mirror` (provider-coupled, not Hermes-coupled; since 2026-09-18 it files canonical knowledge as OpenViking resources — `viking://resources/<ns>/<item>/` with L0/L1 sidecars from the item's title/preview — the layout the plugin's per-step context recall reads), `checkpoint` (re-anchored to `DSH_HOME`, §3.2) |

### 3.2 Preserved contracts and constants

- **Bridge HTTP contract** — route set, SSE frame shape unchanged; bearer semantics since #715: `AGENTKEYS_BRIDGE_TOKEN` (the per-delegate in-pod bearer the broker injects at create) gates EVERY route but `/healthz` **fail-closed** (401 when unset or wrong — the pre-#715 "open when unset" is gone: an instance name alone opened chat/context to the internet, measured 2026-09-22), `AGENTKEYS_SANDBOX_MGMT_TOKEN` keeps its own fail-closed gate on `/v1/sandbox/mgmt/*`. The five consumers present the bearer: the daemon (chat loop, scheduler, app runtime — already did), the broker on the console's behalf (`/v1/agent/bridge`, which also carries the gateway's secret token), the ESP32 bench demo and dev tooling (`AGENTKEYS_BRIDGE_TOKEN` env), the image smoke + local twin (a fixed local value). The bridge plugin binds `:8090` at plugin activation and creates the agent lazily (bind-first, the #589 readiness discipline).
- **Sandbox env contract** (`agentkeys-protocol` `sandbox_env`) — `ARK_BASE_URL` / `ARK_API_KEY` / `LLM_ENDPOINT_ID` names kept; new keys (`DSH_HOME`, OpenViking keys) must be present in the **function env template**, not only the image (the #587 drift class; the boot gate catches it).
- **Checkpoint (#594)** — export/import snapshots `DSH_HOME`; the reserved memory object key migrates from `checkpoint/hermes-home` to `checkpoint/dsh-home` with a read-both window (decision, §7).
- **ACP is not used.** The bridge plugin drives `ctx.agents` in-process; `dsh-acp`, the subagent drivers and `dsh-mcp-client`-as-integration are not mounted.

## 4. Permission model (normative)

### 4.1 Three planes, one authority

| Plane | Vocabulary | Question it answers | Enforced by | Owner-visible? |
|---|---|---|---|---|
| **Authority** | AgentKeys grant strings (§4.2) | what authority does this delegate *identity* hold | chain grants → cap-mint → workers → IAM (D1; survives a hostile sandbox) | yes — the permission sheet / page |
| **Action** | tool calls | which actions may the *model* attempt, now, in this session | in-loop: monotonic guard + fail-closed approval, per-agent presets | only as the same sheet rows (a projection, §4.2) |
| **Blast radius** | OS filesystem paths, per spawned process | what may an *allowed* command touch inside the pod | kernel (Landlock/bwrap via dsh's sandbox seam, where the pod kernel permits) | never — operator diagnostics only |

The action plane is **not a second authority list**. On shared territory it is a compiled projection of the same grants, applied earlier (denial before a doomed cap-mint round trip; ungranted tools absent from the model's schema). Its genuinely new coverage is the model-invoked actions that never reach the data plane — bash, file edits, web fetch — which today have no permission surface. The blast-radius plane governs file effects only; **it is not network control** — egress posture remains the pod/VPC boundary plus key custody, unchanged from today.

### 4.2 Unified grant vocabulary

Scope-grant services are strings; the vocabulary gets two families:

| Family | Services | Consumers | Workers mint caps? |
|---|---|---|---|
| **Data services** (existing) | `knowledge:<ns>` · `cred:<service>` · `channel:<id>` · `proposal:<ns>` · `config` | broker cap-mint + the per-class workers | yes |
| **Capability services** (new) | `plugin:<id>` — may this capability provider be mounted in the session; `tool:<class>` (`tool:web`, `tool:code`, `tool:schedule`, …) — may this action family run | the preset compiler (mount) and the guard (call class) **only** | never |
| **The publish action** (2026-09-17) | `publish_to_slot` — the suite's own tool (`@agentkeys/dsh-suite/publish`), the delegate's "act" verb: one event to a bound pub slot through `agentkeys-daemon --publish-once`. **Not a capability class**: the guard allows it when the delegate holds *any* `channel-pub:<id>` data service and denies it otherwise (an allow-once cannot mint a feed); *which* feed is the cap-mint's verdict. Why it exists: the image's `publish-to-slot` shell helper needs `tool:code`, which no application sheet grants — a chef told to publish its card wrote a file instead (measured on the clock and on demand). | the guard (pub-grant presence) + broker cap-mint (the feed) | yes (the channel worker) |
| **The propose action** (2026-09-18) | `propose_to_owner` — the suite's own tool (`@agentkeys/dsh-suite/propose`), the delegate's "propose" verb: one durable learning into the owner's review queue through `agentkeys-daemon --propose-once` (rate- and size-bounded there). **Not a capability class**: the guard allows it when the delegate holds *any* `proposal:<ns>` data service (every installed application holds its own inbox) and denies it otherwise; *which* namespace is the cap-mint's verdict. Why it exists: the image's `propose-to-owner` shell helper needs `tool:code`, which no application sheet grants — no application could propose. | the guard (proposal-grant presence) + broker cap-mint (the namespace) | yes (the memory worker's inbox) |

With capability services the action plane becomes **`compiled(authority)` everywhere, with no hand-authored remainder**. The projection ladder:

| Altitude | Question | Mechanism | iOS analog (the whole scheme = a provisioning profile) |
|---|---|---|---|
| Mount | may this capability exist in the session? | `plugin:<id>` grant → preset row; revocation = live unmount (Cordis revertible effects, no restart) | capability present in the provisioning profile |
| Call class | may this action family run? | `tool:<class>` grant → guard allow; ungranted class absent from the schema | entitlement, enforced by the OS, invisible to users |
| Single call | may *this* call run *now*? | `ctx.approval` ask → owner push → `allowed-once`; "always allow" = a grant ceremony, never a local rule | the runtime "Allow Once" dialog |

**Invariants (normative):**

1. The chain is the only writable authority (D1). Anything the harness persists about permissions is at most a cache the compiler owns.
2. The AgentKeys guard is **default-deny over a grant-compiled allowlist** and monotonic: an unmapped tool — including any tool a future dsh version introduces — is denied until a grant is projected onto it.
3. On shared territory the action plane is equal-or-stricter than the authority plane, never wider.
4. There is exactly **one** way authority changes: the grant ceremony (sheet, toggle, or prompt escalation all route to it).
5. Per-use decisions are audited twice: the session log's `approval/asked`/`decided` + `tool/call`/`tool/result` pairs, teed to the audit worker's op_kind space.

### 4.3 Inter-app references — deferred

**Owner decision 2026-08-23: apps do not reference each other directly, and no app-to-app machinery ships in this migration.** Anything one app produces that another consumes is a memory or resource object under an ordinary data-service grant (`knowledge:<ns>`, `cred:<service>`) owned by the same household master — no template `exports`/`imports`, no request channels, no per-app dependency semantics, no direction qualifier on memory grants. The sheet therefore has exactly two sections (§4.4). Revisit only if a concrete family app needs an app-to-app intent; the deferred design (memory-grant sharing with a direction qualifier, request channels, inactive-until-installed) is recorded on the closed issue #618.

Inside one dsh process, plugin→plugin access is structural (declared `inject`, realms, interception — `vendor/cordis/src/context.ts`), trust-on-mount, curated by the profile we bake; model-driven calls into other plugins or agents go through `ctx.tools` and therefore through the guard. `plugin:<id>` grants are minted with the install batch and surface only as a read-only "Built with" disclosure, never a toggle.

### 4.4 Owner surfaces (parent-control)

Four surfaces, each backed by exactly one mechanism: **install sheet** (two sections — "Data & devices" for data-service grants, "Capabilities" for tool classes; one Touch ID = one #427 `executeBatch` minting every listed grant), **permissions page** (the same two sections as toggles — a toggle *is* a grant; off = the revocation ceremony; "Built with" is read-only disclosure), **runtime ask** (a companion push via the #573 inbox: Allow once / Deny; "Always allow" opens the grant ceremony; ignoring it fails closed), **activity report** (per app, in owner language, denials shown). No dsh UI is mounted; parent-control is the only owner-facing surface.

### 4.5 MCP policy

No MCP servers, no MCP configuration, no MCP as an integration path for new capabilities. **Decision A (2026-08-23):** the OpenViking plugin's loopback stdio proxy to the co-located `openviking-server` is accepted as in-image plumbing between two processes we ship — MCP is never an *extension surface*, and the `mcp__*` tools the plugin registers are governed by the guard like every other tool. No other MCP anywhere.

### 4.6 Future-proofing

A future dsh "always allow" or any other permission-surface change cannot move the design (invariants 1–4). Two mechanical defenses ship with the migration: the dsh bump gate **diffs the permission contract between pins** (`ApprovalOutcome`/`ApprovalPolicy` vocabularies, the `ToolGuard` contract, the pipeline ordering doc) and stops the bump for review on any change; and a boot-time runtime invariant (dsh's `ctx.invariants`) asserts the approval configuration carries **no standing allow rules**, failing the profile loud at activation.

## 5. Design-rules compliance (arch.md §1a)

| Rule | Verdict | Why |
|---|---|---|
| D1 chain is the single authority | pass | grants remain the only writable policy; the guard/answerer project them, never originate authority |
| D2 stateless broker | pass | no broker change; no new durable store anywhere (a dsh-side cache, if ever used, is compiler-owned and reconstructible) |
| D3 keys never leave their machine | pass | K10 stays in the signer (#552); the credential provider resolves per operation via cap-mint, nothing at rest in the sandbox |
| D4 no ambient authority | pass | creds are references resolved per operation; an ungranted VAULT-mapped reference fails `MISSING_CREDENTIAL`; unmapped tools are denied. One scoped exception (#631): a reference NOT mapped to a vault service falls through to the launch environment — that is the §3.2 gate-pair transport (`ARK_API_KEY` arrives as broker-injected spawn env, and dsh consults only the mounted credentials service, never env, once one exists), not a grant bypass: vault-mapped refs never read env |
| D5 broker never writes chain | pass | untouched |
| D6 PII off-chain | pass | capability-service strings (`tool:web`, `plugin:<id>`) carry no PII |
| D7 one owner per contract | n/a | no contract change |

**§1a exception registry:** no new row required.

## 6. Canonical names (proposed §5 rows, added when implementing)

| Term | Definition | Not |
|---|---|---|
| `AgentKeys plugin suite` | the `@agentkeys/*` dsh plugins that enforce AgentKeys authority inside a delegate's runtime | "bundle" (dsh's distribution format), "hooks" |
| `capability service` | a grant string consumed only by the preset compiler / the guard: `plugin:<id>`, `tool:<class>` | a data class; a cap-mintable service |
| `action plane` / `authority plane` / `blast-radius plane` | the three enforcement planes of §4.1 | "permission layers" (ambiguous) |
| `bridge plugin` | the dsh plugin serving the sandbox bridge HTTP contract | `hermes_bridge.py` (retired) |

## 7. Decisions (settled 2026-08-23) and validation items

- **OpenViking transport — A.** Upstream `@openviking/dsh-memory-plugin` as-is (its loopback stdio proxy to the in-sandbox server); no fork. suite-7 assertions rename to the plugin's `mcp__…` tool names.
- **Checkpoint key — migrate.** `checkpoint/hermes-home` → `checkpoint/dsh-home`; the daemon reads both during the rollout window and writes only the new key; the old key is dropped in the Hermes deprecation step.
- **Inter-app references — deferred** (§4.3); the memory-grant direction qualifier goes with it (read-only cross-app sharing was its only driver).
- **Validation item (work, not a decision):** capability-service strings must pass the scope-service catalog + broker validation (the #572 lockstep `MOCK_SCOPE_SERVICES` trap applies) and get parent-control rendering — verified in #614: no wire-contract change (the frozen protocol key-set tests are untouched; the family is a string value, not a new field).

## 8. Verification gates before the default flips

1. Pod boot: CreateSandbox → `:8090` Ready inside the veFaaS budget (the Mac 1.8 s is directional only).
2. Landlock/bwrap availability inside a veFaaS pod (`uname -r` ≥ 5.13, `landlock` listed in `/sys/kernel/security/lsm`, dsh `sandbox-local` reports `full|partial`); absence costs nothing Hermes had.
3. Function env template carries every baked key (`DSH_HOME`, OpenViking keys).
4. The pinned `openviking` server supports the `viking://~` home alias the 0.2.1 plugin requires.
5. Suites 1–3, 6, 7 green on the VE dialect with the dsh image (suite-7 assertions renamed to the plugin's `mcp__…` tool names, decision A).
6. Bump-gate permission-contract diff + the no-standing-allows boot invariant in place.

## 9. References

- Paper: *A Programming Paradigm for Spatiotemporal Composability* (Shi, Zhang, Cui — PKU / DeepSeek-AI; github.com/cordiverse/paper) — §1.2.2, §3, §5, §6.2–6.4.
- github.com/deepseek-ai/deepseek-harness — `docs/architecture.md`, `docs/tool-execution-pipeline.md`, `docs/subsystems/{approval,tools,sandbox,permission-presets,credentials}.md`, `packages/{acp,hooks,mcp,llm,subagent,preset,boot}`, `native/landlock-run`; versions measured 2026-08-15 (rc.7) and 2026-08-23 (0.1.1-rc.2).
- github.com/volcengine/OpenViking `examples/dsh-memory-plugin` — README, `package.json`, `mcp.mjs`, `uri-guard.mjs` (0.2.1, 2026-08-23); `tools.mjs` (0.1.0, 2026-08-15).
- This repo: the sandbox bridge + image (`docker/hermes-sandbox/`), `crates/agentkeys-daemon/`, [`arch.md`](../arch.md) §17.5–17.6 and §22d, [`ve-sandbox-image-pipeline.md`](ve-sandbox-image-pipeline.md).
