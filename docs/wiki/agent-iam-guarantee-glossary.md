Companion to [`docs/agent-iam-strategy.md`](../../docs/agent-iam-strategy.md). Defines the load-bearing terminology AgentKeys uses when describing what an integration delivers — so vendor conversations don't confuse "the LLM can call our tool" with "the policy check actually runs."

## 1. IAM tool vs IAM guarantee

The distinction is about **who decides whether the policy check actually runs**.

| | Defined as... | Whether it runs is decided by... | Failure mode |
|---|---|---|---|
| **IAM tool** | A function in the LLM's tool registry (e.g. `agentkeys.permission.check(scope=…)`) | The LLM, based on its prompt + context + sampling | LLM forgets / skips / is jailbroken → unauthorized action proceeds |
| **IAM guarantee** | A non-LLM gate sitting in the execution path before the sensitive action runs | The runtime (hook system, certified-stack in-path endpoint, OS capability, syscall filter) — deterministically | Runtime gate fails closed; action cannot proceed without an allow verdict |

**Concrete example — payment scenario:**

- *Tool-only:* User says "buy hotpot." The LLM has both `agentkeys.permission.check` and `payment.execute` in its tool registry. The system prompt asks it to check permission first. A prompt-injection in the user's input convinces the LLM to skip. **No guarantee.**
- *Guarantee:* User says "buy hotpot." The LLM emits `payment.execute(amount_rmb=600)`. The Task Host's `PreToolUse` hook fires before the call leaves the host, executes `agentkeys.permission.check(scope=payment.spend, amount=600)`, gets `denied: daily_spend_cap_exceeded`, **physically blocks the tool call from running**. The LLM's intent is irrelevant. **Guarantee.**

Anchored in [`agent-iam-strategy.md`](../../docs/agent-iam-strategy.md) §3.1 (bounded revocation: *"high-risk = always online permission check + fresh cap-token mint per call"*) and [issue #133](https://github.com/litentry/agentKeys/issues/133) (*"hooks move those guarantees out of LLM discretion and into the runtime"*).

## 2. How AgentKeys delivers guarantees — two agent-first seams

Both are non-LLM gates in the execution path; each is primary for its deployment shape. (The generic OpenAI-compatible proxy that an earlier revision kept as a *fallback* for unmanaged hooks-less hosts was **dropped 2026-06-19** — agent-first direction; see §4.)

| Seam | Mechanism | Where it sits | Strategy-doc fit |
|---|---|---|---|
| **Hooks** — primary for hook-capable Task Hosts ([#133](https://github.com/litentry/agentKeys/issues/133)) | Task Host fires `PreToolUse` / `PostToolUse` / `SessionEnd` hooks that execute AgentKeys MCP tool calls synchronously around tool use | Inside the Task Host runtime, between LLM tool-call emission and execution | Stays cleanly on §2.1 Authority Host side; lifecycle-event-scoped, not in the path of every byte |
| **Certified-stack in-path endpoint** — primary for device stacks | The stack routes its LLM turn to an AgentKeys OpenAI-compatible endpoint (Volcano RTC CustomLLM → cap-check + memory-inject + audit → Ark/Doubao) | At the one point where a *certified* stack resolves the LLM turn | Bounded to one validated vendor (not an open gateway), so the §2.4 risk stays low; the Phase-1 primary device seam |

### 2.1 Hooks vs the certified-stack in-path endpoint — full trade-off table

Mechanically the in-path endpoint **is** a proxy — it sits in the LLM-call path — but scoped to **one certified stack** rather than offered as an open `OPENAI_BASE_URL` gateway to any host. The right-hand column (formerly "proxy") describes that bounded in-path endpoint.

| Dimension | Hook approach | Certified in-path endpoint |
|---|---|---|
| **Where it sits** | Inside the Task Host runtime, between "LLM decided to call tool X" and "tool X runs" | Between the LLM client and the LLM provider (OpenAI / DashScope / Anthropic / etc.) |
| **What it sees** | Tool-call events: `name`, `params`, `result`; lifecycle events: `Stop`, `SessionEnd` | Every prompt, every completion, every `tool_calls` array, every `tool_result` |
| **What it can enforce** | Allow/deny tool calls; trigger side effects at lifecycle events | Anything in the LLM conversation: rewrite system prompt, strip/replace tool_calls, redact PII, terminate session |
| **Host modification needed** | Edit host's settings file (`~/.claude/settings.json` / `~/.codex/hooks.json` / `~/.hermes/config.yaml` / etc.) | Point the certified stack's LLM turn at our endpoint (e.g. Volcano RTC CustomLLM config / `OPENAI_BASE_URL=https://…/v1`) |
| **Host must support...** | A hook lifecycle vocabulary (PreToolUse, PostToolUse, Stop). Each host has its own. | OpenAI-compatible Chat Completions API — the de facto standard |
| **Cross-runtime portability** | Per-host adapter code | One implementation works for all OpenAI-compatible clients |
| **Latency added per LLM call** | One sync hook per tool use (~1–50ms with cap pre-warming) | Full network hop on every LLM call (~50–300ms) |
| **Streaming responses** | Preserved | In-path endpoint must re-stream upstream; doable but extra engineering |
| **Vendor sends prompts through AgentKeys?** | No | Yes — privacy / data-residency / compliance implications |
| **Strategy-doc §2.4 zero-orchestration risk** | Low — scoped to lifecycle events | Bounded — in the LLM-turn path, but scoped to one certified stack and limited to cap-check + memory-inject + audit (no retry / fallback / cache). The *unscoped* generic proxy would not have this bound — which is why it was dropped |
| **Works for non-tool actions** (e.g. roll up session memory) | Yes — `Stop`/`SessionEnd` hooks | Yes — observe final assistant turn |
| **Works for certified device stacks** (Volcano RTC CustomLLM, …) | No — a device stack has no hook surface | Yes — the stack routes its LLM turn to our endpoint. (Arbitrary *unmanaged* hooks-less chatbots/scripts are **not** a target — the generic proxy that would have served them was dropped) |
| **Failure mode** | If host misfires hook, guarantee lost | If the in-path endpoint is down, no LLM turns resolve (fail closed) |
| **Comparable products** | Small space — Claude Code, Codex, Hermes, OpenClaw hooks | The *unscoped* version is the crowded gateway space (Vercel AI Gateway, Helicone, Portkey, OpenRouter, Cloudflare AI Gateway) — exactly why we ship a certified-stack endpoint, not an open gateway |

## 3. Hook availability across runtimes (verified 2026-05-28)

Live-probed where possible; flagged where inferred.

| Runtime | Hooks? | Lifecycle events available | Config location | Wire protocol | Claude-Code-compat shape | Confidence |
|---|---|---|---|---|---|---|
| **Claude Code** | ✅ Yes (richest) | ~24 events: `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `PermissionRequest`, `PermissionDenied`, `Stop`, `StopFailure`, `SubagentStart`, `SubagentStop`, `PreCompact`, `PostCompact`, `FileChanged`, `CwdChanged`, `ConfigChange`, `InstructionsLoaded`, `Elicitation/Result`, `Notification`, `TaskCreated/Completed`, `WorktreeCreate/Remove`, `Setup` | `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`, plugin `hooks.json` | stdin JSON `{session_id, hook_event_name, tool_name, tool_input, cwd, …}`; stdout JSON `{decision, reason, hookSpecificOutput.permissionDecision, additionalContext, …}` or exit 2 to block; types: `command`/`http`/`mcp_tool`/`prompt`/`agent` | reference shape | **Verified** ([code.claude.com/docs/en/hooks](https://code.claude.com/docs/en/hooks)) |
| **Codex (OpenAI)** | ✅ Yes | 10 events: `SessionStart`, `SubagentStart`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `UserPromptSubmit`, `SubagentStop`, `Stop` | `~/.codex/hooks.json`, `~/.codex/config.toml` (inline `[hooks]`), repo-local `.codex/hooks.json`, `.codex/config.toml` | stdin JSON `{session_id, transcript_path, cwd, hook_event_name, model, permission_mode}`; stdout JSON `{continue, stopReason, systemMessage, suppressOutput}` | Field names overlap (`PreToolUse`/`hook_event_name`); not officially declared Claude-Code-compatible. Needs a thin `decision ↔ continue` shim. | **Verified** ([developers.openai.com/codex/hooks](https://developers.openai.com/codex/hooks)) |
| **Hermes** (NousResearch) | ✅ Yes | 5+ events confirmed in source: `pre_tool_call`, `post_tool_call`, `pre_llm_call`, `on_session_end`, `subagent_stop`. Tool-call events accept `matcher:` to filter by tool name. | `~/.hermes/config.yaml` `hooks:` block + first-use consent allowlist at `~/.hermes/shell-hooks-allowlist.json` (auto-accept via `--accept-hooks`, `HERMES_ACCEPT_HOOKS=1`, or `hooks_auto_accept: true`) | stdin JSON `{hook_event_name, tool_name, tool_input, session_id, cwd, extra}`; stdout JSON — **explicitly accepts BOTH shapes**: Claude-Code-style `{"decision": "block", "reason": "…"}` AND Hermes-canonical `{"action": "block", "message": "…"}`. `pre_llm_call` supports `{"context": "…"}` injection. | ✅ **First-class** (per `agent/shell_hooks.py` docstring: *"either shape accepted; normalised internally"*) | **Verified live** — `hermes hooks --help` + source at `~/.hermes/hermes-agent/agent/shell_hooks.py` |
| **OpenClaw** | ⚠️ Likely yes (inferred from lineage) | Probably the same `pre_tool_call`/`post_tool_call`/`on_session_end`/`subagent_stop` set as Hermes — Hermes ships a `hermes claw` subcommand labeled *"OpenClaw migration tools"*. Public docs surface only HTTP webhook ingress, not lifecycle hooks. | Likely `~/.openclaw/config.yaml` (same shape as Hermes) — verify before promising | Likely identical to Hermes (Claude-Code-compatible) — verify | Likely ✅ — verify | **Inferred** — confirm by running `openclaw hooks --help` against a live install |
| **"Kimiclaw"** (hosted OpenClaw — hypothetical) | 🔧 Depends on host | If hosted faithfully, same events as OpenClaw; multi-tenant config moves from `~/.openclaw/config.yaml` to a per-tenant settings API. | Tenant settings panel + API (hypothetical) | Same as OpenClaw (assumed) | Same as OpenClaw (assumed) | **Hypothetical** — product doesn't exist yet under that name |
| **xiaozhi-server** (xinnan-tech) | ❌ No formal hooks | Plugin system (`core/providers/tools/`) supports custom tool registration + MCP integration (server/client/endpoint MCP protocols), but **no lifecycle hook surface** found in README/docs. Plugins are tool-level, not lifecycle-level. | `mcp_server_settings.json` registers MCP servers; plugin hot-loading via plugin system | None for hooks (only MCP tool registration) | N/A | **Inferred** — verify by reading source if production matters |

### 3.1 Reading the table

**Tier-1 hook hosts** — Claude Code, Codex, Hermes, (likely) OpenClaw:

- All four have lifecycle hooks the runtime fires deterministically around tool calls.
- All four converge on roughly the same shape: `~/.<host>/{settings,config,hooks}.{json,yaml,toml}` registers commands; stdin JSON with `hook_event_name` + `tool_name` + `tool_input`; stdout JSON with `decision`/`reason` to block.
- **Hermes is explicitly cross-compatible with Claude Code's JSON shape** — confirmed in source. Codex shape is similar but not officially declared compatible. OpenClaw likely follows Hermes.
- One shell script written for Claude Code can probably be reused across Hermes (definite) and OpenClaw (likely) with minor or zero shim. Codex needs a `decision` ↔ `continue` mapper.
- **Issue #133's reference-hook bundle is realistic across all four with low per-host adapter cost.**

**Hooks-less hosts** — xiaozhi-server, vendor mobile chatbots, plain `openai.ChatCompletion` scripts:

- No deterministic lifecycle gate, and **not agent runtimes**. AgentKeys does not ship a generic proxy to wrap them — that fallback was dropped 2026-06-19 (agent-first; §4).
- A **certified device stack** (e.g. Volcano RTC CustomLLM) gets a guarantee via the in-path endpoint (§2). An arbitrary hooks-less chatbot/script is reached, if at all, via SDK / MCP / direct adapter — not by routing it through an LLM gateway.

## 4. Decision (2026-05-28; revised 2026-06-19)

> **AgentKeys delivers IAM guarantees through two agent-first non-LLM seams — hooks for hook-capable Task Hosts, and the certified-stack in-path endpoint for device stacks. The generic OpenAI-compatible proxy fallback for unmanaged hooks-less hosts was dropped 2026-06-19: a host earns a guarantee by being an agent runtime or a certified device stack, not by being wrapped in a gateway.**

Rationale (anchored in [`agent-iam-strategy.md`](../../docs/agent-iam-strategy.md) §3.6):

| Both seams are agent-first | Why the generic proxy was dropped |
|---|---|
| **Hooks** stay cleanly on §2.1 Authority Host side — scoped to lifecycle events, not the path of every byte. One reference bundle ports across Tier-1 (Claude Code, Codex, Hermes, likely OpenClaw) thanks to Hermes's Claude-Code-compatible shape; issue [#133](https://github.com/litentry/agentKeys/issues/133) is the canonical track (reference hook configs + `agentkeys hook check` + cap-mint pre-warming). | A proxy in the path of every byte invites scope creep ("also retry?" "fallback model?" "cache?") that edges toward Task-Host territory — §2.4 mission-creep risk. |
| **The certified in-path endpoint** is a proxy *scoped to one validated stack* (Volcano RTC CustomLLM) — cap-check + memory-inject + audit only — so it is bounded, end-to-end-validated (latency / auth / billing), and the Phase-1 primary device seam. | The *generic, unscoped* version is a crowded, undifferentiated space (Vercel AI Gateway, Helicone, Portkey, OpenRouter, Cloudflare AI Gateway); non-agent hosts are better reached via SDK / MCP / direct adapter than by AgentKeys becoming a gateway business. |

## 5. Phased rollout

| Phase | Track | Deliverable |
|---|---|---|
| **Phase 1** (this PR + immediate follow-up) | MCP server | Extend [`crates/agentkeys-mcp-server`](../../crates/agentkeys-mcp-server) with the 7 Phase-1 tools (`identity.whoami`, `memory.get`, `memory.put`, `permission.check`, `cap.mint`, `cap.revoke`, `audit.append`) per strategy doc §4.2 |
| **Phase 1** | `agentkeys wire <runtime>` CLI + Hermes adapter | Single command that drops AgentKeys hook scripts into `~/.hermes/agent-hooks/` and appends the `hooks:` block to `~/.hermes/config.yaml` — three-act demo (Permissioned Memory / Deterministic Denial / Online Revocation per strategy doc §4.3). Full plan: `docs/plan/phase-1-fresh-user-wire-onboarding.md` (operator-internal) |
| **Phase 1** (device pilot) | Certified in-path endpoint | Volcano RTC CustomLLM → AgentKeys turn endpoint (cap-check + memory-inject + audit → Ark/Doubao) — the primary device seam; arch.md §22d.3 |
| **Phase 3** ([#133](https://github.com/litentry/agentKeys/issues/133)) | Hooks production | Reference hook configs for Hermes + Claude Code + Codex + OpenClaw; `agentkeys hook check` CLI helper; cap-mint pre-warming for sub-50ms p99 |
| **Phase 3b** | ~~Proxy fallback~~ **DROPPED (2026-06-19)** | The generic OpenAI-compatible proxy for unmanaged hooks-less hosts is no longer planned — agent-first; see §4. |
| **Phase 4** | Standards | Propose MCP extensions for IAM-grade auth headers; OAuth-for-Agents engagement. Per strategy doc §5 Phase 5. |

## 6. Cross-references

- [`docs/agent-iam-strategy.md`](../../docs/agent-iam-strategy.md) — strategic anchor: Authority Host vs Task Host (§2.1), zero-orchestration hard line (§2.4), MCP as integration surface (§2.3), Phase 1 MCP scope (§4.2), three-act demo (§4.3), 12-month roadmap (§5)
- [`docs/plan/issue-103-aiosandbox-hermes-esp32-demo.md`](../archived/issue-103-aiosandbox-hermes-esp32-demo.md) — execution plan for Phase 1
- `docs/plan/phase-1-fresh-user-wire-onboarding.md` (operator-internal) — Phase 1 plan that ships the `agentkeys wire` CLI delivering these hooks (the previous operator-facing summary at `docs/demo-aiosandbox-runbook.md` §6 was archived 2026-05-28)
- [Issue #133](https://github.com/litentry/agentKeys/issues/133) — Phase 3 LLM-host hook integration; the canonical track for the hooks deliverable
- [Issue #103](https://github.com/litentry/agentKeys/issues/103) — Phase 1 demo umbrella
