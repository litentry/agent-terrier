Companion to [`docs/agent-iam-strategy.md`](../../docs/agent-iam-strategy.md). Defines the load-bearing terminology AgentKeys uses when describing what an integration delivers — so vendor conversations don't confuse "the LLM can call our tool" with "the policy check actually runs."

## 1. IAM tool vs IAM guarantee

The distinction is about **who decides whether the policy check actually runs**.

| | Defined as... | Whether it runs is decided by... | Failure mode |
|---|---|---|---|
| **IAM tool** | A function in the LLM's tool registry (e.g. `agentkeys.permission.check(scope=…)`) | The LLM, based on its prompt + context + sampling | LLM forgets / skips / is jailbroken → unauthorized action proceeds |
| **IAM guarantee** | A non-LLM gate sitting in the execution path before the sensitive action runs | The runtime (hook system, proxy, OS capability, syscall filter) — deterministically | Runtime gate fails closed; action cannot proceed without an allow verdict |

**Concrete example — payment scenario:**

- *Tool-only:* User says "buy hotpot." The LLM has both `agentkeys.permission.check` and `payment.execute` in its tool registry. The system prompt asks it to check permission first. A prompt-injection in the user's input convinces the LLM to skip. **No guarantee.**
- *Guarantee:* User says "buy hotpot." The LLM emits `payment.execute(amount_rmb=600)`. The Task Host's `PreToolUse` hook fires before the call leaves the host, executes `agentkeys.permission.check(scope=payment.spend, amount=600)`, gets `denied: daily_spend_cap_exceeded`, **physically blocks the tool call from running**. The LLM's intent is irrelevant. **Guarantee.**

Anchored in [`agent-iam-strategy.md`](../../docs/agent-iam-strategy.md) §3.1 (bounded revocation: *"high-risk = always online permission check + fresh cap-token mint per call"*) and [issue #133](https://github.com/litentry/agentKeys/issues/133) (*"hooks move those guarantees out of LLM discretion and into the runtime"*).

## 2. How AgentKeys delivers guarantees — two tracks

| Track | Mechanism | Where it sits | Strategy-doc fit |
|---|---|---|---|
| **Primary — Hooks** ([#133](https://github.com/litentry/agentKeys/issues/133)) | Task Host fires `PreToolUse` / `PostToolUse` / `SessionEnd` hooks that execute AgentKeys MCP tool calls synchronously around tool use | Inside the Task Host runtime, between LLM tool-call emission and execution | Stays cleanly on §2.1 Authority Host side; lifecycle-event-scoped, not in the path of every byte |
| **Fallback — Proxy** | LLM client's `base_url` points at an AgentKeys-hosted OpenAI-compatible endpoint that intercepts prompts + tool_calls + responses, enforces policy, logs audit, then forwards | Between the LLM client and the LLM provider | Works for hook-less hosts but edges toward §2.4 mission-creep; competitively crowded space (Vercel AI Gateway, Helicone, Portkey, OpenRouter) |

### 2.1 Hooks vs proxy — full trade-off table

| Dimension | Hook approach | Proxy approach |
|---|---|---|
| **Where it sits** | Inside the Task Host runtime, between "LLM decided to call tool X" and "tool X runs" | Between the LLM client and the LLM provider (OpenAI / DashScope / Anthropic / etc.) |
| **What it sees** | Tool-call events: `name`, `params`, `result`; lifecycle events: `Stop`, `SessionEnd` | Every prompt, every completion, every `tool_calls` array, every `tool_result` |
| **What it can enforce** | Allow/deny tool calls; trigger side effects at lifecycle events | Anything in the LLM conversation: rewrite system prompt, strip/replace tool_calls, redact PII, terminate session |
| **Host modification needed** | Edit host's settings file (`~/.claude/settings.json` / `~/.codex/hooks.json` / `~/.hermes/config.yaml` / etc.) | Change one env var: `OPENAI_BASE_URL=https://agentkeys-proxy.../v1` |
| **Host must support...** | A hook lifecycle vocabulary (PreToolUse, PostToolUse, Stop). Each host has its own. | OpenAI-compatible Chat Completions API — the de facto standard |
| **Cross-runtime portability** | Per-host adapter code | One implementation works for all OpenAI-compatible clients |
| **Latency added per LLM call** | One sync hook per tool use (~1–50ms with cap pre-warming) | Full network hop on every LLM call (~50–300ms) |
| **Streaming responses** | Preserved | Proxy must re-stream upstream; doable but extra engineering |
| **Vendor sends prompts through AgentKeys?** | No | Yes — privacy / data-residency / compliance implications |
| **Strategy-doc §2.4 zero-orchestration risk** | Low — scoped to lifecycle events | Higher — in the path of every byte invites scope creep |
| **Works for non-tool actions** (e.g. roll up session memory) | Yes — `Stop`/`SessionEnd` hooks | Yes — observe final assistant turn |
| **Works for hooks-less hosts** (legacy chatbots, mobile SDKs, plain `openai.ChatCompletion` scripts) | No — needs host cooperation | Yes — change one env var |
| **Failure mode** | If host misfires hook, guarantee lost | If proxy is down, no LLM calls work at all (fail closed) |
| **Comparable products** | Small space — Claude Code, Codex, Hermes, OpenClaw, xiaozhi-server hooks | Crowded — Vercel AI Gateway, Helicone, LangSmith, Portkey, OpenRouter, Cloudflare AI Gateway |

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

**Tier-2 hosts without hooks** — xiaozhi-server, vendor mobile chatbots, plain `openai.ChatCompletion` scripts:

- No deterministic lifecycle gate. Only the proxy fallback delivers IAM guarantees here.
- Use the proxy approach. Strategy doc §2.4 mission-creep risk applies; the proxy track is **sequenced after** the hook track lands.

## 4. Decision (2026-05-28)

> **AgentKeys ships hooks as the primary IAM-guarantee mechanism, with the OpenAI-compatible proxy as a lower-priority fallback for hosts that don't expose a hook system.**

Rationale (anchored in [`agent-iam-strategy.md`](../../docs/agent-iam-strategy.md)):

| Why hooks first | Why proxy second (not first, not skipped) |
|---|---|
| Stays cleanly on §2.1 Authority Host side — hooks are scoped to lifecycle events, not in the path of every byte | Some hosts (xiaozhi-server, vendor mobile SDKs, single-turn `openai.ChatCompletion` scripts) have no hook surface — without the fallback they're unreachable |
| Tier-1 hosts cover the strategically-important runtimes (Claude Code, Codex, Hermes, likely OpenClaw) — one investment, four runtimes | Proxy lives in the request path → invites scope creep ("can you also retry?" "fallback model?" "cache?") that edges toward Task Host territory — §2.4 mission-creep risk |
| Hermes's Claude-Code-compatible JSON shape means a single reference script bundle ports across Tier-1 with thin shims — low per-host adapter cost | Crowded competitive space (Vercel AI Gateway, Helicone, LangSmith, Portkey, OpenRouter, Cloudflare AI Gateway) — we want this only when our authority position is established and we own the IAM-shaped differentiation |
| Issue [#133](https://github.com/litentry/agentKeys/issues/133) is the canonical track for this work; reference hook configs + `agentkeys hook check` CLI helper + cap-mint pre-warming are already scoped | Proxy work is tracked separately; lands after #133 hook references ship + at least one vendor pilot is on hooks |

## 5. Phased rollout

| Phase | Track | Deliverable |
|---|---|---|
| **Phase 1** (this PR + immediate follow-up) | MCP server | Extend [`crates/agentkeys-mcp-server`](../../crates/agentkeys-mcp-server) with the 7 Phase-1 tools (`identity.whoami`, `memory.get`, `memory.put`, `permission.check`, `cap.mint`, `cap.revoke`, `audit.append`) per strategy doc §4.2 |
| **Phase 1** | `agentkeys wire <runtime>` CLI + Hermes adapter | Single command that drops AgentKeys hook scripts into `~/.hermes/agent-hooks/` and appends the `hooks:` block to `~/.hermes/config.yaml` — three-act demo (Permissioned Memory / Deterministic Denial / Online Revocation per strategy doc §4.3). Full plan: [`docs/plan/phase-1-fresh-user-wire-onboarding.md`](../plan/phase-1-fresh-user-wire-onboarding.md) |
| **Phase 3** ([#133](https://github.com/litentry/agentKeys/issues/133)) | Hooks production | Reference hook configs for Hermes + Claude Code + Codex + OpenClaw; `agentkeys hook check` CLI helper; cap-mint pre-warming for sub-50ms p99 |
| **Phase 3b** (after #133) | Proxy fallback | OpenAI-compatible proxy endpoint for hooks-less hosts (xiaozhi-server, vendor mobile chatbots). Lower priority. |
| **Phase 4** | Standards | Propose MCP extensions for IAM-grade auth headers; OAuth-for-Agents engagement. Per strategy doc §5 Phase 5. |

## 6. Cross-references

- [`docs/agent-iam-strategy.md`](../../docs/agent-iam-strategy.md) — strategic anchor: Authority Host vs Task Host (§2.1), zero-orchestration hard line (§2.4), MCP as integration surface (§2.3), Phase 1 MCP scope (§4.2), three-act demo (§4.3), 12-month roadmap (§5)
- [`docs/plan/issue-103-aiosandbox-hermes-esp32-demo.md`](../plan/issue-103-aiosandbox-hermes-esp32-demo.md) — execution plan for Phase 1
- [`docs/plan/phase-1-fresh-user-wire-onboarding.md`](../plan/phase-1-fresh-user-wire-onboarding.md) — Phase 1 plan that ships the `agentkeys wire` CLI delivering these hooks (the previous operator-facing summary at `docs/demo-aiosandbox-runbook.md` §6 was archived 2026-05-28)
- [Issue #133](https://github.com/litentry/agentKeys/issues/133) — Phase 3 LLM-host hook integration; the canonical track for the hooks deliverable
- [Issue #103](https://github.com/litentry/agentKeys/issues/103) — Phase 1 demo umbrella
