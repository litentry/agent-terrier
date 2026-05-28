# Phase 1 — Fresh-user onboarding via `agentkeys wire`

**Status:** DRAFT 2026-05-28
**Tracking issue:** TBD (to be filed)
**Strategic anchor:** [`docs/agent-iam-strategy.md`](../../agent-iam-strategy.md) §4 (Revised Phase 1)
**Architecture record:** [`docs/arch.md`](../../arch.md) §22d (IAM-guarantee delivery — hooks-first, proxy-fallback) — to be extended with §22d.6 once this plan lands
**Replaces:** the C4/C5/C6 Rust-runtime sections of [`issue-103-aiosandbox-hermes-esp32-demo.md`](issue-103-aiosandbox-hermes-esp32-demo.md), now superseded by real Hermes + AgentKeys hooks
**Companions:**
- [`docs/wiki/agent-iam-guarantee-glossary.md`](../../wiki/agent-iam-guarantee-glossary.md) — IAM guarantee architecture (the previous operator-facing summary at `docs/demo-aiosandbox-runbook.md` §6 was archived 2026-05-28; a new lean runbook lands with this plan's Phase 1.a implementation)
- [`docs/wiki/agent-iam-guarantee-glossary.md`](../../wiki/agent-iam-guarantee-glossary.md) — terminology (IAM tool vs IAM guarantee, hooks vs proxy)
- [Issue #133](https://github.com/litentry/agentKeys/issues/133) — the canonical track for hook reference configs (this plan delivers it as `agentkeys wire`)

## 1. Goal — the 7-step user journey

A fresh user reaches the **Agent IAM "surprise" moment** (Act 1 Permissioned Memory from strategy doc §4.3) in under 15 minutes, with **zero manual config-file editing**.

The 7 steps:

| # | User action | What happens | Where state lives |
|---|---|---|---|
| 1 | Install aiosandbox: `docker run --security-opt seccomp=unconfined ... ghcr.io/agent-infra/sandbox:latest` | Sandbox container up; native MCP at `:8080/mcp` | Container runtime |
| 2 | `curl -fsSL https://agentkeys.io/install.sh \| bash` | AgentKeys CLI installed; bootstraps device key; requests pairing — arch.md §10.2 link-code flow | `~/.agentkeys/` (device-local) |
| 3 | On master device: approve pairing; `agentkeys creds add <provider>`, `agentkeys memory grant <namespace>` | Master device approves; LLM API keys land in the credential broker; memory namespaces scoped | AgentKeys broker (cloud) + master device K10/K11 |
| 4 | Install a Task Host: `pip install hermes-agent` / `brew install codex` / `npm i -g @anthropic-ai/claude-code` / etc. **Do NOT run the runtime's setup wizard.** | Task Host binary on disk, no config yet | `~/.<runtime>/` (uninitialized) |
| 5 | `agentkeys wire hermes` (or `wire codex`, `wire claude-code`, `wire openclaw`, …) | Single CLI command. Idempotent. | Drives steps 6 from the master device |
| 6 | AgentKeys: (a) fetches provider-specific LLM key from broker, (b) writes runtime bootstrap config (model/base_url/api_key), (c) drops AgentKeys hook scripts into the runtime's canonical hook dir, (d) appends `hooks:` block to runtime config, (e) pre-approves first-use consent, (f) verifies with the runtime's `hooks doctor` equivalent | Runtime is now wired with AgentKeys IAM guarantees | Runtime config + AgentKeys audit row |
| 7 | User opens the runtime; first conversation: *"Where am I going this weekend?"* → memory-aware response referencing the travel-namespace memory | Act 1 Permissioned Memory plays out. The user never edited a config file. | The surprise moment |

This is the **demo Phase 1 ships** — same three acts from strategy doc §4.3 (Permissioned Memory / Deterministic Denial / Online Revocation), accessed through a user journey that doesn't require config-file fluency.

## 2. The central design question — manual vs automatic onboarding

The pivotal design call: when an open-source LLM runtime without OAuth (Hermes, OpenClaw) hasn't been bootstrapped yet, who completes its setup?

### Two extremes

| | Manual (user runs the runtime's wizard) | Automatic (AgentKeys writes the config files) |
|---|---|---|
| **Fresh-user friction** | User runs `agentkeys wire …` AND `hermes setup` — two wizards | One command — `agentkeys wire …` is enough |
| **Demo "surprise" effect** | Diluted — user already configured the runtime, so "memory just works" feels less magical | Strong — user installed and never set up; first chat already remembers them |
| **Maintenance burden on AgentKeys** | Low — runtime's own wizard owns the format | Higher — AgentKeys must track each runtime's config schema; nightly drift check needed |
| **Trust surface** | Lower — AgentKeys doesn't touch unrelated runtime config | Higher — AgentKeys writes to runtime config files (privileged config per Hermes shell-hooks docs) |
| **Failure recovery** | User runs the runtime's wizard, ignores AgentKeys | If our adapter has a bug, the runtime is in a broken state requiring manual fix |
| **Edge cases** | Runtime's wizard handles OAuth state, region picks, model availability natively | We have to replicate that logic per-runtime |
| **Vendor moat** | "AgentKeys is the IAM layer" | "AgentKeys is the single CLI that wires up everything" — broader pitch surface |

### Decision: hybrid (automatic for IAM-gate config; runtime owns its own bootstrap)

The right design is **not either-or**. The split:

- **AgentKeys automatically writes the IAM-gate config**: the `hooks:` block in `~/.hermes/config.yaml` (or equivalent), the hook scripts in `~/.hermes/agent-hooks/`, the first-use consent pre-approval. This is the part AgentKeys *must* own — vendors won't write our hook scripts for us, and the value proposition collapses if users have to.
- **AgentKeys automatically writes the LLM-provider config** *when the user has provisioned an API key with us* in step 3: model picker, base_url, api_key. The key comes from the credential broker — same trust chain that gates memory/payment scopes. If the user hasn't provisioned a key, we prompt to add one (`agentkeys creds add openai`) and re-run.
- **The runtime's own bootstrap stays manual for OAuth flows** (Claude Code login, Codex login, Hermes Portal OAuth). These cannot be scripted from another machine — they require interactive consent at the runtime's own auth surface. `agentkeys wire <runtime>` prints clear next-step instructions when it detects an OAuth-required runtime in an unauthed state.
- **Idempotency is the trick**: per CLAUDE.md's idempotent-remote-setup rule, `agentkeys wire <runtime>` is safe to re-run. It diffs current config against intended config, writes only on drift, logs `ok proceeding / skip <reason> / fail <reason>` per step.
- **Drift detection runs nightly**: a `Cron` job re-runs `agentkeys wire --check-only <runtime>` on the master device, alerts the user if a runtime config has drifted (e.g. user manually edited the `hooks:` block) so AgentKeys can re-converge or back off cleanly.

This hybrid keeps the magic for the common case (provider provisioned + non-OAuth host) while not pretending we can drive every flow. Vendors with OAuth-required Task Hosts (Claude Code, Codex) get a partial-automation experience plus a clear "now run `claude login`" instruction — still better than figuring out config formats themselves.

### Why this matches the strategy doc

- **§2.1 Authority Host vs Task Host** — AgentKeys writes IAM-gate config (Authority concern); the runtime's own LLM-bootstrap config is technically Task-Host territory, but threading the LLM API key through the credential broker is an Authority-side service. The hybrid stays on the right side of the line.
- **§2.4 Zero orchestration** — `agentkeys wire` is configuration provisioning, not runtime orchestration. It runs once + on drift. It does not sit in the agent's request path.
- **§2.5 Deploy → grow → standardize** — ship the hybrid for Hermes (open-source, scriptable) first; expand to OAuth-required hosts once we have a vendor pilot validating the wire model.

## 3. The `agentkeys wire <runtime>` CLI surface

### 3.1 Command shape

```
agentkeys wire <runtime>
  [--check-only]                    # diff against intended config; no writes
  [--reapply]                       # force re-write even if drift-free
  [--llm-provider <name>]           # override the credential the broker mints (e.g. openai|anthropic|dashscope)
  [--actor-omni <omni>]             # which actor identity to wire (default: master's primary)
  [--scope <namespace>[,<ns>...]]   # memory namespaces this runtime can read
  [--accept-hooks]                  # auto-accept first-use consent (default: yes)
  [--dry-run]                       # print intended actions; touch nothing
  [--verbose]                       # detailed log per adapter step
```

`<runtime>` is one of the Tier-1 hosts (hermes, openclaw, claude-code, codex) for Phase 1; xiaozhi-server moves into Phase 3b (via proxy fallback, see strategy doc §5 Phase 3b).

### 3.2 Per-invocation output

Per CLAUDE.md idempotent-remote-setup convention:

```
[agentkeys wire hermes] step 1 — detect runtime version: ok proceeding (hermes v0.14.0)
[agentkeys wire hermes] step 2 — verify master pairing: ok proceeding (master O_kevin_001, K11 valid)
[agentkeys wire hermes] step 3 — fetch LLM credential for openai: ok proceeding (cap_id=cap_a1b2c3, ttl=3600s)
[agentkeys wire hermes] step 4 — write hermes model config: skip already configured (model.provider=openai matches)
[agentkeys wire hermes] step 5 — drop hook scripts to ~/.hermes/agent-hooks/: ok proceeding (3 scripts)
[agentkeys wire hermes] step 6 — append hooks: block to ~/.hermes/config.yaml: ok proceeding (3 entries added, 0 changed)
[agentkeys wire hermes] step 7 — pre-approve first-use consent: ok proceeding (HERMES_ACCEPT_HOOKS=1 via auto_accept config flag)
[agentkeys wire hermes] step 8 — hermes hooks doctor: ok proceeding (all 3 hooks pass; mtime drift clean)
[agentkeys wire hermes] step 9 — audit row: ok proceeding (wire_complete event appended)
[agentkeys wire hermes] complete (8 ok, 1 skip, 0 fail)
```

### 3.3 What the adapter writes — Hermes example

After `agentkeys wire hermes`, the following lands in the user's filesystem:

```yaml
# ~/.hermes/config.yaml  (existing keys preserved; AgentKeys appends only)
hooks:
  pre_tool_call:
    - matcher: "^(payment|email|credential).*"
      command: "~/.hermes/agent-hooks/agentkeys-pretool-permission-gate.sh"
      timeout: 5
  post_tool_call:
    - matcher: ".*"
      command: "~/.hermes/agent-hooks/agentkeys-posttool-audit.sh"
      timeout: 5
  pre_llm_call:
    - command: "~/.hermes/agent-hooks/agentkeys-prellm-memory-inject.sh"
      timeout: 5

hooks_auto_accept: true
```

```bash
# ~/.hermes/agent-hooks/agentkeys-pretool-permission-gate.sh
#!/usr/bin/env bash
# Issued by `agentkeys wire hermes` v<X>. Do not edit by hand — re-run wire to update.
exec agentkeys hook check --event pre_tool_call --actor "$AGENTKEYS_ACTOR_OMNI"
```

```bash
# ~/.hermes/agent-hooks/agentkeys-posttool-audit.sh
#!/usr/bin/env bash
exec agentkeys hook audit --event post_tool_call --actor "$AGENTKEYS_ACTOR_OMNI"
```

```bash
# ~/.hermes/agent-hooks/agentkeys-prellm-memory-inject.sh
#!/usr/bin/env bash
exec agentkeys hook memory-inject --event pre_llm_call --actor "$AGENTKEYS_ACTOR_OMNI" --scope travel,personal
```

The user-facing `agentkeys hook check / audit / memory-inject` subcommands wrap the host's stdin/stdout JSON convention (per [issue #133](https://github.com/litentry/agentKeys/issues/133)'s `agentkeys hook check` helper), call AgentKeys MCP tools via the local daemon's cap-cached path, and return the right shape to the host.

### 3.4 Adapter trait

Internally, `agentkeys wire` dispatches to one adapter per runtime. The trait:

```rust
#[async_trait]
pub trait RuntimeAdapter: Send + Sync {
    /// Stable identifier (`"hermes"`, `"codex"`, `"claude-code"`, …)
    fn name(&self) -> &'static str;

    /// Detect installed runtime + version; returns None if not installed.
    async fn detect(&self) -> Result<Option<RuntimeInstall>, AdapterError>;

    /// Compute intended-state config given an WireRequest (actor, scopes, credential refs).
    async fn plan(&self, req: &WireRequest, install: &RuntimeInstall) -> Result<WirePlan, AdapterError>;

    /// Diff intended state against current state; emit step-by-step actions.
    async fn diff(&self, plan: &WirePlan) -> Result<Vec<WireAction>, AdapterError>;

    /// Apply (or check) a single action idempotently.
    async fn apply(&self, action: &WireAction, dry_run: bool) -> Result<ActionOutcome, AdapterError>;

    /// Verify post-apply state via the runtime's own health/doctor command.
    async fn verify(&self, plan: &WirePlan) -> Result<VerifyReport, AdapterError>;
}
```

Each adapter lives in a separate file under `crates/agentkeys-cli/src/wire/adapters/` so version bumps for each runtime stay isolated.

## 4. Per-runtime adapter specifications

| Runtime | Hooks system | Adapter writes | LLM-key flow | Manual steps user must do |
|---|---|---|---|---|
| **Hermes** | Shell hooks in `~/.hermes/config.yaml` (verified via [`agent-iam-guarantee-glossary.md`](../../wiki/agent-iam-guarantee-glossary.md) §3) | `hooks:` block + scripts in `~/.hermes/agent-hooks/` + `hooks_auto_accept: true`. Bootstrap: `hermes config set model.provider …` etc. | Fetched from broker; written into `~/.hermes/config.yaml` under `model.api_key` | None for default flow; Nous Portal OAuth only if user wants Portal-routed inference |
| **OpenClaw** | Likely shell hooks (inferred from Hermes lineage; **verify before locking in**) | Likely same as Hermes; verify with live install | Same as Hermes | TBD pending verification |
| **Claude Code** | Hooks via `~/.claude/settings.json` (24+ events) | `hooks.PreToolUse/PostToolUse/Stop/etc.` blocks; scripts in `~/.claude/hooks/` | Anthropic API key via `claude config set` OR Claude account OAuth | `claude login` if using account auth |
| **Codex** | Hooks via `~/.codex/hooks.json` or `~/.codex/config.toml` (10 events) | Hook bindings via the `[hooks]` table; scripts in `~/.codex/hooks/` | OpenAI API key via `codex auth login` OR ChatGPT account | `codex auth login` |
| **xiaozhi-server** | No formal hooks — Phase 3b proxy fallback | n/a (out of Phase 1 wire scope) | n/a | Use the proxy fallback per strategy §5 Phase 3b |

Only Hermes is in Phase 1.a (initial ship); OpenClaw + Claude Code + Codex land in Phase 1.b after the Hermes adapter validates the approach.

## 5. Implementation surface

### 5.1 New CLI subcommand
- `agentkeys wire <runtime>` — main entry point. Lives in `crates/agentkeys-cli/`.

### 5.2 Hook-helper subcommands (called BY the dropped hook scripts)
- `agentkeys hook check --event <event> --actor <omni>` — reads host JSON from stdin, calls `agentkeys.permission.check` via MCP, returns host-appropriate JSON to stdout.
- `agentkeys hook audit --event <event> --actor <omni>` — reads host JSON, calls `agentkeys.audit.append`, returns `{}`.
- `agentkeys hook memory-inject --event pre_llm_call --actor <omni> --scope <ns>` — reads host JSON, calls `agentkeys.memory.get(actor, namespaces)`, returns `{"context": "..."}`.

These three helpers are what makes the hook scripts trivial (single `exec` line) and updatable without touching the user's filesystem — bug fixes ship in the AgentKeys CLI binary.

### 5.3 Adapter modules
- `crates/agentkeys-cli/src/wire/mod.rs` — dispatcher
- `crates/agentkeys-cli/src/wire/adapters/hermes.rs` — Phase 1.a
- `crates/agentkeys-cli/src/wire/adapters/openclaw.rs` — Phase 1.b
- `crates/agentkeys-cli/src/wire/adapters/claude_code.rs` — Phase 1.b
- `crates/agentkeys-cli/src/wire/adapters/codex.rs` — Phase 1.b

### 5.4 Drift-detection cron
- `agentkeys cron install --wire-drift-check` — schedules `agentkeys wire --check-only --all` nightly; alerts the user via the parent-control web UI if a wired runtime has drifted.

### 5.5 AgentKeys MCP server (prerequisite, tracked separately under [#107](https://github.com/litentry/agentKeys/issues/107))
- The 7 Phase-1 tools from strategy doc §4.2 must be live before `agentkeys wire` can complete. Wire is the *operator-facing* surface; the MCP server is the *runtime-facing* surface.

## 6. Deliverables (Phase 1.a)

| # | Deliverable | Tracking | Verify by |
|---|---|---|---|
| 1 | `agentkeys-mcp-server` exposes 7 Phase-1 tools | [#107](https://github.com/litentry/agentKeys/issues/107) | MCP `tools/list` returns the 7 tools |
| 2 | `agentkeys wire hermes` subcommand | this plan | Fresh aiosandbox + hermes install + `agentkeys wire hermes` → `hermes chat` shows memory-aware response |
| 3 | `agentkeys hook check / audit / memory-inject` helpers | this plan | Synthetic stdin JSON → expected stdout JSON for each event |
| 4 | Hermes adapter (`crates/agentkeys-cli/src/wire/adapters/hermes.rs`) | this plan | Unit tests for plan/diff/apply/verify against a stubbed Hermes home |
| 5 | Pre-approval logic for Hermes consent | this plan | `hermes hooks doctor` reports all 3 hooks approved + clean |
| 6 | Drift-detection check (single-invocation, no cron yet) | this plan | `agentkeys wire hermes --check-only` after manual edit reports diff + exit code |
| 7 | Write NEW lean operator runbook from scratch using the 7-step wire flow (the previous runbook was archived 2026-05-28 under `docs/archived/demo-aiosandbox-runbook-rust-runtime-2026-05.md`) | New `docs/operator-runbook-wire.md` (TBD path) | Operator follows runbook end-to-end in <15 min |
| 8 | 7-step storyboard demo script (vendor pitch) | strategy doc §4.3 update | 4-minute live demo lands the surprise moment |

## 7. Risks + open questions

| Risk | Mitigation |
|---|---|
| Runtime config schema drifts (Hermes/Codex/Claude Code release new version with breaking config changes) | Nightly drift-check; pin a supported version range per adapter; warn on unsupported versions; fall back to "print instructions" mode |
| User has hand-edited config; AgentKeys overwrites their changes | Adapter MUST preserve existing keys (only add/modify within the AgentKeys-owned section, marked with sentinel comments); detect non-AgentKeys hooks and refuse to clobber |
| Hook script invokes `agentkeys` CLI which isn't on PATH for the runtime's subprocess | Adapter writes absolute path to `agentkeys` binary into hook scripts; verifies with `hermes hooks doctor` after install |
| API key rotation — credential broker rotates LLM key, runtime's cached config now stale | Hook scripts fetch the key on-demand from the daemon (cap-cached), not from a frozen value in the config file. Adapter writes a placeholder + a fetch hook; never writes the literal key into the config |
| OAuth-required runtimes can't be wired fully | Adapter detects unauth state; emits clear "run `claude login` then re-run `agentkeys wire claude-code`" instruction; exits non-zero |
| Audit row for `wire_complete` could leak which runtimes the operator uses if audit is shared | Audit row is per-actor-omni; visible only to the operator's master device + parent-control UI; not exposed to third parties |
| User runs `agentkeys wire` on a non-master device | Reject — wire requires master device for credential mint authorization; print error pointing at the master device |

### Open questions
1. **Detection of installed runtimes** — do we scan `$PATH` + well-known config dirs, or require the user to opt-in per-runtime? **Initial answer**: opt-in per `agentkeys wire <runtime>` invocation; no auto-detection. Detection-and-warn can land in Phase 1.b.
2. **Version pinning** — how strictly do we match the runtime's version? **Initial answer**: per-adapter min/max version constants; warn on out-of-range but attempt the wire anyway (the user can re-run with `--force` after upgrading).
3. **Cred rotation policy** — when LLM keys rotate, do we auto-re-wire or wait for the next user-initiated call? **Initial answer**: hook scripts fetch keys on-demand from daemon cap-cache, so rotation is transparent. Only the model.provider / model.default fields are pinned in config and rarely change.
4. **`wire --all` semantics** — should `agentkeys wire --all` wire every installed runtime, or only ones the user has explicitly opted into? **Initial answer**: only explicitly-opted-in runtimes, recorded in `~/.agentkeys/wired_runtimes.toml`.

## 8. Sequencing within Phase 1

### Phase 1.a (this PR's follow-up scope, ~2 weeks)

1. Land `agentkeys-mcp-server` 7-tool surface ([#107](https://github.com/litentry/agentKeys/issues/107))
2. Land `agentkeys hook check / audit / memory-inject` helpers
3. Land `agentkeys wire hermes` adapter
4. Update demo runbook to the 7-step wire flow
5. End-to-end demo: fresh aiosandbox + fresh hermes install + `agentkeys wire hermes` + Act 1 Permissioned Memory

### Phase 1.b (~2-3 weeks after 1.a)

1. Add `agentkeys wire claude-code` adapter
2. Add `agentkeys wire codex` adapter
3. Add `agentkeys wire openclaw` adapter (verify hook system first)
4. Add `agentkeys wire --check-only` drift detection
5. Add nightly drift-check cron

### Phase 1.c (~4 weeks after 1.b)

1. Parent-control web UI shows wired-runtime status + drift alerts
2. Audit-feed integration showing wire-completion events
3. Vendor onboarding documentation referencing the wire model

### Phase 3b (separate from this plan, post-Phase-3 per strategy doc §5)

1. OpenAI-compatible proxy for hosts without hooks (xiaozhi-server, mobile chatbots, plain `openai.ChatCompletion` scripts)

## 9. What is removed from this PR (contradictions superseded by this plan)

The previous direction in this PR built a custom Rust HTTP runtime (`agentkeys-hermes-runtime`) that bridged memory → LLM. That approach is **superseded** by:

- Real Hermes (NousResearch) as the Task Host inside aiosandbox
- AgentKeys MCP server providing the 7 IAM tools
- AgentKeys hooks (delivered by `agentkeys wire`) wrapping those tools as IAM guarantees

Artifacts archived 2026-05-28 (moved to `docs/archived/` per CLAUDE.md "Move stale files there, don't delete"):

| Artifact (pre-archive path) | Disposition | Archived location |
|---|---|---|
| `docs/demo-aiosandbox-runbook.md` | Moved (entire file — including the §6 architecture content, now duplicated in [arch.md §22d](../../arch.md) + [wiki glossary](../../wiki/agent-iam-guarantee-glossary.md)) | [`docs/archived/demo-aiosandbox-runbook-rust-runtime-2026-05.md`](../../archived/demo-aiosandbox-runbook-rust-runtime-2026-05.md) |
| `docs/verify-issue-103.md` | Moved (tested the obsolete Rust crate); replaced by per-step verification in the future wire-flow runbook | [`docs/archived/verify-issue-103-rust-runtime-2026-05.md`](../../archived/verify-issue-103-rust-runtime-2026-05.md) |
| `scripts/setup-demo-aiosandbox.sh` | Moved (provisioned the Rust runtime image); replaced by `agentkeys wire hermes` | [`docs/archived/setup-demo-aiosandbox-rust-runtime-2026-05.sh`](../../archived/setup-demo-aiosandbox-rust-runtime-2026-05.sh) |
| `docker/aiosandbox-demo/` (directory: Dockerfile + supervisord configs + nginx fragment) | Moved; Hermes install goes via `agentkeys wire hermes` against a stock sandbox container | [`docs/archived/aiosandbox-demo-rust-runtime-2026-05/`](../../archived/aiosandbox-demo-rust-runtime-2026-05/) |

Code-side contradictions still requiring disposition (await operator confirmation before removing):

| Artifact | Recommended disposition | Reason |
|---|---|---|
| [`crates/agentkeys-hermes-runtime/`](../../../crates/agentkeys-hermes-runtime/) (entire crate, ~600 lines of Rust + tests) | Remove from `Cargo.toml` workspace `members`; delete crate dir (git history preserves) | The crate's role is now played by real Hermes inside aiosandbox; the wire CLI replaces the HTTP runtime. No follow-up needs this code. |
| [`crates/agentkeys-daemon/src/demo_memory.rs`](../../../crates/agentkeys-daemon/src/demo_memory.rs) + `--demo-memory` daemon flag + the `run_demo_memory_mode()` function in `main.rs` | Remove the module, the flag, and the dispatch path | Replaced by `agentkeys.memory.get` MCP tool calling the production memory worker; demo memory ingest is via `agentkeys creds add` / `agentkeys memory put` from the master CLI instead. |
| [`tests/fixtures/demo-profile.md`](../../../tests/fixtures/demo-profile.md) | **Keep** — re-used as the seed profile content loaded into S3 by the Phase 1 demo bootstrap | Still the canonical demo-user profile; new role is "S3 seed", not "compile-time include" |

The fixture [`tests/fixtures/demo-profile.md`](../../../tests/fixtures/demo-profile.md) STAYS — it's still the demo profile content, just loaded into S3 (via the real memory worker path) instead of bundled into a Rust binary.

## 10. Cross-references

- [strategy doc §4](../../agent-iam-strategy.md) — Phase 1 demo storyboard (three acts) that this plan operationalizes
- [strategy doc §3.6](../../agent-iam-strategy.md) — IAM tool vs IAM guarantee distinction; this plan delivers the guarantee layer
- [arch.md §22d](../../arch.md) — IAM-guarantee delivery (hooks-first, proxy-fallback) at the architecture level
- [wiki glossary](../../wiki/agent-iam-guarantee-glossary.md) — standalone terminology + hook availability table across runtimes
- [issue #107](https://github.com/litentry/agentKeys/issues/107) — AgentKeys MCP server (prerequisite for this plan)
- [issue #133](https://github.com/litentry/agentKeys/issues/133) — Phase 3 hook integration; this plan ships Phase 1's hook-driven IAM guarantees as `agentkeys wire`

## 11. What landed / What did NOT land (per [CLAUDE.md plan-completion policy](../../../CLAUDE.md))

### What landed (Phase 1.a, this PR)

1. **`agentkeys hook` helpers** — [`crates/agentkeys-cli/src/hook.rs`](../../../crates/agentkeys-cli/src/hook.rs). Three subcommands (`check`, `audit`, `memory-inject`) that read host stdin JSON, call AgentKeys MCP tools over HTTP (`tools/call` → `result.structuredContent`), and emit host-shaped stdout JSON. `check` fails CLOSED. 6 unit tests.
2. **`agentkeys wire hermes`** — [`crates/agentkeys-cli/src/wire.rs`](../../../crates/agentkeys-cli/src/wire.rs). `RuntimeAdapter` trait + `HermesAdapter`: detects Hermes, writes 3 hook scripts to `~/.hermes/agent-hooks/` (identity baked in, absolute `agentkeys` path), merges a sentinel-delimited managed `hooks:` block into `~/.hermes/config.yaml` (preserves other keys, refuses to clobber foreign `hooks:`), sets `hooks_auto_accept: true`, verifies via `hermes hooks doctor`. Idempotent (`ok proceeding / skip / fail` per step); `--check-only` reports drift without writing. 7 unit tests.
3. **CLI wiring** — `Commands::Wire` + `Commands::Hook` + `HookAction` in [`main.rs`](../../../crates/agentkeys-cli/src/main.rs); `pub mod hook; pub mod wire;` in [`lib.rs`](../../../crates/agentkeys-cli/src/lib.rs).
4. **MCP server 7 tools** — already shipped under [#107](https://github.com/litentry/agentKeys/issues/107); verified the hook helpers call them correctly.
5. **Drift detection** — `agentkeys wire hermes --check-only` (single-invocation; the nightly cron wrapper is deferred — see below).
6. **Operator runbook** — [`docs/operator-runbook-wire.md`](../../operator-runbook-wire.md) — the 7-step flow + the three-act demo verification, with commands verified end-to-end.
7. **End-to-end smoke test verified** (against the in-memory MCP backend on the host):
   - Act 1 Permissioned Memory: `memory-inject travel` → `{"context":"## Memory: travel\nChengdu trip — Apr 12 to 16, hotpot at Yulin."}`
   - Act 2 Deterministic Denial: `check --scope payment.spend` over-cap → `{"decision":"block","reason":"daily_spend_cap_exceeded: cap=500, requested=600, period=daily"}`; under-cap → `{}`
   - Auto-audit: `hook audit` → `{}`
   - `wire hermes` (stub Hermes): apply → idempotent re-run (all skips) → `--check-only` plan

### Divergences from the plan-as-written

- **Module layout**: §5.3 specified `wire/mod.rs` + `wire/adapters/{hermes,openclaw,claude_code,codex}.rs`. Phase 1.a ships a single flat `wire.rs` with the `RuntimeAdapter` trait + `HermesAdapter` inline — the per-adapter file split lands in Phase 1.b when the 2nd adapter arrives (premature directory structure for one adapter). The trait seam (`RuntimeAdapter`) is present, so the split is mechanical.
- **Memory result field**: the plan assumed the hook decodes `plaintext_b64`; the MCP `memory.get` tool layer already decodes it into a `content` field, so the hook reads `content` directly (see `hook::extract_memory_content`).

### What did NOT land (deferred, with reason)

- **Phase 1.b adapters** (Claude Code, Codex, OpenClaw) — out of this PR's scope by the agreed Full-Phase-1.a cut. The `RuntimeAdapter` trait is the seam they slot into. Tracked: [#133](https://github.com/litentry/agentKeys/issues/133).
- **Nightly drift-check cron** (`agentkeys cron install --wire-drift-check`) — the `--check-only` primitive landed; scheduling it via cron + parent-UI alerting is Phase 1.b.
- **Real master-pairing identity flow** (steps 2-3 of the journey) — the wire command defaults to the in-memory demo actor/operator; production identity comes from the existing `agentkeys init` pairing, wired via `--actor-omni` / `--operator-omni` (supported, not yet defaulted from a live session).
- **Cap-mint pre-warming for sub-50ms hook latency** (plan §6 deliverable 5 of the broader list / strategy §5 Phase 3) — the hooks call the MCP server per-invocation; the daemon cap-cache optimization is a Phase 3 latency concern, not a correctness gap.
- **Live demo against real Hermes inside aiosandbox** — verified on the host with a stub Hermes (`hermes --version` + `hooks doctor`) + the real in-memory MCP backend. The real-Hermes-in-sandbox run is an operator step in the runbook §5–7.
