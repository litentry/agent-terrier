# AgentKeys

Credential broker for AI agents. A master (human) delegates scoped, revocable access to third-party service credentials (OpenRouter, OpenAI, etc.) to agent sandboxes — without ever handing the agent the raw keys.

Status: pre-v0. Stage 5 in progress (see `harness/progress.json`).

Architecture, language choices, trust boundaries: [`docs/arch.md`](docs/arch.md).

---

## 👤 For humans

### What it does

- **Master CLI** (`agentkeys`) — runs on your laptop; owns a session key in the OS keychain; approves pair/recover/scope-change requests.
- **Sandbox daemon** (`agentkeys-daemon`) — runs inside the agent sandbox; brokers credential reads over MCP + a Unix socket; never exposes raw keys to the agent.
- **Provisioner** (`agentkeys-provisioner` + `provisioner-scripts`) — Rust orchestrator drives TypeScript/Playwright scrapers to sign up for services and hand the resulting API key back through the trust boundary.
- **Mock backend** (`agentkeys-mock-server`) — v0-only; mirrors the Heima parachain API so we can build end-to-end before the chain integration lands.

### Workspace layout

```
crates/
  agentkeys-types/          shared types (Identity, Session, Scope, ...)
  agentkeys-core/            CredentialBackend trait, RPC client, crypto
  agentkeys-cli/             master CLI binary
  agentkeys-daemon/          sandbox daemon binary
  agentkeys-mcp/             MCP adapter
  agentkeys-provisioner/     provisioner orchestrator
  agentkeys-mock-server/     v0-only mock backend (axum + SQLite)
provisioner-scripts/         TypeScript + Playwright scrapers (npm)
docs/                        specs, stage plans, execution runbook
harness/                     stage-gated build harness + progress
```

~80% Rust, 100% of the security-critical path in Rust. TypeScript is confined to browser automation and (post-MVP) the Web GUI frontend.

### Build & test

```
cargo build
cargo test
npm test --prefix provisioner-scripts
```

Per-crate tests:

```
cargo test -p agentkeys-types
cargo test -p agentkeys-core
cargo test -p agentkeys-mock-server
cargo test -p agentkeys-cli
cargo test -p agentkeys-daemon -p agentkeys-mcp
cargo test -p agentkeys-provisioner
```

### First-machine setup

Fresh laptop? Start with [`docs/dev-setup.md`](docs/dev-setup.md) — it walks you through rustup, jj, Node, AWS CLI, browser, and runs the workspace smoke tests.

### Inner-loop dev

Iterating on the broker, signer, mock-server, or operator-side scripts? [`docs/spec/broker-and-operator-dev-guide.md`](docs/spec/broker-and-operator-dev-guide.md) covers the local edit-build-test loop: which process to run on which port, how to point harness scripts at `localhost`, how to use `harness/v2-stage*-demo.sh` for resumable step-by-step testing.

### License

Dual-licensed under **MIT OR Apache-2.0**, at your choice.

---

## 🤖 For AI coding agents

**You must read these before making any change.** They override defaults from your training data and cover the project-specific guardrails.

| Read | Why |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Project-specific rules: docs layout, /create-pr workflow in worktrees, terminology-source-of-truth, branch push policy, idempotent-remote-setup invariants, runbook-fix-fold-back policy. **Read first, every session.** |
| [`docs/arch.md`](docs/arch.md) | Single source of truth for component inventory (K1–K11), trust boundaries, HDKD actor tree, per-actor binding ceremonies. When the per-doc detail outgrows arch.md, link outward — never duplicate. |
| [`docs/spec/plans/development-stages.md`](docs/spec/plans/development-stages.md) | The 8-stage build plan. Each stage has a `harness/stage-N-done.sh` gate; never self-grade — run the gate. |
| [`docs/spec/plans/execution-plan.md`](docs/spec/plans/execution-plan.md) | Orchestration runbook (ralph, team, ultraqa workflows). |
| [`docs/spec/broker-and-operator-dev-guide.md`](docs/spec/broker-and-operator-dev-guide.md) | Inner edit-build-test loop for broker + operator-side code. Use this before suggesting changes to the broker's run-time behavior. |

### Hard rules (from CLAUDE.md)

These are non-negotiable. Violating them produces broken PRs / corrupted state.

- **Use `jj` (Jujutsu), never raw `git`.** Common mappings in CLAUDE.md. The one exception: inside a Claude Code `.claude/worktrees/<name>/` worktree, the initial commit must use `git` (jj can't colocate in a git-worktree); then `cd` to the main repo and push via `jj git push`. Never include `Co-Authored-By:` lines in those commits.
- **Branch `evm` pushes immediately.** On `evm`, push after every `jj describe` — the remote broker host pulls from `origin/evm` to redeploy. "I'll push at the end" silently breaks deploys.
- **Diagnose before edit.** Reproduce the failure locally first; isolate the layer (shell / client / doc / broker code / network). If the cause is local to the operator's shell, respond with the one-line fix — don't edit the repo.
- **Land the fix everywhere.** Once a local repro proves a fix is correct, land it the same turn — search the repo for every affected file, commit, push to `origin/evm`. Don't stop at "verified locally" or "fixed one file."
- **Runbook fix fold-back.** When an operator hits a runbook failure, two things land in the same turn: (1) the targeted fix, (2) a revision to the runbook so the next operator doesn't hit the same trap.
- **No hardcoded values.** Use env var + default, CLI flag + default, or a config file. If you must hardcode temporarily, log it in [`hardcoded.md`](hardcoded.md) with file:line + reason + what would unblock dynamic.
- **Idempotent remote setup.** Every script that mutates remote state (AWS / Heima / CI / VM / DNS) must exit 0 on re-run without re-applying. Pre-check with `get-*` before mutating; log `ok | skip <reason> | fail <reason>`.
- **Plan completion is all-or-nothing.** When implementing a plan, every numbered step must be done — or the PR summary's "What did NOT land" section must explicitly list what was skipped and why.
- **Terminology source of truth.** Never invent a new name for a concept arch.md already names. If you find divergence, fix it in the same commit or document the alias in arch.md's "Canonical names" section.

### Per-session protocol

1. `jj log --limit 10 && cat harness/progress.json && bash harness/init.sh $(jq -r .current_stage harness/progress.json)`
2. Read the stage contract for the current stage in `docs/spec/plans/development-stages.md`.
3. Pick the HIGHEST-PRIORITY incomplete deliverable from `harness/features.json`.
4. Implement ONE deliverable, run `cargo test -p <crate>`, `jj describe`, update `harness/features.json`, `jj new`.

### Single entry points

Don't reach for ad-hoc `systemctl`, `scp`, or `forge script` — these are wrapped:

- **Remote broker host** (binary upgrades, systemd, nginx, env tweaks): `bash scripts/setup-broker-host.sh`
- **Heima chain bring-up** (deploy, binding ceremonies, scope grants, K11 enroll, audit-row append, worker smoke): `bash scripts/setup-heima.sh`
