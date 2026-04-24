# AgentKeys

Credential broker for AI agents. A master (human) delegates scoped, revocable access to third-party service credentials (OpenRouter, OpenAI, etc.) to agent sandboxes — without ever handing the agent the raw keys.

Status: pre-v0. Stage 5 in progress (see `harness/progress.json`).

## What it does

- **Master CLI** (`agentkeys`) — runs on your laptop; owns a session key in the OS keychain; approves pair/recover/scope-change requests.
- **Sandbox daemon** (`agentkeys-daemon`) — runs inside the agent sandbox; brokers credential reads over MCP + a Unix socket; never exposes raw keys to the agent.
- **Provisioner** (`agentkeys-provisioner` + `provisioner-scripts`) — Rust orchestrator drives TypeScript/Playwright scrapers to sign up for services and hand the resulting API key back through the trust boundary.
- **Mock backend** (`agentkeys-mock-server`) — v0-only; mirrors the Heima parachain API so we can build end-to-end before the chain integration lands.

Architecture, language choices, trust boundaries: [`docs/spec/architecture.md`](docs/spec/architecture.md).

## Workspace layout

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

## Build & test

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

## Development

Staged build plan in [`docs/spec/plans/development-stages.md`](docs/spec/plans/development-stages.md). Each stage has a `harness/stage-N-done.sh` gate that must exit 0 before the stage is marked complete. Contributor workflow: [`CLAUDE.md`](CLAUDE.md).

Version control uses [jj (Jujutsu)](https://github.com/jj-vcs/jj), not raw git.

## License

Dual-licensed under **MIT OR Apache-2.0**, at your choice.
