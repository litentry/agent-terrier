# AgentKeys — Component Architecture and Language Choices

**Date:** 2026-04-09 (revised against ceo-plan.md Round 13 runtime reality check)
**Scope:** Cross-cutting architecture document covering all components of AgentKeys, the language chosen for each, the trust boundaries between them, and the Cargo workspace layout.

**Parent docs (read first for context):**
- [`./design-spec.md`](design-spec.md) — product vision, MVP criteria, why Rust end-to-end was chosen
- [`/Users/hanwencheng/Projects/project-life/.omc/specs/deep-interview-agentkeys.md`](../../../../.omc/specs/deep-interview-agentkeys.md) — full prior-interview spec (11 rounds, 19% ambiguity, PASSED)

**Sibling architecture docs:**
- [`./1-step-analysis.md`](./1-step-analysis.md) — auth-layer sub-analysis (session keys, wallet identity, kernel hardening, user flows)
- [`./open-source-posture.md`](./open-source-posture.md) — open/closed split, licensing, reproducible builds, security-audit roadmap
- [`./heima-open-questions.md`](./heima-open-questions.md) — Kai meeting agenda for the Heima TEE worker reality check

**Companion research:**
- [`./heima-cli-exploration.md`](./heima-cli-exploration.md) — 1Password CLI feature comparison

---

## 1. The commitment: Strategy 2 (pragmatic Rust + targeted TypeScript)

The design-spec says **Rust end-to-end**. After enumerating all components, that commitment is **correct for every component inside the trust boundary** but would fight the ecosystem for **browser automation scripts**, where TypeScript + Playwright is meaningfully better than any Rust option.

**Strategy 2 locks in:**
- **Rust** for everything in the trust boundary (CLI, daemon, core library, MCP adapter, CLI adapter, mock backend client, provisioner orchestrator).
- **TypeScript + Playwright** for browser automation scripts inside the agent sandbox.
- **TypeScript** for the audit indexer (Subsquid, post-MVP) and Web GUI frontend (Tauri hybrid, post-MVP).

**Single monorepo, single Cargo workspace, multiple crates:**

| Repo | GitHub | Contents |
|------|--------|----------|
| `agentkeys` | agentkeys/agentkeys | Hub: docs, architecture, Kai spec, issue tracking, README |
| `agentkeys-core` | agentkeys/agentkeys-core | `CredentialBackend` trait, shared types, mock backend HTTP client |
| `agentkeys-cli` | agentkeys/agentkeys-cli | Master CLI binary (depends on core via Cargo git dep) |
| `agentkeys-daemon` | agentkeys/agentkeys-daemon | Sandbox daemon binary (depends on core via Cargo git dep) |
| `agentkeys-mock-server` | agentkeys/agentkeys-mock-server | Temporary v0-only mock backend binary (depends on core) |
| `agentkeys-provisioner` | agentkeys/agentkeys-provisioner | Rust orchestrator library (depends on core) |
| `provisioner-scripts` | agentkeys/provisioner-scripts | TypeScript + Playwright scrapers (npm package) |

Cross-repo dependencies use Cargo `[dependencies] agentkeys-core = { git = "..." }`. All repos in the same local directory for development.

**Rust proportion of the codebase: ~75-80%**, including **100% of the security-critical path**. Every line of code that touches a session key, a wallet private key, an OS keychain entry, or a chain signing operation is in Rust. The cross-language boundaries are all at natural process/sandbox boundaries; no in-process polyglot.

## 2. Component inventory

| # | Component | Where it runs | Primary job |
|---|---|---|---|
| 1 | `agentkeys` CLI | User's Mac/PC/Linux | `init`, `store`, `read`, `run`, `approve`, `revoke`, `teardown`, `usage`, `link`, `feedback` |
| 2 | `agentkeys-daemon` | Inside agent sandbox (as `gem` UID on stock sandbox) | Holds session key in `memfd_secret`; exposes MCP + CLI sockets; hosts provisioner as MCP tool |
| 3 | MCP adapter | Same process as #2 | Speaks MCP protocol on stdio/socket, translates to daemon internal API |
| 4 | CLI adapter | Same process as #2 | Line-protocol on Unix socket for `agentkeys read` etc. |
| 5 | Heima RPC client library | Linked into #1 and #2 | session-signed extrinsics over wss, scale-codec, signing |
| 6 | x402 / EVM library | Linked into #1 | ERC-20 USDC transfers, x402 HTTP payment headers, wallet signing |
| 7 | Provisioner orchestrator (Rust) | Inside agent sandbox, subprocess of daemon | Exposed as MCP tool `agentkeys.provision` on daemon; spawns browser automation, encrypts credentials to backend |
| 8 | Browser automation scripts (TypeScript) | Inside agent sandbox, child of #7 | Playwright/CDP flows for OpenRouter (v0), more services later |
| 9 | Ephemeral email integration (TypeScript) | Inside agent sandbox, child of #7 | Reads verification codes from burner email backends |
| 10 | Audit log indexer | Post-MVP, own host | Subsquid/Subquery indexing Heima extrinsics for `agentkeys usage` |
| 11 | Web GUI | Post-MVP, user's device, local-first | Master management UI, live audit, wallet balance (Tauri shell) |
| 12 | Heima TEE worker extensions | Kai's code, Gramine-SGX | New AgentKeys module (pending Kai conversation) |
| 13 | New Heima pallets | Substrate runtime | `pallet-secrets-vault` if Q2 of the Kai meeting says we build it |
| M | Mock backend service (v0-only) | Small VPS | Mirrors Heima API contract: session mgmt, credential storage, audit, rendezvous relay, auth-request primitive. Axum + SQLite. Deleted when Heima integration lands in v0.1. |
| 14 | `@agentkeys/daemon` npm package | Any environment a cloud LLM can install into | TypeScript wrapper + bundled prebuilt Rust binary. Ships the daemon to cloud LLM sandboxes via `npx @agentkeys/daemon`. |

## 3. Language choice per component

| # | Component | Language | Reasoning |
|---|---|---|---|
| 1 | Master CLI | **Rust** | `clap` + `anyhow` + `tokio` + `keyring-rs` + `subxt` + `alloy`; all mature, all security-sensitive (session key in OS keychain), cross-compiles to all three OS targets. |
| 2 | agentkeys-daemon | **Rust** | Non-negotiable. Needs `memfd_secret()`, `mlock2()`, `seccomp-bpf`, `prctl`, `capset` — all with clean Rust bindings (`nix`, `libseccomp-rs`). Security-critical and auditable. |
| 3 | MCP adapter | **Rust** (with TS shim as fallback) | MCP is stdio/JSON. Rust crates (`rmcp`, `mcp-rs`) exist. For our narrow surface (~5 tools), Rust is adequate. Fallback: tiny TS shim forwarding to CLI socket. |
| 4 | CLI adapter | **Rust** | Trivial line-protocol, same process as daemon. |
| 5 | Heima RPC client | **Rust** (via `subxt`) | Official Substrate RPC client. scale-codec, WebSocket, signing with session keys. |
| 6 | x402 library | **Rust** | x402 is HTTP-header-based. EVM signing via `alloy`. |
| 7 | Provisioner orchestrator | **Rust** | Spawns the TS browser subprocess, reads JSON output, encrypts API key, submits to backend. Touches plaintext credentials briefly; must be auditable. |
| 8 | Browser automation scripts | **TypeScript + Playwright** | The one exception. See section 5. Runs as a subprocess of #7 inside the agent sandbox; never holds crypto material or session keys. |
| 9 | Ephemeral email integration | **TypeScript** | Bundled with #8. IMAP / burner-email clients are mature in TS. |
| 10 | Audit indexer | **TypeScript (Subsquid)** for v0.1, **Rust** (via `subxt`) for v0 | Indexer is read-only, not in trust boundary. |
| 11 | Web GUI (post-MVP) | **Rust (Tauri backend) + TypeScript (frontend)** | Tauri reuses #1 and #5 directly. |
| 12 | TEE worker extensions | **Rust** | Heima's TEE worker is already Rust. |
| 13 | New Heima pallets | **Rust** | Substrate pallets are Rust by construction. |
| M | Mock backend | **Rust** | Axum + SQLite. Same types as `agentkeys-core`. |
| 14 | `@agentkeys/daemon` npm package | **TypeScript** wrapper | Postinstall picks the right prebuilt Rust binary for the host arch. Follows the esbuild/biome/swc pattern. |

## 4. Architecture diagram

```
┌─ User's Laptop ────────────────────────────────────────────────┐
│                                                                 │
│  ┌──────────────────────────┐     Rust:                        │
│  │ agentkeys CLI (#1)       │     - clap / anyhow / tokio      │
│  │                          │     - keyring-rs → OS keychain   │
│  │  (+ optional Web GUI #11 │     - subxt → Heima RPC          │
│  │   post-MVP: Tauri)       │     - alloy-rs → x402 / EVM      │
│  └────────────┬─────────────┘                                  │
│               │                                                 │
└───────────────┼─────────────────────────────────────────────────┘
                │
                │ (1) approve pair/recover
                │ (2) store / read / revoke / teardown / usage
                │ (3) link identity
                ▼
┌─ Mock backend (#M, v0-only) ──────────────────────────────────┐
│  Rust (axum + SQLite)                                          │
│  - session management         - credential storage             │
│  - rendezvous relay           - authorization-request primitive │
│  - audit log                  - scope enforcement              │
│  Mirrors Heima API contract. Replaced by Heima in v0.1.       │
└────────────────────────┬───────────────────────────────────────┘
                         │
                         │ HTTPS (session-authenticated)
                         │
┌─ Heima parachain (v0.1+) ─────────────────────────────────────┐
│                                                                 │
│  ┌──────────────────┐  ┌────────────────────────────────────┐  │
│  │ TEE worker (#12) │  │ Pallets (Rust / Substrate):        │  │
│  │ (Rust / Gramine) │  │  - pallet-teebag       (existing)  │  │
│  │                  │  │  - pallet-omni-account (existing)  │  │
│  │ AgentKeys module │  │  - identity-management (existing)  │  │
│  │ (#12, pending    │  │  - pallet-secrets-vault (NEW, #13) │  │
│  │  Kai)            │  │                                    │  │
│  └──────────────────┘  └────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─ Agent sandbox (single trust domain) ─────────────────────────┐
│                                                                 │
│  ┌──────────────────┐                                          │
│  │ agent process    │ ◄─── MCP ───┐                            │
│  │ (OpenClaw /      │     socket  │                            │
│  │  Claude Code /   │             │                            │
│  │  custom)         │             │                            │
│  └──────────────────┘             │                            │
│                                   │                            │
│  ┌────────────────────────────────┴──────────────────────────┐ │
│  │ agentkeys-daemon (#2, #3, #4, #5)                         │ │
│  │                                                           │ │
│  │ Rust:                                                     │ │
│  │ - memfd_secret + mlock2        - MCP adapter (#3)         │ │
│  │ - prctl + seccomp-bpf          - CLI adapter (#4)         │ │
│  │ - cap drop (no Landlock/LSM)   - Heima/mock RPC (#5)      │ │
│  │                                                           │ │
│  │ MCP tool: agentkeys.provision ──┐                         │ │
│  │                                 │                         │ │
│  │  ┌─────────────────────────────┐│                         │ │
│  │  │ Provisioner orchestrator #7 ││                         │ │
│  │  │ (Rust, subprocess of daemon)││                         │ │
│  │  └──────────┬──────────────────┘│                         │ │
│  │             │ stdio/JSON        │                         │ │
│  │             ▼                   │                         │ │
│  │  ┌──────────────────────────┐   │                         │ │
│  │  │ Browser automation (#8)  │   │                         │ │
│  │  │ TypeScript + Playwright  │   │                         │ │
│  │  │  + stealth plugins       │   │                         │ │
│  │  │                          │   │                         │ │
│  │  │ Email integration (#9)   │   │                         │ │
│  │  │ TypeScript (IMAP / APIs) │   │                         │ │
│  │  │                          │   │                         │ │
│  │  │ Never touches crypto.    │   │                         │ │
│  │  └──────────────────────────┘   │                         │ │
│  └─────────────────────────────────┘                         │ │
│                                                                 │
│  Session at: /home/gem/.agentkeys/session (stock sandbox)      │
│  Registered: [program:agentkeys-daemon] in supervisord         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─ Cloud LLM sandbox (ChatGPT / Claude.ai / Kimi Claw) ────────┐
│  Same daemon, installed via: npx @agentkeys/daemon (#14)       │
│  Session at: $HOME/.agentkeys/session                          │
│  Lifecycle: ephemeral per chat session; recovery via approve   │
└─────────────────────────────────────────────────────────────────┘

┌─ Post-MVP: Audit indexer (#10) ────────────┐
│ v0: Rust + subxt                            │
│ v0.1: TypeScript + Subsquid                 │
│ Exposes JSON/GraphQL for `agentkeys usage`  │
└─────────────────────────────────────────────┘
```

**Key changes from prior diagram:** The provisioner runs INSIDE the agent sandbox as an MCP tool on the daemon, not in a separate provisioner sandbox. In v0 there is no separate provisioner trust domain — the provisioner is a subprocess of the daemon. The mock backend is shown as a v0-only component between the CLI and Heima.

## 5. The TypeScript exception for component #8

Browser automation is an arms race against anti-bot systems. The state-of-the-art counters — `playwright-extra`, `puppeteer-extra-plugin-stealth`, `camoufox`, `patchright` — live almost entirely in the TypeScript/Python ecosystems. No Rust equivalents at comparable maturity.

**What we'd lose by forcing Rust for #8:** dev loop for per-service scripts becomes significantly slower, anti-detection is meaningfully weaker, and signup flows break constantly as services update their UIs — TypeScript iteration speed matters.

**What we'd gain:** a strictly-one-language story in the writeup.

**Trade verdict:** not worth it. Provisioner script quality directly affects product quality.

**Trust boundary stays clean:** The provisioner runs inside the agent sandbox. The TypeScript subprocess never sees the master session key or the Heima signing path. The Rust orchestrator (#7) spawns it as a child process, passes parameters over stdin/env, receives the obtained API key over stdout as JSON. The Rust side then encrypts the key and submits it to the backend. TypeScript is never in the cryptographic path. The language boundary is at a process boundary; no in-process polyglot.

## 6. Cargo workspace layout

Single monorepo, single Cargo workspace, multiple crates. Simplest for v0.

```
agentkeys/                             # Git monorepo root
├── Cargo.toml                         # workspace definition
├── Cargo.lock                         # committed (for reproducibility)
├── rust-toolchain.toml                # pinned toolchain version
├── crates/
│   ├── agentkeys-types/               # lib: shared types (Identity, Session,
│   │                                  #       Scope, WalletAddress, AgentIdentity)
│   ├── agentkeys-core/                # lib: CredentialBackend trait, Heima RPC
│   │                                  #       client (subxt), crypto, x402 (alloy),
│   │                                  #       auth-request types + canonical CBOR,
│   │                                  #       mock backend HTTP client
│   │   └── tests/
│   │       └── auth_request_vectors.json  # canonical test vectors
│   ├── agentkeys-cli/                 # bin: master CLI (init, store, read, run,
│   │                                  #       approve, revoke, teardown, usage,
│   │                                  #       link, feedback)
│   ├── agentkeys-daemon/              # bin: sandbox daemon w/ memfd_secret,
│   │                                  #       mlock2, seccomp-bpf, cap drop.
│   │                                  #       Runs as gem UID on stock sandbox.
│   │                                  #       No Landlock, no LSM, no UID split.
│   ├── agentkeys-mcp/                 # lib: MCP adapter (get_credential,
│   │                                  #       provision — wraps -core API)
│   ├── agentkeys-provisioner/         # lib: provisioner orchestrator, exposed
│   │                                  #       as MCP tool agentkeys.provision,
│   │                                  #       spawns TS subprocess, handles IPC
│   ├── agentkeys-mock-server/         # bin: v0-only mock backend (axum + SQLite),
│   │                                  #       rendezvous relay, auth-request
│   │                                  #       primitive. Deleted when Heima lands.
│   └── agentkeys-tauri/               # bin: (post-MVP) Tauri backend
│       └── frontend/                  # TS+React/Solid/Svelte UI
├── provisioner-scripts/               # SEPARATE npm package — TypeScript
│   ├── package.json
│   ├── tsconfig.json
│   ├── scrapers/
│   │   └── openrouter.ts             # v0: single service, agent-driven via MCP
│   ├── lib/
│   │   ├── email.ts                  # IMAP / burner-email client
    │   └── stealth.ts                # stealth plugin config
    └── config/
        └── default.ts
```

Each Rust repo has its own `Cargo.toml` and `Cargo.lock` (committed for reproducibility). Pin `rust-toolchain.toml` per repo.

**Key crate dependencies:**

| Crate | Purpose |
|---|---|
| `clap` | CLI argument parsing |
| `anyhow` / `thiserror` | Error handling |
| `tokio` | Async runtime |
| `subxt` | Substrate/Heima RPC client |
| `parity-scale-codec`, `scale-info` | SCALE encoding/decoding |
| `alloy` | EVM / x402 signing |
| `keyring` | OS keychain integration |
| `nix` | Unix syscalls |
| `libseccomp` | seccomp-bpf filters |
| `libc` | `memfd_secret()` syscall binding |
| `rmcp` (or manual) | MCP protocol adapter |
| `serde` / `serde_json` | Serialization |
| `tracing` / `tracing-subscriber` | Structured logging |
| `reqwest` | HTTP client |
| `rustls` | TLS (no OpenSSL dependency) |
| `rpassword` | Interactive password/passphrase prompts |
| `dirs` | OS-specific config/data paths |
| `axum` | Mock backend HTTP framework (#M) |
| `rusqlite` | Mock backend storage (#M) |

**Provisioner TypeScript dependencies:**

| Package | Purpose |
|---|---|
| `playwright` | Browser automation |
| `playwright-extra` + `puppeteer-extra-plugin-stealth` | Anti-detection |
| `imapflow` or `node-imap` | Burner email IMAP |
| `zod` | Runtime type validation for orchestrator IPC |
| `ts-node` | Run TS directly |

## 7. Trust domains, process boundaries, and language boundaries

| Trust domain | Contents | Language | Boundary type |
|---|---|---|---|
| **Master's Mac** | Master CLI #1, OS Keychain (holds session key), Tauri Web GUI #11 | Rust (+TS frontend for Tauri) | Network (TLS to mock backend / Heima) |
| **Agent sandbox** | agentkeys-daemon #2, agent process, provisioner #7, browser automation #8+#9 | Rust daemon + TS provisioner subprocess + whatever the agent is | Unix socket (agent <-> daemon), process boundary (daemon -> TS subprocess), network (daemon <-> backend) |
| **Mock backend (v0)** | Axum server #M, SQLite, rendezvous relay, auth-request state | Rust | HTTPS from CLI and daemon |
| **Heima parachain (v0.1+)** | TEE worker #12, pallets #13, chain state | Rust (Gramine-SGX) | Consensus + public RPC |

All cross-language interactions are at process or network boundaries. No in-process FFI, no shared memory across language runtimes.

**v0 note:** The provisioner is NOT a separate trust domain. It runs inside the agent sandbox as a subprocess of the daemon. The daemon exposes provisioning as an MCP tool (`agentkeys.provision`); the agent calls it. The TS subprocess inherits the sandbox's isolation — no additional sandboxing layer in v0.

## 8. CLI command list

| Command | What it does | Audience |
|---|---|---|
| `agentkeys init` | Google OAuth, master session -> OS keychain | Human (Master) |
| `agentkeys store <agent> <service> <key>` | Manually save a credential scoped to an agent | Human (Master) |
| `agentkeys read <agent> <service>` | Retrieve a credential | Human or daemon |
| `agentkeys run <agent> -- <cmd>` | Inject credential as env var + exec child process | Human (Master) |
| `agentkeys approve <pair-code>` | Approve a pair/recover/scope-change request from a daemon | Human (Master) |
| `agentkeys revoke <agent>` | Kill an agent's session immediately | Human (Master) |
| `agentkeys teardown <agent>` | Delete all credentials + revoke all sessions for an agent | Human (Master) |
| `agentkeys usage [agent]` | Query audit log (replaces `list`) | Human (Master) |
| `agentkeys link <agent> --alias/--email/--ens` | Link a human-readable identity for recovery | Human (Master) |
| `agentkeys feedback` | Open a GitHub Discussion for feedback | Human |

**Not CLI commands:** `provision` is MCP-only (`agentkeys.provision` tool on the daemon). The agent calls it autonomously via MCP.

**Removed from prior list:** `setup` (now MCP-only as `agentkeys.provision`), `attach` (superseded by child-initiates `approve` flow), `fund` (deferred — no real USDC in v0), `list` (use `usage` instead).

## 9. `@agentkeys/daemon` npm package (#14)

For cloud LLM environments (ChatGPT sandbox, Claude.ai code execution, Kimi Claw, Manus) where the user cannot run shell commands directly — only chat with their agent.

The npm package wraps prebuilt Rust binaries following the esbuild/biome/swc pattern: postinstall picks the right binary for the host arch. Entry point:

- `npx @agentkeys/daemon` — new pair (daemon generates pair code, displays in chat)
- `npx @agentkeys/daemon --recover agent-A` — recovery with human-readable alias

No pair code argument needed from the Mac side. The daemon generates the code itself. User types in their LLM chat: *"please run `npx @agentkeys/daemon`"* and the daemon displays the pair code for them to approve on their Mac via `agentkeys approve <code>`.

Lifecycle is ephemeral per chat session by design. Recovery flow handles re-attach.

## 10. Rust proportion estimate

| Layer | Language | % of code |
|---|---|---|
| Trust-boundary core (daemon, CLI, core lib, MCP/CLI adapters, types, provisioner orchestrator, RPC client, x402) | Rust | ~60% |
| Mock backend (#M, v0-only) | Rust | ~10% |
| Heima pallets + TEE extensions (#12, #13) | Rust | ~10% |
| Provisioner browser scripts + email (#8, #9) | TypeScript | ~10% |
| npm wrapper (#14) | TypeScript | ~2% |
| Audit indexer (#10), v0 | Rust or TS | ~3% |
| Web GUI frontend (#11), post-MVP | TypeScript | ~5% |

**Rust: ~80% of lines, 100% of security-critical path.** TypeScript is strictly confined to: browser automation inside the agent sandbox, the npm daemon wrapper, the read-only indexer, and the Web GUI frontend. None of these touch the trust boundary.

## 11. License

All AgentKeys repositories are dual-licensed under **MIT OR Apache-2.0**, at the user's choice. This applies to `agentkeys-core`, `agentkeys-cli`, `agentkeys-daemon`, `agentkeys-mock-server`, `agentkeys-provisioner`, `provisioner-scripts`, and the `@agentkeys/daemon` npm package.

## 12. Cross-references

- **Session key storage details (kernel hardening):** see `1-step-analysis.md` SS3.3, SS3.3a
- **Two-interface daemon design (MCP + CLI):** see `1-step-analysis.md` SS3.4
- **CLI UX and env-var injection model:** see `1-step-analysis.md` SS3.4a
- **User flows (how all these components interact at runtime):** see `1-step-analysis.md` SS4
- **v0 demo suite (what the components need to support):** see `1-step-analysis.md` SS9
- **Open/closed source split, licensing, reproducible builds, threat model:** see `open-source-posture.md`
- **TEE worker (#12) open questions:** see `heima-open-questions.md` — especially Q1, Q2, Q3, Q11
- **CredentialBackend trait contract:** see `credential-backend-interface.md`
- **CEO plan (v0 scope, approach B, DX spec):** see `plans/ceo-plan.md`

---

*Living document. Update when the component inventory, repo structure, or language split changes.*
