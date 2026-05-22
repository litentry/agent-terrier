# AgentKeys — Technical Brief for Heima Team

**Date:** 2026-04-09
**Audience:** Heima parachain developers (familiar with Substrate, TEE workers, pallets)
**Purpose:** High-level overview of AgentKeys, what it reuses from Heima, what it needs built, and the v0 → v0.1 migration path.

---

## 1. The Problem

AI agents (Claude Code, OpenClaw, custom bots) run inside cloud sandboxes and need API credentials for services like OpenRouter, Brave Search, Notion, etc. Today this means:

- Manually creating accounts on each service per agent
- Pasting API keys into `.env` files
- No revocation, no audit trail, no scoping
- If an agent is compromised, the attacker gets permanent keys with no TTL

AgentKeys solves this in two ways: (1) humans store existing API keys via CLI (`agentkeys store`), and (2) agents with browser control (e.g., OpenClaw) autonomously provision new accounts via MCP (`agentkeys.provision`) — Playwright browser automation creates real accounts and obtains API keys without human intervention. All credentials are stored in the backend (mock for v0, Heima TEE for v0.1), agents consume them via MCP, and everything is revocable on-chain in ≤ 1 block.

---

## 2. Architecture Overview

```
┌─ User's Mac ──────────────────────────────────┐
│                                                │
│  agentkeys CLI (Rust)                          │
│  ├── Google OAuth / Passkey → session key      │
│  ├── Session key stored in OS keychain         │
│  ├── subxt → talks to Heima (v0.1)             │
│  └── Talks to mock backend (v0)                │
│                                                │
└────────────────────┬───────────────────────────┘
                     │
                     │  session-authenticated HTTPS
                     ▼
┌─ Credential Backend (abstracted) ─────────────┐
│                                                │
│  v0:   MockBackend (Rust/axum, SQLite on VPS)  │
│  v0.1: HeimaBackend (TEE worker + pallets)     │
│                                                │
│  Responsibilities:                             │
│  ├── Master key custody + signing              │
│  ├── Credential blob storage (encrypted)       │
│  ├── Session management (scoped children)      │
│  ├── Scope enforcement on reads                │
│  ├── Audit log                                 │
│  ├── Rendezvous relay (for daemon pairing)     │
│  └── Authorization-request primitive (OTP)     │
│                                                │
└──────┬─────────────────────────┬───────────────┘
       │                         │
       │  wss / HTTPS            │  wss / HTTPS
       ▼                         ▼
┌─ Agent Sandbox ──────┐  ┌─ Cloud LLM Sandbox ──────┐
│ (agent-infra/sandbox │  │ (ChatGPT, Claude.ai,     │
│  or Fly.io VM)       │  │  Kimi Claw, Manus, etc.) │
│                      │  │                           │
│  agentkeys-daemon    │  │  agentkeys-daemon         │
│  (Rust binary)       │  │  (via npm package)        │
│  ├── memfd_secret    │  │  ├── Ephemeral lifecycle  │
│  ├── seccomp-bpf     │  │  ├── Recover on re-pair   │
│  ├── MCP server      │  │  └── MCP server           │
│  └── Talks to backend│  │                           │
│                      │  └───────────────────────────┘
│  Agent process       │
│  (reads creds via    │
│   MCP or env vars)   │
└──────────────────────┘
```

---

## 3. What AgentKeys Reuses from Heima

| Heima Component | How AgentKeys Uses It | Status |
|---|---|---|
| `pallet-omni-account` | Wallet-as-identity: each user and agent gets an EVM wallet address as canonical ID | Reuse as-is |
| `pallet-identity-management` / `RegisterUserByOmniAccount` | Google OAuth → account creation flow | Reuse as-is |
| `pallet-teebag` shielding key | Client encrypts credential blobs to the TEE's public shielding key before storage — TEE decrypts on read | Reuse as-is |
| TEE worker infrastructure (Gramine-SGX) | Runtime for credential storage, session management, scope enforcement | Reuse + extend |
| `subxt` RPC over wss | CLI and daemon talk to Heima via session-signed extrinsics | Standard Substrate client |
| On-chain events | Audit trail: every credential store/read/revoke emits an event, indexed by Subsquid | Standard Substrate |

---

## 4. What AgentKeys Needs Built in Heima (v0.1)

These are the **new** capabilities AgentKeys needs. v0 mocks all of them in a SQLite-backed server. The mock backend's API contract is designed as the spec for these Heima features.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Heima Parachain (v0.1)                        │
│                                                                  │
│  ┌─ Existing (reuse) ──────┐  ┌─ New (build) ────────────────┐ │
│  │                          │  │                               │ │
│  │  pallet-omni-account    │  │  Scoped child-session keys    │ │
│  │  pallet-teebag          │  │  (TEE worker extension)       │ │
│  │  identity-management    │  │  ← Q1: can TEE mint scoped    │ │
│  │                          │  │     sessions from a parent?   │ │
│  └──────────────────────────┘  │                               │ │
│                                │  pallet-secrets-vault (NEW)   │ │
│  ┌─ Existing TEE worker ────┐ │  ← Q2: per-agent encrypted   │ │
│  │                          │  │     blob storage, indexed by  │ │
│  │  Gramine-SGX runtime    │  │     (owner, agent, service)   │ │
│  │  Identity verification  │  │                               │ │
│  │  Shielding key mgmt     │  │  TEE-side scope enforcement   │ │
│  │                          │  │  ← Q3: enforce "agent-A can   │ │
│  │  + AgentKeys module:    │  │     only read agent-A's creds" │ │
│  │    - Master key custody │  │     at each read, not just at  │ │
│  │    - Session signing    │  │     session creation           │ │
│  │    - Auth-request OTP   │  │                               │ │
│  │    - Rendezvous relay   │  │  Revocation propagation       │ │
│  │    - Recover re-encrypt │  │  ← Q9: must be ≤ 1 block (~6s)│ │
│  └──────────────────────────┘ │     This is our ONLY defense   │ │
│                                │     on stock sandboxes         │ │
│                                └───────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### Detailed breakdown

| Feature | Mock Backend (v0) | Heima (v0.1) | Priority |
|---|---|---|---|
| **Scoped child-session minting** | Server generates a token tagged with `(parent, scope)` | TEE worker derives a child key from parent, scope attached as metadata; child key can only access credentials matching its scope | P0 — load-bearing for multi-agent isolation |
| **Credential blob storage** | SQLite `credentials` table: `(owner, agent_id, service, ciphertext)` | New pallet (`pallet-secrets-vault`?) stores encrypted blobs on-chain, keyed by `(owner, agent_id, service)`, encrypted to TEE shielding key | P0 — core product function |
| **TEE-side scope enforcement** | Server checks `session.scope` matches `agent_id` at read time | TEE worker checks scope before decrypting; a compromised daemon cannot bypass | P0 — security claim depends on this |
| **Session revocation** | Server deletes session from DB; next read returns 401 | TEE worker policy table removes session; propagation must be ≤ 1 block | P0 — only defense against compromised agents |
| **Rendezvous relay** | SQLite `rendezvous` table with 5-min TTL; long-poll endpoint | TEE-held ephemeral state, queried via extrinsic; E2E encrypted payload (TEE sees only ciphertext) | P1 — needed for cloud LLM pairing |
| **Authorization-request primitive** | SQLite `auth_requests` table; CSPRNG nonce, HMAC-derived OTP, session-auth approval, single-use | TEE generates nonce, derives OTP, stores request with TTL, signs with user's master key after session-auth approval, enforces single-use | P1 — generalized consent mechanism |
| **Master key custody** | Server holds Ed25519 keypair per user | TEE holds keypair; private key never leaves enclave | P1 — trust model upgrade |
| **Recover re-encryption** | Server re-encrypts credential blobs to new daemon pubkey (plaintext handling server-side) | TEE re-encrypts inside enclave so shielding key never leaves | P1 — ephemeral cloud LLM support |

---

## 5. The `CredentialBackend` Trait — the Handoff Spec

The Rust trait that abstracts over backends. The mock backend implements this for v0; Heima implements the same trait for v0.1. **No CLI or daemon code changes when swapping backends.**

The trait defines 16 async methods across five groups: session management, credential storage, audit, rendezvous (daemon pairing through the backend), and authorization requests (generalized consent). See [`credential-backend-interface.md`](credential-backend-interface.md) for the full Rust trait definition, `AuthRequestType` enum, canonical CBOR serialization spec, and replay-resistance invariants.

### Trait method → Heima primitive mapping (unique-to-this-doc "Existing or New?" column)

| Trait Method | Existing or New? |
|---|---|
| `create_session` | Existing (Google OAuth → `pallet-identity-management`) |
| `create_child_session` | **New (Q1)** |
| `store_credential` | **New (Q2)** |
| `read_credential` | **New (Q3)** |
| `revoke_session` | **New (Q9)** — verify propagation latency |
| `shielding_key` | Existing (`pallet-teebag`) |
| `query_audit` | Existing (chain events + Subsquid) |
| `register/poll/deliver_rendezvous` | **New** |
| `open/fetch/approve/await_auth_request` | **New** |
| `teardown_agent` | Composition of new primitives |

For the full Heima primitive mapping with implementation notes, see [`credential-backend-interface.md` §"Mapping to Heima Primitives"](credential-backend-interface.md).

---

## 6. User Flows

### Flow A — First-time setup

```
User (Mac)              Mock Backend / Heima         Agent Sandbox
    │                          │                          │
    │ agentkeys init           │                          │
    │ (Google OAuth)           │                          │
    │─────────────────────────►│                          │
    │                          │ create account            │
    │                          │ generate master keypair   │
    │                          │ generate mock wallet addr │
    │◄─────────────────────────│                          │
    │ JWT auth token → file    │  (NOTE: original spec said│
    │ (was: session key →      │  "session key → OS        │
    │  OS keychain; corrected  │  keychain"; corrected     │
    │  2026-04-12 per Heima    │  after verifying Heima    │
    │  source verification)    │  uses JWT auth tokens)    │
```

### Flow B — Pair a daemon (universal, works for Docker / cloud VM / cloud LLM)

**Child initiates, Master approves.** Same direction as Chromecast pairing, OAuth device flow, Signal device linking.

```
Daemon (any sandbox)         Backend / Heima              User (Mac)
    │                          │                          │
    │ daemon starts             │                          │
    │ generates own keypair     │                          │
    │                          │                          │
    │ open_auth_request(Pair,  │                          │
    │   {daemon_pubkey, scope})│                          │
    │─────────────────────────►│                          │
    │                          │ returns pair_code + OTP  │
    │◄─────────────────────────│                          │
    │                          │                          │
    │ register_rendezvous      │                          │
    │─────────────────────────►│                          │
    │ poll_rendezvous           │                          │
    │──── (long-poll) ────────►│                          │
    │                          │                          │
    │ displays in terminal     │                          │
    │ or LLM chat:             │                          │
    │ "Pair code: ABCD-EFGH"   │                          │
    │ "Approve on your Mac"    │                          │
    │                          │                          │
    │                          │   user sees pair code     │
    │                          │   agentkeys approve       │
    │                          │     ABCD-EFGH             │
    │                          │◄─────────────────────────│
    │                          │   fetch_auth_request      │
    │                          │──────────────────────────►│
    │                          │   shows details + OTP     │
    │                          │   user confirms match     │
    │                          │◄─────────────────────────│
    │                          │   approve_auth_request    │
    │                          │                          │
    │                          │ backend signs internally │
    │                          │ with user's master key   │
    │                          │                          │
    │ deliver via rendezvous   │                          │
    │◄─────────────────────────│                          │
    │ daemon decrypts           │                          │
    │ child session + wallet   │                          │
    │ → memfd_secret            │                          │
    │                          │                          │
    │ post-pair recommendation:│                          │
    │ link a human-readable ID │                          │
    │ (email, alias, ENS name) │                          │
    │ for future recovery      │                          │
```

The daemon starts with no arguments (no `--pair-code` from the master). It generates the pair code itself, displays it, and waits. The user carries the code to their Mac and approves. One natural interaction on each side.

### Flow C — Agent requests a credential (the hot path)

```
Agent Process           agentkeys-daemon             Backend / Heima TEE
    │                          │                          │
    │ MCP: get_credential      │                          │
    │  (service: "openrouter") │                          │
    │─────────────────────────►│                          │
    │                          │ read_credential          │
    │                          │ (child_session,          │
    │                          │  agent_wallet,           │
    │                          │  "openrouter")           │
    │                          │─────────────────────────►│
    │                          │                          │ verify scope
    │                          │                          │ decrypt blob
    │                          │◄─────────────────────────│
    │◄─────────────────────────│                          │
    │ OPENROUTER_API_KEY=sk-...│                          │
    │                          │ (explicit_bzero after    │
    │                          │  forwarding)             │
```

### Flow D — Revocation (compromised agent)

```
User (Mac)              Backend / Heima              Daemon (compromised)
    │                          │                          │
    │ agentkeys revoke agent-A │                          │
    │─────────────────────────►│                          │
    │                          │ revoke child session     │
    │                          │ (≤ 1 block / ~6s)        │
    │                          │                          │
    │                          │          next MCP call:   │
    │                          │◄─────────────────────────│
    │                          │  → DENIED                │
    │                          │─────────────────────────►│
    │                          │          stolen session   │
    │                          │          is now dead      │
```

### Flow E — Recover (ephemeral cloud LLM daemon dies, user starts new session)

**Child initiates recovery, Master approves.** The daemon identifies the agent to recover via a human-readable linked identity (email, alias, ENS name) — linked after first pair, stored in the identity graph (`pallet-omni-account`). Without a linked identity, the raw wallet address also works.

```
New Daemon                   Backend / Heima              User (Mac)
    │                          │                          │
    │ user tells LLM:          │                          │
    │ "recover agent-A"        │                          │
    │                          │                          │
    │ daemon starts             │                          │
    │ generates new keypair     │                          │
    │                          │                          │
    │ open_auth_request(       │                          │
    │   Recover,               │                          │
    │   {human_id: "agent-A",  │                          │
    │    new_daemon_pubkey})    │                          │
    │─────────────────────────►│                          │
    │                          │ look up agent-A via      │
    │                          │ identity graph            │
    │◄── pair_code + OTP ──────│                          │
    │                          │                          │
    │ register_rendezvous      │                          │
    │─────────────────────────►│                          │
    │ poll_rendezvous           │                          │
    │──── (long-poll) ────────►│                          │
    │                          │                          │
    │ displays in LLM chat:    │                          │
    │ "Recovery code: WXYZ"    │                          │
    │ "Approve on your Mac"    │                          │
    │                          │                          │
    │                          │   agentkeys approve WXYZ │
    │                          │◄─────────────────────────│
    │                          │   shows: "Recover        │
    │                          │    agent-A to new daemon" │
    │                          │   user confirms           │
    │                          │◄─────────────────────────│
    │                          │   approve_auth_request    │
    │                          │                          │
    │                          │ re-encrypt agent-A's     │
    │                          │ wallet + creds to new    │
    │                          │ daemon pubkey             │
    │                          │                          │
    │ deliver via rendezvous   │                          │
    │◄─────────────────────────│                          │
    │ same wallet address      │                          │
    │ same credentials         │                          │
    │ no re-provisioning       │                          │
    │                          │                          │
    │                          │ old daemon pubkey revoked │
```

**Identity linking recommendation:** after first pair, prompt: `agentkeys link agent-A --email bot@example.com` or `--alias my-openrouter-bot`. This creates an entry in the identity graph (reuses `pallet-omni-account` identity linking). On recover, the daemon uses this human-readable ID instead of a raw wallet address. Without linking, recover still works but requires the wallet address — less ergonomic for cloud LLM chat.

### Flow F — Agent-driven provisioning via MCP (the OpenRouter demo)

**The agent provisions its own credentials autonomously.** This is the "instant keys" magic: an agent with browser control (e.g., OpenClaw) calls an MCP tool, and browser automation creates a real service account without human intervention.

```
Agent (OpenClaw)             agentkeys-daemon             Backend / Heima
    │                          │                          │
    │ MCP: agentkeys.provision │                          │
    │  (service: "openrouter") │                          │
    │─────────────────────────►│                          │
    │                          │ spawn Playwright          │
    │                          │ subprocess                │
    │                          │                          │
    │                          │ ┌─────────────────────┐  │
    │                          │ │ openrouter.ts        │  │
    │                          │ │ - navigate signup    │  │
    │                          │ │ - create account     │  │
    │                          │ │ - generate API key   │  │
    │                          │ │ - return key to      │  │
    │                          │ │   orchestrator       │  │
    │                          │ └─────────────────────┘  │
    │                          │                          │
    │                          │ store_credential         │
    │                          │ (agent_wallet,           │
    │                          │  "openrouter",           │
    │                          │  encrypted_key)          │
    │                          │─────────────────────────►│
    │                          │                          │ store blob
    │                          │◄─────────────────────────│
    │◄─────────────────────────│                          │
    │ MCP response:            │                          │
    │ {status: "provisioned",  │                          │
    │  service: "openrouter"}  │                          │
    │                          │                          │
    │ MCP: agentkeys.          │                          │
    │  get_credential          │                          │
    │  (service: "openrouter") │                          │
    │─────────────────────────►│ read_credential          │
    │                          │─────────────────────────►│
    │                          │◄─────────────────────────│
    │◄─────────────────────────│                          │
    │ OPENROUTER_API_KEY=sk-...│                          │
```

**Key points for Heima team:**
- The Playwright browser automation (TypeScript) runs inside the sandbox as a subprocess of the daemon. It never touches crypto — it only returns the plaintext API key to the Rust orchestrator.
- The orchestrator encrypts the key to the backend's shielding key (`pallet-teebag` in v0.1) before calling `store_credential`. The plaintext key never leaves the sandbox.
- The agent calls two MCP tools: `agentkeys.provision` (one-time, creates the account) and `agentkeys.get_credential` (repeated, reads the stored key). Both go through the daemon.
- The human is NOT involved in this flow. The agent does it autonomously after being paired. The human's role was earlier: `agentkeys approve` to pair the daemon, and optionally `agentkeys store` for credentials that can't be auto-provisioned.

---

## 7. v0 → v0.1 Migration Path

```
v0 (now)                              v0.1 (after Parachain team review)
─────────────────────────────────     ─────────────────────────────────
Mock backend (axum + SQLite)     →    Heima TEE worker + pallets
  session tokens in SQLite        →     scoped session keys in TEE
  credential blobs in SQLite      →     pallet-secrets-vault on-chain
  scope check in Rust server      →     scope check inside SGX enclave
  master key on VPS disk          →     master key in TEE (never leaves)
  audit log in SQLite             →     on-chain events + Subsquid
  rendezvous in SQLite            →     TEE-held ephemeral state
  auth-request in SQLite          →     TEE nonce gen + internal signing

CLI and daemon code:              →    ZERO CHANGES (same trait)
```

The `CredentialBackend` trait is the contract. v0's mock backend is the executable spec. When Heima implements the same trait methods as extrinsics + TEE worker calls, the CLI and daemon swap backends via a config flag. No rewrite.

---

## 8. Key Questions (Priority Order)

After Round 13 runtime probe findings, the priority has shifted:

| # | Question | Why It Matters | Impact if "No" |
|---|----------|---------------|----------------|
| **Q9** | How fast can Heima propagate a session revocation? | Revocation latency is our **only** defense against compromised agents on stock sandboxes (no UID isolation possible — see runtime probe). Must be ≤ 1 block (~6s). | v0.1 security story collapses; hardened sandbox fork becomes a blocker. |
| **Q1** | Can TEE worker mint scoped child sessions from a parent? | Core multi-agent isolation mechanism. Each agent gets a session that can only access its own credentials. | Must build it. No workaround — scoping is fundamental. |
| **Q2** | Can Heima store per-agent credential blobs keyed by `(owner, agent, service)`? | Core storage. `pallet-secrets-vault` or repurpose existing storage. | Must build it. This is the product. |
| **Q3** | Is scope enforcement at each `read_credential` TEE-side or daemon-side only? | Determines the security claim: "TEE-gated" (strong) vs "daemon-gated" (weaker, daemon compromise = game over). | Daemon-gated is acceptable for v0.1 but the pitch is weaker. |
| **Q6** | Does `client_id` in `omni-executor` support multi-tenant registration? | AgentKeys needs its own `client_id` to avoid polluting Heima's own OAuth flow. | Minor — can work around with a dedicated OAuth client. |

---

## 9. Tech Stack Summary

| Layer              | Technology                                       | Notes                                                                 |
| ------------------ | ------------------------------------------------ | --------------------------------------------------------------------- |
| CLI + daemon       | Rust (`clap`, `tokio`, `keyring-rs`, `rmcp`)     | Single language for all trust-boundary code                           |
| Heima RPC client   | `subxt`                                          | Standard Substrate client, session-signed extrinsics                  |
| EVM / wallet       | `alloy-rs`                                       | Wallet address generation, x402 signing (v0.2+)                       |
| Kernel hardening   | `memfd_secret`, `mlock2`, `seccomp-bpf`, `prctl` | In-process, no root needed, verified working on `agent-infra/sandbox` |
| Browser automation | TypeScript + Playwright                          | Provisioning scripts triggered by agents via MCP `agentkeys.provision` — not a CLI command. Agent-initiated, never touches crypto directly. |
| Mock backend       | Rust (`axum`, `sqlx`, SQLite)                    | Temporary v0 component, deleted when Heima integration lands          |
| Daemon packaging   | npm wrapper around prebuilt Rust binary          | For cloud LLM assistant installation (`npx @agentkeys/daemon`)        |
| License            | MIT OR Apache-2.0                                | Dual-licensed                                                         |

---

## 10. Related Documents

| Document                                                                                             | What's in it                                                                                                   |
| ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| [`credential-backend-interface.md`](credential-backend-interface.md)                                 | Full Rust trait definition, `AuthRequestType` enum, canonical serialization spec, replay-resistance invariants |
| [`architecture.md`](architecture.md)                                                                 | 13-component inventory, language split rationale, trust domain diagram                                         |
| [`heima-open-questions.md`](heima-open-questions.md)                                                 | Full meeting agenda with 12 questions, hinge decisions, walk-out deliverable                                   |
| [`plans/ceo-plan.md`](plans/ceo-plan.md)                                                             | v0 scope decisions, component list, auth flow, deferred items                                                  |
| [`plans/eng-review-test-plan.md`](plans/eng-review-test-plan.md)                                     | 50+ test cases including rendezvous, auth-request, sandbox hardening                                           |
| [`../research/aiosandbox/agent-infra-sandbox-runtime-probe.md`](../research/aiosandbox/agent-infra-sandbox-runtime-probe.md) | Empirical probe of `agent-infra/sandbox` — why UID isolation is impossible on stock image                      |
| [`1-step-analysis.md`](1-step-analysis.md)                                                           | Deep auth-layer analysis (990 lines), session key tiers, user flows, threat model                              |
