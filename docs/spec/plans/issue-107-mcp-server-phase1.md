# Issue #107 — AgentKeys MCP server (Phase 1)

Plan document for the Phase 1 MCP server. Issue: https://github.com/litentry/agentKeys/issues/107.

## 1. What landed

The new crate `crates/agentkeys-mcp-server/` ships the 10 tools listed in
issue #107 (7 active + 3 schema-only). It is additive — no existing crate
was modified beyond adding the new member to the workspace `Cargo.toml`.

| File | Purpose |
|---|---|
| [`src/main.rs`](../../../crates/agentkeys-mcp-server/src/main.rs) | binary entry, CLI parsing, transport selection |
| [`src/lib.rs`](../../../crates/agentkeys-mcp-server/src/lib.rs) | crate root, public exports for tests |
| [`src/mcp.rs`](../../../crates/agentkeys-mcp-server/src/mcp.rs) | JSON-RPC 2.0 + MCP envelope types |
| [`src/server.rs`](../../../crates/agentkeys-mcp-server/src/server.rs) | dispatcher routing `initialize`/`tools/list`/`tools/call`/`ping` |
| [`src/transport.rs`](../../../crates/agentkeys-mcp-server/src/transport.rs) | HTTP (axum) + stdio transports |
| [`src/auth.rs`](../../../crates/agentkeys-mcp-server/src/auth.rs) | Bearer + `X-AgentKeys-Actor` header validation |
| [`src/policy.rs`](../../../crates/agentkeys-mcp-server/src/policy.rs) | deterministic policy engine for `permission.check` |
| [`src/config.rs`](../../../crates/agentkeys-mcp-server/src/config.rs) | CLI + env → `Config` |
| [`src/errors.rs`](../../../crates/agentkeys-mcp-server/src/errors.rs) | `McpError` → JSON-RPC error mapping |
| [`src/backend/mod.rs`](../../../crates/agentkeys-mcp-server/src/backend/mod.rs) | `Backend` trait + wire types |
| [`src/backend/http_backend.rs`](../../../crates/agentkeys-mcp-server/src/backend/http_backend.rs) | production `HttpBackend` over reqwest |
| [`src/backend/broker.rs`](../../../crates/agentkeys-mcp-server/src/backend/broker.rs) | broker cap-mint request shape |
| [`src/backend/memory.rs`](../../../crates/agentkeys-mcp-server/src/backend/memory.rs) | memory-worker request shapes |
| [`src/backend/audit.rs`](../../../crates/agentkeys-mcp-server/src/backend/audit.rs) | audit-worker `AppendV2` request shape |
| [`src/tools/mod.rs`](../../../crates/agentkeys-mcp-server/src/tools/mod.rs) | tool registry + `inputSchema` for each |
| [`src/tools/identity.rs`](../../../crates/agentkeys-mcp-server/src/tools/identity.rs) | `agentkeys.identity.whoami` |
| [`src/tools/permission.rs`](../../../crates/agentkeys-mcp-server/src/tools/permission.rs) | `agentkeys.permission.check` |
| [`src/tools/cap.rs`](../../../crates/agentkeys-mcp-server/src/tools/cap.rs) | `agentkeys.cap.mint` + `agentkeys.cap.revoke` |
| [`src/tools/memory.rs`](../../../crates/agentkeys-mcp-server/src/tools/memory.rs) | `agentkeys.memory.get` + `agentkeys.memory.put` |
| [`src/tools/audit.rs`](../../../crates/agentkeys-mcp-server/src/tools/audit.rs) | `agentkeys.audit.append` |
| [`src/tools/stubs.rs`](../../../crates/agentkeys-mcp-server/src/tools/stubs.rs) | M4 schema-only stubs |
| [`tests/common/mod.rs`](../../../crates/agentkeys-mcp-server/tests/common/mod.rs) | shared `MockBackend` |
| [`tests/three_acts.rs`](../../../crates/agentkeys-mcp-server/tests/three_acts.rs) | three-act demo storyboard |
| [`tests/http_auth.rs`](../../../crates/agentkeys-mcp-server/tests/http_auth.rs) | acceptance #3 — bearer + actor negative paths |
| [`tests/schema_only_stubs.rs`](../../../crates/agentkeys-mcp-server/tests/schema_only_stubs.rs) | acceptance #2 — `not_implemented_in_v1` shape |
| [`Dockerfile`](../../../crates/agentkeys-mcp-server/Dockerfile) | two-stage rust:slim → debian:slim image |
| [`README.md`](../../../crates/agentkeys-mcp-server/README.md) | run + xiaozhi-server integration recipe |
| [`.github/workflows/mcp-server.yml`](../../../.github/workflows/mcp-server.yml) | CI: test + clippy + GHCR image publish |

Workspace touchpoints:
- [`Cargo.toml`](../../../Cargo.toml) added `crates/agentkeys-mcp-server` to `members`.

## 2. Architecture

```
┌──────────────────┐  POST /mcp (JSON-RPC)             ┌─────────────────────┐
│  xiaozhi-server  │ ─Authorization: Bearer <vendor>──>│  agentkeys-mcp-     │
│  / Volcano Ark   │  X-AgentKeys-Actor: <omni>        │       server        │
│  / Claude Code   │                                   │                     │
└──────────────────┘                                   │  • auth.rs          │
                                                       │  • policy.rs        │
                                                       │  • tools/*          │
                                                       │  • backend trait    │
                                                       └──────────┬──────────┘
                                                                  │
                       ┌──────────────────┬────────────────┬──────┴──────┐
                       ▼                  ▼                ▼             ▼
                  ┌─────────┐       ┌──────────┐    ┌──────────┐  ┌──────────┐
                  │ broker  │       │ memory   │    │ audit    │  │ (no LLM, │
                  │ cap-mint│       │ worker   │    │ worker   │  │ no DB,   │
                  │         │       │          │    │          │  │ no chain)│
                  └─────────┘       └──────────┘    └──────────┘  └──────────┘
```

Key design choices:

1. **Rust over Python.** The issue prefers Python; we picked Rust because
   (a) the rest of the workspace is Rust — single toolchain, one CI; (b)
   the broker/worker DTOs come from `agentkeys-core` and would drift if
   re-declared in Pydantic; (c) MCP is a wire protocol — xiaozhi-server
   doesn't care what language is on the other side. Phase 0's existing
   `crates/agentkeys-mcp/` (Rust JSON-RPC over stdio) was the
   pre-existing proof. Issue's "Rust as fallback" clause covers it.
2. **Backend trait.** Production uses `HttpBackend` (reqwest); tests use
   `MockBackend`. The trait stays narrow — one method per backend
   operation, opaque cap-token blob, no shared DB.
3. **Deterministic policy engine.** `permission.check` lives in
   `policy.rs`. Pure function, no I/O, no LLM. The storyboard's Act 2
   wording (`cap=500, requested=600, period=daily`) is locked in by a
   unit test in `policy.rs`.
4. **Cap.revoke is a graceful stub.** Broker `/v1/revoke/cap/:id` lands
   in M4 (paired with vendor portal #114). M1 returns
   `{ok:true, revocation:"local_only", note:"..."}` so the parent UI
   can render the verdict immediately. Swap to the real call when the
   broker endpoint exists; the tool's wire format does not change.
5. **Namespace at request body for M1.** Per #108 partial deferral — the
   namespace travels in the MemoryGet/Put body, not in the signed
   CapPayload. The worker accepts it as metadata; cryptographic binding
   to the cap lands in M4.

## 3. Acceptance criteria — status

| Criterion | Status | Evidence |
|---|---|---|
| 1. 7 active tools respond correctly when invoked from xiaozhi-server | ✅ wired; live demo operator-driven | `tests/three_acts.rs`, `tests/http_auth.rs::tools_list_works_through_http` |
| 2. 3 schema-only tools return documented `not_implemented_in_v1` shape | ✅ | `tests/schema_only_stubs.rs` (3 tests) |
| 3. Bearer + actor header scoping — wrong token 401, no-header 403, wrong actor 403 | ✅ | `tests/http_auth.rs` (6 tests) |
| 4. Unit tests per tool happy + at least 1 negative path | ✅ | 17 unit tests + tool-specific tests under `tools/*::tests` |
| 5. Integration test against mock backend exercising three-act storyboard | ✅ | `tests/three_acts.rs` (5 tests) |
| 6. CI publishes the MCP server image; one-command deploy | ✅ workflow + Dockerfile | `.github/workflows/mcp-server.yml`, `crates/agentkeys-mcp-server/Dockerfile` |
| 7. Demo: invoke each active tool from a real xiaozhi-server session | ⏳ operator-driven | see §5 below |

## 4. Test summary

```text
cargo test -p agentkeys-mcp-server

unit tests:           17 / 17  (auth, policy, identity, permission)
http_auth.rs:          6 /  6  (acceptance #3)
schema_only_stubs.rs:  3 /  3  (acceptance #2)
three_acts.rs:         5 /  5  (acceptance #5)
─────────────────────────────
total:                31 / 31
```

## 5. Demo runbook

Full two-mode runbook in
[`issue-107-mcp-demo-runbook.md`](issue-107-mcp-demo-runbook.md).

- **Mode A — dev / fresh-laptop.** No broker, no workers, no hardware.
  Boots `--backend in-memory` and walks Acts 1/2/3 via `curl`. Asserted
  by `scripts/mcp-demo-mode-a.sh` (regression check for the runbook
  itself).
- **Mode B protocol layer — verified.** `scripts/mcp-demo-mode-b-protocol.sh`
  uses the same Anthropic Python `mcp` SDK that xiaozhi-server imports
  (confirmed by reading `xinnan-tech/xiaozhi-esp32-server@7f73dae` —
  file `main/xiaozhi-server/core/providers/tools/server_mcp/mcp_client.py`)
  to drive `initialize` → `tools/list` → all three acts → schema-only
  stubs end-to-end over Streamable HTTP.
- **Mode C xiaozhi-server integration code — verified.**
  `scripts/mcp-demo-mode-c-xiaozhi-client.sh` loads xiaozhi-server's
  **own** `ServerMCPClient` class from upstream source and instantiates
  it against this MCP server. Same imports, same config-loading path,
  same tool-name sanitization, same `call_tool` signature. Bundles a
  deterministic fake-LLM so the full LLM → `ServerMCPClient` →
  `/mcp` → tools loop is exercised without a real model. When this
  passes, the remaining failure modes are downstream of MCP: LLM
  tool-choice (model + prompt engineering) and MagicLick audio I/O
  (hardware).
- **Mode D — xiaozhi MCP-endpoint relay end-to-end.** `scripts/mcp-demo-mode-d-xiaozhi-endpoint.sh`
  stands up a tiny mock relay that mirrors `xinnan-tech/mcp-endpoint-server`'s
  tool/client routing (`/mcp_endpoint/mcp/?token=…` for tool side,
  `/mcp_endpoint/call/?token=…` for xiaozhi side). It then connects our
  MCP server to the tool side via the new `--transport mcp-endpoint`
  mode and drives the three acts from the client side. **This is the
  hardware-free + LLM-key-free path to the full demo.** When mode D
  passes, the only remaining production work is deploying the real
  relay (systemd on EC2, not Docker) and registering the relay URL
  with a xiaozhi.me agent. No MagicLick firmware flash needed — the
  xiaozhi cloud talks to existing devices through the relay.
- **Mode B operator-driven residual.** What's left after modes A/B/C/D
  is a live broker + workers deploy (one command via
  `scripts/setup-broker-host.sh` + `scripts/setup-heima.sh`), the
  real `mcp-endpoint-server` running as systemd next to the broker,
  and registration of the relay URL with a xiaozhi.me agent in 智控台.
  No paid LLM account, no MagicLick toy, no Docker.

## 6. What did NOT land (deferred)

Each is intentional. Cross-linked to issues / milestones.

- **Broker `/v1/identity/whoami`** — M4, paired with vendor portal #114.
  Today `identity.whoami` synthesizes locally from auth context.
- **Broker `/v1/revoke/cap/:id`** — M4. Today `cap.revoke` is a
  local-only stub. Tool's wire format will not change when the broker
  endpoint lands.
- **Namespace as SIGNED `CapPayload` field** — follow-up to #108. Today
  namespace is request-body metadata.
- **Active delegation + approval (`delegation.grant` /
  `delegation.revoke` / `approval.request`)** — M4. Today: schema-only
  stubs returning `not_implemented_in_v1` per issue spec.
- **Per-vendor bearer rotation policy** — M2 with the vendor onboarding
  portal #114.
- **Audit Tier-2 actual on-chain `appendRootV2`** — out of scope for
  #107; covered by #109 (partial flush cadence already lives at 120s
  per CLAUDE.md M1 expectations).
- **Volcano Ark marketplace registration** — #112, deferred per issue.
- **xiaozhi-server final integration tag/release** — paired with #112.
- **Live operator demo (acceptance #7)** — operator-driven, cannot be
  completed in this PR. Runbook above.

## 7. Follow-ups / clean-ups for the next operator

- The HTTP transport accepts `X-AgentKeys-Session-Bearer` to forward to
  the broker cap-mint endpoint. If the deployment topology lets the MCP
  server own a service account JWT instead, we can drop this header —
  open question for the M2 vendor portal work.
- `CapMintOp::data_class` is hardcoded as a static string; if a third
  data class lands (per arch.md §15.6 payments-audit), the enum and the
  registered tool schemas need a matching extension. Closed-extension
  pattern — additive.
- The Dockerfile copies the entire workspace into the build stage for
  simplicity; a leaner version uses `cargo chef` to cache deps across
  builds.
