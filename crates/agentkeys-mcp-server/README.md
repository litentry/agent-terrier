# agentkeys-mcp-server

AgentKeys MCP server — Phase 1 (issue [#107](https://github.com/litentry/agentKeys/issues/107)).

Adapts the Phase 0 backend (broker, memory worker, audit worker, signer)
into 10 MCP tools an LLM host (xiaozhi-server, Volcano Ark, Claude Code,
etc.) can call.

## Tools

| Tool | Status | Backend it talks to |
|---|---|---|
| `agentkeys.identity.whoami` | active | local (M4 lifts to broker `/v1/identity/whoami`) |
| `agentkeys.memory.get` | active | broker `/v1/cap/memory-get` → memory worker `/v1/memory/get` |
| `agentkeys.memory.put` | active | broker `/v1/cap/memory-put` → memory worker `/v1/memory/put` |
| `agentkeys.permission.check` | active | deterministic policy engine (no LLM) |
| `agentkeys.cap.mint` | active | broker `/v1/cap/{cred,memory}-{store,fetch,put,get}` |
| `agentkeys.cap.revoke` | active | M1 stub — broker endpoint scheduled for M4 |
| `agentkeys.audit.append` | active | audit worker `/v1/audit/append/v2` |
| `agentkeys.delegation.grant` | schema-only | returns `not_implemented_in_v1` |
| `agentkeys.delegation.revoke` | schema-only | returns `not_implemented_in_v1` |
| `agentkeys.approval.request` | schema-only | returns `not_implemented_in_v1` |

## Run

> **Real-data-only (#207):** the MCP server has **one backend — `http`** (the
> real broker + workers, which IS the shared `agentkeys-backend-client::BackendClient`).
> The former `--backend in-memory` fixture was removed; transport/protocol
> conformance is now proven by the Rust [`tests/transport_conformance.rs`](tests/transport_conformance.rs)
> (a subprocess MCP client over HTTP + stdio against the real backend).

### Local (HTTP, against a real broker / workers)

```bash
cargo run -p agentkeys-mcp-server -- \
  --listen 0.0.0.0:8088 \
  --broker-url https://broker.litentry.org \
  --memory-url https://memory.litentry.org \
  --audit-url  https://audit.litentry.org \
  --vendor-tokens "magiclick:demo-tok,volcano-ark:tok-va"
```

### Stdio (for an MCP host that launches it as a subprocess)

```bash
cargo run -p agentkeys-mcp-server -- --transport stdio
```

### xiaozhi MCP-endpoint relay (no firmware flash, no LLM key)

Connect outward to a xiaozhi-style `mcp-endpoint-server` relay URL as a
WebSocket client. The relay forwards MCP frames between this server (as
the tool) and the xiaozhi cloud / xiaozhi-server (as the client). No
HTTP listen socket; no per-vendor bearer (the relay URL's token is the
binding).

```bash
cargo run -p agentkeys-mcp-server -- \
  --transport mcp-endpoint \
  --backend http \
  --broker-url https://broker.litentry.org \
  --memory-url https://memory.litentry.org \
  --audit-url  https://audit.litentry.org \
  --mcp-endpoint 'ws://<relay-host>:8004/mcp_endpoint/mcp/?token=<your-tool-token>'
```

### Docker

```bash
docker build -t agentkeys-mcp-server -f crates/agentkeys-mcp-server/Dockerfile .
docker run --rm -p 8088:8088 \
  -e AGENTKEYS_BROKER_URL=https://broker.litentry.org \
  -e AGENTKEYS_MEMORY_URL=https://memory.litentry.org \
  -e AGENTKEYS_AUDIT_URL=https://audit.litentry.org \
  -e MCP_VENDOR_TOKENS="magiclick:demo-tok" \
  agentkeys-mcp-server
```

## Auth

HTTP transport demands two headers per call:

| Header | Purpose | On failure |
|---|---|---|
| `Authorization: Bearer <token>` | per-vendor identification | 401 |
| `X-AgentKeys-Actor: <omni>` | binds the call to one actor | 403 |

Optionally `X-AgentKeys-Session-Bearer: <token>` forwards a session JWT to
the broker cap-mint endpoint (required when the broker enforces OIDC).

A tool argument naming a different actor than the header returns a JSON-RPC
error with code `-32003` (FORBIDDEN). Per the issue acceptance criteria,
that mismatch SHOULD also append an audit row in production deployments;
the audit emission is operator-driven for v1 and lands in M2 alongside
the vendor onboarding portal.

## xiaozhi-server integration

Write to `main/xiaozhi-server/data/.mcp_server_settings.json` (the leading
dot + the `data/` prefix are required — verified against
[`xinnan-tech/xiaozhi-esp32-server`](https://github.com/xinnan-tech/xiaozhi-esp32-server)
commit `7f73dae`, file `main/xiaozhi-server/core/providers/tools/server_mcp/mcp_manager.py`).

```json
{
  "mcpServers": {
    "agentkeys": {
      "url": "https://agentkeys-mcp.example.com/mcp",
      "transport": "streamable-http",
      "headers": {
        "Authorization": "Bearer <vendor token>",
        "X-AgentKeys-Actor": "<actor omni>"
      }
    }
  }
}
```

The `"transport": "streamable-http"` line is **required** — without it,
xiaozhi-server defaults to SSE (`mcp.client.sse.sse_client`) and our
server's `/mcp` endpoint isn't an SSE endpoint.

For local development with the stdio transport:

```json
{
  "mcpServers": {
    "agentkeys": {
      "command": "/path/to/agentkeys-mcp-server",
      "args": ["--transport", "stdio"]
    }
  }
}
```

**Protocol-level verification:** [`tests/transport_conformance.rs`](tests/transport_conformance.rs)
(Rust, `cargo test`) boots the real binary as a subprocess and drives it as an
MCP client through the full `initialize` → `tools/list` → `tools/call` lifecycle
over **HTTP + stdio**, against the real `http` backend — asserting a spec-compliant
client (the Anthropic SDK, xiaozhi's `ServerMCPClient`, Claude Desktop) can
discover + drive every tool, that auth gates (401/403), and that the stdio stream
stays pure JSON-RPC. (This replaced the former bash+python `mcp-demo-mode-*`
demos in #207 — Rust, no python, real backend.)

## Three-act demo storyboard

Per [`docs/agent-iam-strategy.md`](../../docs/agent-iam-strategy.md) §4.3:

1. **Permissioned Memory** — `memory.get(actor=O_kevin_001, namespace="travel")`
   returns Chengdu trip context only; other namespaces (`family`, `profile`)
   are not surfaced even though they exist for the same actor.
2. **Deterministic Denial** — `permission.check(actor, scope="payment.spend",
   amount_rmb=600)` returns `verdict=deny, reason=daily_spend_cap_exceeded`
   from the policy engine. No LLM in the decision path.
3. **Online Revocation** — `cap.revoke(cap_id)` followed by `audit.append`
   records the parent's revocation event in the off-chain feed; the next
   `permission.check` on the revoked scope denies.

Exercised by `tests/three_acts.rs`.

## Tests

```bash
cargo test -p agentkeys-mcp-server
```

Coverage:

- unit tests across auth, policy, identity, permission
- HTTP transport tests (bearer + actor header negative paths)
- schema-only stub shape assertions
- three-act integration tests against a `MockBackend` (the trait's test seam)
- `transport_conformance.rs` — real-binary subprocess driven as an MCP client
  over HTTP + stdio against the real `http` backend (#207; `CONFORMANCE_BROKER_URL`
  points the round-trip at a real broker, else a hermetic well-formed error)

## What this crate is NOT

- It does NOT mint cap-tokens directly — the broker does. We only
  shape the request.
- It does NOT verify cap-token signatures — the workers do.
- It does NOT speak to the chain — the broker + audit worker do.
- It does NOT make policy decisions for anything other than
  `permission.check`. Every other tool's verdict comes from on-chain
  + broker state.

## Out of scope for M1 (tracked separately)

- Broker `/v1/identity/whoami` + `/v1/revoke/cap/:id` — M4 (paired with
  vendor portal #114)
- Namespace as a SIGNED `CapPayload` field — follow-up to #108
- Active delegation + approval — M4 (#107 says explicitly: schema-only
  for v1)
- Vendor onboarding portal — M2 (#114)
- Volcano Ark marketplace registration — M2

See [`docs/archived/issue-107-mcp-server-phase1.md`](../../docs/archived/issue-107-mcp-server-phase1.md)
for the full plan + follow-ups.
