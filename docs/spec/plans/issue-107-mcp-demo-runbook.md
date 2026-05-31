# Issue #107 — Phase 1 MCP server demo runbook

Two demo modes:

| Mode | Audience | Hardware | LLM key | External services | Time to first byte |
|---|---|---|---|---|---|
| **A. Dev / fresh-laptop** | engineers, vendor prospects | none | none | none | ~2 min |
| **B. Full xiaozhi-server + MagicLick** | end-to-end vendor demo | MagicLick 2.5 toy | Doubao or Qwen | live broker + workers + xiaozhi-server | ~45 min |

Run mode A first to validate the MCP server + the three-act storyboard. Run mode B when you have hardware + LLM key + a live broker deployed.

---

## A. Dev / fresh-laptop demo

### TL;DR — one line, end to end

```bash
bash scripts/mcp-demo-mode-a.sh
```

That's it. The script builds the binary, allocates an ephemeral port, boots
the server with `--backend in-memory`, walks all three acts of the storyboard
with JSON-RPC assertions, exercises the auth negative paths, and cleans up.
Expected output ends with `ALL ASSERTIONS PASSED.` (19 checks). This is the
same one-liner the CI workflow runs (see [`.github/workflows/mcp-server.yml`](../../../.github/workflows/mcp-server.yml)) — copy-paste-equivalent in CI and on
your laptop.

If you want to walk the demo manually instead of running the script, the
sections below show every step + every assertion line by line.

### Prerequisites

- Rust toolchain (`stable`, matches `rust-toolchain.toml`).
- macOS or Linux. `curl` + a JSON pretty-printer (`jq` preferred, `python3`
  as a fallback; the smoke script auto-detects).
- Nothing else. No broker, no workers, no Docker, no LLM key.

### 1. Build + run the server

```bash
cd ~/Projects/agentKeys      # or wherever you cloned

cargo run -p agentkeys-mcp-server -- \
  --backend in-memory \
  --listen 127.0.0.1:8088
```

Expected log lines:

```text
INFO agentkeys_mcp_server: backend=in-memory (dev demo); seeded with three-act fixture (actor 0xa0c7…01a0c7)
INFO agentkeys_mcp_server: agentkeys-mcp-server listening (HTTP) addr=127.0.0.1:8088
```

What got seeded into the in-memory backend:

| Actor | Namespace | Content |
|---|---|---|
| `0xa0c7…01a0c7` | `travel` | "Chengdu trip — Apr 12 to 16, hotpot at Yulin." |
| `0xa0c7…01a0c7` | `family` | "Wife's bday Aug 3 (gift idea: hiking boots)." |
| `0xa0c7…01a0c7` | `profile` | "Allergic to shellfish. Prefers windowed flights." |

A default vendor token `magiclick:demo-tok` is auto-seeded in dev mode so the runbook stays one-command. Override with `--vendor-tokens` if you need a different pair.

### 2. Sanity check — healthz + tools/list

In a second terminal:

```bash
curl -sS http://127.0.0.1:8088/healthz
# → {"name":"agentkeys-mcp-server","ok":true}

curl -sS -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "x-agentkeys-actor: 0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' \
  | python3 -c "import sys,json;print(len(json.load(sys.stdin)['result']['tools']),'tools')"
# → 10 tools
```

### 3. Act 1 — Permissioned Memory

The MCP host (xiaozhi-server / Claude / etc.) decides it needs memory context and calls `memory.get` scoped to the `travel` namespace:

```bash
curl -sS -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "x-agentkeys-actor: 0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7" \
  -H "content-type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "params":{
      "name":"agentkeys.memory.get",
      "arguments":{
        "actor":"0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7",
        "namespace":"travel",
        "operator_omni":"0x07e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8",
        "device_key_hash":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      }
    },
    "id":1
  }' | python3 -m json.tool
```

Expected `structuredContent`:

```json
{
  "content": "Chengdu trip — Apr 12 to 16, hotpot at Yulin.",
  "namespace": "travel",
  "ok": true
}
```

**Why this matters — and what's M1 vs M4:** in this dev demo the MCP server forwards `namespace` to the in-memory backend, which honors it as a storage key. That makes the dev demo visibly namespace-scoped. **In M1 production**, the real memory worker today does NOT enforce `namespace` cryptographically — the wire field flows through but the S3 key derivation only uses `(actor, service)`. Lifting `namespace` into the SIGNED `CapPayload` so the worker can enforce it is M4 follow-up to #108 ([plan §6](issue-107-mcp-server-phase1.md#6-what-did-not-land-deferred)). The dev demo demonstrates the wire shape; cryptographic enforcement lands later.

### 4. Act 2 — Deterministic Denial

The MCP host calls `permission.check` to authorize a 600 RMB hotpot order. The policy engine sees the daily cap is 500 RMB and returns a deny verdict with the storyboard's exact reason string:

```bash
curl -sS -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "x-agentkeys-actor: 0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7" \
  -H "content-type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "params":{
      "name":"agentkeys.permission.check",
      "arguments":{
        "actor":"0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7",
        "scope":"payment.spend",
        "params":{"amount_rmb":600}
      }
    },
    "id":1
  }' | python3 -m json.tool
```

Expected `structuredContent`:

```json
{
  "verdict": "deny",
  "reason": "daily_spend_cap_exceeded",
  "scope": "payment.spend",
  "explanation": "cap=500, requested=600, period=daily"
}
```

**Why this matters:** the verdict came from `crate::policy::PolicyEngine`, a pure function. **No LLM, no inference, no network call.** Change the amount to `200` and re-run — verdict flips to `accept`. Change the scope to anything not in the policy table (e.g. `nuke.launch`) — verdict is `deny` with reason `scope_not_in_policy_table` (closed-world default-deny).

### 5. Act 3 — Online Revocation

Three steps: mint a cap, revoke that exact cap by its nonce, and append the audit event. Then verify that revoking an unknown cap fails — a real revoke list, not a rubber stamp.

```bash
# 5a. Mint a memory_get cap so we have a real cap_id to revoke.
CAP=$(curl -sS -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "x-agentkeys-actor: 0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7" \
  -H "content-type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "params":{
      "name":"agentkeys.cap.mint",
      "arguments":{
        "actor":"0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7",
        "op":"memory_get",
        "params":{
          "operator_omni":"0x07e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8",
          "service":"memory",
          "device_key_hash":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        },
        "ttl":300
      }
    },
    "id":1
  }')
# Pick `cap_id` (the cap's nonce) out of the response — `jq` or `python3`:
CAP_ID=$(echo "$CAP" | jq -r '.result.structuredContent.cap.payload.nonce' 2>/dev/null \
  || echo "$CAP" | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['structuredContent']['cap']['payload']['nonce'])")
echo "cap_id = $CAP_ID"

# 5b. Revoke THAT cap (by its nonce).
curl -sS -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "x-agentkeys-actor: 0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7" \
  -H "content-type: application/json" \
  -d "$(printf '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"agentkeys.cap.revoke","arguments":{"cap_id":"%s"}},"id":1}' "$CAP_ID")" \
  | python3 -m json.tool

# 5c. Try to revoke a cap that was never minted — MUST fail. This is the
# difference from a rubber-stamp implementation.
curl -sS -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "x-agentkeys-actor: 0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"agentkeys.cap.revoke","arguments":{"cap_id":"this-cap-was-never-minted"}},"id":1}' \
  | python3 -m json.tool

# 5d. Audit row for the revoke event.
curl -sS -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "x-agentkeys-actor: 0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7" \
  -H "content-type: application/json" \
  -d "$(printf '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"agentkeys.audit.append","arguments":{"actor":"0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7","event":{"operator_omni":"0x07e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8a107e8","op_kind":3,"op_body":{"cap_id":"%s","reason":"parent_revoke"},"result":0,"intent_text":"parent revoked payment access"}}},"id":1}' "$CAP_ID")" \
  | python3 -m json.tool
```

Expected: 5b succeeds (`"revocation":"in_memory"`), 5c returns a JSON-RPC error with body `unknown cap_id: this-cap-was-never-minted`, 5d returns `{"ok": true, "envelope_hash": "0x<32-byte sha256>"}`. The `envelope_hash` is a SHA-256 over the audit input — two different appends produce two different hashes.

**Why this matters:** revoke + audit are decoupled by design. The dev backend tracks minted nonces and refuses to revoke unknown ones — so a typo or a stale cap surfaces immediately. In M1 production, broker-side revocation is still a follow-up (`cap.revoke` is a graceful stub against the real backend per [plan §6](issue-107-mcp-server-phase1.md#6-what-did-not-land-deferred)); the dev demo shows the contract the broker will honor in M4.

### 6. Acceptance-criterion #3 — auth negative paths

Demonstrate the bearer + actor scoping rules from the issue:

```bash
# Wrong token → 401
curl -sS -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer nope" \
  -H "x-agentkeys-actor: 0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
# → 401

# Missing X-AgentKeys-Actor header → 403
curl -sS -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
# → 403

# Tool param actor != header actor → JSON-RPC error code -32003
curl -sS -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "x-agentkeys-actor: O_alice" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"agentkeys.identity.whoami","arguments":{"actor":"O_bob"}},"id":1}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('error code:',d['error']['code'])"
# → error code: -32003
```

### 7. Schema-only stubs

The 3 deferred tools return the exact wire shape from the issue:

```bash
curl -sS -X POST http://127.0.0.1:8088/mcp \
  -H "authorization: Bearer demo-tok" \
  -H "x-agentkeys-actor: 0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"agentkeys.delegation.grant","arguments":{}},"id":1}' \
  | python3 -m json.tool
```

Expected error body:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "not_implemented_in_v1",
    "data": {
      "error": "not_implemented_in_v1",
      "scheduled_for": "M4",
      "spec_url": "https://github.com/litentry/agentKeys/blob/main/docs/spec/plans/milestones-roadmap.md#m4"
    }
  },
  "id": 1
}
```

### 8. Tear down

Ctrl-C the server. No state to clean up — the in-memory backend dies with the process.

### What dev-mode does NOT prove

- The broker actually mints valid cap-tokens with the on-chain device-binding ceremony.
- The memory worker actually re-verifies cap signatures and decrypts S3 envelopes.
- The audit worker actually anchors the Merkle root on-chain inside the 2-min SLA.
- xiaozhi-server's Doubao / Qwen LLM actually decides to call the right tools at the right moments.

For those, see mode **B** below.

---

## B. Full xiaozhi demo via the MCP-endpoint relay (no firmware flash, no LLM key)

> **Hardware-free, account-light.** The xiaozhi cloud already runs the LLM and already talks to xiaozhi devices in the wild. We register our MCP server as a tool with that cloud — no firmware to flash, no Doubao/Qwen key to provision. The only thing you need from xiaozhi's side is **a xiaozhi.me account with one agent (智能体)** so they hand us a relay URL to connect to. Mode D in the repo verifies this whole loop against a local mock relay, so every layer is exercised before you ever touch a real device.

### B.0 How to test §B — four tiers from no resources to live cloud

§B has resource requirements that can't be satisfied from a fresh laptop alone (live broker, xiaozhi.me agent, paired device). The correct way to test it is a **ladder of verification** — each tier catches a class of bugs the next-cheaper tier can't. Run them top-down and only move on when the current tier is green.

| Tier | What it proves | What you need | One-line command |
|---|---|---|---|
| 1 | Server boots; in-memory backend three-act flow works; auth scoping works | Rust toolchain + curl + jq/python3 | `bash scripts/mcp-demo-mode-a.sh` |
| 2 | MCP wire protocol is spec-compliant (Anthropic SDK can drive us) | `uv` (Python launcher) | `bash scripts/mcp-demo-mode-b-protocol.sh` |
| 3 | xiaozhi-server's actual production integration class (`ServerMCPClient`) can call every tool, with sanitized names + deterministic fake-LLM tool choice | `uv` + git (clones xiaozhi-server) | `bash scripts/mcp-demo-mode-c-xiaozhi-client.sh` |
| 4 | xiaozhi-style relay topology — two ws paths, token pairing, frame forwarding — end-to-end through `--transport mcp-endpoint` | `uv` (mock relay is Python) | `bash scripts/mcp-demo-mode-d-xiaozhi-endpoint.sh` |
| 5 | Live broker + workers + real `mcp-endpoint-server` on EC2 + a xiaozhi.me agent + a paired device | All of the above + AWS access + xiaozhi.me account + voice device | §B.4–§B.10 below |

Tiers 1–4 are **CI-able**. They run in `.github/workflows/mcp-server.yml` and assert every claim in this section. **When all four pass, the only remaining failure modes are operator deploy errors and cloud-side config** — neither is a bug in our code.

Tier 5 is operator-driven. There is no software substitute for "did the chain actually mint the cap with the right device binding" — that's why tier 5 is on hardware + live infrastructure.

The fastest way to validate a §B change end-to-end without live resources: re-run **tier 4** (`mode-d`). It's the closest hardware-free approximation of production. The relay routing, the WebSocket frame protocol, the `--transport mcp-endpoint` reconnect logic, the three-act tool wiring — all exercised exactly as they will be in production. Tier 5 only adds: real `mcp-endpoint-server` binary instead of the mock, the xiaozhi cloud talking instead of a fake client, a real voice device instead of a script.

### B.1 Topology

```
┌──────────────────────┐       audio / ws        ┌─────────────────────────┐
│  any xiaozhi device  │ ─────────────────────── │  xiaozhi cloud (LLM,    │
│  already in the wild │                         │  STT, TTS, intent)      │
└──────────────────────┘                         │                         │
                                                 │  智控台 + mcp_endpoint  │
                                                 │  config: ws://relay/... │
                                                 └────────────┬────────────┘
                                                              │ ws
                                                              ▼
                                              ┌───────────────────────────┐
                                              │  mcp-endpoint-server      │
                                              │  (relay; one Python proc, │
                                              │   github.com/xinnan-tech/ │
                                              │   mcp-endpoint-server)    │
                                              └─────┬────────────┬────────┘
                                                    │ tool path  │ client path
                                                    │            │
                                                    ▼            ▼
                              ┌──────────────────────────────────────────┐
                              │  agentkeys-mcp-server                    │
                              │  --transport mcp-endpoint                │
                              │  --mcp-endpoint ws://relay/.../?token=…  │
                              └─────┬────────────────┬───────────────────┘
                                    │                │
                                    ▼                ▼
                          ┌──────────────┐ ┌──────────────┐
                          │ broker       │ │ memory       │
                          │ + audit      │ │ + cred       │
                          │   worker     │ │   worker     │
                          └──────────────┘ └──────────────┘
                                    │
                                    ▼
                          ┌──────────────────┐
                          │ Heima parachain  │
                          └──────────────────┘
```

What this path eliminates from the original draft:

- No MagicLick toy needs to be flashed. The xiaozhi cloud runs the device's voice loop. Any xiaozhi device already paired with your agent works.
- No Doubao/Qwen API key. The xiaozhi cloud's LLM is the one that decides to call our tools — your agent config (system prompt) tunes that.
- No Docker. The MCP server, the relay, and the broker all live as systemd units on the same EC2 host per the existing `setup-broker-host.sh` pattern.

### B.2 Prerequisites (fresh laptop → demo)

1. **AWS access** — `agentkeys-admin` profile, per [`docs/cloud-setup.md`](../../cloud-setup.md).
2. **Heima chain access** — operator wallet funded on Heima mainnet (`AGENTKEYS_CHAIN=heima`).
3. **Operator workstation env** sourced: `set -a && source scripts/operator-workstation.env && set +a`.
4. **A xiaozhi.me account** with one agent (智能体) created. Free tier is fine.
5. **uv** (Python launcher) on the laptop — required for the mode-B/C/D pre-flight scripts. `brew install uv` or [official installer](https://docs.astral.sh/uv/).
6. **Rust toolchain** (matches `rust-toolchain.toml`).
7. **Foundry + Docker** are NOT prerequisites for this path (Foundry only if you also need to redeploy contracts; Docker is intentionally not used).

You do NOT need: a MagicLick toy, a Doubao/Qwen API key, Ollama, or ESP-IDF.

### B.3 Pre-flight against the repo — no cloud account needed yet

Run all four hardware-free smoke scripts first. If any fails, fix it before touching the EC2 host.

```bash
bash scripts/mcp-demo-mode-a.sh                  # curl + in-memory backend
bash scripts/mcp-demo-mode-b-protocol.sh         # Anthropic mcp SDK (uv)
bash scripts/mcp-demo-mode-c-xiaozhi-client.sh   # xiaozhi-server's ServerMCPClient
bash scripts/mcp-demo-mode-d-xiaozhi-endpoint.sh # xiaozhi-style WS relay
```

Mode D is the closest hardware-free approximation of B: it spins up a tiny mock relay that mirrors `xinnan-tech/mcp-endpoint-server`'s tool/client routing exactly, then drives the relay from a fake xiaozhi client through all three acts. When this passes, the only difference between dev and prod is the relay binary and the cloud-side talker.

### B.4 Stand up the chain + broker + workers

One-command idempotent bring-up of the existing AgentKeys infra per CLAUDE.md's "single entry point" rules:

```bash
# If the AWS account hasn't been bootstrapped yet, this provisions
# all DNS A records — including mcp.litentry.org / test-mcp.litentry.org
# — alongside DKIM/SPF/DMARC/MX. Idempotent; safe to re-run.
bash scripts/setup-cloud.sh --env-file scripts/operator-workstation.env

AGENTKEYS_CHAIN=heima bash scripts/setup-heima.sh
bash scripts/setup-broker-host.sh --upgrade
AGENTKEYS_CHAIN=heima bash scripts/verify-heima-contracts.sh
```

> **Chain targeting** — the `verify-heima-contracts.sh` invocation above
> reads contract addresses from `scripts/operator-workstation.env` (the
> default `$ENV_FILE`). With `AGENTKEYS_CHAIN=heima` it verifies the
> **live v2 stage-1 contracts on Heima mainnet** (the addresses in
> [`docs/spec/deployed-contracts.md`](deployed-contracts.md)) — there is no
> separate "test" set of contracts. Demo isolation is per-actor (fresh
> `operator_omni` / `actor_omni` / `device_key_hash` per run, cap-mint
> enforces device binding on chain). For an off-prod env file (e.g. a
> staging operator-workstation file), set `ENV_FILE=/path/to/x.env`
> ahead of the command — `setup-heima.sh --test` already does this for
> its own test path.

Capture for the next step:

- `BROKER_URL=https://broker.litentry.org`
- `MEMORY_WORKER_URL=https://memory.litentry.org`
- `AUDIT_WORKER_URL=https://audit.litentry.org`
- A real actor omni from `heima-agent-register.sh` (32-byte hex).
- A device key hash from `heima-device-register.sh` (32-byte hex).

### B.5 Deploy the MCP server on the broker (hosted-LLM path — issue #152, deferred)

> **Moved.** The broker-hosted MCP endpoint is the **Hosted-LLM** path (a remote vendor LLM connects *inward* over WSS) — tracked in [#152](https://github.com/litentry/agentKeys/issues/152) and **deferred**. It is a broker-host concern, so it no longer lives in `setup-cloud.sh` (which is IAM/permission-only). The old `setup-cloud.sh --only-step 15` SSM-ran `setup-mcp-host.sh`, cloning `main` and cold-building via `cargo install --git` (~10–20 min EVERY run). Enable it on the broker with [`setup-mcp-host.sh`](../../../scripts/setup-mcp-host.sh) (cached incremental `cargo build -p` against the checkout); thereafter `setup-broker-host.sh` re-converges it automatically — **no flag to remember**:

```bash
# On the broker (reach it via scripts/ssh-broker.sh), from the /opt/agentkeys-src checkout:
sudo bash /opt/agentkeys-src/scripts/setup-mcp-host.sh            # prod  → mcp.${ZONE}
sudo bash /opt/agentkeys-src/scripts/setup-mcp-host.sh --test     # test → test-mcp.${ZONE}
```

Once the MCP binary is installed, every `setup-broker-host.sh` run keeps it converged (idempotent), so routine broker setups need nothing extra. **The Local-LLM / Task-agent wire demo does NOT need this** — that MCP server runs in the agent's own sandbox (see [`docs/operator-runbook-wire.md`](../../operator-runbook-wire.md) + `harness/phase1-wire-demo.sh`).

**Local development install (laptop / Claude Code / Codex CLI / Claude Desktop):**

```bash
cargo install --git https://github.com/litentry/agentKeys agentkeys-mcp-server
```

This is the canonical install path until M6 ships GH Releases + a native installer ([#134](https://github.com/litentry/agentKeys/issues/134)). Binary lands at `~/.cargo/bin/agentkeys-mcp-server`. Then wire it into your LLM host:

```bash
# Claude Code — user scope, available in every project
claude mcp add --scope user agentkeys \
  -e MCP_TRANSPORT=stdio -e MCP_BACKEND=in-memory \
  -- ~/.cargo/bin/agentkeys-mcp-server

# Codex CLI — append to ~/.codex/config.toml:
#   [mcp_servers.agentkeys]
#   command = "~/.cargo/bin/agentkeys-mcp-server"
#   env = { MCP_TRANSPORT = "stdio", MCP_BACKEND = "in-memory" }

# Claude Desktop (macOS) — merge into ~/Library/Application Support/Claude/claude_desktop_config.json:
#   { "mcpServers": { "agentkeys": { "command": "~/.cargo/bin/agentkeys-mcp-server",
#       "env": { "MCP_TRANSPORT": "stdio", "MCP_BACKEND": "in-memory" } } } }
```

Switch `MCP_BACKEND=in-memory` → `MCP_BACKEND=http` and set `AGENTKEYS_BROKER_URL` / `AGENTKEYS_MEMORY_URL` / `AGENTKEYS_AUDIT_URL` to point at a real broker.

**setup-mcp-host.sh modes (when running on broker directly).** The script has two relay modes; setup-cloud.sh step 15 defaults to mode A (recommended).

- **Mode A — xiaozhi-hosted (DEFAULT).** Xiaozhi.me hosts the relay; the script just runs `agentkeys-mcp-server` pointing at xiaozhi's WS URL. No nginx, no certbot, no `mcp.litentry.org` DNS needed.

  ```bash
  bash scripts/setup-mcp-host.sh --xiaozhi-endpoint 'wss://api.xiaozhi.me/mcp/?token=…'
  bash scripts/setup-mcp-host.sh                                   # re-run; URL loaded from disk
  ```

- **Mode B — self-hosted relay (custom endpoints).** Operator runs their own `mcp-endpoint-server` behind nginx with a real cert. Needs the `mcp.litentry.org` DNS A record from `setup-cloud.sh` step 6.

  ```bash
  bash scripts/setup-mcp-host.sh --self-hosted-relay              # prod → mcp.litentry.org
  bash scripts/setup-mcp-host.sh --self-hosted-relay --test       # test → test-mcp.litentry.org
  ```

> **ACME account email** — Let's Encrypt records one email per ACME account; used for cert-expiry / renewal-failure notifications. The script picks one of three behaviors:
> 1. If `/etc/letsencrypt/accounts/` already has a registered ACME account (very common — `setup-broker-host.sh` will have registered one for the broker host), the new cert is issued against that account. **No email flag needed.** This is the normal path.
> 2. If you pass `--certbot-email <addr>`, that address is used. Pick any mailbox you actually monitor — a team alias if Litentry has one (`agentkeys@litentry.org` / `infra@litentry.org`), or your personal address.
> 3. If neither applies, the script falls through to `--register-unsafely-without-email` — cert still issues; no expiry notifications. You can re-run later with `--certbot-email` to attach a recovery address.

> **DNS A record** — the A record for `$MCP_HOST` (prod `mcp.litentry.org`, test `test-mcp.litentry.org`) is provisioned by `scripts/setup-cloud.sh` step 6 alongside the broker + signer + worker subdomains — one batched Route53 UPSERT, all 7 A records point at the same EIP. Run it once at account bootstrap:
>
> ```bash
> set -a && source scripts/operator-workstation.env && set +a    # or .test.env + --test
> bash scripts/setup-cloud.sh --env-file scripts/operator-workstation.env --only-step 6
> ```
>
> If you run `setup-mcp-host.sh` before that, step 8 polls public DNS for 3 min, then skips the cert and prints the exact command to fix it. Services (relay + MCP server) stay up — TLS activates on the re-run after DNS is live.

What the script lands:

- `/opt/agentkeys/mcp-endpoint/src/` — pinned clone of `xinnan-tech/mcp-endpoint-server` (default ref: `main`; override with `--relay-ref <sha>`).
- `/opt/agentkeys/mcp-endpoint/src/.venv/` — Python venv with the relay's requirements.
- `/usr/local/bin/agentkeys-mcp-server` — release binary, installed via `cargo install --git $AGENTKEYS_REPO_URL --branch $AGENTKEYS_REV` (defaults `litentry/agentKeys` + `main`). Cached at `~/.cache/agentkeys-mcp-install/` and `install`ed to `/usr/local/bin/` only when its sha256 drifts.
- `/etc/agentkeys/mcp.env` — `MCP_ENDPOINT=ws://127.0.0.1:8004/mcp_endpoint/mcp/?token=<auto-generated>` + the broker/memory/audit URLs (0600, owned by the run user).
- `/etc/agentkeys/mcp-tool-token` + `/etc/agentkeys/mcp-health-key` — the persistent secrets the URL tokens are derived from. Generated on first run only; subsequent runs preserve them so the relay URLs stay stable across deploys.
- `/etc/systemd/system/mcp-endpoint-server.service` + `/etc/systemd/system/agentkeys-mcp-server.service` — diff-then-write; daemon-reload + restart only when content changed.
- `/etc/nginx/sites-available/mcp.litentry.org` — vhost terminating TLS for `mcp.litentry.org`, upgrading `wss://` to `ws://127.0.0.1:8004/`, with HTTP→HTTPS redirect and the `Upgrade`/`Connection` headers required for WebSocket. Reload only when content changed.
- Let's Encrypt cert via `certbot --nginx -d mcp.litentry.org` — reused on subsequent runs.

Outputs at the end of each run — capture for §B.7:

```text
Tool URL  (this MCP server connects here):
  wss://mcp.litentry.org/mcp_endpoint/mcp/?token=<TOKEN>
Client URL (xiaozhi cloud / xiaozhi-server connects here):
  wss://mcp.litentry.org/mcp_endpoint/call/?token=<TOKEN>
Health URL (智控台 health probe):
  https://mcp.litentry.org/mcp_endpoint/health?key=<KEY>
```

Verify both services are alive:

```bash
sudo journalctl -u mcp-endpoint-server -n 30 --no-pager
sudo journalctl -u agentkeys-mcp-server -n 30 --no-pager
# Expected log line on the MCP server after the relay accepts it:
#   INFO agentkeys_mcp_server: mcp-endpoint: connected; awaiting MCP frames
```

If the MCP server fails to connect, the binary backs off and retries 1–600s exponentially (mirrors `mcp_pipe.py`). It will pick up automatically once the relay is healthy.

> **Why wss + domain name** — the xiaozhi cloud's 智控台 won't accept a plain `http://<eip>:8004/...` URL in production. TLS termination at nginx for `mcp.litentry.org` lets you paste a `wss://` URL into 智控台 and have it round-trip through the same vhost that fronts the broker.

### B.6 Clone and run xiaozhi-server (single-module path)

> Skip if you are using **智控台 full-module deploy** (xiaozhi cloud hosts the server). Only needed when you want to run xiaozhi-server locally — e.g. a laptop demo or a staging env.

**Clone:**

```bash
git clone https://github.com/xinnan-tech/xiaozhi-esp32-server
cd xiaozhi-esp32-server
```

**Install dependencies** (requires Python 3.10+; `uv` or plain `pip` both work):

```bash
uv sync          # faster — recommended
# or: pip install -r requirements.txt
```

**Copy config and set the MCP endpoint URL:**

```bash
cp data/config.yaml data/.config.yaml   # note the leading dot
```

Open `data/.config.yaml` and add the `mcp_endpoint` key. Use the **Tool URL** printed at the end of `scripts/setup-mcp-host.sh` (§B.5):

```yaml
# data/.config.yaml — minimal changes from defaults

server:
  websocket: ws://0.0.0.0:8000/xiaozhi/v1/
  http_port: 8002

mcp_endpoint: "wss://mcp.litentry.org/mcp_endpoint/mcp/?token=<TOKEN-from-B.5>"
```

**Env vars for the server** — none beyond the config file. All LLM, STT, and TTS
settings already point at the xiaozhi cloud in the default `config.yaml`. No
Doubao/Qwen key, no Ollama, no local GPU.

**Start:**

```bash
uv run python app/main.py
```

Expected startup output:

```text
INFO:     Application startup complete.
mcp接入点是 wss://mcp.litentry.org/mcp_endpoint/mcp/?token=…
当前支持的函数列表: ['agentkeys_memory_get', 'agentkeys_memory_put',
  'agentkeys_permission_check', 'agentkeys_cap_mint', 'agentkeys_cap_revoke',
  'agentkeys_audit_append', 'agentkeys_identity_whoami', ...]
```

When the function list appears the relay is routing correctly and the three acts are ready (§B.8).

> **Vendor token vs relay token** — for the xiaozhi relay path there is no separate vendor token to mint. The `?token=…` appended to the relay URL IS the auth token; it was auto-generated by `setup-mcp-host.sh` during §B.5 and is stable across re-deploys. Bearer-token vendor auth applies only to direct HTTP calls to the MCP server (mode A/B dev demo) — xiaozhi-server never makes those calls.

> **Broker URLs** — already wired into the MCP server's `/etc/agentkeys/mcp.env` by `setup-mcp-host.sh` (§B.5). The defaults `https://broker.litentry.org`, `https://memory.litentry.org`, `https://audit.litentry.org` are set there. If you deploy against a different broker host, update `AGENTKEYS_BROKER_URL` / `AGENTKEYS_MEMORY_URL` / `AGENTKEYS_AUDIT_URL` in that file and `sudo systemctl restart agentkeys-mcp-server`.

### B.7 Register the relay URL on your xiaozhi.me agent (智控台)

There are two registration paths depending on how you deploy xiaozhi-server. The official guide is at [`docs/mcp-endpoint-enable.md`](https://github.com/xinnan-tech/xiaozhi-esp32-server/blob/main/docs/mcp-endpoint-enable.md); the short version:

**Full-module (智控台) deploy:**

1. 智控台 → 参数字典 → 系统功能配置 → enable `MCP接入点` and save.
2. 智控台 → 参数字典 → 参数管理 → search `server.mcp_endpoint` and paste the **Health URL** printed at the end of `setup-mcp-host.sh`:
   `https://mcp.litentry.org/mcp_endpoint/health?key=<KEY>`.
3. 智控台 → 智能体管理 → 配置角色 → 编辑功能 → MCP接入点 → save.

**Single-module deploy:**

Edit `data/.config.yaml` (note the leading dot + `data/` prefix; verified against `xinnan-tech/xiaozhi-esp32-server@7f73dae`):

```yaml
server:
  websocket: ws://<host>:<port>/xiaozhi/v1/
  http_port: 8002

mcp_endpoint: wss://mcp.litentry.org/mcp_endpoint/mcp/?token=<TOKEN-from-setup-mcp-host.sh>
```

Restart xiaozhi-server. The startup log should now print `mcp接入点是 ws://...`. When your agent connects, look for: `当前支持的函数列表: [..., 'agentkeys_permission_check', 'agentkeys_memory_get', 'agentkeys_cap_mint', ...]`.

### B.8 Run the three acts

Any voice device already paired with your xiaozhi agent works. Or use xiaozhi-server's text-input diagnostic to skip the audio loop entirely (no MagicLick toy required).

1. **Act 1**: ask *"我这周末去哪里玩？"* (Where am I going this weekend?)
   - Expected: the cloud LLM calls `agentkeys.memory.get(namespace="travel")`, the relay forwards to the MCP server, the MCP server hits the live memory worker, the LLM synthesizes a TTS reply naming Chengdu.
   - **Verify**: `journalctl -u agentkeys-mcp-server -f` shows the tool call land; `journalctl -u mcp-endpoint-server -f` shows the relay forwarding.
2. **Act 2**: ask *"帮我点 600 块的火锅"* (Order me 600 RMB of hotpot.)
   - Expected: `agentkeys.permission.check` returns `verdict=deny, reason=daily_spend_cap_exceeded, explanation=cap=500, requested=600, period=daily`. The LLM refuses politely.
   - **Verify**: tail the MCP server log; the verdict came from `crate::policy::PolicyEngine`, deterministic and pure.
3. **Act 3**: From the parent-control UI (or via curl through the relay against the same agent) call `agentkeys.cap.revoke(<cap_id>)`. Re-ask "帮我点 200 块的火锅" — `permission.check` denies via the revoked cap path (or, in M1, succeeds because broker revoke is an M4 follow-up; the demo here is of the *flow*).

### B.9 What to capture for the vendor pitch

- A 15-second video of Act 1 (cloud LLM names the city correctly).
- A 15-second video of Act 2 (cloud LLM refuses politely; the parent UI shows the audit row).
- A screenshot of the chain explorer showing the audit anchor batch in the next 2-min window.
- Time from voice trigger to MCP tool call landing on the broker — should be <500 ms for `permission.check`, ~1 s for `memory.get` (S3 + decrypt round trip).

### B.10 Tear down

```bash
sudo systemctl disable --now agentkeys-mcp-server mcp-endpoint-server
# Broker + workers stay up — shared infra. Only stop them when decommissioning the env.
```

### B.11 What's verified vs operator-driven

**Verified — automatable, no hardware, no LLM key, no xiaozhi account needed** (run in CI):

- ✅ MCP wire protocol over Streamable HTTP (`mode-b-protocol.sh`).
- ✅ xiaozhi-server's `ServerMCPClient` integration code (`mode-c-xiaozhi-client.sh`).
- ✅ xiaozhi-style relay topology (tool side + client side, same token, two ws paths) — `mode-d-xiaozhi-endpoint.sh` spins up a mock relay and runs every act through it.
- ✅ Hardened dev demo with 19 assertions, port-free preflight, JSON-RPC parse, content-dependent envelope hash, hex32 wire-compatible fixtures (`mode-a.sh`).

**Operator-driven — needs a live deploy + a xiaozhi.me account**:

- ☁️ Live broker + workers (one-command via `setup-broker-host.sh` + `setup-heima.sh`).
- 🔑 `mcp-endpoint-server` deployed as systemd next to the broker.
- 🆔 xiaozhi.me agent created and the relay URL registered (智控台 or `data/.config.yaml`).
- 📞 At least one xiaozhi device (any model, no firmware change) paired with the agent for Acts 1–3 over voice. Alternatively: text-input diagnostic mode on xiaozhi-server skips the audio loop entirely.

**Known gaps to fold back when you run it**:

- Parent-control UI (#111) — until it lands, simulate Act 3's revoke via a curl call through the relay between the two voice prompts.
- Live broker `/v1/revoke/cap/:id` lands in M4 — until then, `cap.revoke` is the structured stub on the MCP server.
- Vendor token mint is hand-edited into `MCP_VENDOR_TOKENS` for the HTTP transport. The mcp-endpoint transport bypasses vendor tokens (the relay URL token is the binding) so this isn't on the critical path for B.
- The MCP-server systemd unit is already re-converged by `setup-broker-host.sh` once installed (state-driven, no flag — #152). Follow-up: bring the `mcp-endpoint` relay unit under the same auto-convergence so both come up from state with nothing to pass.
---

## Where to file demo-specific bugs

- MCP server bug (this crate's code path) → issue on `litentry/agentKeys` labeled `area/mcp`.
- xiaozhi-server bug → upstream at `xinnan-tech/xiaozhi-esp32-server`.
- MagicLick firmware bug → upstream at `xiaozhi-esp32` repo.
- Broker / worker bug → `litentry/agentKeys` labeled `area/broker` / `area/worker`.

## See also

- [`docs/spec/plans/issue-107-mcp-server-phase1.md`](issue-107-mcp-server-phase1.md) — the canonical plan + landed-vs-deferred table for #107.
- [`docs/agent-iam-strategy.md`](../../agent-iam-strategy.md) §4.3 — the three-act demo storyboard.
- [`docs/research/xiaozhi-hermes-architecture.md`](../../research/xiaozhi-hermes-architecture.md) — why xiaozhi-server's stock MCP support means no fork needed.
- [`crates/agentkeys-mcp-server/README.md`](../../../crates/agentkeys-mcp-server/README.md) — server-side ops reference.
